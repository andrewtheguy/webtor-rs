//! HTTP over a Tor directory stream.
//!
//! A directory cache answers HTTP/1.0 on a `BEGIN_DIR` stream, and two
//! unrelated things need that: assembling a directory out of the documents an
//! authority signs, and publishing an onion service descriptor. Neither is
//! about the other, so what they share is here — the request shapes, the
//! response framing, and the decoding — and nothing in this module knows what
//! any of those documents mean.

use crate::error::{Result, TorError};
use flate2::read::ZlibDecoder;
use futures::{AsyncReadExt, AsyncWriteExt};
use std::io::Read;
use std::sync::Arc;
use tor_proto::client::ClientTunnel;

/// Bounds what one directory response off a Tor stream may buffer. The bridge
/// serving it is untrusted, so this caps an endless stream and a decompression
/// bomb; it does not bound directory data supplied by the embedding page.
const MAX_DIRECTORY_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
/// A response whose headers run past this is not one a directory sent. Every
/// path here reads its headers through `directory_response_metadata`, so this
/// is the one place the bound is applied.
const MAX_DIRECTORY_HEADER_BYTES: usize = 8 * 1024;

/// GET one document from the directory cache at the end of `tunnel`, with
/// the request shape Tor clients use, and return the decoded body.
pub(crate) async fn fetch_directory_document(
    tunnel: &Arc<ClientTunnel>,
    path: &str,
) -> Result<String> {
    let mut stream = tunnel
        .clone()
        .begin_dir_stream()
        .await
        .map_err(|e| TorError::Internal(format!("Failed to begin dir stream: {}", e)))?;
    let request = format!(
        "GET {} HTTP/1.0\r\n\
         Host: directory\r\n\
         Accept-Encoding: deflate\r\n\
         Connection: close\r\n\
         \r\n",
        path
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| TorError::Network(format!("Failed to write dir request: {}", e)))?;
    stream
        .flush()
        .await
        .map_err(|e| TorError::Network(format!("Failed to flush dir request: {}", e)))?;
    let response = read_directory_response(&mut stream).await?;
    let body = decode_directory_response(&response)?;
    String::from_utf8(body)
        .map_err(|e| TorError::serialization(format!("Directory document is not UTF-8: {}", e)))
}

/// POST one document to the directory cache at the end of `tunnel`, with the
/// request shape a Tor onion service uses to publish its descriptor. The
/// response body is empty; only its status matters.
pub(crate) async fn post_directory_document(
    tunnel: &Arc<ClientTunnel>,
    path: &str,
    document: &str,
) -> Result<()> {
    let mut stream = tunnel
        .clone()
        .begin_dir_stream()
        .await
        .map_err(|e| TorError::Internal(format!("Failed to begin dir stream: {}", e)))?;
    // The same request shape Arti sends: no Host, no Content-Type, and the
    // encodings every Tor speaks.
    let request = format!(
        "POST {} HTTP/1.0\r\n\
         Accept-Encoding: deflate, identity\r\n\
         Content-Length: {}\r\n\
         \r\n{}",
        path,
        document.len(),
        document
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| TorError::Network(format!("Failed to write dir request: {}", e)))?;
    stream
        .flush()
        .await
        .map_err(|e| TorError::Network(format!("Failed to flush dir request: {}", e)))?;
    // A stored descriptor is answered with a status line and nothing else, and
    // the relay may hold the stream open afterwards — so this reads to the end
    // of the headers rather than to end of stream.
    let status = read_directory_status(&mut stream).await?;
    if status != 200 {
        return Err(TorError::DirectoryStatus(status));
    }
    Ok(())
}

/// Read one directory response's headers and return its HTTP status.
async fn read_directory_status<R>(stream: &mut R) -> Result<u16>
where
    R: futures::AsyncRead + Unpin,
{
    let mut response = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        if let Some((body_start, _)) = directory_response_metadata(&response)? {
            let header_text = std::str::from_utf8(&response[..body_start - 4]).map_err(|e| {
                TorError::ConsensusFetch(format!("Directory response headers are not UTF-8: {e}"))
            })?;
            return parse_directory_status(header_text);
        }
        let read = stream.read(&mut buffer).await.map_err(|e| {
            TorError::Network(format!("Failed to read directory response: {e}"))
        })?;
        if read == 0 {
            return Err(TorError::ConsensusFetch(
                "Directory closed the stream before answering".to_string(),
            ));
        }
        response.extend_from_slice(&buffer[..read]);
    }
}

/// The status code out of a response's header block.
fn parse_directory_status(header_text: &str) -> Result<u16> {
    let status_line = header_text.lines().next().ok_or_else(|| {
        TorError::ConsensusFetch("Directory response had no HTTP status".to_string())
    })?;
    status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| {
            TorError::ConsensusFetch("Directory response had an invalid HTTP status".to_string())
        })?
        .parse::<u16>()
        .map_err(|e| {
            TorError::ConsensusFetch(format!("Directory response status was invalid: {e}"))
        })
}

async fn read_directory_response<R>(stream: &mut R) -> Result<Vec<u8>>
where
    R: futures::AsyncRead + Unpin,
{
    let mut response = Vec::new();
    let mut buffer = [0_u8; 8192];
    let mut metadata = None;

    loop {
        let read = stream
            .read(&mut buffer)
            .await
            .map_err(|e| TorError::Network(format!("Failed to read directory response: {}", e)))?;
        if read == 0 {
            break;
        }

        response.extend_from_slice(&buffer[..read]);
        if response.len() > MAX_DIRECTORY_RESPONSE_BYTES {
            return Err(TorError::ConsensusFetch(format!(
                "Directory response exceeded {} bytes",
                MAX_DIRECTORY_RESPONSE_BYTES
            )));
        }

        if metadata.is_none() {
            metadata = directory_response_metadata(&response)?;
        }
        if let Some((body_start, Some(content_length))) = metadata {
            let expected_length = body_start.checked_add(content_length).ok_or_else(|| {
                TorError::ConsensusFetch("Directory Content-Length overflowed".to_string())
            })?;
            if response.len() >= expected_length {
                response.truncate(expected_length);
                break;
            }
        }
    }

    let (body_start, content_length) = directory_response_metadata(&response)?.ok_or_else(|| {
        TorError::ConsensusFetch("Directory response had incomplete HTTP headers".to_string())
    })?;
    if let Some(content_length) = content_length {
        let actual_length = response.len().saturating_sub(body_start);
        if actual_length != content_length {
            return Err(TorError::ConsensusFetch(format!(
                "Directory response body was truncated (expected {}, received {})",
                content_length, actual_length
            )));
        }
    }

    Ok(response)
}

fn directory_response_metadata(response: &[u8]) -> Result<Option<(usize, Option<usize>)>> {
    let Some(header_end) = response.windows(4).position(|window| window == b"\r\n\r\n") else {
        if response.len() > MAX_DIRECTORY_HEADER_BYTES {
            return Err(TorError::ConsensusFetch(format!(
                "Directory response headers exceeded {MAX_DIRECTORY_HEADER_BYTES} bytes"
            )));
        }
        return Ok(None);
    };
    let body_start = header_end + 4;
    let header_text = std::str::from_utf8(&response[..header_end]).map_err(|e| {
        TorError::ConsensusFetch(format!("Directory response headers are not UTF-8: {}", e))
    })?;
    let content_length = header_text.lines().skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    });

    Ok(Some((body_start, content_length)))
}

fn decode_directory_response(response: &[u8]) -> Result<Vec<u8>> {
    let (body_start, content_length) = directory_response_metadata(response)?.ok_or_else(|| {
        TorError::ConsensusFetch("Directory response had incomplete HTTP headers".to_string())
    })?;
    let header_text = std::str::from_utf8(&response[..body_start - 4]).map_err(|e| {
        TorError::ConsensusFetch(format!("Directory response headers are not UTF-8: {}", e))
    })?;
    let status = parse_directory_status(header_text)?;
    if status != 200 {
        return Err(TorError::DirectoryStatus(status));
    }
    let mut lines = header_text.lines();
    lines.next();

    let mut content_encoding = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-encoding") {
                content_encoding = Some(value.trim().to_ascii_lowercase());
            }
        }
    }

    let body_end = content_length
        .and_then(|length| body_start.checked_add(length))
        .unwrap_or(response.len());
    if body_end > response.len() {
        return Err(TorError::ConsensusFetch(
            "Directory response body was truncated".to_string(),
        ));
    }
    let encoded_body = &response[body_start..body_end];

    match content_encoding.as_deref() {
        None | Some("identity") => Ok(encoded_body.to_vec()),
        Some("deflate") => {
            let mut decoded = Vec::new();
            ZlibDecoder::new(encoded_body)
                .take((MAX_DIRECTORY_RESPONSE_BYTES + 1) as u64)
                .read_to_end(&mut decoded)
                .map_err(|e| {
                    TorError::ConsensusFetch(format!(
                        "Failed to decompress directory response: {}",
                        e
                    ))
                })?;
            if decoded.len() > MAX_DIRECTORY_RESPONSE_BYTES {
                return Err(TorError::ConsensusFetch(format!(
                    "Decompressed directory response exceeded {} bytes",
                    MAX_DIRECTORY_RESPONSE_BYTES
                )));
            }
            Ok(decoded)
        }
        Some(encoding) => Err(TorError::ConsensusFetch(format!(
            "Directory returned unsupported Content-Encoding {}",
            encoding
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;

    #[test]
    fn directory_response_decodes_deflate_content() {
        let expected = b"network-status-version 3 microdesc\n";
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(expected).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut response = format!(
            "HTTP/1.0 200 OK\r\nContent-Encoding: deflate\r\nContent-Length: {}\r\n\r\n",
            compressed.len()
        )
        .into_bytes();
        response.extend_from_slice(&compressed);

        assert_eq!(decode_directory_response(&response).unwrap(), expected);
    }

    #[test]
    fn headers_that_never_end_are_refused_rather_than_buffered() {
        let response = vec![b'x'; MAX_DIRECTORY_HEADER_BYTES + 1];

        let error = directory_response_metadata(&response).unwrap_err();

        assert!(error.to_string().contains("headers exceeded"), "{error}");
    }

    /// The same call is how every path waits for the rest of a header block,
    /// so a partial one has to come back as "not yet" and not as an error.
    #[test]
    fn headers_within_the_bound_are_waited_for() {
        let partial = directory_response_metadata(b"HTTP/1.0 200 OK\r\n").unwrap();

        assert!(partial.is_none());
    }

    #[test]
    fn directory_response_rejects_http_errors() {
        let response = b"HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        let error = decode_directory_response(response).unwrap_err();

        assert!(matches!(error, TorError::DirectoryStatus(404)));
    }
}
