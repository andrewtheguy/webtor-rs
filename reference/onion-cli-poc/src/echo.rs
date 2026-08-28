//! The echo itself: publish and answer, or connect and read back.
//!
//! One line in, the same line out. Deliberately the smallest protocol that
//! still proves a v3 onion service came up, published, and carried bytes both
//! ways — anything richer would start testing the protocol instead of the
//! onion service.
//!
//! The stdout contract is what `tests/tools/interop-cli.ts` reads:
//! `serve` prints the `.onion` address on its own line, then `ready` once
//! clients can reach it; `connect` prints the echo and nothing else. Progress
//! goes to the log, which is stderr.

use anyhow::{Context, Result, bail};
use futures::StreamExt as _;
use tokio::io::{AsyncBufReadExt, AsyncReadExt as _, AsyncWriteExt, BufReader};
use tor_cell::relaycell::msg::{Connected, End};
use tor_hscrypto::pk::HsId;
use tor_hsservice::StreamRequest;
use tor_proto::client::stream::DataStream;
use tor_proto::stream::IncomingStreamRequest;

use crate::client;

/// Total bytes either side will read from one connection. A cap keeps a peer
/// from growing our buffers without bound; anything past it reads as EOF.
const MAX_CONNECTION_BYTES: u64 = 64 * 1024;

/// Publish an ephemeral onion service and echo lines until interrupted.
pub async fn serve(port: u16) -> Result<()> {
    let tor = client::bootstrap().await?;
    let (service, requests) = client::Service::launch(&tor)?;

    println!("{}", service.address());
    log::info!(
        "publishing a descriptor for {}; this usually takes under a minute",
        service.address()
    );
    service.wait_until_reachable().await?;
    println!("ready");

    let mut requests = Box::pin(requests);
    loop {
        let request = tokio::select! {
            // Unwinding normally lets the service tell its introduction points
            // it is going away, rather than leaving them to time it out.
            result = shutdown_signal() => {
                result.context("failed to listen for a shutdown signal")?;
                log::info!("shutting down");
                return Ok(());
            }
            request = requests.next() => match request {
                Some(request) => request,
                None => bail!("the onion service stopped accepting requests"),
            },
        };

        tokio::spawn(async move {
            if let Err(e) = answer(request, port).await {
                log::warn!("echo connection failed: {e:#}");
            }
        });
    }
}

/// Accept one stream request on `port` and echo every line that arrives.
async fn answer(request: StreamRequest, port: u16) -> Result<()> {
    // A service answers one virtual port. Anything else is a client asking for
    // something this service does not publish, and is refused rather than
    // quietly answered on the wrong port.
    match request.request() {
        IncomingStreamRequest::Begin(begin) if begin.port() == port => {}
        other => {
            log::warn!("refusing an unexpected stream request: {other:?}");
            return request
                .reject(End::new_misc())
                .await
                .context("failed to refuse a stream request");
        }
    }

    let stream = request
        .accept(Connected::new_empty())
        .await
        .context("failed to accept a stream request")?;
    log::info!("echo connection open");
    echo_lines(stream).await?;
    log::info!("echo connection closed");
    Ok(())
}

/// Read lines off `stream` and write each one straight back.
async fn echo_lines(stream: DataStream) -> Result<()> {
    let (reader, mut writer) = stream.split();
    let mut lines = BufReader::new(reader.take(MAX_CONNECTION_BYTES)).lines();

    loop {
        let line = match lines.next_line().await {
            Ok(Some(line)) => line,
            Ok(None) => break,
            // The client hanging up is how a connection normally ends here,
            // and Tor reports it as an END cell rather than a clean EOF.
            Err(e) if is_disconnect(&e) => {
                log::debug!("client disconnected: {e}");
                break;
            }
            Err(e) => return Err(e).context("failed to read a line"),
        };

        log::info!("echoing {} byte(s)", line.len());
        writer
            .write_all(format!("{line}\n").as_bytes())
            .await
            .context("failed to write the echo")?;
        writer.flush().await.context("failed to flush the echo")?;
    }

    // Sends an END with reason DONE, so the client sees a clean close.
    let _ = writer.shutdown().await;
    Ok(())
}

/// Connect to `address`, send `message` as one line, and return the echo.
pub async fn connect(address: &str, port: u16, message: &str) -> Result<String> {
    if message.contains('\n') {
        bail!("the message must be a single line");
    }

    // Validate the address before bootstrapping, which otherwise spends tens of
    // seconds fetching a directory only to reject the address afterwards.
    let (host, port) = split_address(address, port)?;

    let tor = client::bootstrap().await?;
    log::info!("connecting to {host}:{port}");
    let stream = client::connect(&tor, &host, port).await?;

    let (reader, mut writer) = stream.split();
    writer
        .write_all(format!("{message}\n").as_bytes())
        .await
        .context("failed to send the message")?;
    writer.flush().await.context("failed to flush the message")?;

    let mut reply = String::new();
    match BufReader::new(reader.take(MAX_CONNECTION_BYTES))
        .read_line(&mut reply)
        .await
    {
        // Nothing read at all: the service hung up before echoing. An empty
        // echo is not this case — it arrives as the one byte `\n`.
        Ok(0) => bail!("the service closed the stream without echoing anything"),
        Ok(_) => {}
        // A partial line is discarded by `read_line`, so this is the same
        // truncation as above, just reported as an END cell instead of an EOF.
        Err(e) if is_disconnect(&e) => {
            log::debug!("service disconnected: {e}");
            bail!("the service closed the stream without echoing a full line");
        }
        Err(e) => return Err(e).context("failed to read the echo"),
    }

    // Sends an END with reason DONE rather than letting the drop look abrupt.
    let _ = writer.shutdown().await;

    Ok(reply.trim_end_matches('\n').to_owned())
}

/// Split `address` into a canonical v3 onion host and a port, falling back to
/// `default_port`.
///
/// A port in the address wins, so the line `serve` prints can be pasted
/// straight into `connect`.
///
/// The host has to be a v3 `.onion` address, checksum and all. Arti treats a
/// host without the suffix as an ordinary name and would resolve it through an
/// exit node, so a typo that drops the suffix has to be refused here rather
/// than turning into a connection to the plain internet.
fn split_address(address: &str, default_port: u16) -> Result<(String, u16)> {
    let (host, port) = match address.rsplit_once(':') {
        Some((host, port)) => (
            host,
            port.parse()
                .with_context(|| format!("invalid port in address {address:?}"))?,
        ),
        None => (address, default_port),
    };

    let host: HsId = host
        .parse()
        .with_context(|| format!("invalid v3 onion address {host:?}"))?;
    Ok((
        safelog::DisplayRedacted::display_unredacted(&host).to_string(),
        port,
    ))
}

/// Whether an I/O error just means the peer went away.
///
/// A Tor stream never ends with a plain EOF. The far side sends an END cell,
/// whose reason Arti maps to an `ErrorKind` — and the reason depends on how the
/// peer let go: a shut-down writer sends `DONE`, a dropped stream sends `MISC`.
/// So rather than enumerate reasons, treat any END as the end of the
/// conversation. If the stream is already torn down by the time we read, Arti
/// reports `NotConnected` instead and no END cell is involved.
fn is_disconnect(err: &std::io::Error) -> bool {
    use std::io::ErrorKind::{BrokenPipe, ConnectionAborted, ConnectionReset, NotConnected};

    if matches!(
        err.kind(),
        NotConnected | ConnectionReset | ConnectionAborted | BrokenPipe
    ) {
        return true;
    }

    err.get_ref()
        .and_then(|source| source.downcast_ref::<tor_proto::Error>())
        .is_some_and(|e| matches!(e, tor_proto::Error::EndReceived(_)))
}

/// Resolve when the process is asked to stop.
#[cfg(unix)]
async fn shutdown_signal() -> std::io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut term = signal(SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result,
        _ = term.recv() => Ok(()),
    }
}

/// Resolve when the process is asked to stop.
#[cfg(not(unix))]
async fn shutdown_signal() -> std::io::Result<()> {
    tokio::signal::ctrl_c().await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real address printed by a running service, so the checksum is genuine.
    const ONION: &str = "zrmxlosp6cvmkhxwhx7267wkvqyztsrmloqw76eu4fhn2gsbg5zk4kad.onion";

    #[test]
    fn a_bare_address_uses_the_default_port() {
        assert_eq!(
            split_address(ONION, crate::DEFAULT_PORT).unwrap(),
            (ONION.to_owned(), crate::DEFAULT_PORT)
        );
    }

    #[test]
    fn a_port_in_the_address_wins() {
        assert_eq!(
            split_address(&format!("{ONION}:1234"), crate::DEFAULT_PORT).unwrap(),
            (ONION.to_owned(), 1234)
        );
    }

    #[test]
    fn a_non_numeric_port_is_an_error() {
        assert!(split_address(&format!("{ONION}:"), crate::DEFAULT_PORT).is_err());
        assert!(split_address(&format!("{ONION}:http"), crate::DEFAULT_PORT).is_err());
    }

    #[test]
    fn a_non_onion_host_is_an_error() {
        // Without this, Arti would route these out through an exit node.
        assert!(split_address("example.com", crate::DEFAULT_PORT).is_err());
        assert!(split_address("example.com:80", crate::DEFAULT_PORT).is_err());
        assert!(split_address("127.0.0.1:9735", crate::DEFAULT_PORT).is_err());
    }

    #[test]
    fn a_malformed_onion_host_is_an_error() {
        // Too short to be v3, a bad checksum, and a subdomain.
        assert!(split_address("abc.onion", crate::DEFAULT_PORT).is_err());
        let mut wrong = ONION.to_owned();
        wrong.replace_range(0..1, "a");
        assert!(split_address(&wrong, crate::DEFAULT_PORT).is_err());
        assert!(split_address(&format!("www.{ONION}"), crate::DEFAULT_PORT).is_err());
    }

    #[test]
    fn the_host_comes_back_canonicalized() {
        assert_eq!(
            split_address(&ONION.to_uppercase(), crate::DEFAULT_PORT)
                .unwrap()
                .0,
            ONION
        );
    }
}
