//! Browser WebRTC DataChannel stream used by the Snowflake client transport.

use crate::error::{Result, TorError};
use crate::snowflake_broker::BrokerClient;
use futures::channel::mpsc;
use futures::{AsyncRead, AsyncWrite, FutureExt, StreamExt};
use js_sys::{Array, Object, Reflect};
use std::cell::RefCell;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};
use tracing::{info, trace, warn};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{
    RtcConfiguration, RtcDataChannel, RtcDataChannelInit, RtcDataChannelState,
    RtcIceGatheringState, RtcPeerConnection, RtcSdpType, RtcSessionDescriptionInit,
};

const DATA_CHANNEL_LABEL: &str = "webrtc";
const ICE_GATHERING_TIMEOUT_MS: u32 = 10_000;
const DATA_CHANNEL_TIMEOUT_MS: u32 = 10_000;

pub struct WebRtcStream {
    peer_connection: RtcPeerConnection,
    data_channel: RtcDataChannel,
    receiver: mpsc::UnboundedReceiver<io::Result<Vec<u8>>>,
    buffered: Vec<u8>,
    _on_message: Closure<dyn FnMut(web_sys::MessageEvent)>,
    _on_error: Closure<dyn FnMut(web_sys::Event)>,
    _on_close: Closure<dyn FnMut(web_sys::Event)>,
}

impl WebRtcStream {
    pub async fn connect(
        broker_url: &str,
        fingerprint: &str,
        stun_urls: &[String],
    ) -> Result<Self> {
        if stun_urls.is_empty() {
            return Err(TorError::configuration(
                "Snowflake WebRTC requires at least one STUN URL",
            ));
        }

        info!("Creating Snowflake WebRTC connection");
        let configuration = create_rtc_configuration(stun_urls)?;
        let peer_connection = RtcPeerConnection::new_with_configuration(&configuration)
            .map_err(|error| {
                TorError::network(format!("Failed to create RTCPeerConnection: {error:?}"))
            })?;
        let data_channel = peer_connection.create_data_channel_with_data_channel_dict(
            DATA_CHANNEL_LABEL,
            &RtcDataChannelInit::new(),
        );
        data_channel.set_binary_type(web_sys::RtcDataChannelType::Arraybuffer);

        let (sender, receiver) = mpsc::unbounded();
        let message_sender = sender.clone();
        let error_sender = sender.clone();
        let close_sender = sender;

        let on_message = Closure::wrap(Box::new(move |event: web_sys::MessageEvent| {
            match event.data().dyn_into::<js_sys::ArrayBuffer>() {
                Ok(buffer) => {
                    let bytes = js_sys::Uint8Array::new(&buffer).to_vec();
                    if bytes.is_empty() {
                        return;
                    }
                    trace!("Snowflake WebRTC received {} bytes", bytes.len());
                    let _ = message_sender.unbounded_send(Ok(bytes));
                }
                Err(_) => {
                    let _ = message_sender.unbounded_send(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Snowflake WebRTC received a non-binary message",
                    )));
                }
            }
        }) as Box<dyn FnMut(web_sys::MessageEvent)>);
        data_channel.set_onmessage(Some(on_message.as_ref().unchecked_ref()));

        let on_error = Closure::wrap(Box::new(move |_: web_sys::Event| {
            let _ = error_sender.unbounded_send(Err(io::Error::other(
                "Snowflake WebRTC DataChannel error",
            )));
        }) as Box<dyn FnMut(web_sys::Event)>);
        let on_close = Closure::wrap(Box::new(move |_: web_sys::Event| {
            close_sender.close_channel();
        }) as Box<dyn FnMut(web_sys::Event)>);
        data_channel.set_onclose(Some(on_close.as_ref().unchecked_ref()));

        // Own the browser callbacks before negotiation starts so every error
        // path clears them and closes the peer connection through Drop.
        let stream = Self {
            peer_connection,
            data_channel,
            receiver,
            buffered: Vec::new(),
            _on_message: on_message,
            _on_error: on_error,
            _on_close: on_close,
        };

        let offer = create_offer(&stream.peer_connection).await?;
        let answer = BrokerClient::new(broker_url, fingerprint)
            .negotiate(offer)
            .await?;
        set_answer(&stream.peer_connection, &answer).await?;
        wait_for_channel_open(&stream.data_channel).await?;
        stream
            .data_channel
            .set_onerror(Some(stream._on_error.as_ref().unchecked_ref()));
        info!("Snowflake WebRTC DataChannel opened");

        Ok(stream)
    }

    fn send(&self, data: &[u8]) -> Result<()> {
        if self.data_channel.ready_state() != RtcDataChannelState::Open {
            return Err(TorError::network("Snowflake WebRTC DataChannel is not open"));
        }
        self.data_channel
            .send_with_u8_array(data)
            .map_err(|error| TorError::network(format!("WebRTC send failed: {error:?}")))
    }
}

fn create_rtc_configuration(stun_urls: &[String]) -> Result<RtcConfiguration> {
    let configuration = RtcConfiguration::new();
    let servers = Array::new();
    for stun_url in stun_urls {
        if !stun_url.starts_with("stun:") {
            return Err(TorError::configuration(format!(
                "Invalid STUN URL for Snowflake WebRTC: {stun_url}"
            )));
        }
        let server = Object::new();
        Reflect::set(
            &server,
            &JsValue::from_str("urls"),
            &JsValue::from_str(stun_url),
        )
        .map_err(|_| {
            TorError::Internal("Failed to configure a Snowflake STUN URL".to_string())
        })?;
        servers.push(&server);
    }
    configuration.set_ice_servers(&servers);
    Ok(configuration)
}

async fn create_offer(peer_connection: &RtcPeerConnection) -> Result<String> {
    let offer = wasm_bindgen_futures::JsFuture::from(peer_connection.create_offer())
        .await
        .map_err(|error| TorError::network(format!("Failed to create SDP offer: {error:?}")))?;
    let offer: RtcSessionDescriptionInit = offer.unchecked_into();
    wasm_bindgen_futures::JsFuture::from(peer_connection.set_local_description(&offer))
        .await
        .map_err(|error| TorError::network(format!("Failed to set SDP offer: {error:?}")))?;

    wait_for_ice_gathering(peer_connection).await?;
    let description = peer_connection
        .local_description()
        .ok_or_else(|| TorError::Internal("WebRTC local description is unavailable".to_string()))?;
    let sdp = description.sdp();
    let candidate_count = sdp.matches("a=candidate:").count();
    info!("Snowflake SDP contains {candidate_count} ICE candidates");
    if candidate_count == 0 {
        return Err(TorError::network(
            "Snowflake WebRTC gathered no ICE candidates",
        ));
    }

    serde_json::to_string(&serde_json::json!({ "type": "offer", "sdp": sdp }))
        .map_err(|error| TorError::serialization(format!("Failed to encode SDP offer: {error}")))
}

async fn set_answer(peer_connection: &RtcPeerConnection, encoded: &str) -> Result<()> {
    let value: serde_json::Value = serde_json::from_str(encoded)
        .map_err(|error| TorError::tor_protocol(format!("Invalid SDP answer: {error}")))?;
    let sdp = value
        .get("sdp")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| TorError::tor_protocol("Snowflake SDP answer has no sdp field"))?;
    let answer = RtcSessionDescriptionInit::new(RtcSdpType::Answer);
    answer.set_sdp(sdp);
    wasm_bindgen_futures::JsFuture::from(peer_connection.set_remote_description(&answer))
        .await
        .map_err(|error| TorError::network(format!("Failed to set SDP answer: {error:?}")))?;
    Ok(())
}

async fn wait_for_ice_gathering(peer_connection: &RtcPeerConnection) -> Result<()> {
    if peer_connection.ice_gathering_state() == RtcIceGatheringState::Complete {
        return Ok(());
    }

    let (sender, receiver) = futures::channel::oneshot::channel();
    let sender = Rc::new(RefCell::new(Some(sender)));
    let callback_sender = sender.clone();
    let callback_connection = peer_connection.clone();
    let callback = Closure::wrap(Box::new(move |_: web_sys::Event| {
        if callback_connection.ice_gathering_state() == RtcIceGatheringState::Complete {
            if let Some(sender) = callback_sender.borrow_mut().take() {
                let _ = sender.send(());
            }
        }
    }) as Box<dyn FnMut(web_sys::Event)>);
    peer_connection.set_onicegatheringstatechange(Some(callback.as_ref().unchecked_ref()));
    if peer_connection.ice_gathering_state() == RtcIceGatheringState::Complete {
        if let Some(sender) = sender.borrow_mut().take() {
            let _ = sender.send(());
        }
    }

    let timeout = gloo_timers::future::TimeoutFuture::new(ICE_GATHERING_TIMEOUT_MS);
    futures::select! {
        result = receiver.fuse() => {
            result.map_err(|_| TorError::network("Snowflake ICE gathering was cancelled"))?;
        }
        _ = timeout.fuse() => {
            warn!("Snowflake ICE gathering timed out; using candidates gathered so far");
        }
    }

    peer_connection.set_onicegatheringstatechange(None);
    Ok(())
}

async fn wait_for_channel_open(data_channel: &RtcDataChannel) -> Result<()> {
    if data_channel.ready_state() == RtcDataChannelState::Open {
        return Ok(());
    }

    let (sender, receiver) = futures::channel::oneshot::channel::<Result<()>>();
    let sender = Rc::new(RefCell::new(Some(sender)));
    let open_sender = sender.clone();
    let on_open = Closure::wrap(Box::new(move |_: web_sys::Event| {
        if let Some(sender) = open_sender.borrow_mut().take() {
            let _ = sender.send(Ok(()));
        }
    }) as Box<dyn FnMut(web_sys::Event)>);
    let error_sender = sender;
    let on_error = Closure::wrap(Box::new(move |_: web_sys::Event| {
        if let Some(sender) = error_sender.borrow_mut().take() {
            let _ = sender.send(Err(TorError::network(
                "Snowflake WebRTC DataChannel failed to open",
            )));
        }
    }) as Box<dyn FnMut(web_sys::Event)>);
    data_channel.set_onopen(Some(on_open.as_ref().unchecked_ref()));
    data_channel.set_onerror(Some(on_error.as_ref().unchecked_ref()));

    let timeout = gloo_timers::future::TimeoutFuture::new(DATA_CHANNEL_TIMEOUT_MS);
    let result = futures::select! {
        result = receiver.fuse() => result
            .map_err(|_| TorError::network("Snowflake DataChannel open was cancelled"))?,
        _ = timeout.fuse() => Err(TorError::timeout(
            "Snowflake WebRTC DataChannel did not open within 10 seconds",
        )),
    };
    data_channel.set_onopen(None);
    data_channel.set_onerror(None);
    result
}

impl Drop for WebRtcStream {
    fn drop(&mut self) {
        self.data_channel.set_onmessage(None);
        self.data_channel.set_onerror(None);
        self.data_channel.set_onclose(None);
        self.data_channel.set_onopen(None);
        self.data_channel.close();
        self.peer_connection.close();
    }
}

impl AsyncRead for WebRtcStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if !self.buffered.is_empty() {
            let length = output.len().min(self.buffered.len());
            output[..length].copy_from_slice(&self.buffered[..length]);
            self.buffered.drain(..length);
            return Poll::Ready(Ok(length));
        }

        match self.receiver.poll_next_unpin(context) {
            Poll::Ready(Some(Ok(data))) => {
                let length = output.len().min(data.len());
                output[..length].copy_from_slice(&data[..length]);
                self.buffered.extend_from_slice(&data[length..]);
                Poll::Ready(Ok(length))
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Err(error)),
            Poll::Ready(None) => Poll::Ready(Ok(0)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for WebRtcStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.send(input) {
            Ok(()) => Poll::Ready(Ok(input.len())),
            Err(error) => Poll::Ready(Err(io::Error::other(error.to_string()))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.data_channel.close();
        Poll::Ready(Ok(()))
    }
}
