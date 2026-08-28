//! Browser WebSocket byte stream retained for the future Snowflake path.

use crate::error::{Result, TorError};
use futures::channel::mpsc;
use futures::{AsyncRead, AsyncWrite, StreamExt};
use js_sys::{ArrayBuffer, Uint8Array};
use std::cell::RefCell;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{BinaryType, ErrorEvent, MessageEvent, WebSocket};

pub(crate) struct WebSocketStream {
    socket: WebSocket,
    receiver: mpsc::UnboundedReceiver<io::Result<Vec<u8>>>,
    read_buffer: Vec<u8>,
    _on_message: Closure<dyn FnMut(MessageEvent)>,
    _on_error: Closure<dyn FnMut(ErrorEvent)>,
    _on_close: Closure<dyn FnMut(web_sys::CloseEvent)>,
}

impl WebSocketStream {
    pub(crate) async fn connect(url: &str) -> Result<Self> {
        let socket = WebSocket::new(url)
            .map_err(|error| TorError::network(format!("WebSocket creation failed: {error:?}")))?;
        socket.set_binary_type(BinaryType::Arraybuffer);

        let (sender, receiver) = mpsc::unbounded();
        let message_sender = sender.clone();
        let error_sender = sender.clone();
        let close_sender = sender;
        let (open_sender, open_receiver) = futures::channel::oneshot::channel();
        let open_sender = Rc::new(RefCell::new(Some(open_sender)));

        let on_message = Closure::wrap(Box::new(move |event: MessageEvent| {
            let data = if let Ok(buffer) = event.data().dyn_into::<ArrayBuffer>() {
                Some(Uint8Array::new(&buffer).to_vec())
            } else {
                event.data().as_string().map(String::into_bytes)
            };
            if let Some(data) = data {
                let _ = message_sender.unbounded_send(Ok(data));
            }
        }) as Box<dyn FnMut(MessageEvent)>);
        socket.set_onmessage(Some(on_message.as_ref().unchecked_ref()));

        let error_open_sender = open_sender.clone();
        let on_error = Closure::wrap(Box::new(move |event: ErrorEvent| {
            let message = event.message();
            if let Some(sender) = error_open_sender.borrow_mut().take() {
                let _ = sender.send(Err(message.clone()));
            }
            let _ = error_sender.unbounded_send(Err(io::Error::other(message)));
        }) as Box<dyn FnMut(ErrorEvent)>);
        socket.set_onerror(Some(on_error.as_ref().unchecked_ref()));

        let close_open_sender = open_sender.clone();
        let on_close = Closure::wrap(Box::new(move |event: web_sys::CloseEvent| {
            let message = format!(
                "WebSocket closed with code {}: {}",
                event.code(),
                event.reason()
            );
            if let Some(sender) = close_open_sender.borrow_mut().take() {
                let _ = sender.send(Err(message.clone()));
            }
            if event.was_clean() {
                let _ = close_sender.unbounded_send(Ok(Vec::new()));
            } else {
                let _ = close_sender.unbounded_send(Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    message,
                )));
            }
        }) as Box<dyn FnMut(web_sys::CloseEvent)>);
        socket.set_onclose(Some(on_close.as_ref().unchecked_ref()));

        let open_callback_sender = open_sender;
        let on_open = Closure::once(move || {
            if let Some(sender) = open_callback_sender.borrow_mut().take() {
                let _ = sender.send(Ok::<(), String>(()));
            }
        });
        socket.set_onopen(Some(on_open.as_ref().unchecked_ref()));

        match open_receiver.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(TorError::network(error)),
            Err(_) => {
                return Err(TorError::network(
                    "WebSocket open callback was dropped",
                ))
            }
        }
        socket.set_onopen(None);

        Ok(Self {
            socket,
            receiver,
            read_buffer: Vec::new(),
            _on_message: on_message,
            _on_error: on_error,
            _on_close: on_close,
        })
    }
}

impl Drop for WebSocketStream {
    fn drop(&mut self) {
        self.socket.set_onopen(None);
        self.socket.set_onmessage(None);
        self.socket.set_onerror(None);
        self.socket.set_onclose(None);
        let _ = self.socket.close();
    }
}

impl AsyncRead for WebSocketStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if !self.read_buffer.is_empty() {
            let count = output.len().min(self.read_buffer.len());
            output[..count].copy_from_slice(&self.read_buffer[..count]);
            self.read_buffer.drain(..count);
            return Poll::Ready(Ok(count));
        }

        match self.receiver.poll_next_unpin(context) {
            Poll::Ready(Some(Ok(data))) => {
                let count = output.len().min(data.len());
                output[..count].copy_from_slice(&data[..count]);
                self.read_buffer.extend_from_slice(&data[count..]);
                Poll::Ready(Ok(count))
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Err(error)),
            Poll::Ready(None) => Poll::Ready(Ok(0)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for WebSocketStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.socket.send_with_u8_array(data) {
            Ok(()) => Poll::Ready(Ok(data.len())),
            Err(error) => Poll::Ready(Err(io::Error::other(format!(
                "WebSocket send failed: {error:?}"
            )))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(
            self.socket
                .close()
                .map_err(|error| io::Error::other(format!("WebSocket close failed: {error:?}"))),
        )
    }
}
