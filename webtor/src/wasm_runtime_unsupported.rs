//! The parts of [`tor_rtcompat::Runtime`] a browser cannot provide.
//!
//! `tor-proto` bounds its channel and channel-reactor generics on the whole
//! `Runtime` supertrait, but on the client path it only ever uses the runtime as
//! a `SleepProvider + CoarseTimeProvider`. The browser has no sockets, no
//! listeners, no UDP and no TLS stack of its own, so the remaining supertraits
//! are implemented here as refusals rather than as working providers.
//!
//! Everything that can report a failure returns `io::ErrorKind::Unsupported`.
//! [`Blocking`] has no error channel, so it degrades instead: `spawn_blocking`
//! runs the closure inline, which yields the right value on a target that has no
//! second thread to move it to. Only `reenter_block_on` panics, since a browser
//! thread cannot be blocked on a future at all; it is reachable only from inside
//! a thread `spawn_blocking` was supposed to have created.

use crate::wasm_runtime::WasmRuntime;
use async_trait::async_trait;
use futures::task::{FutureObj, Spawn, SpawnError};
use futures::{AsyncRead, AsyncWrite};
use std::borrow::Cow;
use std::future::Future;
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::net;
use std::pin::Pin;
use std::task::{Context, Poll};
use tor_general_addr::unix;
use tor_rtcompat::tls::TlsConnector;
use tor_rtcompat::unimpl::{FakeListener, FakeStream};
use tor_rtcompat::{
    Blocking, CertifiedConn, NetStreamProvider, StreamOps, TcpConnectOptions, TcpListenOptions,
    TlsProvider, UdpProvider, UdpSocket, UnixConnectOptions, UnixListenOptions,
};

/// Build the error every unsupported provider reports.
fn unsupported(what: &'static str) -> IoError {
    IoError::new(
        ErrorKind::Unsupported,
        format!("{what} is not available in the browser"),
    )
}

/// An uninhabited type, so the stub streams below can never be constructed.
#[derive(Clone, Copy, Debug)]
enum Never {}

impl Spawn for WasmRuntime {
    fn spawn_obj(&self, future: FutureObj<'static, ()>) -> Result<(), SpawnError> {
        wasm_bindgen_futures::spawn_local(future);
        Ok(())
    }
}

impl Blocking for WasmRuntime {
    type ThreadHandle<T: Send + 'static> = futures::future::Ready<T>;

    fn spawn_blocking<F, T>(&self, f: F) -> Self::ThreadHandle<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        // WASM has no thread to hand this to, so run it here. The caller still
        // gets its value; it just does not get the concurrency.
        futures::future::ready(f())
    }

    fn reenter_block_on<F>(&self, _future: F) -> F::Output
    where
        F: Future,
        F::Output: Send + 'static,
    {
        panic!("the browser runtime cannot block on a future");
    }
}

#[async_trait]
impl NetStreamProvider<net::SocketAddr> for WasmRuntime {
    type Stream = FakeStream;
    type Listener = FakeListener<net::SocketAddr>;
    type ConnectOptions = TcpConnectOptions;
    type ListenOptions = TcpListenOptions;

    async fn connect(
        &self,
        _addr: &net::SocketAddr,
        _options: &Self::ConnectOptions,
    ) -> IoResult<Self::Stream> {
        Err(unsupported("outgoing TCP"))
    }

    async fn listen(
        &self,
        _addr: &net::SocketAddr,
        _options: &Self::ListenOptions,
    ) -> IoResult<Self::Listener> {
        Err(unsupported("listening for TCP"))
    }
}

#[async_trait]
impl NetStreamProvider<unix::SocketAddr> for WasmRuntime {
    type Stream = FakeStream;
    type Listener = FakeListener<unix::SocketAddr>;
    type ConnectOptions = UnixConnectOptions;
    type ListenOptions = UnixListenOptions;

    async fn connect(
        &self,
        _addr: &unix::SocketAddr,
        _options: &Self::ConnectOptions,
    ) -> IoResult<Self::Stream> {
        Err(unsupported("Unix-domain sockets"))
    }

    async fn listen(
        &self,
        _addr: &unix::SocketAddr,
        _options: &Self::ListenOptions,
    ) -> IoResult<Self::Listener> {
        Err(unsupported("Unix-domain sockets"))
    }
}

/// The TLS stream the connector below never manages to return.
#[derive(Clone, Copy, Debug)]
pub struct NoTlsStream(Never);

/// A TLS connector that refuses every negotiation.
///
/// `TlsProvider::tls_connector` has to hand back a connector by value, so unlike
/// the stream types this one is constructible; it reports the refusal from
/// `negotiate_unvalidated` instead.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoTlsConnector;

#[async_trait]
impl<S: Send + 'static> TlsConnector<S> for NoTlsConnector {
    type Conn = NoTlsStream;

    async fn negotiate_unvalidated(&self, _stream: S, _sni_hostname: &str) -> IoResult<Self::Conn> {
        Err(unsupported("TLS from the runtime"))
    }
}

impl TlsProvider<FakeStream> for WasmRuntime {
    type Connector = NoTlsConnector;
    type TlsStream = NoTlsStream;
    type Acceptor = NoTlsConnector;
    type TlsServerStream = NoTlsStream;

    fn tls_connector(&self) -> Self::Connector {
        NoTlsConnector
    }

    fn tls_acceptor(
        &self,
        _settings: tor_rtcompat::tls::TlsAcceptorSettings,
    ) -> IoResult<Self::Acceptor> {
        Err(unsupported("acting as a TLS server"))
    }

    fn supports_keying_material_export(&self) -> bool {
        false
    }
}

impl AsyncRead for NoTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        match self.0 {}
    }
}

impl AsyncWrite for NoTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<IoResult<usize>> {
        match self.0 {}
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        match self.0 {}
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        match self.0 {}
    }
}

impl StreamOps for NoTlsStream {
    fn set_tcp_notsent_lowat(&self, _notsent_lowat: u32) -> IoResult<()> {
        match self.0 {}
    }

    fn new_handle(&self) -> Box<dyn StreamOps + Send + Unpin> {
        match self.0 {}
    }
}

impl CertifiedConn for NoTlsStream {
    fn export_keying_material(
        &self,
        _len: usize,
        _label: &[u8],
        _context: Option<&[u8]>,
    ) -> IoResult<Vec<u8>> {
        match self.0 {}
    }

    fn peer_certificate(&self) -> IoResult<Option<Cow<'_, [u8]>>> {
        match self.0 {}
    }

    fn own_certificate(&self) -> IoResult<Option<Cow<'_, [u8]>>> {
        match self.0 {}
    }
}

/// The UDP socket the provider below never manages to bind.
#[derive(Debug)]
pub struct NoUdpSocket(Never);

#[async_trait]
impl UdpProvider for WasmRuntime {
    type UdpSocket = NoUdpSocket;

    async fn bind(&self, _addr: &net::SocketAddr) -> IoResult<Self::UdpSocket> {
        Err(unsupported("UDP"))
    }
}

#[async_trait]
impl UdpSocket for NoUdpSocket {
    async fn recv(&self, _buf: &mut [u8]) -> IoResult<(usize, net::SocketAddr)> {
        match self.0 {}
    }

    async fn send(&self, _buf: &[u8], _target: &net::SocketAddr) -> IoResult<usize> {
        match self.0 {}
    }

    fn local_addr(&self) -> IoResult<net::SocketAddr> {
        match self.0 {}
    }
}
