//! Async KCP stream wrapper
//!
//! This module provides an async wrapper around the `kcp` crate that works
//! with any AsyncRead + AsyncWrite transport (not just UDP sockets).
//!
//! KCP provides reliable, ordered delivery over an unreliable transport.
//!
//! Data flow:
//! - send() -> snd_queue -> update() -> flush() -> output -> transport
//! - transport -> input() -> rcv_buf -> recv() -> application

use crate::time::Instant;
use futures::{AsyncRead, AsyncWrite};
use gloo_timers::future::TimeoutFuture;
use kcp::Kcp;
use std::collections::VecDeque;
use std::future::Future;
use std::io::{self, Write};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tracing::debug;

/// How often KCP's own clock runs while the transport is quiet.
///
/// Retransmissions, window probes and any segment the send window would not
/// take when it was queued leave KCP only from `update()`. Nothing else calls
/// it once both ends fall silent, so without this a burst that fills the
/// window — several circuits created at once, or a descriptor upload — wedges
/// the connection permanently.
const TICK_MIN_MS: u32 = 10;
const TICK_MAX_MS: u32 = 100;

/// Where KCP puts the packets it wants sent.
///
/// KCP is a datagram protocol: it calls `write` once per packet, each no
/// larger than its MTU, and the peer's KCP expects to receive them the same
/// way. So each one is kept separate here and handed to the transport on its
/// own, which is what turns it into one Turbo frame. Concatenating them into
/// a single write would hand the bridge one oversized packet instead of the
/// dozen it is waiting for.
#[derive(Clone)]
struct OutputBuffer {
    packets: Arc<Mutex<VecDeque<Vec<u8>>>>,
}

impl OutputBuffer {
    fn new() -> Self {
        Self {
            packets: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    fn take(&self) -> VecDeque<Vec<u8>> {
        let mut packets = self.packets.lock().unwrap();
        std::mem::take(&mut *packets)
    }
}

impl Write for OutputBuffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.packets.lock().unwrap().push_back(buf.to_vec());
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// KCP configuration
#[derive(Debug, Clone)]
pub struct KcpConfig {
    /// Conversation ID (must match on both ends)
    pub conv: u32,
    /// Enable nodelay mode for faster retransmission
    pub nodelay: bool,
    /// Update interval in milliseconds
    pub interval: i32,
    /// Fast resend trigger (0 = off, 2 = on duplicate ACK)
    pub resend: i32,
    /// Disable congestion control
    pub nc: bool,
    /// Send window size
    pub snd_wnd: u16,
    /// Receive window size
    pub rcv_wnd: u16,
}

impl Default for KcpConfig {
    fn default() -> Self {
        Self {
            conv: 0,
            // Match Snowflake Go client settings:
            // conn.SetNoDelay(0, 0, 0, 1) means:
            // nodelay=0 (default), interval=0 (default 100ms), resend=0 (off), nc=1 (congestion off)
            nodelay: false,
            interval: 100, // Default KCP interval
            resend: 0,     // No fast resend
            nc: true,      // Disable congestion control (nc=1 in Go)
            snd_wnd: 128,
            rcv_wnd: 128,
        }
    }
}

/// Async KCP stream
pub struct KcpStream<S> {
    kcp: Kcp<OutputBuffer>,
    output: OutputBuffer,
    transport: S,
    start_time: Instant,
    /// Packets KCP has produced that the transport has not taken yet.
    pending_write: VecDeque<Vec<u8>>,
    /// Wakes the reader when KCP's clock next needs to run.
    tick: Option<TimeoutFuture>,
}

impl<S> KcpStream<S> {
    pub fn new(transport: S, config: KcpConfig) -> Self {
        let output = OutputBuffer::new();
        // Use stream mode like Snowflake Go client (SetStreamMode(true))
        let mut kcp = Kcp::new_stream(config.conv, output.clone());

        // Configure KCP to match Snowflake Go client settings
        kcp.set_nodelay(config.nodelay, config.interval, config.resend, config.nc);
        kcp.set_wndsize(config.snd_wnd, config.rcv_wnd);

        Self {
            kcp,
            output,
            transport,
            start_time: Instant::now(),
            pending_write: VecDeque::new(),
            tick: None,
        }
    }

    fn current_ms(&self) -> u32 {
        self.start_time.elapsed().as_millis() as u32
    }
}

impl<S: AsyncWrite + Unpin> KcpStream<S> {
    /// Hand KCP's packets to the transport one at a time, so each becomes its
    /// own frame, and keep whatever the transport would not take yet.
    fn drain_output(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.pending_write.append(&mut self.output.take());
        while let Some(packet) = self.pending_write.pop_front() {
            match Pin::new(&mut self.transport).poll_write(cx, &packet) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {
                    self.pending_write.push_front(packet);
                    return Poll::Pending;
                }
            }
        }
        Pin::new(&mut self.transport).poll_flush(cx)
    }

    /// Run KCP's clock while the transport has nothing to deliver, and arm
    /// the next run. Always returns `Pending`: it produces protocol traffic,
    /// never application bytes.
    fn poll_tick(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        if let Some(tick) = self.tick.as_mut() {
            match Pin::new(tick).poll(cx) {
                // The timer is still running, and holds the waker.
                Poll::Pending => return Poll::Pending,
                Poll::Ready(()) => self.tick = None,
            }
        }

        let current = self.current_ms();
        if let Err(error) = self.kcp.update(current) {
            return Poll::Ready(Err(io::Error::other(format!(
                "KCP update error: {error:?}"
            ))));
        }
        if let Poll::Ready(Err(error)) = self.drain_output(cx) {
            return Poll::Ready(Err(error));
        }

        let delay = self.kcp.check(current).clamp(TICK_MIN_MS, TICK_MAX_MS);
        let mut tick = TimeoutFuture::new(delay);
        // Poll once so the timer holds this task's waker.
        let _ = Pin::new(&mut tick).poll(cx);
        self.tick = Some(tick);
        Poll::Pending
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for KcpStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        // Try to receive from KCP first
        match self.kcp.recv(buf) {
            Ok(n) => {
                debug!("KCP read: received {} bytes from KCP queue", n);
                return Poll::Ready(Ok(n));
            }
            Err(kcp::Error::RecvQueueEmpty) => {}
            Err(e) => {
                return Poll::Ready(Err(io::Error::other(format!(
                    "KCP recv error: {:?}",
                    e
                ))))
            }
        }

        // Need more data from transport
        let mut temp = [0u8; 4096];
        match Pin::new(&mut self.transport).poll_read(cx, &mut temp) {
            Poll::Ready(Ok(0)) => {
                debug!("KCP read: transport EOF");
                Poll::Ready(Ok(0))
            }
            Poll::Ready(Ok(n)) => {
                debug!("KCP read: got {} bytes from transport, feeding to KCP", n);
                // Feed to KCP
                if let Err(e) = self.kcp.input(&temp[..n]) {
                    debug!("KCP read: input error: {:?}", e);
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("KCP input error: {:?}", e),
                    )));
                }

                // Update KCP
                let current = self.current_ms();
                if let Err(e) = self.kcp.update(current) {
                    return Poll::Ready(Err(io::Error::other(format!(
                        "KCP update error: {:?}",
                        e
                    ))));
                }

                // Send whatever that produced — ACKs above all, or the peer
                // retransmits.
                if let Poll::Ready(Err(e)) = self.drain_output(cx) {
                    return Poll::Ready(Err(e));
                }

                // Try recv again
                match self.kcp.recv(buf) {
                    Ok(n) => {
                        debug!("KCP read: received {} bytes after input", n);
                        Poll::Ready(Ok(n))
                    }
                    Err(kcp::Error::RecvQueueEmpty) => {
                        debug!("KCP read: recv queue still empty, pending");
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Err(e) => Poll::Ready(Err(io::Error::other(format!(
                        "KCP recv error: {:?}",
                        e
                    )))),
                }
            }
            Poll::Ready(Err(e)) => {
                debug!("KCP read: transport error: {}", e);
                Poll::Ready(Err(e))
            }
            // Nothing to read is when KCP's own clock has to run: see
            // `poll_tick`.
            Poll::Pending => self.poll_tick(cx),
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for KcpStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        debug!("KCP write: sending {} bytes", buf.len());

        // Queue data in KCP
        match self.kcp.send(buf) {
            Ok(n) => {
                debug!("KCP write: queued {} bytes in KCP", n);

                // Update KCP state first (required before flush)
                let current = self.current_ms();
                if let Err(e) = self.kcp.update(current) {
                    return Poll::Ready(Err(io::Error::other(format!(
                        "KCP update error: {:?}",
                        e
                    ))));
                }

                // Force flush to produce output immediately
                if let Err(e) = self.kcp.flush() {
                    return Poll::Ready(Err(io::Error::other(format!(
                        "KCP flush error: {:?}",
                        e
                    ))));
                }

                // KCP owns the bytes now, so this always reports them
                // written: answering `Pending` here would have the caller
                // offer the same buffer again and queue it twice. Anything
                // the transport would not take stays for the tick to send.
                match self.drain_output(cx) {
                    Poll::Ready(Err(e)) => {
                        debug!("KCP write: transport error: {}", e);
                        Poll::Ready(Err(e))
                    }
                    _ => Poll::Ready(Ok(n)),
                }
            }
            Err(e) => Poll::Ready(Err(io::Error::other(format!(
                "KCP send error: {:?}",
                e
            )))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let current = self.current_ms();
        if let Err(e) = self.kcp.update(current) {
            return Poll::Ready(Err(io::Error::other(format!(
                "KCP update error: {e:?}"
            ))));
        }
        if let Err(e) = self.kcp.flush() {
            return Poll::Ready(Err(io::Error::other(format!(
                "KCP flush error: {e:?}"
            ))));
        }
        self.drain_output(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Flush before closing
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        Pin::new(&mut self.transport).poll_close(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kcp_config_default() {
        let config = KcpConfig::default();
        // Match Snowflake Go settings: nodelay=false, interval=100, nc=true
        assert!(!config.nodelay);
        assert_eq!(config.interval, 100);
        assert!(config.nc);
    }

    /// Every packet KCP writes stays its own packet: merging them would hand
    /// the bridge one oversized datagram instead of the several it expects.
    #[test]
    fn output_buffer_keeps_packet_boundaries() {
        let mut buf = OutputBuffer::new();
        buf.write_all(b"first").unwrap();
        buf.write_all(b"second").unwrap();

        let packets = buf.take();
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0], b"first");
        assert_eq!(packets[1], b"second");
        assert!(buf.take().is_empty());
    }
}
