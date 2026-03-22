//! Sniff utilities for inbound handlers.
//! Provides `SniffedStream` — a stream wrapper that replays a prefix buffer
//! (captured during protocol sniffing) before delegating to the inner stream.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A stream wrapper that replays a captured prefix before delegating reads to `inner`.
///
/// Used after sniffing: the inbound reads initial bytes to detect protocol,
/// then wraps the stream so the outbound sees those bytes replayed transparently.
#[allow(dead_code)] // Used by optional inbound adapters when their protocol features are enabled.
pub(crate) struct SniffedStream<S> {
    inner: S,
    prefix: Vec<u8>,
    pos: usize,
}

impl<S> SniffedStream<S> {
    /// Create a new `SniffedStream`. The `prefix` bytes will be served first on read,
    /// then reads delegate to `inner`.
    #[allow(dead_code)] // Constructor is referenced only from optional protocol paths.
    pub(crate) fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            prefix,
            pos: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for SniffedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();

        // Serve prefix bytes first
        if me.pos < me.prefix.len() {
            let remaining = &me.prefix[me.pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            me.pos += to_copy;
            return Poll::Ready(Ok(()));
        }

        // Prefix exhausted — delegate to inner stream
        Pin::new(&mut me.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SniffedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
