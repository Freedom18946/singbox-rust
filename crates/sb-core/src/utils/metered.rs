//! metered 流包装：对 AsyncRead/AsyncWrite 进行字节计数
//!
//! 当前设计：
//! - 仅在内部维护计数（AtomicU64），提供 `snapshot()` 读取。
//! - 后续将对接 `sb-metrics::outbound` 的 bytes_{in,out}_total 指标。
//!
//! 用法示例：
//! ```ignore
//! let stream = TcpStream::connect(addr).await?;
//! let mut m = MeteredStream::new(stream, "direct");
//! // 读写...
//! let (in_b, out_b) = m.snapshot();
//! ```

use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Debug)]
pub struct Counters {
    in_bytes: AtomicU64,
    out_bytes: AtomicU64,
}

impl Counters {
    fn new() -> Self {
        Self {
            in_bytes: AtomicU64::new(0),
            out_bytes: AtomicU64::new(0),
        }
    }
    pub fn add_in(&self, n: u64) { self.in_bytes.fetch_add(n, Ordering::Relaxed); }
    pub fn add_out(&self, n: u64) { self.out_bytes.fetch_add(n, Ordering::Relaxed); }
    pub fn snapshot(&self) -> (u64, u64) {
        (self.in_bytes.load(Ordering::Relaxed), self.out_bytes.load(Ordering::Relaxed))
    }
}

/// 为便于将来做指标标签，这里保留 kind 字段（如 direct/http/socks）
#[derive(Debug)]
pub struct MeteredStream<S> {
    inner: S,
    kind: &'static str,
    ctr: Arc<Counters>,
}

impl<S> MeteredStream<S> {
    pub fn new(inner: S, kind: &'static str) -> Self {
        Self { inner, kind, ctr: Arc::new(Counters::new()) }
    }
    pub fn into_inner(self) -> S { self.inner }
    pub fn counters(&self) -> Arc<Counters> { self.ctr.clone() }
    pub fn kind(&self) -> &'static str { self.kind }
    pub fn snapshot(&self) -> (u64, u64) { self.ctr.snapshot() }
}

impl<S: AsyncRead + Unpin> AsyncRead for MeteredStream<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let pre = buf.filled().len();
        let inner = Pin::new(&mut self.inner);
        match inner.poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let post = buf.filled().len();
                if post > pre {
                    self.ctr.add_in((post - pre) as u64);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for MeteredStream<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        let inner = Pin::new(&mut self.inner);
        match inner.poll_write(cx, data) {
            Poll::Ready(Ok(n)) => {
                if n > 0 { self.ctr.add_out(n as u64); }
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[tokio::test]
    async fn test_metered() {
        let (mut a, mut b) = duplex(1024);
        let mut m = MeteredStream::new(a, "direct");
        let writer = tokio::spawn(async move {
            b.write_all(b"hello").await.unwrap();
            b.shutdown().await.unwrap();
        });
        let mut buf = vec![0u8; 8];
        let n = m.read(&mut buf).await.unwrap();
        assert_eq!(n, 5);
        let (in_b, out_b) = m.snapshot();
        assert_eq!(in_b, 5);
        assert_eq!(out_b, 0);
        writer.await.unwrap();
    }
}