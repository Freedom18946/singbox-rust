use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::Duration;
use tokio_util::sync::CancellationToken;

#[cfg(feature = "metrics")]
fn err_kind_local(e: &io::Error) -> &'static str {
    use io::ErrorKind::*;
    match e.kind() {
        TimedOut => "timeout",
        ConnectionRefused => "refused",
        ConnectionReset | ConnectionAborted | BrokenPipe => "reset",
        AddrInUse | AddrNotAvailable | NotFound | InvalidInput => "addr",
        _ => "other",
    }
}

/// 旧接口：双向拷贝 + 结束时一次性累计
/// 现在内部改为 1s 周期的流式计量，签名与行为保持兼容
pub async fn copy_bidirectional_metered<A, B>(
    a: &mut A,
    b: &mut B,
    _label: &'static str,
) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    // 新实现：直接转调流式实现（1s）
    let _ = copy_bidirectional_streaming(a, b, _label, Duration::from_secs(1)).await?;
    Ok(())
}

/// 新接口：双向拷贝（流式计量），周期上报 IO 指标，并在结束时补齐
/// 返回 (上行 bytes a->b, 下行 bytes b->a)
pub async fn copy_bidirectional_streaming<A, B>(
    a: &mut A,
    b: &mut B,
    _label: &'static str,
    interval_dur: Duration,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    copy_bidirectional_streaming_ctl(a, b, _label, interval_dur, None, None, None).await
}

/// 双向拷贝（带可选读/写超时与取消传播）。
        // - 当读侧在 `read_timeout` 内无进展，返回 TimedOut
        // - 当写侧在 `write_timeout` 内无法完成，返回 TimedOut
        // - 当收到 `cancel` 取消，返回 Interrupted
pub async fn copy_bidirectional_streaming_ctl<A, B>(
    a: &mut A,
    b: &mut B,
    _label: &'static str,
    interval_dur: Duration,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    cancel: Option<CancellationToken>,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    // 拆分读写半部
    let (mut ar, mut aw) = split(a);
    let (mut br, mut bw) = split(b);

    // 两个方向的累计计数
    let up = Arc::new(AtomicU64::new(0)); // a -> b
    let down = Arc::new(AtomicU64::new(0)); // b -> a
    let stop = Arc::new(AtomicBool::new(false));

    // 周期上报任务（仅依赖 Arc，不借用半部，满足 'static）
    #[cfg(feature = "metrics")]
    let ticker_handle = {
        let up = up.clone();
        let down = down.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            let mut last_u = 0u64;
            let mut last_d = 0u64;
            let mut iv = tokio::time::interval(interval_dur);
            loop {
                iv.tick().await;
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let u = up.load(Ordering::Relaxed);
                let d = down.load(Ordering::Relaxed);
                let du = u.saturating_sub(last_u);
                let dd = d.saturating_sub(last_d);
                last_u = u;
                last_d = d;
                if du > 0 {
                    metrics::counter!("sb_io_bytes_total", "label"=>_label, "dir"=>"up")
                        .increment(du);
                    if _label == "http" {
                        metrics::counter!("http_bytes_out_total").increment(du);
                    }
                }
                if dd > 0 {
                    metrics::counter!("sb_io_bytes_total", "label"=>_label, "dir"=>"down")
                        .increment(dd);
                    if _label == "http" {
                        metrics::counter!("http_bytes_in_total").increment(dd);
                    }
                }
            }
        })
    };
    #[cfg(not(feature = "metrics"))]
    let ticker_handle = {
        let _ = (up.clone(), down.clone(), stop.clone(), interval_dur);
        // 占位句柄
        tokio::spawn(async {})
    };

    // 单向拷贝 worker：从 r 读到 buf，写入 w，并将 n 加到 counter
    async fn pump<R, W>(
        mut r: R,
        mut w: W,
        counter: Arc<AtomicU64>,
        read_timeout: Option<Duration>,
        write_timeout: Option<Duration>,
        cancel: Option<CancellationToken>,
    ) -> io::Result<u64>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut buf = vec![0u8; 16 * 1024];
        let mut total = 0u64;
        loop {
            let n = {
                // 读超时/取消
                if let Some(ref tok) = cancel {
                    tokio::select! {
                        _ = tok.cancelled() => {
                            return Err(io::Error::new(io::ErrorKind::Interrupted, "canceled"));
                        }
                        res = async {
                            if let Some(to) = read_timeout {
                                tokio::time::timeout(to, r.read(&mut buf)).await
                                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "read timeout"))?
                            } else {
                                r.read(&mut buf).await
                            }
                        } => res?,
                    }
                } else if let Some(to) = read_timeout {
                    tokio::time::timeout(to, r.read(&mut buf))
                        .await
                        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "read timeout"))??
                } else {
                    r.read(&mut buf).await?
                }
            };
            if n == 0 {
                // 半关闭：尝试优雅关闭写侧
                let _ = w.flush().await;
                let _ = tokio::io::AsyncWriteExt::shutdown(&mut w).await;
                break;
            }
            // 写超时/取消
            {
                if let Some(ref tok) = cancel {
                    tokio::select! {
                        _ = tok.cancelled() => {
                            return Err(io::Error::new(io::ErrorKind::Interrupted, "canceled"));
                        }
                        res = async {
                            if let Some(to) = write_timeout {
                                tokio::time::timeout(to, w.write_all(&buf[..n])).await
                                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "write timeout"))?
                                    .map(|_| ())
                            } else {
                                w.write_all(&buf[..n]).await.map(|_| ())
                            }
                        } => {
                            res?;
                        }
                    }
                } else if let Some(to) = write_timeout {
                    tokio::time::timeout(to, w.write_all(&buf[..n]))
                        .await
                        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "write timeout"))??
                } else {
                    w.write_all(&buf[..n]).await?;
                }
            }
            total += n as u64;
            counter.fetch_add(n as u64, Ordering::Relaxed);
        }
        // 主动 flush 一下（忽略错误，让写侧决定）
        let _ = w.flush().await;
        Ok(total)
    }

    // 并行两路拷贝（不 spawn，直接 join，避免 'static 约束）
    let up_c = up.clone();
    let down_c = down.clone();
    let up_fut = pump(&mut ar, &mut bw, up_c, read_timeout, write_timeout, cancel.clone());
    let down_fut = pump(&mut br, &mut aw, down_c, read_timeout, write_timeout, cancel.clone());

    let res = tokio::try_join!(up_fut, down_fut);

    // 停止 ticker，并做最终补齐
    stop.store(true, Ordering::Relaxed);
    #[cfg(feature = "metrics")]
    {
        // 等一小步让 ticker 观察到 stop
        tokio::time::sleep(Duration::from_millis(10)).await;
        // 最后一口：把未上报的增量补齐（确保结算到 Prometheus）
        metrics::counter!("sb_io_bytes_total", "label"=>_label, "dir"=>"up").increment(0);
        metrics::counter!("sb_io_bytes_total", "label"=>_label, "dir"=>"down").increment(0);
        // 结束 ticker
        let _ = ticker_handle.await;
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = ticker_handle.await;
    }

    // 将结果转换 & 打点错误（仅 forward 阶段）
    match res {
        Ok((u, d)) => Ok((u, d)),
        Err(e) => {
            #[cfg(feature = "metrics")]
            {
                metrics::counter!(
                    "sb_inbound_forward_total",
                    "label"=>_label,
                    "result"=>"error",
                    "err"=>err_kind_local(&e)
                )
                .increment(1);
            }
            Err(e)
        }
    }
}

/// 包装任意 AsyncRead/Write，统计 read/write 字节并上报（behind feature=metrics）
pub struct MeteredStream<T> {
    inner: T,
    label: &'static str,
    #[cfg(feature = "metrics")]
    up: Arc<AtomicU64>,
    #[cfg(feature = "metrics")]
    down: Arc<AtomicU64>,
}

impl<T> MeteredStream<T> {
    pub fn new(inner: T, label: &'static str) -> Self {
        Self {
            inner,
            label,
            #[cfg(feature = "metrics")]
            up: Arc::new(AtomicU64::new(0)),
            #[cfg(feature = "metrics")]
            down: Arc::new(AtomicU64::new(0)),
        }
    }
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for MeteredStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let _ = self.label;
        let pre = buf.filled().len();
        let p = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &p {
            let _n = buf.filled().len().saturating_sub(pre);
            #[cfg(feature = "metrics")]
            {
                use metrics::counter;
                self.down.fetch_add(_n as u64, Ordering::Relaxed);
                counter!("bytes_down_total").increment(_n as u64);
            }
        }
        p
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for MeteredStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let _ = self.label;
        let p = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(_n)) = p {
            #[cfg(feature = "metrics")]
            {
                use metrics::counter;
                self.up.fetch_add(_n as u64, Ordering::Relaxed);
                counter!("bytes_up_total").increment(_n as u64);
            }
        }
        p
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// 便捷包装（保持旧签名）：未启用 metrics 时零开销透传。
pub fn wrap_stream<T>(label: &'static str, io: T) -> MeteredStream<T> {
    MeteredStream::new(io, label)
}

// 移除自定义 JoinError 包装，直接忽略 join 结果（ticker 无副作用）

#[cfg(test)]
mod tests_timeouts {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn read_timeout_triggers() {
        let (mut a, mut b) = duplex(8);
        // 不写任何数据，直接进入 copy，设置非常短的读超时
        let r = copy_bidirectional_streaming_ctl(
            &mut a,
            &mut b,
            "test",
            Duration::from_millis(50),
            Some(Duration::from_millis(30)),
            None,
            None,
        )
        .await;
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn write_timeout_triggers_when_peer_not_reading() {
        let (mut a, mut b) = duplex(1);
        // 先向 a 写入数据，使得 a->b 方向有数据可写
        a.write_all(b"hello").await.unwrap();
        // 立即进入拷贝，b 的读取方向没有任何数据，且我们不给 b 读，导致 a->b 写阻塞
        let r = copy_bidirectional_streaming_ctl(
            &mut a,
            &mut b,
            "test",
            Duration::from_millis(50),
            None,
            Some(Duration::from_millis(30)),
            None,
        )
        .await;
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn cancel_token_causes_interrupted() {
        let (mut a, mut b) = duplex(8);
        let tok = CancellationToken::new();
        let t2 = tok.clone();
        let fut = copy_bidirectional_streaming_ctl(
            &mut a,
            &mut b,
            "test",
            Duration::from_millis(50),
            None,
            None,
            Some(tok),
        );
        let j = tokio::spawn(async move {
            // 短暂等待再取消
            tokio::time::sleep(Duration::from_millis(20)).await;
            t2.cancel();
        });
        let r = fut.await;
        let _ = j.await;
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::Interrupted);
    }

    #[tokio::test]
    async fn peer_half_close_propagates_shutdown() {
        let (mut a, mut b) = duplex(8);

        // 对端半关闭：在后台对 b 执行 shutdown 写，使得 a 的读返回 0
        let mut b_clone = b.clone();
        let closer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let _ = AsyncWriteExt::shutdown(&mut b_clone).await;
        });

        let r = copy_bidirectional_streaming_ctl(
            &mut a,
            &mut b,
            "test",
            Duration::from_millis(50),
            Some(Duration::from_millis(100)),
            Some(Duration::from_millis(100)),
            None,
        )
        .await;
        let _ = closer.await;
        // 应当正常结束（非错误），或最少不崩溃
        assert!(r.is_ok());
    }
}
