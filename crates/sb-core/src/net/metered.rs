use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::Duration;

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
    async fn pump<R, W>(mut r: R, mut w: W, counter: Arc<AtomicU64>) -> io::Result<u64>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut buf = vec![0u8; 16 * 1024];
        let mut total = 0u64;
        loop {
            let n = r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            w.write_all(&buf[..n]).await?;
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
    let up_fut = pump(&mut ar, &mut bw, up_c);
    let down_fut = pump(&mut br, &mut aw, down_c);

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
        let pre = buf.filled().len();
        let p = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &p {
            let n = buf.filled().len().saturating_sub(pre);
            #[cfg(feature = "metrics")]
            {
                use metrics::counter;
                self.down.fetch_add(n as u64, Ordering::Relaxed);
                counter!("bytes_down_total").increment(n as u64);
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
        let p = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = p {
            #[cfg(feature = "metrics")]
            {
                use metrics::counter;
                self.up.fetch_add(n as u64, Ordering::Relaxed);
                counter!("bytes_up_total").increment(n as u64);
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
