//! Unified dialing helpers: DNS → `SocketAddr` list → connect with per-attempt timeout & fallback.
use crate::dns::resolve::{resolve_all_compat as resolve_all, resolve_socketaddr};
use crate::util::env::{env_bool, env_duration_ms};
use std::io;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// 解析一个地址并尝试连接（单地址路径）；`SB_DNS_CACHE_ENABLE=1` 时走缓存解析。
pub async fn dial_hostport(host: &str, port: u16, per_attempt: Duration) -> io::Result<TcpStream> {
    let sa = resolve_socketaddr(host, port).await?;
    timeout(per_attempt, TcpStream::connect(sa))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("dial timeout to {sa}")))?
}

/// 解析全部候选地址并逐个尝试；每个地址都有独立的 `per_attempt` 超时。
/// 成功则立即返回；全部失败合并成 `io::ErrorKind::Other`。
pub async fn dial_all(host: &str, port: u16, per_attempt: Duration) -> io::Result<TcpStream> {
    let addrs = resolve_all(host, port).await?;
    let mut last_err: Option<io::Error> = None;
    for sa in addrs {
        match timeout(per_attempt, TcpStream::connect(sa)).await {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => {
                last_err = Some(io::Error::new(
                    e.kind(),
                    format!("connect {sa} failed: {e}"),
                ));
            }
            Err(_) => {
                last_err = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("connect {sa} timed out"),
                ));
            }
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address to dial")))
}

/// 工具：把已经知道的 `SocketAddr` 列表逐个尝试。
pub async fn dial_socketaddrs<I>(iter: I, per_attempt: Duration) -> io::Result<TcpStream>
where
    I: IntoIterator<Item = std::net::SocketAddr>,
{
    let mut last_err: Option<io::Error> = None;
    for sa in iter {
        match timeout(per_attempt, TcpStream::connect(sa)).await {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => {
                last_err = Some(io::Error::new(
                    e.kind(),
                    format!("connect {sa} failed: {e}"),
                ));
            }
            Err(_) => {
                last_err = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("connect {sa} timed out"),
                ));
            }
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address to dial")))
}

/// 统一读取"每次拨号超时"（毫秒）。默认 4000ms。测试/排障可通过 `SB_DIAL_TIMEOUT_MS` 调整。
pub fn per_attempt_timeout() -> Duration {
    env_duration_ms("SB_DIAL_TIMEOUT_MS", 4000)
}

/// 便捷拨号：当 `SB_DIAL_USE_ALL=1` 时走 `dial_all`，否则走 `dial_hostport`。
pub async fn dial_pref(host: &str, port: u16) -> io::Result<TcpStream> {
    let t = per_attempt_timeout();
    if env_bool("SB_DIAL_USE_ALL") {
        dial_all(host, port, t).await
    } else {
        dial_hostport(host, port, t).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn resolve_localhost_works_without_cache() {
        // 不依赖外网，只要本机解析 localhost 就能过
        std::env::remove_var("SB_DNS_CACHE_ENABLE");
        let sa = resolve_socketaddr("localhost", 80)
            .await
            .expect("resolve localhost");
        // 只校验产生了某个本地回环地址
        assert!(sa.ip().is_loopback());
    }

    #[tokio::test]
    async fn dial_to_local_listener_succeeds() {
        // 本地起 listener，使用 dial_all("localhost", port) 拨通
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let _guard = tokio::spawn(async move {
            // 接一把，保持一会儿
            if let Ok((_s, _p)) = listener.accept().await {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });
        let _c = dial_all("localhost", port, Duration::from_millis(200))
            .await
            .expect("dial localhost listener");
    }
}
