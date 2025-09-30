//! R77: Trojan E2E Harness（默认**跳过 TLS**，仅做 TCP+首包；feature=proto_trojan_min）
//! - connect_env(host,port,pass,{tls,timeout_ms})：按参数执行最小连通检查与首包写入
//! - 仅作为**工具/验证**，非最终数据通道；Admin 受 SB_ADMIN_ALLOW_NET 守门
use crate::trojan_min::TrojanHello;
use sb_transport::dialer::{Dialer, TcpDialer};
#[cfg(feature = "transport_tls")]
use sb_transport::tls::{webpki_roots_config, TlsDialer};
use tokio::io::AsyncWriteExt;
use tokio::time::{timeout, Duration, Instant};

#[derive(Debug, Clone)]
pub struct ConnectOpts {
    pub tls: bool,
    pub timeout_ms: u64,
}

impl Default for ConnectOpts {
    fn default() -> Self {
        Self {
            tls: false,
            timeout_ms: 100,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConnectReport {
    pub path: &'static str, // "tcp" | "tls"
    pub elapsed_ms: u64,
}

/// 仅 TCP，写入首包
async fn tcp_hello(host: &str, port: u16, pass: &str, to: Duration) -> Result<(), String> {
    let d = TcpDialer;
    let mut s = timeout(to, d.connect(host, port))
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| format!("{:?}", e))?;
    let hello = TrojanHello {
        password: pass.into(),
        host: host.into(),
        port,
    };
    let buf = hello.to_bytes();
    timeout(to, s.write_all(&buf))
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| format!("{:?}", e))?;
    Ok(())
}

/// TCP+TLS（若编译开启），写入首包；若未开启 TLS 特性，回退到 TCP 模式
pub async fn connect_env(
    host: &str,
    port: u16,
    pass: &str,
    opts: ConnectOpts,
) -> Result<ConnectReport, String> {
    let to = Duration::from_millis(opts.timeout_ms.max(10).min(10_000));
    if opts.tls {
        #[cfg(feature = "transport_tls")]
        {
            let d = TlsDialer::from_env(TcpDialer, webpki_roots_config());
            let t0 = Instant::now();
            let mut s = timeout(to, d.connect(host, port))
                .await
                .map_err(|_| "timeout".to_string())?
                .map_err(|e| format!("{:?}", e))?;
            let hello = TrojanHello {
                password: pass.into(),
                host: host.into(),
                port,
            };
            let buf = hello.to_bytes();
            timeout(to, s.write_all(&buf))
                .await
                .map_err(|_| "timeout".to_string())?
                .map_err(|e| format!("{:?}", e))?;
            return Ok(ConnectReport {
                path: "tls",
                elapsed_ms: t0.elapsed().as_millis() as u64,
            });
        }
        #[cfg(not(feature = "transport_tls"))]
        { /* 回退 TCP */ }
    }
    let t0 = Instant::now();
    tcp_hello(host, port, pass, to).await?;
    Ok(ConnectReport {
        path: "tcp",
        elapsed_ms: t0.elapsed().as_millis() as u64,
    })
}
