use anyhow::Result;
use sb_config::inbound::InboundDef;
use sb_core::pipeline::Inbound; // 使 .serve() 在作用域内
use sb_core::router::Router;
use serde_json::json;
use std::sync::Arc;
use std::{io, net::SocketAddr};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration, Instant};
use tracing::{info, warn}; // Added import for json macro

/// 以统一的枚举(`InboundDef`)驱动 inbounds 启动；
/// - HTTP / SOCKS：from_json 后后台托管
/// - TUN：受 feature = "tun" 控制；禁用时只打印告警
pub async fn build_and_run_inbounds(_router: Arc<dyn Router>, defs: Vec<InboundDef>) -> Result<()> {
    let mut handles: Vec<JoinHandle<()>> = Vec::new();

    for def in defs {
        match def {
            InboundDef::Http(mut v) => {
                // 1) 解析监听地址（兼容两种写法）
                let addr: SocketAddr = if let (Some(host), Some(port)) = (
                    v.get("listen").and_then(|x| x.as_str()),
                    v.get("listen_port").and_then(|x| x.as_u64()),
                ) {
                    format!("{}:{}", host, port)
                        .parse()
                        .map_err(io::Error::other)?
                } else if let Some(sock) = v.get("listen").and_then(|x| x.as_str()) {
                    sock.parse().map_err(io::Error::other)?
                } else {
                    return Err(io::Error::other("http inbound missing listen/listen_port").into());
                };

                // 规范化配置：确保 from_json 能看到显式的 listen 和 listen_port
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("listen".to_string(), json!(addr.ip().to_string()));
                    obj.insert("listen_port".to_string(), json!(addr.port()));
                }

                // 2) 构造并启动入站
                let inbound = sb_adapters::inbound::http::HttpInbound::from_json(&v)?;
                handles.push(tokio::spawn(async move {
                    if let Err(e) = inbound.serve().await {
                        warn!("http inbound serve exited: {e}");
                    }
                }));

                // 3) 端口就绪主动探测（<=5s，每 200ms 尝试一次）
                wait_tcp_ready(addr, Duration::from_millis(200), Duration::from_secs(5)).await?;
                info!("http inbound ready on {}", addr);
            }
            #[cfg(feature = "socks")]
            InboundDef::Socks(v) => {
                let inbound = sb_adapters::inbound::socks::SocksInbound::from_json(&v)?;
                handles.push(tokio::spawn(async move {
                    let _ = inbound.serve().await;
                }));
            }
            #[cfg(not(feature = "socks"))]
            InboundDef::Socks(_) => {
                warn!("`socks` feature disabled; skip SOCKS5 inbound");
            }
            InboundDef::Tun(v) => {
                #[cfg(feature = "tun")]
                {
                    let inbound =
                        sb_adapters::inbound::tun::TunInbound::from_json(&v, _router.clone())?;
                    handles.push(tokio::spawn(async move {
                        let _ = inbound.serve().await;
                    }));
                }
                #[cfg(not(feature = "tun"))]
                {
                    let _ = v;
                    tracing::warn!("`tun` feature disabled; skip TUN inbound");
                }
            }
        }
    }

    // 守护进程场景：不等待各 inbound 退出
    let _ = handles;
    Ok(())
}

/// 等待 TCP 端口可连接：每 step 尝试一次，最多等待 total
async fn wait_tcp_ready(addr: SocketAddr, step: Duration, total: Duration) -> io::Result<()> {
    let deadline = Instant::now() + total;
    loop {
        match TcpStream::connect(addr).await {
            Ok(_s) => return Ok(()),
            Err(last) => {
                if Instant::now() >= deadline {
                    return Err(io::Error::other(format!(
                        "inbound not ready on {addr} (last: {last})"
                    )));
                }
                sleep(step).await;
            }
        }
    }
}
