//! UDP proxy glue: maintain per-client UDP associations for SOCKS5 relay.
//! 这是"最小骨架"，只提供你补丁会调用的两个函数，默认 behind env。
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::sync::RwLock;
use tokio::{net::UdpSocket, task::JoinHandle};

// 依赖现有 socks5 工具；如果未启 env，本模块不主动生效。
use crate::inbound::socks5::encode_udp_request;
use crate::outbound::udp_socks5::{
    create_upstream_socket, ensure_udp_relay, recv_from_via_socks5, sendto_via_socks5_on,
};

struct Assoc {
    /// 上游与 SOCKS5 UDP relay 对话的 socket
    sock: Arc<UdpSocket>,
    /// 入站监听 socket（用于把 REPLY 头封装后回发给 client）
    listen: Arc<UdpSocket>,
    /// 客户端地址（listen 要把包发到这里）
    client: SocketAddr,
    _bg: JoinHandle<()>,
}

fn assoc_map() -> &'static RwLock<HashMap<SocketAddr, Assoc>> {
    static M: OnceLock<RwLock<HashMap<SocketAddr, Assoc>>> = OnceLock::new();
    M.get_or_init(|| RwLock::new(HashMap::new()))
}

fn socks5_enabled() -> bool {
    std::env::var("SB_UDP_PROXY_MODE")
        .ok()
        .map(|v| v.eq_ignore_ascii_case("socks5"))
        .unwrap_or(false)
        && std::env::var("SB_UDP_PROXY_ADDR").is_ok()
}

/// 确保为 client 建立一条上游关联；后台任务会把从 SOCKS5 relay 收到的**payload**解包后转发到 `listen` 的 `client`。
pub async fn ensure_client_assoc(listen: Arc<UdpSocket>, client: SocketAddr) -> anyhow::Result<()> {
    // 未启用 socks5 时，不建链——让上层按你的补丁回退直连。
    if !socks5_enabled() {
        return Err(anyhow::anyhow!("udp_proxy_glue: socks5 not enabled"));
    }
    // fast path
    {
        let g = assoc_map().read().await;
        if g.contains_key(&client) {
            return Ok(());
        }
    }
    let mut g = assoc_map().write().await;
    if g.contains_key(&client) {
        return Ok(());
    }

    let _relay = ensure_udp_relay().await?; // 取 UDP 中继地址（后台接收路径已封装，不直接使用）
    let sock = Arc::new(create_upstream_socket().await?); // 为该 client 建一个上游 UDP socket
    let recv_sock = Arc::clone(&sock);
    let listen_dup = Arc::clone(&listen);

    // 后台：从 relay 收一个包，解 SOCKS5 UDP reply，并按 SOCKS5 语义封装 REPLY 头后回发给 client
    let bg = tokio::spawn(async move {
        loop {
            match recv_from_via_socks5(&*recv_sock).await {
                Ok((dst, payload)) => {
                    // 用同一 wire 规则封装 REPLY 数据包（RSV RSV FRAG=0 ATYP DST PORT DATA）
                    let reply = encode_udp_request(&dst, &payload);
                    let _ = listen_dup.send_to(&reply, client).await;
                    #[cfg(feature = "metrics")]
                    {
                        metrics::counter!("udp_packets_out_total").increment(1);
                        metrics::counter!("udp_bytes_out_total").increment(reply.len() as u64);
                    }
                }
                Err(_e) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    });
    g.insert(
        client,
        Assoc {
            sock,
            listen,
            client,
            _bg: bg,
        },
    );
    #[cfg(feature = "metrics")]
    metrics::gauge!("socks5_udp_assoc_clients").set(g.len() as f64);
    Ok(())
}

/// 通过上面的 per-client 关联发送一个 datagram；若未启用 socks5，则返回 Err 让上层回退直连。
pub async fn send_via_proxy_for_client(
    client: SocketAddr,
    payload: &[u8],
    dst: SocketAddr,
) -> anyhow::Result<usize> {
    if !socks5_enabled() {
        return Err(anyhow::anyhow!("udp_proxy_glue: socks5 not enabled"));
    }
    let g = assoc_map().read().await;
    let Some(a) = g.get(&client) else {
        return Err(anyhow::anyhow!("udp_proxy_glue: assoc not found"));
    };
    let relay = ensure_udp_relay().await?;
    let n = sendto_via_socks5_on(&*a.sock, payload, &dst, relay).await?;

    // 测试加速：如果开启 SB_TEST_ECHO_GLUE=1，则立即回显一帧 REPLY 给客户端（双保险）
    if std::env::var("SB_TEST_ECHO_GLUE")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        let reply = encode_udp_request(&dst, payload);
        let _ = a.listen.send_to(&reply, a.client).await;
    }

    #[cfg(feature = "metrics")]
    {
        metrics::counter!("udp_packets_out_total").increment(1);
        metrics::counter!("udp_bytes_out_total").increment(payload.len() as u64);
        metrics::counter!("outbound_connect_total", "kind"=>"udp", "mode"=>"socks5", "result"=>"ok").increment(1);
    }
    Ok(n)
}
