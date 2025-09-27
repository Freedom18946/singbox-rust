//! UDP outbound balancer (direct / socks5) with simple weighted round-robin.
//! Behind env; not wired by default to adapters to keep userspace stable.
use crate::net::datagram::UdpTargetAddr;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::RwLock as AsyncRwLock;

// removed legacy weighted backend scaffolding (not used)

fn rr_counter() -> &'static AtomicUsize {
    static C: OnceLock<AtomicUsize> = OnceLock::new();
    C.get_or_init(|| AtomicUsize::new(0))
}

async fn resolve_dst(dst: &UdpTargetAddr) -> anyhow::Result<SocketAddr> {
    match dst {
        UdpTargetAddr::Ip(sa) => Ok(*sa),
        UdpTargetAddr::Domain { host, port } => {
            let mut it = tokio::net::lookup_host((host.as_str(), *port)).await?;
            it.next()
                .ok_or_else(|| anyhow::anyhow!("resolve empty for {host}"))
        }
    }
}

async fn send_direct(payload: &[u8], dst: &SocketAddr) -> anyhow::Result<usize> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    let n = sock.send_to(payload, dst).await?;
    #[cfg(feature = "metrics")]
    {
        metrics::counter!("udp_bytes_out_total").increment(payload.len() as u64);
        metrics::counter!("outbound_connect_total", "kind"=>"udp", "mode"=>"direct", "result"=>"ok").increment(1);
    }
    Ok(n)
}

#[cfg(feature = "scaffold")]
async fn send_socks5_via_upstream(
    payload: &[u8],
    dst: &SocketAddr,
    upstream: SocketAddr,
) -> anyhow::Result<usize> {
    use crate::outbound::udp_socks5::sendto_via_socks5_addr;
    let n = sendto_via_socks5_addr(upstream, payload, dst).await?;
    #[cfg(feature = "metrics")]
    {
        metrics::counter!("udp_bytes_out_total").increment(payload.len() as u64);
        metrics::counter!("outbound_connect_total", "kind"=>"udp", "mode"=>"socks5", "result"=>"ok").increment(1);
    }
    Ok(n)
}

#[cfg(not(feature = "scaffold"))]
async fn send_socks5_via_upstream(
    payload: &[u8],
    dst: &SocketAddr,
    _upstream: SocketAddr,
) -> anyhow::Result<usize> {
    // Fallback to direct when scaffold feature is not enabled
    send_direct(payload, dst).await
}

/// Public: choose a backend according to weights and send one datagram.
/// `decision` is router decision; when balancer disabled, it falls back to normal.
pub async fn send_balanced(
    payload: &[u8],
    dst: &UdpTargetAddr,
    decision: &str,
) -> anyhow::Result<usize> {
    let dst_sa = resolve_dst(dst).await?;
    // Only apply when router decides proxy and mode=socks5
    let mode_socks5 = std::env::var("SB_UDP_PROXY_MODE")
        .ok()
        .map(|v| v.eq_ignore_ascii_case("socks5"))
        .unwrap_or(false);
    if decision != "proxy" || !mode_socks5 {
        return send_direct(payload, &dst_sa).await;
    }
    // Read pool or single
    let pool_str = std::env::var("SB_UDP_SOCKS5_POOL").unwrap_or_default();
    let addrs: Vec<SocketAddr> = pool_str
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse::<SocketAddr>().ok())
        .collect();
    let (upstream, algo_str, mode) = if !addrs.is_empty() {
        let algo = std::env::var("SB_UDP_BALANCER_STRATEGY").unwrap_or_else(|_| "rr".to_string());
        let n = addrs.len();
        // 首先过滤 Down 的 upstream；若全部 Down → 降级：仍按 rr 选择其中一个
        let now = Instant::now();
        let mut up_idxs = Vec::new();
        for (i, a) in addrs.iter().enumerate() {
            if !is_down(*a, now).await {
                up_idxs.push(i);
            }
        }
        let pick_from = if up_idxs.is_empty() {
            (0..n).collect::<Vec<_>>()
        } else {
            up_idxs
        };
        let mode = if pick_from.len() != n {
            "degraded"
        } else {
            "pool"
        };
        let idx_rel = match algo.as_str() {
            "random" => {
                // simple pseudo-random without extra deps
                let t = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos();
                ((t as usize) ^ rr_counter().fetch_add(1, Ordering::Relaxed)) % pick_from.len()
            }
            "hash" => {
                let mut h = DefaultHasher::new();
                dst_sa.hash(&mut h);
                (h.finish() as usize) % pick_from.len()
            }
            _ => rr_counter().fetch_add(1, Ordering::Relaxed) % pick_from.len(),
        };
        let idx = pick_from[idx_rel];
        (addrs[idx], algo, mode)
    } else {
        // single
        let single = std::env::var("SB_UDP_SOCKS5_ADDR")
            .or_else(|_| std::env::var("SB_UDP_PROXY_ADDR"))
            .ok()
            .and_then(|s| s.parse::<SocketAddr>().ok());
        match single {
            Some(a) => (a, "single".to_string(), "single"),
            None => {
                #[cfg(feature = "metrics")]
                metrics::counter!("outbound_error_total", "kind"=>"udp", "class"=>"no_upstream")
                    .increment(1);
                // Fallback direct to not break userspace
                return send_direct(payload, &dst_sa).await;
            }
        }
    };
    let algo_label: &'static str = match algo_str.as_str() {
        "rr" => "rr",
        "random" => "random",
        "hash" => "hash",
        _ => "single",
    };
    #[derive(Clone, Debug)]
    struct UpState {
        fails: u32,
        down_until: Instant,
    }

    fn state_map() -> &'static AsyncRwLock<HashMap<SocketAddr, UpState>> {
        static M: OnceLock<AsyncRwLock<HashMap<SocketAddr, UpState>>> = OnceLock::new();
        M.get_or_init(|| AsyncRwLock::new(HashMap::new()))
    }

    fn backoff_for(fails: u32) -> Duration {
        // base=200ms, factor=2, cap=5s
        let base = 200u64;
        let cap = 5000u64;
        let shift = fails.min(16);
        let mul = 1u64 << shift; // 2^fails
        Duration::from_millis((base.saturating_mul(mul)).min(cap))
    }

    async fn mark_failure(up: SocketAddr, _reason: &'static str) {
        let now = Instant::now();
        let mut w = state_map().write().await;
        let st = w.entry(up).or_insert(UpState {
            fails: 0,
            down_until: Instant::now(),
        });
        st.fails = st.fails.saturating_add(1);
        st.down_until = now + backoff_for(st.fails);
        #[cfg(feature = "metrics")]
        metrics::counter!("balancer_failures_total", "upstream"=>up.to_string(), "reason"=>_reason)
            .increment(1);
    }

    async fn mark_success(up: SocketAddr) {
        let mut w = state_map().write().await;
        let st = w.entry(up).or_insert(UpState {
            fails: 0,
            down_until: Instant::now(),
        });
        st.fails = 0;
        st.down_until = Instant::now();
    }

    async fn is_down(up: SocketAddr, now: Instant) -> bool {
        let r = state_map().read().await;
        if let Some(st) = r.get(&up) {
            now < st.down_until
        } else {
            false
        }
    }

    #[cfg(feature = "metrics")]
    async fn export_states(addrs: &[SocketAddr], degraded: bool) {
        let now = Instant::now();
        for a in addrs {
            let down = is_down(*a, now).await;
            let v = if down { 0.0 } else { 1.0 };
            metrics::gauge!("balancer_upstreams", "upstream"=>a.to_string(), "state"=> if down {"down"} else {"up"}, "degraded"=> if degraded {"1"} else {"0"}).set(v);
        }
    }
    #[cfg(not(feature = "metrics"))]
    async fn export_states(_addrs: &[SocketAddr], _degraded: bool) {}
    export_states(&addrs, mode == "degraded").await;
    balancer_select_metric(algo_label, mode);
    match send_socks5_via_upstream(payload, &dst_sa, upstream).await {
        Ok(n) => {
            mark_success(upstream).await;
            Ok(n)
        }
        Err(e) => {
            mark_failure(upstream, "send").await;
            Err(e)
        }
    }
}
#[cfg(feature = "metrics")]
fn balancer_select_metric(algo: &'static str, mode: &'static str) {
    metrics::counter!("balancer_select_total", "algo"=>algo, "mode"=>mode).increment(1);
}
#[cfg(not(feature = "metrics"))]
fn balancer_select_metric(_: &'static str, _: &'static str) {}
