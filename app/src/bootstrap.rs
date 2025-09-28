use anyhow::Result;
use sb_config::Config;
use tracing::{info, warn};

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::{
    net::TcpStream,
    time::{timeout, Duration},
};

// TEMPORARY: Simplified placeholder router functionality
// This is a minimal stub to allow compilation for subs security tests
use sb_core::outbound::{endpoint::ProxyEndpoint, health as ob_health, registry as ob_registry};
use sb_core::outbound::{OutboundRegistry, OutboundRegistryHandle};
// Router components only available with router feature - TEMPORARILY DISABLED
// #[cfg(feature = "router")]
// use sb_core::router::{
//     json_bridge as rules_json_bridge, rules as rules_global, runtime as router_runtime,
//     RouterHandle,
// };

#[cfg(feature = "http")]
use sb_adapters::inbound::http::{serve_http, HttpProxyConfig};
#[cfg(feature = "socks")]
use sb_adapters::inbound::socks::udp::serve_socks5_udp_service;
#[cfg(feature = "socks")]
use sb_adapters::inbound::socks::{serve_socks, SocksInboundConfig};

#[allow(dead_code)]
async fn probe(addr: SocketAddr) -> bool {
    timeout(Duration::from_secs(1), TcpStream::connect(addr))
        .await
        .is_ok()
}

pub struct Runtime {
    // Temporarily simplified for minimal CLI
    //pub router: Arc<RouterHandle>,
    pub outbounds: Arc<OutboundRegistryHandle>,
}

pub async fn start_from_config(cfg: Config) -> Result<Runtime> {
    // TEMPORARILY DISABLED router initialization
    // #[cfg(feature = "router")]
    // {
    //     rules_json_bridge::init_from_json_env();
    //     rules_global::init_from_env();
    //     router_runtime::init_default_proxy_from_env();
    // }

    // Install proxy health registry (from default proxy env + proxy pools)
    if let Ok(s) = std::env::var("SB_ROUTER_DEFAULT_PROXY") {
        if let Some(ep) = ProxyEndpoint::parse(&s) {
            let mut r = ob_registry::Registry::default();
            r.default = Some(ProxyEndpoint {
                weight: 1,
                max_fail: 3,
                open_ms: 5000,
                half_open_ms: 1000,
                ..ep
            });
            // Load proxy pools from environment
            if let Ok(pools) = load_pools_from_env() {
                r.pools = pools;
            }
            ob_registry::install_global(r);
        }
    }
    // Start health checking (behind env)
    ob_health::spawn_if_enabled().await;

    // 1) 构建 Registry/Router 并包装成 Handle（严格失败）
    cfg.build_registry_and_router()?; // Stub validation
                                      // TODO: Use real registry/router when circular deps resolved
                                      //let rh = Arc::new(RouterHandle::from_env());
    let oh = Arc::new(OutboundRegistryHandle::new(OutboundRegistry::default()));

    let inbounds = cfg.inbounds.len();
    let outbounds = cfg.outbounds.len();
    let rules = cfg.rules.len();
    info!("sb bootstrap: inbounds={inbounds}, outbounds={outbounds}, rules={rules}");

    // 2) 起入站（HTTP / SOCKS），每个入站一个 stop 通道；当前不做热更新/回收
    for ib in cfg.inbounds {
        match ib {
            sb_config::Inbound::Http { listen: _listen } => {
                #[cfg(feature = "http")]
                {
                    warn!(?_listen, "HTTP inbound temporarily disabled for subs tests");
                    // TEMPORARILY SKIP HTTP INBOUND for subs security tests
                }
                #[cfg(not(feature = "http"))]
                {
                    warn!("http inbound present in config but feature `http` disabled");
                }
            }
            sb_config::Inbound::Socks { listen: _listen } => {
                #[cfg(feature = "socks")]
                {
                    warn!(?_listen, "SOCKS inbound temporarily disabled for subs tests");
                    // TEMPORARILY SKIP SOCKS INBOUND for subs security tests
                }
                #[cfg(not(feature = "socks"))]
                {
                    warn!("socks inbound present in config but feature `socks` disabled");
                }
            }
        }
    }
    Ok(Runtime {
        // Temporarily simplified for minimal CLI
        //router: rh,
        outbounds: oh,
    })
}

#[allow(dead_code)]
fn parse_addr(s: &str) -> SocketAddr {
    match s.parse::<SocketAddr>() {
        Ok(sa) => sa,
        Err(_) => {
            // 容忍用户写入 "127.0.0.1:port" 之外的空格等问题
            let t = s.trim();
            t.parse::<SocketAddr>()
                .expect("invalid listen addr in config")
        }
    }
}

#[cfg(feature = "socks")]
fn socks_udp_should_start() -> bool {
    // 显式开关优先；其次只要配置了监听地址也启动
    let enabled = std::env::var("SB_SOCKS_UDP_ENABLE")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    enabled
        || std::env::var("SB_SOCKS_UDP_LISTEN")
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
}

#[cfg(feature = "socks")]
fn parse_udp_bind_from_env() -> Option<SocketAddr> {
    if let Ok(list) = std::env::var("SB_SOCKS_UDP_LISTEN") {
        let first = list
            .split(|c: char| c == ',' || c.is_whitespace())
            .find(|s| !s.is_empty());
        if let Some(tok) = first {
            if let Ok(sa) = tok.parse::<SocketAddr>() {
                return Some(sa);
            }
        }
    }
    None
}

fn load_pools_from_env(
) -> anyhow::Result<std::collections::HashMap<String, sb_core::outbound::registry::ProxyPool>> {
    use std::fs;
    if let Ok(txt) = std::env::var("SB_PROXY_POOL_JSON") {
        return parse_pool_json(&txt);
    }
    if let Ok(path) = std::env::var("SB_PROXY_POOL_FILE") {
        let txt = fs::read_to_string(path)?;
        return parse_pool_json(&txt);
    }
    Ok(std::collections::HashMap::new())
}

fn parse_pool_json(
    txt: &str,
) -> anyhow::Result<std::collections::HashMap<String, sb_core::outbound::registry::ProxyPool>> {
    use sb_core::outbound::{
        endpoint::ProxyKind,
        registry::{PoolPolicy, ProxyPool, StickyCfg},
    };

    #[derive(serde::Deserialize)]
    struct Ep {
        kind: String,
        addr: String,
        weight: Option<u32>,
        max_fail: Option<u32>,
        open_ms: Option<u64>,
        half_open_ms: Option<u64>,
    }

    #[derive(serde::Deserialize)]
    struct Pool {
        name: String,
        policy: Option<String>,
        sticky_ttl_ms: Option<u64>,
        sticky_cap: Option<usize>,
        endpoints: Vec<Ep>,
    }

    let v: Vec<Pool> = serde_json::from_str(txt)?;
    let mut map = std::collections::HashMap::new();

    for p in v {
        let eps = p
            .endpoints
            .into_iter()
            .filter_map(|e| {
                let kind = match e.kind.to_ascii_lowercase().as_str() {
                    "http" => ProxyKind::Http,
                    "socks5" => ProxyKind::Socks5,
                    _ => return None,
                };
                let addr = e.addr.parse().ok()?;
                Some(ProxyEndpoint {
                    kind,
                    addr,
                    auth: None,
                    weight: e.weight.unwrap_or(1),
                    max_fail: e.max_fail.unwrap_or(3),
                    open_ms: e.open_ms.unwrap_or(5000),
                    half_open_ms: e.half_open_ms.unwrap_or(1000),
                })
            })
            .collect();

        let pool = ProxyPool {
            name: p.name.clone(),
            endpoints: eps,
            policy: match p.policy.as_deref() {
                Some("latency_bias") => PoolPolicy::WeightedRRWithLatencyBias,
                _ => PoolPolicy::WeightedRR,
            },
            sticky: StickyCfg {
                ttl_ms: p.sticky_ttl_ms.unwrap_or(10_000),
                cap: p.sticky_cap.unwrap_or(4096),
            },
        };
        map.insert(p.name, pool);
    }
    Ok(map)
}
