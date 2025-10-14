// crates/sb-adapters/src/inbound/socks/mod.rs
//! SOCKS5 入站（TCP CONNECT + 可选 UDP ASSOCIATE 宣告）
//! - 与 HTTP 入站相同的路由/出站抽象：RouterHandle + OutboundRegistryHandle + Endpoint
//! - P1.5：IO 计量统一走 sb_core::net::metered

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    select,
    sync::{mpsc, oneshot},
};

use tracing::{debug, info, warn};

use once_cell::sync::OnceCell;
use sb_core::outbound::health as ob_health;
use sb_core::outbound::{
    direct_connect_hostport, http_proxy_connect_through_proxy, socks5_connect_through_socks5,
    ConnectOpts,
};
use sb_core::outbound::{health::MultiHealthView, registry, selector::PoolSelector};
use sb_core::outbound::{Endpoint, OutboundRegistryHandle};
use sb_core::router::rules as rules_global;
use sb_core::router::rules::{Decision as RDecision, RouteCtx as RulesRouteCtx};
use sb_core::router::runtime::{default_proxy, ProxyChoice};
use sb_core::router::{RouteCtx, RouterHandle, Transport};

static SELECTOR: OnceCell<PoolSelector> = OnceCell::new();
// 本文件只用到了 inbound_parse，其他两个会在具体错误路径里再接入
use sb_core::telemetry::inbound_parse;

#[cfg(feature = "metrics")]
use metrics;

pub mod tcp;
pub mod udp;

#[derive(Clone, Debug)]
pub struct SocksInboundConfig {
    pub listen: SocketAddr,
    /// 给 UDP ASSOCIATE 用于宣告的地址；仅在 Some 时回复非 0 地址。
    pub udp_bind: Option<SocketAddr>,
    pub router: Arc<RouterHandle>,
    pub outbounds: Arc<OutboundRegistryHandle>,
    /// 保留给未来：当我们在这里内置启动 udp 模块时使用
    #[allow(dead_code)]
    pub udp_nat_ttl: Duration,
}

pub async fn serve_socks(
    cfg: SocksInboundConfig,
    mut stop_rx: mpsc::Receiver<()>,
    ready_tx: Option<oneshot::Sender<()>>,
) -> io::Result<()> {
    let listener = TcpListener::bind(cfg.listen).await?;
    let actual = listener.local_addr().unwrap_or(cfg.listen);
    info!(addr=?cfg.listen, actual=?actual, "SOCKS5 bound");
    if let Some(tx) = ready_tx {
        let _ = tx.send(());
    }

    // 可通过环境变量在测试时禁止 stop 打断（与 HTTP 入站一致）
    let disable_stop = std::env::var("SB_SOCKS_DISABLE_STOP").as_deref() == Ok("1");

    loop {
        select! {
            _ = stop_rx.recv(), if !disable_stop => break,
            r = listener.accept() => {
                let (mut cli, peer) = match r {
                    Ok(v) => v,
                    Err(e) => { warn!(error=%e, "accept failed"); continue; }
                };
                let cfg_clone = cfg.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(&mut cli, peer, &cfg_clone).await {
                        // 客户端在方法协商后立刻断开（脚本探活的典型场景），降级为 debug
                        if e.kind() == io::ErrorKind::UnexpectedEof {
                            tracing::debug!(
                                peer=%peer,
                                "socks: client closed after method (expected in probe)"
                            );
                            return;
                        }
                        // 其他错误继续告警
                        warn!(peer=%peer, error=%e, "socks session error");
                    }
                });
            }
        }
    }
    Ok(())
}

// 兼容旧别名
pub async fn run(cfg: SocksInboundConfig, stop_rx: mpsc::Receiver<()>) -> io::Result<()> {
    // NOTE(linus): UDP Associate 骨架已就绪，但默认不启用。
    // 后续批次将基于配置/env 决定是否绑定一个 UDP socket 并回送 BND.ADDR。
    // 占位示例（请勿取消注释，直到接入完整转发表/上游发送）：
    //
    // if std::env::var("SB_SOCKS_UDP_ENABLE").is_ok() {
    //     let sock = std::sync::Arc::new(udp::bind_udp_any(false).await?);
    //     udp::spawn_nat_evictor(&udp::UdpRuntime {
    //         nat: self.nat_map.clone(),
    //         evict_interval: std::time::Duration::from_secs(30),
    //         assoc_timeout: std::time::Duration::from_secs(60),
    //     });
    //     tokio::spawn(udp::serve_udp_datagrams(sock));
    // }
    serve_socks(cfg, stop_rx, None).await
}
pub async fn serve(cfg: SocksInboundConfig, stop_rx: mpsc::Receiver<()>) -> io::Result<()> {
    serve_socks(cfg, stop_rx, None).await
}

async fn handle_conn(
    cli: &mut TcpStream,
    peer: SocketAddr,
    cfg: &SocksInboundConfig,
) -> io::Result<()> {
    #[cfg(feature = "metrics")]
    metrics::counter!("inbound_connections_total",
        "protocol" => "socks", "network" => "tcp")
    .increment(1);

    // --- greeting ---
    let ver = read_u8(cli).await?;
    if ver != 0x05 {
        inbound_parse("socks", "error", "bad_version");
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad ver"));
    }
    let n_methods = read_u8(cli).await? as usize;
    let mut methods = vec![0u8; n_methods];
    cli.read_exact(&mut methods).await?;
    // 仅支持 NO_AUTH
    cli.write_all(&[0x05, 0x00]).await?;

    // --- request header ---
    let mut head = [0u8; 4];
    cli.read_exact(&mut head).await?;
    // VER, CMD, RSV, ATYP
    if head[0] != 0x05 {
        inbound_parse("socks", "error", "bad_version");
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad req ver"));
    }
    let cmd = head[1];
    let atyp = head[3];

    // 解析目标
    let (endpoint, _host_for_route, _port) = match atyp {
        0x01 => {
            let mut b = [0u8; 4];
            cli.read_exact(&mut b).await?;
            let port = read_u16(cli).await?;
            let ip = IpAddr::V4(Ipv4Addr::from(b));
            (
                Endpoint::Ip(SocketAddr::new(ip, port)),
                ip.to_string(),
                port,
            )
        }
        0x04 => {
            let mut b = [0u8; 16];
            cli.read_exact(&mut b).await?;
            let port = read_u16(cli).await?;
            let ip = IpAddr::V6(Ipv6Addr::from(b));
            (
                Endpoint::Ip(SocketAddr::new(ip, port)),
                ip.to_string(),
                port,
            )
        }
        0x03 => {
            let len = read_u8(cli).await? as usize;
            let mut d = vec![0u8; len];
            cli.read_exact(&mut d).await?;
            let host = String::from_utf8_lossy(&d).to_string();
            let port = read_u16(cli).await?;
            (Endpoint::Domain(host.clone(), port), host, port)
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "bad atyp")),
    };

    match cmd {
        0x01 => {
            // CONNECT
            // 握手阶段（greeting/auth/req）完成
            inbound_parse("socks", "ok", "greeting+request");

            let mut decision = RDecision::Direct;
            let proxy = default_proxy();

            // 运行态规则引擎（先判决）
            if let Some(eng) = rules_global::global() {
                let (dom, ip, port) = match &endpoint {
                    Endpoint::Domain(h, p) => (Some(h.as_str()), None, Some(*p)),
                    Endpoint::Ip(sa) => (None, Some(sa.ip()), Some(sa.port())),
                };
                let ctx = RulesRouteCtx {
                    domain: dom,
                    ip,
                    transport_udp: false,
                    port,
                    process_name: None,
                    process_path: None,
                    inbound_tag: None,
                    outbound_tag: None,
                    auth_user: None,
                    query_type: None,
                };
                let d = eng.decide(&ctx);
                #[cfg(feature = "metrics")]
                {
                    metrics::counter!("router_decide_total", "decision"=> match &d { RDecision::Direct=>"direct", RDecision::Proxy(_)=>"proxy", RDecision::Reject=>"reject" }).increment(1);
                }
                if matches!(d, RDecision::Reject) {
                    // SOCKS5: REP=0x02 (connection not allowed by ruleset)
                    reply(cli, 0x02, None).await?;
                    return Ok(());
                }
                decision = d;
            }

            #[cfg(feature="metrics")]
            metrics::counter!("router_route_total",
                "inbound"=>"socks5",
                "decision"=>match &decision { RDecision::Direct=>"direct", RDecision::Proxy(_)=>"proxy", RDecision::Reject=>"reject" },
                "proxy_kind"=>proxy.label()
            ).increment(1);

            // Health check fallback logic
            let fallback_enabled = std::env::var("SB_PROXY_HEALTH_FALLBACK_DIRECT")
                .ok()
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);

            if fallback_enabled && matches!(decision, RDecision::Proxy(_)) {
                if let Some(st) = ob_health::global_status() {
                    if !st.is_up() {
                        tracing::warn!(
                            "router: proxy unhealthy; fallback to direct (socks5 inbound)"
                        );
                        #[cfg(feature = "metrics")]
                        metrics::counter!(
                            "router_route_fallback_total",
                            "from" => "proxy",
                            "to" => "direct",
                            "inbound" => "socks5"
                        )
                        .increment(1);
                        // Override routing result to Direct
                        decision = RDecision::Direct;
                    }
                }
            }

            let opts = ConnectOpts::default();

            // 与上游建立连接（根据决策与默认代理）
            let mut srv = match decision {
                RDecision::Direct => match &endpoint {
                    Endpoint::Domain(host, port) => {
                        direct_connect_hostport(host, *port, &opts).await?
                    }
                    Endpoint::Ip(sa) => {
                        direct_connect_hostport(&sa.ip().to_string(), sa.port(), &opts).await?
                    }
                },
                RDecision::Proxy(pool_name) => {
                    if let Some(name) = pool_name {
                        // Named proxy pool selection
                        let sel = SELECTOR.get_or_init(|| {
                            let ttl = std::env::var("SB_PROXY_STICKY_TTL_MS")
                                .ok()
                                .and_then(|v| v.parse().ok())
                                .unwrap_or(10_000);
                            let cap = std::env::var("SB_PROXY_STICKY_CAP")
                                .ok()
                                .and_then(|v| v.parse().ok())
                                .unwrap_or(4096);
                            PoolSelector::new_with_capacity(
                                cap,
                                std::time::Duration::from_millis(ttl),
                            )
                        });
                        let _health = MultiHealthView;
                        let target_str = match &endpoint {
                            Endpoint::Domain(host, port) => format!("{}:{}", host, port),
                            Endpoint::Ip(sa) => sa.to_string(),
                        };

                        if let Some(reg) = registry::global() {
                            if let Some(_pool) = reg.pools.get(&name) {
                                if let Some(ep) = sel.select(&name, peer, &target_str, &()) {
                                    match ep.kind {
                                        sb_core::outbound::endpoint::ProxyKind::Http => {
                                            match &endpoint {
                                                Endpoint::Domain(host, port) => {
                                                    http_proxy_connect_through_proxy(
                                                        &ep.addr.to_string(),
                                                        host,
                                                        *port,
                                                        &opts,
                                                    )
                                                    .await?
                                                }
                                                Endpoint::Ip(sa) => {
                                                    http_proxy_connect_through_proxy(
                                                        &ep.addr.to_string(),
                                                        &sa.ip().to_string(),
                                                        sa.port(),
                                                        &opts,
                                                    )
                                                    .await?
                                                }
                                            }
                                        }
                                        sb_core::outbound::endpoint::ProxyKind::Socks5 => {
                                            match &endpoint {
                                                Endpoint::Domain(host, port) => {
                                                    socks5_connect_through_socks5(
                                                        &ep.addr.to_string(),
                                                        host,
                                                        *port,
                                                        &opts,
                                                    )
                                                    .await?
                                                }
                                                Endpoint::Ip(sa) => {
                                                    socks5_connect_through_socks5(
                                                        &ep.addr.to_string(),
                                                        &sa.ip().to_string(),
                                                        sa.port(),
                                                        &opts,
                                                    )
                                                    .await?
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    // Pool empty or all endpoints down - fallback to direct or default proxy
                                    match fallback_enabled {
                                        true => {
                                            #[cfg(feature = "metrics")]
                                            metrics::counter!("router_route_fallback_total", "from" => "proxy", "to" => "direct", "reason" => "pool_empty").increment(1);
                                            match &endpoint {
                                                Endpoint::Domain(host, port) => {
                                                    direct_connect_hostport(host, *port, &opts)
                                                        .await?
                                                }
                                                Endpoint::Ip(sa) => {
                                                    direct_connect_hostport(
                                                        &sa.ip().to_string(),
                                                        sa.port(),
                                                        &opts,
                                                    )
                                                    .await?
                                                }
                                            }
                                        }
                                        false => {
                                            reply(cli, 0x01, None).await?; // General failure
                                            return Ok(());
                                        }
                                    }
                                }
                            } else {
                                // Pool not found - fallback to default proxy
                                match proxy {
                                    ProxyChoice::Direct => match &endpoint {
                                        Endpoint::Domain(host, port) => {
                                            direct_connect_hostport(host, *port, &opts).await?
                                        }
                                        Endpoint::Ip(sa) => {
                                            direct_connect_hostport(
                                                &sa.ip().to_string(),
                                                sa.port(),
                                                &opts,
                                            )
                                            .await?
                                        }
                                    },
                                    ProxyChoice::Http(addr) => match &endpoint {
                                        Endpoint::Domain(host, port) => {
                                            http_proxy_connect_through_proxy(
                                                addr, host, *port, &opts,
                                            )
                                            .await?
                                        }
                                        Endpoint::Ip(sa) => {
                                            http_proxy_connect_through_proxy(
                                                addr,
                                                &sa.ip().to_string(),
                                                sa.port(),
                                                &opts,
                                            )
                                            .await?
                                        }
                                    },
                                    ProxyChoice::Socks5(addr) => match &endpoint {
                                        Endpoint::Domain(host, port) => {
                                            socks5_connect_through_socks5(addr, host, *port, &opts)
                                                .await?
                                        }
                                        Endpoint::Ip(sa) => {
                                            socks5_connect_through_socks5(
                                                addr,
                                                &sa.ip().to_string(),
                                                sa.port(),
                                                &opts,
                                            )
                                            .await?
                                        }
                                    },
                                }
                            }
                        } else {
                            // No registry - fallback to default proxy
                            match proxy {
                                ProxyChoice::Direct => match &endpoint {
                                    Endpoint::Domain(host, port) => {
                                        direct_connect_hostport(host, *port, &opts).await?
                                    }
                                    Endpoint::Ip(sa) => {
                                        direct_connect_hostport(
                                            &sa.ip().to_string(),
                                            sa.port(),
                                            &opts,
                                        )
                                        .await?
                                    }
                                },
                                ProxyChoice::Http(addr) => match &endpoint {
                                    Endpoint::Domain(host, port) => {
                                        http_proxy_connect_through_proxy(addr, host, *port, &opts)
                                            .await?
                                    }
                                    Endpoint::Ip(sa) => {
                                        http_proxy_connect_through_proxy(
                                            addr,
                                            &sa.ip().to_string(),
                                            sa.port(),
                                            &opts,
                                        )
                                        .await?
                                    }
                                },
                                ProxyChoice::Socks5(addr) => match &endpoint {
                                    Endpoint::Domain(host, port) => {
                                        socks5_connect_through_socks5(addr, host, *port, &opts)
                                            .await?
                                    }
                                    Endpoint::Ip(sa) => {
                                        socks5_connect_through_socks5(
                                            addr,
                                            &sa.ip().to_string(),
                                            sa.port(),
                                            &opts,
                                        )
                                        .await?
                                    }
                                },
                            }
                        }
                    } else {
                        // Default proxy (no named pool)
                        match proxy {
                            ProxyChoice::Direct => match &endpoint {
                                Endpoint::Domain(host, port) => {
                                    direct_connect_hostport(host, *port, &opts).await?
                                }
                                Endpoint::Ip(sa) => {
                                    direct_connect_hostport(&sa.ip().to_string(), sa.port(), &opts)
                                        .await?
                                }
                            },
                            ProxyChoice::Http(addr) => match &endpoint {
                                Endpoint::Domain(host, port) => {
                                    http_proxy_connect_through_proxy(addr, host, *port, &opts)
                                        .await?
                                }
                                Endpoint::Ip(sa) => {
                                    http_proxy_connect_through_proxy(
                                        addr,
                                        &sa.ip().to_string(),
                                        sa.port(),
                                        &opts,
                                    )
                                    .await?
                                }
                            },
                            ProxyChoice::Socks5(addr) => match &endpoint {
                                Endpoint::Domain(host, port) => {
                                    socks5_connect_through_socks5(addr, host, *port, &opts).await?
                                }
                                Endpoint::Ip(sa) => {
                                    socks5_connect_through_socks5(
                                        addr,
                                        &sa.ip().to_string(),
                                        sa.port(),
                                        &opts,
                                    )
                                    .await?
                                }
                            },
                        }
                    }
                }
                RDecision::Reject => {
                    // Safety: RDecision::Reject is handled earlier at line 222-225 with early return
                    unreachable!("RDecision::Reject filtered out earlier")
                }
            };

            // 成功：回复 0x00，BND=0.0.0.0:0
            reply(cli, 0x00, None).await?;
            debug!(peer=%peer, "socks connect established");

            // 双向转发 + 计量 + 读/写超时（可选，来自环境）
            fn dur_from_env(key: &str) -> Option<std::time::Duration> {
                std::env::var(key)
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
                    .and_then(|ms| {
                        if ms > 0 {
                            Some(std::time::Duration::from_millis(ms))
                        } else {
                            None
                        }
                    })
            }

            let rt = dur_from_env("SB_TCP_READ_TIMEOUT_MS");
            let wt = dur_from_env("SB_TCP_WRITE_TIMEOUT_MS");
            let (_up, _down) = sb_core::net::metered::copy_bidirectional_streaming_ctl(
                cli,
                &mut srv,
                "socks",
                std::time::Duration::from_secs(1),
                rt,
                wt,
                None,
            )
            .await?;
            Ok(())
        }
        0x03 => {
            // UDP ASSOCIATE
            // 如果声明了 udp_bind，就用它；否则回复 0 地址
            reply(cli, 0x00, cfg.udp_bind).await?;
            #[cfg(feature = "metrics")]
            metrics::counter!("inbound_connections_total",
                "protocol" => "socks", "network" => "udp")
            .increment(1);
            Ok(())
        }
        0x02 => {
            // BIND（不支持）
            inbound_parse("socks", "error", "bad_method");
            reply(cli, 0x07, None).await?; // Command not supported
            Ok(())
        }
        _ => {
            inbound_parse("socks", "error", "bad_method");
            reply(cli, 0x07, None).await?;
            Ok(())
        }
    }
}

// 握手开始处（收到 VERS/NMETHODS 等）
// 如果版本不是 0x05，在返回之前补：
// inbound_parse("socks","error","bad_version");
// 如果认证方法不支持，返回前补：
// inbound_parse("socks","error","bad_method");
// 如果命令不是 CONNECT（或 UDP ASSOCIATE 在此处仅宣告不实现），在返回前补：
// inbound_parse("socks","error","bad_cmd");

// 在各个错误返回点（如版本不匹配、方法不支持、ATYP 不支持等），附带：
// inbound_parse("socks","error","bad_version"|"bad_method"|"bad_cmd"|"bad_atyp");
// 若上游连接/握手失败，在 Err 分支前：
// inbound_forward("socks","error",Some(err_kind(&e)));
// timeout： inbound_forward("socks","timeout",Some("timeout"));

async fn reply(cli: &mut TcpStream, rep: u8, bnd: Option<SocketAddr>) -> io::Result<()> {
    // 统一回复格式：VER=5, REP=rep, RSV=0, ATYP + ADDR + PORT
    let mut buf = Vec::with_capacity(4 + 18 + 2);
    buf.push(0x05);
    buf.push(rep);
    buf.push(0x00);
    match bnd {
        Some(sa) => match sa.ip() {
            IpAddr::V4(v4) => {
                buf.push(0x01);
                buf.extend_from_slice(&v4.octets());
                buf.push((sa.port() >> 8) as u8);
                buf.push((sa.port() & 0xff) as u8);
            }
            IpAddr::V6(v6) => {
                buf.push(0x04);
                buf.extend_from_slice(&v6.octets());
                buf.push((sa.port() >> 8) as u8);
                buf.push((sa.port() & 0xff) as u8);
            }
        },
        None => {
            // 0.0.0.0:0
            buf.push(0x01);
            buf.extend_from_slice(&[0, 0, 0, 0]);
            buf.extend_from_slice(&[0, 0]);
        }
    }
    cli.write_all(&buf).await
}

async fn read_u8(s: &mut TcpStream) -> io::Result<u8> {
    let mut b = [0u8; 1];
    s.read_exact(&mut b).await?;
    Ok(b[0])
}
async fn read_u16(s: &mut TcpStream) -> io::Result<u16> {
    let mut b = [0u8; 2];
    s.read_exact(&mut b).await?;
    Ok(u16::from_be_bytes(b))
}

// 构造 RouteCtx 的小助手（避免借用/解引用细节）
#[allow(dead_code)] // Reserved for context building
fn route_ctx_from_endpoint(ep: &Endpoint) -> RouteCtx<'_> {
    match ep {
        Endpoint::Domain(h, p) => RouteCtx {
            host: Some(h.as_str()),
            ip: None,
            port: Some(*p),
            transport: Transport::Tcp,
            network: "tcp",
        },
        Endpoint::Ip(sa) => RouteCtx {
            host: None,
            ip: Some(sa.ip()),
            port: Some(sa.port()),
            transport: Transport::Tcp,
            network: "tcp",
        },
    }
}

// 供 UDP 子模块复用（入站内部工具）
fn _target_to_string_lossy(ep: &Endpoint) -> String {
    match ep {
        Endpoint::Ip(sa) => sa.to_string(),
        Endpoint::Domain(h, p) => format!("{}:{}", h, p),
    }
}

pub struct SocksInbound {
    // Placeholder fields for the structure
}

impl SocksInbound {
    pub async fn run(&self) -> anyhow::Result<()> {
        // ... 既有 TCP 接受/处理逻辑 ...

        // NOTE(linus): UDP Associate 接入（默认关闭）。仅当显式设置 SB_SOCKS_UDP_ENABLE=1 时启用。
        // 行为守恒：不开关 → 不绑定端口，不起后台任务。
        if std::env::var("SB_SOCKS_UDP_ENABLE").is_ok() {
            // 绑定：支持 SB_SOCKS_UDP_BIND="0.0.0.0:0,[::]:0" 多地址
            let sockets = udp::bind_udp_from_env_or_any()
                .await
                .map_err(|e| anyhow::anyhow!("bind_udp_from_env_or_any failed: {e}"))?;
            // 起 NAT 驱逐占位（内部会 spawn，并持续运行；目前不依赖 self 的成员，零侵入）
            let nat = std::sync::Arc::new(sb_core::net::datagram::UdpNatMap::new(
                std::time::Duration::from_secs(60),
            ));
            udp::spawn_nat_evictor(&udp::UdpRuntime {
                map: nat,
                ttl: std::time::Duration::from_secs(60),
                scan: std::time::Duration::from_secs(30),
            });
            // 后台处理 UDP 报文（解析+上游转发+回写）
            for s in sockets {
                tokio::spawn({
                    let sock = s.clone();
                    async move {
                        // 这里的 sock 已经是 Arc<UdpSocket>，与新签名匹配
                        if let Err(e) = udp::serve_udp_datagrams(sock).await {
                            tracing::warn!("socks/udp serve ended: {e}");
                        }
                    }
                });
                tracing::info!(
                    "socks: UDP inbound enabled (SB_SOCKS_UDP_ENABLE=1) bind={:?}",
                    s.local_addr()
                );
            }
        }

        // NOTE(linus): TCP（仅 UDP_ASSOCIATE）接入（默认关闭）。
        if std::env::var("SB_SOCKS_TCP_ENABLE").is_ok() {
            // 如果用户只开了 TCP 开关而没开 UDP，我们也要保证有一个 UDP 绑定用于 BND.ADDR/PORT
            if udp::get_udp_bind_addr().is_none() {
                let sockets = udp::bind_udp_from_env_or_any()
                    .await
                    .map_err(|e| anyhow::anyhow!("bind_udp_from_env_or_any failed: {e}"))?;
                for s in sockets {
                    tokio::spawn({
                        let sock = s.clone();
                        async move {
                            if let Err(e) = udp::serve_udp_datagrams(sock).await {
                                tracing::warn!("socks/udp (autostart for TCP) ended: {e}");
                            }
                        }
                    });
                    tracing::info!(
                        "socks: auto-enable UDP for TCP UDP_ASSOCIATE, bind={:?}",
                        s.local_addr()
                    );
                }
            }
            let addr =
                std::env::var("SB_SOCKS_TCP_ADDR").unwrap_or_else(|_| "127.0.0.1:1080".to_string());
            let addr_for_log = addr.clone();
            tokio::spawn(async move {
                let addr = addr; // move 进闭包，避免后续 borrow moved value
                if let Err(e) = crate::inbound::socks::tcp::run_tcp(&addr).await {
                    tracing::warn!("socks/tcp run failed: {e}");
                }
            });
            tracing::info!("socks: TCP (UDP_ASSOCIATE) enabled at {}", addr_for_log);
        }
        Ok(())
    }
}
