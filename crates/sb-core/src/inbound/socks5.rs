//! Async SOCKS5 server: no auth, CONNECT (TCP) and UDP ASSOCIATE (minimal).
//! feature = "scaffold"
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::adapter::{Bridge, InboundService};
use crate::log::{self, Level};
use crate::net::metered::{self, TrafficRecorder};

#[cfg(feature = "router")]
use crate::routing::engine::{Engine as RouterEngine, Input as RouterInput};
use sb_platform::process::{ConnectionInfo, Protocol};

#[cfg(feature = "router")]
type EngineX<'a> = RouterEngine<'a>;
#[cfg(not(feature = "router"))]
type EngineX<'a> = Engine;

#[cfg(not(feature = "router"))]
#[derive(Debug)]
pub(crate) struct Engine {
    cfg: sb_config::ir::ConfigIR,
}

#[cfg(not(feature = "router"))]
struct Decision {
    outbound: String,
}

#[cfg(not(feature = "router"))]
impl Engine {
    pub(crate) fn new(cfg: sb_config::ir::ConfigIR) -> Self {
        Self { cfg }
    }

    fn resolve_default_outbound_tag(&self) -> String {
        self.cfg
            .outbounds
            .iter()
            .find_map(|ob| ob.name.clone())
            .unwrap_or_default()
    }

    fn decide(&self, _input: &Input, _fake_ip: bool) -> Decision {
        Decision {
            outbound: self.resolve_default_outbound_tag(),
        }
    }
}

#[cfg(not(feature = "router"))]
impl Clone for Engine {
    fn clone(&self) -> Self {
        Self {
            cfg: self.cfg.clone(),
        }
    }
}

#[cfg(not(feature = "router"))]
#[allow(dead_code)]
struct Input {
    host: String,
    port: u16,
    network: String,
    protocol: String,
}

#[cfg(not(feature = "router"))]
impl Input {
    #[allow(dead_code)]
    fn new() -> Self {
        Self {
            host: String::new(),
            port: 0,
            network: String::new(),
            protocol: String::new(),
        }
    }
}

pub(crate) async fn handle_conn(
    mut cli: TcpStream,
    eng: &EngineX<'static>,
    bridge: &Bridge,
    sniff_enabled: bool,
) -> std::io::Result<()> {
    // greeting
    let mut head = [0u8; 2];
    cli.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not socks5",
        ));
    }
    let n_methods = head[1] as usize;
    let mut methods = vec![0u8; n_methods];
    cli.read_exact(&mut methods).await?;
    // only no-auth
    cli.write_all(&[0x05, 0x00]).await?;

    // request
    let mut reqh = [0u8; 4];
    cli.read_exact(&mut reqh).await?;
    if reqh[1] == 0x03 {
        // UDP ASSOCIATE
        #[cfg(feature = "metrics")]
        sb_metrics::inc_socks_udp_assoc();

        // Allocate a UDP relay socket bound on the same listen interface
        // Note: minimal implementation; NAT and multi-client isolation kept per-association
        let bind_ip = "0.0.0.0".to_string();
        let relay_sock = UdpSocket::bind((bind_ip.as_str(), 0)).await?;
        let relay_addr = relay_sock.local_addr()?;
        let relay = std::sync::Arc::new(relay_sock);

        // Reply success with bound address
        let mut resp = Vec::with_capacity(16);
        resp.extend_from_slice(&[0x05, 0x00, 0x00]); // VER, REP, RSV
        match relay_addr.ip() {
            std::net::IpAddr::V4(v4) => {
                resp.push(0x01); // ATYP IPv4
                resp.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                resp.push(0x04); // ATYP IPv6
                resp.extend_from_slice(&v6.octets());
            }
        }
        resp.extend_from_slice(&relay_addr.port().to_be_bytes());
        cli.write_all(&resp).await?;

        // Spawn UDP relay loop
        let eng_owned = eng.clone();
        let br_owned = bridge.clone();
        tokio::spawn(async move {
            // Track client endpoint (learned from first client datagram)
            let mut client_ep: Option<std::net::SocketAddr> = None;
            // A simple buffer reused for I/O
            let mut buf = vec![0u8; 64 * 1024];
            // Outbound UDP session created lazily on demand
            let mut udp_sess: Option<Arc<dyn crate::adapter::UdpOutboundSession>> = None;
            // Best-effort traffic recorder for relay-originated packets (no NAT/session)
            let mut last_traffic: Option<Arc<dyn TrafficRecorder>> = None;
            // Conntrack wiring (per UDP associate session)
            let mut conntrack_meta: Option<crate::net::datagram::UdpConntrackMeta> = None;
            // One-shot warning to avoid log spam when UDP fallback is disabled.
            let mut udp_no_fallback_reported = false;
            loop {
                let recv_res = if let Some(meta) = &conntrack_meta {
                    tokio::select! {
                        _ = meta.cancel.cancelled() => break,
                        r = relay.recv_from(&mut buf) => r,
                    }
                } else {
                    relay.recv_from(&mut buf).await
                };
                let Ok((n, src)) = recv_res else {
                    break;
                };

                let from_client = match client_ep {
                    None => {
                        // First packet source becomes client endpoint
                        client_ep = Some(src);
                        true
                    }
                    Some(ep) => ep == src,
                };

                if from_client {
                    // Parse SOCKS5 UDP request: RSV(2)=0, FRAG(1)=0, ATYP, DST.ADDR, DST.PORT, DATA
                    if n < 4 {
                        continue;
                    }
                    if buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
                        continue;
                    }
                    let mut p = 3usize;
                    let atyp = buf[p];
                    p += 1;
                    let dst_host = match atyp {
                        0x01 => {
                            // IPv4
                            if p + 4 > n {
                                continue;
                            }
                            let ip =
                                std::net::Ipv4Addr::new(buf[p], buf[p + 1], buf[p + 2], buf[p + 3]);
                            p += 4;
                            ip.to_string()
                        }
                        0x03 => {
                            // Domain
                            if p >= n {
                                continue;
                            }
                            let ln = buf[p] as usize;
                            p += 1;
                            if p + ln > n {
                                continue;
                            }
                            let s = std::str::from_utf8(&buf[p..p + ln])
                                .unwrap_or("")
                                .to_string();
                            p += ln;
                            s
                        }
                        0x04 => {
                            // IPv6
                            if p + 16 > n {
                                continue;
                            }
                            let mut o = [0u8; 16];
                            o.copy_from_slice(&buf[p..p + 16]);
                            p += 16;
                            std::net::Ipv6Addr::from(o).to_string()
                        }
                        _ => continue,
                    };
                    if p + 2 > n {
                        continue;
                    }
                    let dst_port = u16::from_be_bytes([buf[p], buf[p + 1]]);
                    p += 2;
                    if p > n {
                        continue;
                    }
                    let payload = &buf[p..n];

                    #[cfg(feature = "metrics")]
                    sb_metrics::inc_socks_udp_packet("out");

                    // Router decision for UDP (bind outbound at first packet)
                    #[cfg(feature = "router")]
                    let d = {
                        let sniffed = if sniff_enabled {
                            crate::routing::sniff::sniff_datagram(payload)
                        } else {
                            crate::routing::sniff::SniffOutcome::default()
                        };
                        let mut matched_rule_sets = Vec::new();
                        if let Some(router) = &br_owned.router {
                            if let Some(db) = router.rule_set_db() {
                                db.match_host(&dst_host, &mut matched_rule_sets);
                                if let Ok(ip) = dst_host.parse() {
                                    db.match_ip(ip, &mut matched_rule_sets);
                                }
                            }
                        }
                        let clash_mode_str: Option<String> = None;
                        let clash_mode_ref = clash_mode_str.as_deref().map(|s| match s {
                            "rule" => "Rule",
                            "global" => "Global",
                            "direct" => "Direct",
                            _ => s,
                        });
                        let input = RouterInput {
                            host: &dst_host,
                            port: dst_port,
                            network: "udp",
                            protocol: "socks",
                            sniff_alpn: sniffed.alpn.as_deref(),
                            sniff_protocol: sniffed.protocol,
                            rule_set: if matched_rule_sets.is_empty() {
                                None
                            } else {
                                Some(&matched_rule_sets)
                            },
                            clash_mode: clash_mode_ref,
                            network_type: Some(br_owned.context.network_monitor.get_network_type()),
                            network_is_expensive: Some(
                                br_owned.context.network_monitor.is_expensive(),
                            ),
                            network_is_constrained: Some(
                                br_owned.context.network_monitor.is_constrained(),
                            ),
                            ..Default::default()
                        };
                        eng_owned.decide(&input, false)
                    };
                    #[cfg(not(feature = "router"))]
                    let d = {
                        let input = Input {
                            host: dst_host.clone(),
                            port: dst_port,
                            network: "udp".to_string(),
                            protocol: "socks".to_string(),
                        };
                        eng_owned.decide(&input, false)
                    };
                    #[cfg(feature = "router")]
                    let rule = Some(d.matched_rule.clone());
                    #[cfg(not(feature = "router"))]
                    let rule: Option<String> = None;
                    let out_name = d.outbound;
                    let traffic = br_owned
                        .context
                        .v2ray_server
                        .as_ref()
                        .and_then(|s| s.stats())
                        .and_then(|stats| {
                            stats.traffic_recorder(None, Some(out_name.as_str()), None)
                        });
                    last_traffic = traffic.clone();
                    if conntrack_meta.is_none() {
                        let chains = if out_name.eq_ignore_ascii_case("direct") {
                            vec!["DIRECT".to_string()]
                        } else {
                            vec![out_name.clone()]
                        };
                        let client_addr = client_ep.unwrap_or(src);
                        let wiring = crate::conntrack::register_inbound_udp(
                            client_addr,
                            dst_host.clone(),
                            dst_port,
                            dst_host.clone(),
                            "socks_udp",
                            None,
                            Some(out_name.clone()),
                            chains,
                            rule.clone(),
                            None,
                            None,
                            traffic.clone(),
                        );
                        conntrack_meta = Some(crate::net::datagram::UdpConntrackMeta {
                            guard: wiring.guard,
                            cancel: wiring.cancel.clone(),
                            traffic: wiring.traffic.clone(),
                        });
                        last_traffic = Some(wiring.traffic.clone());
                    }

                    // Open UDP session once, if available for outbound
                    if udp_sess.is_none() {
                        if let Some(factory) = br_owned.find_udp_factory(&out_name) {
                            match factory.open_session().await {
                                Ok(sess) => {
                                    // Spawn a receive loop for this session → client endpoint
                                    if let Some(ep) = client_ep {
                                        let relay_c = relay.clone();
                                        let sess_c = sess.clone();
                                        let traffic_c = conntrack_meta
                                            .as_ref()
                                            .map(|m| m.traffic.clone())
                                            .or_else(|| traffic.clone());
                                        let cancel_c =
                                            conntrack_meta.as_ref().map(|m| m.cancel.clone());
                                        tokio::spawn(async move {
                                            loop {
                                                let recv_res = if let Some(cancel) = &cancel_c {
                                                    tokio::select! {
                                                        _ = cancel.cancelled() => break,
                                                        r = sess_c.recv_from() => r,
                                                    }
                                                } else {
                                                    sess_c.recv_from().await
                                                };
                                                let Ok((data, src_addr)) = recv_res else {
                                                    break;
                                                };
                                                // Wrap and forward to client
                                                let mut pkt = Vec::with_capacity(data.len() + 10);
                                                pkt.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV RSV FRAG
                                                match src_addr.ip() {
                                                    std::net::IpAddr::V4(v4) => {
                                                        pkt.push(0x01);
                                                        pkt.extend_from_slice(&v4.octets());
                                                    }
                                                    std::net::IpAddr::V6(v6) => {
                                                        pkt.push(0x04);
                                                        pkt.extend_from_slice(&v6.octets());
                                                    }
                                                }
                                                pkt.extend_from_slice(
                                                    &src_addr.port().to_be_bytes(),
                                                );
                                                pkt.extend_from_slice(&data);
                                                if relay_c.send_to(&pkt, ep).await.is_ok() {
                                                    if let Some(ref recorder) = traffic_c {
                                                        recorder.record_down(data.len() as u64);
                                                        recorder.record_down_packet(1);
                                                    }
                                                }
                                            }
                                        });
                                    }
                                    udp_sess = Some(sess);
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "open udp session failed for outbound '{}': {}",
                                        out_name,
                                        e
                                    );
                                }
                            }
                        }
                    }

                    if let Some(meta) = &conntrack_meta {
                        if meta.cancel.is_cancelled() {
                            continue;
                        }
                    }
                    if let Some(ref sess) = udp_sess {
                        if sess.send_to(payload, &dst_host, dst_port).await.is_ok() {
                            if let Some(meta) = &conntrack_meta {
                                meta.traffic.record_up(payload.len() as u64);
                                meta.traffic.record_up_packet(1);
                            } else if let Some(ref recorder) = traffic {
                                recorder.record_up(payload.len() as u64);
                                recorder.record_up_packet(1);
                            }
                        }
                    } else if !udp_no_fallback_reported {
                        tracing::warn!(
                            "socks5-udp: outbound '{}' has no UDP session; direct fallback is disabled; use adapter bridge/supervisor path",
                            out_name
                        );
                        udp_no_fallback_reported = true;
                    }
                } else {
                    // From remote to client: wrap with SOCKS5 UDP header and forward
                    #[cfg(feature = "metrics")]
                    sb_metrics::inc_socks_udp_packet("in");

                    let mut pkt = Vec::with_capacity(n + 10);
                    pkt.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV RSV FRAG
                    match src.ip() {
                        std::net::IpAddr::V4(v4) => {
                            pkt.push(0x01);
                            pkt.extend_from_slice(&v4.octets());
                        }
                        std::net::IpAddr::V6(v6) => {
                            pkt.push(0x04);
                            pkt.extend_from_slice(&v6.octets());
                        }
                    }
                    pkt.extend_from_slice(&src.port().to_be_bytes());
                    pkt.extend_from_slice(&buf[..n]);
                    if let Some(ep) = client_ep {
                        let _ = relay.send_to(&pkt, ep).await;
                        if let Some(ref recorder) = last_traffic {
                            recorder.record_down(n as u64);
                            recorder.record_down_packet(1);
                        }
                    }
                }
            }
        });

        return Ok(());
    }
    if reqh[1] != 0x01 {
        // Only CONNECT and UDP ASSOCIATE supported minimally
        cli.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        return Err(std::io::Error::other("unsupported SOCKS5 command"));
    }

    let host = match reqh[3] {
        0x01 => {
            // IPv4
            let mut ip = [0u8; 4];
            cli.read_exact(&mut ip).await?;
            std::net::Ipv4Addr::from(ip).to_string()
        }
        0x03 => {
            // domain
            let mut ln = [0u8; 1];
            cli.read_exact(&mut ln).await?;
            let mut name = vec![0u8; ln[0] as usize];
            cli.read_exact(&mut name).await?;
            String::from_utf8_lossy(&name).to_string()
        }
        0x04 => {
            // IPv6
            let mut ip = [0u8; 16];
            cli.read_exact(&mut ip).await?;
            std::net::Ipv6Addr::from(ip).to_string()
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bad atyp",
            ))
        }
    };

    let mut p = [0u8; 2];
    cli.read_exact(&mut p).await?;
    let port = u16::from_be_bytes(p);

    // SOCKS5 规范通常在成功连接目标后再回包；为嗅探 ALPN/SNI，这里采用“乐观回包→快速读取首包→建立上游→回放首包”的策略。
    // 1) 立即回包成功（bound addr 使用 0.0.0.0:0）
    cli.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    // 2) 可选嗅探：快速读取客户端首包（不阻塞）
    let mut sniff_host_opt: Option<String> = None;
    let mut sniff_alpn_opt: Option<String> = None;
    let mut sniff_protocol_opt: Option<&'static str> = None;
    let mut first_payload = Vec::new();
    if sniff_enabled {
        let mut buf = [0u8; 1024];
        if let Ok(Ok(n)) =
            tokio::time::timeout(std::time::Duration::from_millis(150), cli.read(&mut buf)).await
        {
            if n > 0 {
                first_payload.extend_from_slice(&buf[..n]);
                #[cfg(feature = "router")]
                {
                    let sniffed = crate::routing::sniff::sniff_stream(&first_payload);
                    sniff_host_opt = sniffed.host;
                    sniff_alpn_opt = sniffed.alpn;
                    sniff_protocol_opt = sniffed.protocol;
                }
                #[cfg(not(feature = "router"))]
                {
                    // No router, no sniffing logic available
                }
            }
        }
    }

    // 3) 路由决策（允许使用嗅探字段）
    let mut process_name: Option<String> = None;
    let mut process_path: Option<String> = None;

    #[cfg(feature = "router")]
    let d = {
        let sniff_host_ref = sniff_host_opt.as_deref();
        let sniff_alpn_ref = sniff_alpn_opt.as_deref();
        let sniff_proto_ref = sniff_protocol_opt;

        // Process matching
        if let Some(matcher) = &bridge.context.process_matcher {
            let find_process = {
                let opts = bridge.context.network.route_options();
                opts.find_process
            };
            if find_process {
                if let (Ok(local_addr), Ok(remote_addr)) = (cli.local_addr(), cli.peer_addr()) {
                    let conn_info = ConnectionInfo {
                        local_addr,
                        remote_addr,
                        protocol: Protocol::Tcp,
                    };
                    if let Ok(info) = matcher.match_connection(&conn_info).await {
                        process_name = Some(info.name);
                        process_path = Some(info.path);
                    }
                }
            }
        }

        let mut matched_rule_sets = Vec::new();
        if let Some(router) = &bridge.router {
            if let Some(db) = router.rule_set_db() {
                db.match_host(&host, &mut matched_rule_sets);
                if let Ok(ip) = host.parse() {
                    db.match_ip(ip, &mut matched_rule_sets);
                }
            }
        }
        let clash_mode_str: Option<String> = None;
        let clash_mode_ref = clash_mode_str.as_deref().map(|s| match s {
            "rule" => "Rule",
            "global" => "Global",
            "direct" => "Direct",
            _ => s,
        });

        let input = RouterInput {
            host: &host,
            port,
            network: "tcp",
            protocol: "socks",
            sniff_host: sniff_host_ref,
            sniff_alpn: sniff_alpn_ref,
            sniff_protocol: sniff_proto_ref,
            process_name: process_name.as_deref(),
            process_path: process_path.as_deref(),
            rule_set: if matched_rule_sets.is_empty() {
                None
            } else {
                Some(&matched_rule_sets)
            },
            clash_mode: clash_mode_ref,
            package_name: process_name.as_deref(),
            network_type: Some(bridge.context.network_monitor.get_network_type()),
            network_is_expensive: Some(bridge.context.network_monitor.is_expensive()),
            network_is_constrained: Some(bridge.context.network_monitor.is_constrained()),
            ..Default::default()
        };
        eng.decide(&input, false)
    };
    #[cfg(not(feature = "router"))]
    let d = {
        let input = Input {
            host: host.clone(),
            port,
            network: "tcp".to_string(),
            protocol: "socks".to_string(),
        };
        eng.decide(&input, false)
    };
    #[cfg(feature = "router")]
    let rule = Some(d.matched_rule.clone());
    #[cfg(not(feature = "router"))]
    let rule: Option<String> = None;
    let out_name = d.outbound;
    let outbound_tag = out_name.clone();
    let ob = bridge.find_outbound(&out_name).ok_or_else(|| {
        std::io::Error::other(
            "no outbound connector available; direct fallback is disabled in SOCKS5 inbound route path",
        )
    })?;

    // 4) 连接上游并回放首包
    let mut upstream = match ob.connect(&host, port).await {
        Ok(stream) => stream,
        Err(e) => {
            return Err(std::io::Error::other(e));
        }
    };

    // 5) 透传双向数据
    let traffic = bridge
        .context
        .v2ray_server
        .as_ref()
        .and_then(|s| s.stats())
        .and_then(|stats| stats.traffic_recorder(None, Some(outbound_tag.as_str()), None));
    let chains = if outbound_tag.eq_ignore_ascii_case("direct") {
        vec!["DIRECT".to_string()]
    } else {
        vec![outbound_tag.clone()]
    };
    let wiring = crate::conntrack::register_inbound_tcp(
        cli.peer_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0))),
        host.clone(),
        port,
        host.clone(),
        "socks",
        None,
        Some(outbound_tag.clone()),
        chains,
        rule.clone(),
        process_name.clone(),
        process_path.clone(),
        traffic,
    );
    if !first_payload.is_empty() {
        let _ = upstream.write_all(&first_payload).await;
        wiring.traffic.record_up(first_payload.len() as u64);
        wiring.traffic.record_up_packet(1);
    }
    let _guard = wiring.guard;
    let copy_res = metered::copy_bidirectional_streaming_ctl(
        &mut cli,
        &mut upstream,
        "socks",
        Duration::from_secs(1),
        None,
        None,
        Some(wiring.cancel),
        Some(wiring.traffic),
    )
    .await;
    if let Err(e) = copy_res {
        if e.kind() != std::io::ErrorKind::Interrupted {
            return Err(e);
        }
    }

    Ok(())
}

#[derive(Debug)]
pub struct Socks5 {
    listen: String,
    port: u16,
    #[cfg(feature = "router")]
    engine: Option<EngineX<'static>>,
    #[cfg(not(feature = "router"))]
    engine: Option<Engine>,
    bridge: Option<Arc<Bridge>>,
    sniff_enabled: bool,
    shutdown: Arc<AtomicBool>,
    active: Arc<AtomicU64>,
    udp_count: Arc<AtomicU64>,
    rate_limiter: Option<crate::net::tcp_rate_limit::TcpRateLimiter>,
}

impl Socks5 {
    pub fn new(listen: String, port: u16) -> Self {
        let rate_limiter = Some(crate::net::tcp_rate_limit::TcpRateLimiter::new(
            crate::net::tcp_rate_limit::TcpRateLimitConfig::from_env(),
        ));
        Self {
            listen,
            port,
            engine: None,
            bridge: None,
            sniff_enabled: false,
            shutdown: Arc::new(AtomicBool::new(false)),
            active: Arc::new(AtomicU64::new(0)),
            udp_count: Arc::new(AtomicU64::new(0)),
            rate_limiter,
        }
    }

    #[cfg(feature = "router")]
    pub fn with_engine(mut self, eng: EngineX<'static>) -> Self {
        self.engine = Some(eng);
        self
    }

    #[cfg(not(feature = "router"))]
    #[allow(dead_code)]
    pub(crate) fn with_engine(mut self, eng: Engine) -> Self {
        self.engine = Some(eng);
        self
    }

    pub fn with_bridge(mut self, br: Arc<Bridge>) -> Self {
        self.bridge = Some(br);
        self
    }

    /// Enable/disable inbound sniff features (TLS SNI/ALPN)
    pub fn with_sniff(mut self, enabled: bool) -> Self {
        self.sniff_enabled = enabled;
        self
    }

    async fn do_serve_async(&self, eng: EngineX<'static>, br: Arc<Bridge>) -> std::io::Result<()> {
        let addr = format!("{}:{}", self.listen, self.port);
        let listener = TcpListener::bind(&addr).await?;
        log::log(Level::Info, "socks5 listening (async)", &[("addr", &addr)]);

        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }
            match tokio::time::timeout(Duration::from_millis(1000), listener.accept()).await {
                Err(_) => continue,
                Ok(Err(e)) => {
                    log::log(Level::Warn, "accept failed", &[("err", &format!("{}", e))]);
                    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                    continue;
                }
                Ok(Ok((socket, peer_addr))) => {
                    // Rate limit check
                    if let Some(limiter) = &self.rate_limiter {
                        if !limiter.allow_connection(peer_addr.ip()) {
                            tracing::warn!("Rate limit exceeded for {}", peer_addr.ip());
                            continue;
                        }
                    }

                    let active = self.active.clone();
                    active.fetch_add(1, Ordering::Relaxed);
                    // metrics: report updated active count
                    crate::metrics::inbound::set_active_connections(
                        "socks",
                        active.load(Ordering::Relaxed),
                    );
                    let eng_clone = eng.clone();
                    let br_clone = br.clone();
                    let sniff = self.sniff_enabled;
                    tokio::spawn(async move {
                        if let Err(e) = handle_conn(socket, &eng_clone, &br_clone, sniff).await {
                            tracing::debug!(target: "sb_core::inbound::socks5", error = %e, "connection handler failed");
                        }
                        active.fetch_sub(1, Ordering::Relaxed);
                        crate::metrics::inbound::set_active_connections(
                            "socks",
                            active.load(Ordering::Relaxed),
                        );
                    });
                }
            }
        }
        Ok(())
    }
}

impl InboundService for Socks5 {
    fn serve(&self) -> std::io::Result<()> {
        // 阻塞式入口，内部启动 tokio runtime
        #[cfg(not(feature = "router"))]
        let eng = {
            let cfg = sb_config::ir::ConfigIR::default();
            self.engine.clone().unwrap_or_else(|| EngineX::new(cfg))
        };

        #[cfg(feature = "router")]
        let eng = {
            // For router feature, use Box::leak for static lifetime
            let cfg = Box::leak(Box::new(sb_config::ir::ConfigIR::default()));
            self.engine.clone().unwrap_or_else(|| EngineX::new(cfg))
        };
        let br = self.bridge.clone().unwrap_or_else(|| {
            Arc::new(crate::adapter::Bridge::new(crate::context::Context::new()))
        });

        // 使用当前 tokio runtime 或创建新的
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                // Already in a tokio runtime
                handle.block_on(self.do_serve_async(eng, br))
            }
            Err(_) => {
                // No tokio runtime, create one
                let runtime = tokio::runtime::Runtime::new().map_err(std::io::Error::other)?;
                runtime.block_on(self.do_serve_async(eng, br))
            }
        }
    }

    fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    fn active_connections(&self) -> Option<u64> {
        Some(self.active.load(Ordering::Relaxed))
    }

    fn udp_sessions_estimate(&self) -> Option<u64> {
        Some(self.udp_count.load(Ordering::Relaxed))
    }
}

// UDP SOCKS5 utility functions (keep as-is, already async)

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::net::TcpStream as AsyncTcpStream;

/// Perform SOCKS5 greeting without authentication
pub async fn greet_noauth(stream: &mut AsyncTcpStream) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // VER=5, NMETHODS=1, METHODS=[NO_AUTH]
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp != [0x05, 0x00] {
        anyhow::bail!("socks5: server rejected no-auth");
    }
    Ok(())
}

/// Establish UDP association for SOCKS5
pub async fn udp_associate(
    stream: &mut AsyncTcpStream,
    bind_hint: Option<SocketAddr>,
) -> anyhow::Result<SocketAddr> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // VER=5, CMD=3(UDP ASSOCIATE), RSV=0, ATYP/ADDR/PORT
    let bind = bind_hint.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
    let mut req = vec![0x05, 0x03, 0x00];
    match bind.ip() {
        IpAddr::V4(ip) => {
            req.push(0x01);
            req.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            req.push(0x04);
            req.extend_from_slice(&ip.octets());
        }
    }
    req.extend_from_slice(&bind.port().to_be_bytes());
    stream.write_all(&req).await?;

    // Response: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        anyhow::bail!("socks5: bad version {}", head[0]);
    }
    if head[1] != 0x00 {
        anyhow::bail!("socks5: udp associate failed rep={}", head[1]);
    }

    let relay = match head[3] {
        0x01 => {
            let mut a = [0u8; 4];
            let mut p = [0u8; 2];
            stream.read_exact(&mut a).await?;
            stream.read_exact(&mut p).await?;
            SocketAddr::new(IpAddr::V4(Ipv4Addr::from(a)), u16::from_be_bytes(p))
        }
        0x04 => {
            let mut a = [0u8; 16];
            let mut p = [0u8; 2];
            stream.read_exact(&mut a).await?;
            stream.read_exact(&mut p).await?;
            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(a)), u16::from_be_bytes(p))
        }
        0x03 => {
            // Domain-form relay reply: skip domain and return localhost:port.
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;
            let mut p = [0u8; 2];
            stream.read_exact(&mut p).await?;
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), u16::from_be_bytes(p))
        }
        atyp => anyhow::bail!("socks5: bad atyp in reply {}", atyp),
    };

    Ok(relay)
}

/// Encode UDP request packet for SOCKS5
pub fn encode_udp_request(dst: &SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x00, 0x00, 0x00]; // Reserved, Fragment

    match dst {
        SocketAddr::V4(addr) => {
            packet.push(0x01); // IPv4
            packet.extend_from_slice(&addr.ip().octets());
            packet.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            packet.push(0x04); // IPv6
            packet.extend_from_slice(&addr.ip().octets());
            packet.extend_from_slice(&addr.port().to_be_bytes());
        }
    }

    packet.extend_from_slice(payload);
    packet
}

/// Decode UDP reply packet from SOCKS5
pub fn decode_udp_reply(packet: &[u8]) -> anyhow::Result<(SocketAddr, Vec<u8>)> {
    if packet.len() < 7 {
        return Err(anyhow::anyhow!("packet too short"));
    }

    // Skip reserved bytes (3 bytes)
    let atyp = packet[3];
    let mut offset = 4;

    let addr = match atyp {
        0x01 => {
            // IPv4
            if packet.len() < offset + 6 {
                return Err(anyhow::anyhow!("invalid IPv4 packet"));
            }
            let ip = std::net::Ipv4Addr::new(
                packet[offset],
                packet[offset + 1],
                packet[offset + 2],
                packet[offset + 3],
            );
            offset += 4;
            let port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
            offset += 2;
            SocketAddr::from((ip, port))
        }
        0x04 => {
            // IPv6
            if packet.len() < offset + 18 {
                return Err(anyhow::anyhow!("invalid IPv6 packet"));
            }
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&packet[offset..offset + 16]);
            let ip = std::net::Ipv6Addr::from(ip_bytes);
            offset += 16;
            let port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
            offset += 2;
            SocketAddr::from((ip, port))
        }
        _ => {
            return Err(anyhow::anyhow!("unsupported address type"));
        }
    };

    let payload = packet[offset..].to_vec();
    Ok((addr, payload))
}
