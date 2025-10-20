//! TUN inbound - Phase 1 skeleton
//! Currently supports macOS and Windows; Linux support is planned
//! - feature-gated behind `tun`
//! - no real device operations yet; only config + platform stubs
//! - zero deps, zero side effects; merge-safe

use std::io;
use std::sync::Arc;

use serde::Deserialize;
use serde_json::Value;
use tracing::{debug, trace, warn};

use sb_core::outbound::RouteTarget;
use sb_core::router::engine::{RouteCtx, Transport};
use sb_core::router::RouterHandle;
// （如无使用请保持这两个 import 移除，避免未使用警告）
// use std::time::Duration;
// use tokio::time::timeout;

// 2.3e: 轻量指标（无需依赖）
use std::sync::atomic::{AtomicU64, Ordering};
static PACKETS_SEEN: AtomicU64 = AtomicU64::new(0);
static TCP_PROBE_OK: AtomicU64 = AtomicU64::new(0);
static TCP_PROBE_FAIL: AtomicU64 = AtomicU64::new(0);
static SNI_OK: AtomicU64 = AtomicU64::new(0);
static SNI_FAIL: AtomicU64 = AtomicU64::new(0);

#[deprecated(
    since = "0.1.0",
    note = "metrics collection interface; kept for compatibility"
)]
pub fn tun_metrics_snapshot() -> (u64, u64, u64) {
    (
        PACKETS_SEEN.load(Ordering::Relaxed),
        TCP_PROBE_OK.load(Ordering::Relaxed),
        TCP_PROBE_FAIL.load(Ordering::Relaxed),
    )
}
// RequestMeta is not available, using placeholder
#[allow(dead_code)]
struct RequestMeta {
    inbound: Option<String>,
    inbound_tag: Option<String>,
    user: Option<String>,
    dst: sb_core::net::Address,
    host: Option<String>,
    port: Option<u16>,
    transport: Option<String>,
    sniff_host: Option<String>,
}

impl Default for RequestMeta {
    fn default() -> Self {
        Self {
            inbound: None,
            inbound_tag: None,
            user: None,
            dst: sb_core::net::Address::Domain("0.0.0.0".to_string(), 0),
            host: None,
            port: None,
            transport: None,
            sniff_host: None,
        }
    }
}

fn default_platform() -> String {
    "mac".to_string()
}

fn default_name() -> String {
    "utun8".to_string()
}

fn default_mtu() -> u32 {
    1500
}

fn default_timeout_ms() -> u64 {
    10_000
}

/// Minimal config for Phase 1; extended later when wiring real device
#[derive(Debug, Clone, Deserialize)]
pub struct TunInboundConfig {
    #[serde(default = "default_platform")]
    pub platform: String,
    #[serde(default = "default_name")]
    pub name: String,
    #[serde(default = "default_mtu")]
    pub mtu: u32,
    /// 2.3b：默认 dry-run（只路由不拨号）；置为 false 时会拨号并立即关闭以做可达性验证
    #[serde(default)]
    pub dry_run: bool,
    /// 2.3c：将 user 信息注入 RequestMeta / ConnectParams（优先匹配路由规则）
    #[serde(default)]
    pub user_tag: Option<String>,
    /// 2.3c：可选的连接超时（毫秒）；仅用于日志和后续 2.3d/3.x 透传到 ConnectParams.deadline
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

impl Default for TunInboundConfig {
    fn default() -> Self {
        Self {
            platform: default_platform(),
            name: default_name(),
            mtu: default_mtu(),
            dry_run: true,
            user_tag: None,
            timeout_ms: default_timeout_ms(),
        }
    }
}

/// Phase 1 skeleton: holds router handle (unused for now) and config
pub struct TunInbound {
    /// Router handle for routing decisions
    router: Arc<RouterHandle>,
    cfg: TunInboundConfig,
    /// test-only in-memory feeder (Phase 1, no real device yet)
    #[cfg(test)]
    feeder: MemFeeder,
}

impl TunInbound {
    pub fn new(cfg: TunInboundConfig, router: Arc<RouterHandle>) -> Self {
        #[cfg(test)]
        {
            return Self {
                router,
                cfg,
                feeder: MemFeeder::new(),
            };
        }
        #[cfg(not(test))]
        {
            Self { router, cfg }
        }
    }

    /// Phase 1: skeleton；Phase 2.1: utun open + read drop；
    /// Phase 2.2: 解析 IP / TCP / UDP，装配 ConnectParams（仍然不转发负载）
    pub async fn serve(&self) -> io::Result<()> {
        tracing::info!(
            "tun inbound starting: platform={}, name={}, mtu={}",
            self.cfg.platform,
            self.cfg.name,
            self.cfg.mtu
        );
        // Spawn test-only memory feeder pump
        #[cfg(test)]
        {
            if let Some(mut rx) = self.feeder.take_rx().await {
                tokio::spawn(async move {
                    while let Some(frame) = rx.recv().await {
                        // Phase 1：只做占位与可观测；后续解析 IP/TCP/UDP -> ConnectParams
                        tracing::debug!("tun feeder got {} bytes (drop in phase1)", frame.len());
                    }
                });
            }
        }
        // Platform stubs (no-op, but assert compilation paths per OS)
        #[cfg(target_os = "macos")]
        {
            tracing::info!(
                "tun(macos): start name={}, mtu={}",
                self.cfg.name,
                self.cfg.mtu
            );
            // 若启用 utun 特性：打开设备并在此处做 read->parse->装配 ConnectParams（仍然丢弃负载）
            #[cfg(feature = "tun")]
            {
                use sb_core::net::Address;
                use sb_core::session::ConnectParams;
                // RequestMeta 在上层统一导入或直接全路径使用；未用到则移除以消除告警
                // use sb_core::router::RequestMeta;
                // use std::net::{IpAddr, SocketAddr};
                match sys_macos::open_async_fd(&self.cfg.name, self.cfg.mtu).await {
                    Ok(afd) => {
                        let mut buf = vec![0u8; 65536];
                        loop {
                            let mut guard = afd.readable().await?;
                            let readn = match guard.try_io(|f| {
                                use std::io::Read;
                                // get_ref() 返回 &File，无法可变借用；clone 一份再读
                                let mut file_for_read = f.get_ref().try_clone()?;
                                let n = file_for_read.read(&mut buf)?;
                                Ok(n)
                            }) {
                                Ok(Ok(n)) => n,
                                Ok(Err(e)) => {
                                    return Err(e);
                                }
                                Err(_would_block) => continue,
                            };
                            if readn == 0 {
                                break;
                            }
                            if let Some(pkt) = sys_macos::parse_frame(&buf[..readn]) {
                                if let Some((ip, port)) = pkt.dst_socket() {
                                    use std::net::SocketAddr;
                                    use std::time::{Duration, Instant};
                                    let dst = Address::Ip(SocketAddr::new(ip, port));

                                    // --- 组装 RequestMeta（补齐旧字段以兼容 engine.rs）
                                    let _meta = RequestMeta {
                                        inbound: Some(self.cfg.name.clone()),
                                        inbound_tag: Some(self.cfg.name.clone()),
                                        user: self.cfg.user_tag.clone(),
                                        dst: dst.clone(),
                                        ..Default::default()
                                    };

                                    // --- 组装 ConnectParams（携带 timeout/deadline/transport 等）
                                    let now = Instant::now();
                                    let timeout = Duration::from_millis(self.cfg.timeout_ms);
                                    let _params = ConnectParams {
                                        target: dst.clone(),
                                        inbound: Some(self.cfg.name.clone()),
                                        user: self.cfg.user_tag.clone(),
                                        sniff_host: None,
                                        // （若后续仅用于日志，可按需映射为字符串；此处不再保留 Transport::Other）
                                        transport: None,
                                        connect_timeout: Some(timeout),
                                        deadline: Some(now + timeout),
                                    };

                                    // --- 路由选择
                                    // Prefer SNI when available for TLS on port 443; otherwise try HTTP Host on port 80
                                    let sniff_host = if let Some(head) = &pkt.payload_head {
                                        if port == 443 {
                                            if let Some(sni) = sb_core::router::sniff::extract_sni_from_tls_client_hello(head) {
                                                SNI_OK.fetch_add(1, Ordering::Relaxed);
                                                Some(sni)
                                            } else {
                                                SNI_FAIL.fetch_add(1, Ordering::Relaxed);
                                                None
                                            }
                                        } else if port == 80 {
                                            sb_core::router::sniff::extract_http_host_from_request(
                                                head,
                                            )
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    };
                                    let host_str = match sniff_host.as_ref() {
                                        Some(s) if !s.is_empty() => s.clone(),
                                        _ => format!("{}:{}", ip, port),
                                    };
                                    // Heuristic ALPN: UDP:443 is likely QUIC → h3
                                    let _sniff_alpn =
                                        if matches!(pkt.proto, sys_macos::L4::Udp) && port == 443 {
                                            Some("h3".to_string())
                                        } else {
                                            None
                                        };
                                    if let Some(ref a) = _sniff_alpn {
                                        tracing::debug!("tun sniff alpn={}", a);
                                    }
                                    let route_ctx = RouteCtx {
                                        host: Some(&host_str),
                                        ip: Some(ip),
                                        port: Some(port),
                                        transport: match pkt.proto {
                                            sys_macos::L4::Tcp => Transport::Tcp,
                                            sys_macos::L4::Udp => Transport::Udp,
                                            _ => Transport::Tcp, // fallback
                                        },
                                    };
                                    let selected_target =
                                        self.router.select_ctx_and_record(route_ctx);
                                    let selected = match &selected_target {
                                        RouteTarget::Named(name) => Some(name.clone()),
                                        RouteTarget::Kind(kind) => Some(format!("{:?}", kind)),
                                    };

                                    if self.cfg.dry_run {
                                        debug!(
                                            "tun parsed {:?} -> {}:{} | selected={:?} | inbound={} user={:?} timeout={}ms",
                                            pkt.proto, ip, port, selected, self.cfg.name, self.cfg.user_tag, self.cfg.timeout_ms
                                        );
                                    } else {
                                        // 仅对 TCP 做"探测拨号后立即关闭"；UDP 先跳过到 2.4
                                        if matches!(pkt.proto, sys_macos::L4::Tcp) {
                                            // 当前 RequestMeta.transport = Option<String>，用 "tcp"/"udp"/None 表示
                                            let transport_opt: Option<String> = match pkt.proto {
                                                sys_macos::L4::Tcp => Some("tcp".to_string()),
                                                sys_macos::L4::Udp => Some("udp".to_string()),
                                                _ => None,
                                            };
                                            // 2.3e: 计入一帧
                                            PACKETS_SEEN.fetch_add(1, Ordering::Relaxed);

                                            let _meta = RequestMeta {
                                                inbound: Some(self.cfg.name.clone()),
                                                user: self.cfg.user_tag.clone(),
                                                transport: transport_opt,
                                                sniff_host: sniff_host.clone(),
                                                ..Default::default()
                                            };
                                            // 重用之前的路由选择结果
                                            let _probe_selected = selected.clone();
                                            // 避免把 tokio::time::timeout() 遮蔽：本地变量不要叫 `timeout`
                                            let dial_timeout =
                                                Duration::from_millis(self.cfg.timeout_ms);
                                            // 实现探测性连接：基于路由选择的目标进行实际连接测试
                                            let connection_result = match &selected_target {
                                                RouteTarget::Named(outbound_name) => {
                                                    debug!("TUN: Probing connection to {}:{} via outbound '{}'", ip, port, outbound_name);
                                                    // 当前阶段：使用direct连接进行探测
                                                    // 实际实现中应该通过outbound管理器获取具体的连接器
                                                    Self::probe_direct_connection(
                                                        &ip.to_string(),
                                                        port,
                                                        dial_timeout,
                                                    )
                                                    .await
                                                }
                                                RouteTarget::Kind(kind) => {
                                                    debug!(
                                                        "TUN: Probing connection to {}:{} via {:?}",
                                                        ip, port, kind
                                                    );
                                                    match kind {
                                                        sb_core::outbound::OutboundKind::Direct => {
                                                            Self::probe_direct_connection(&ip.to_string(), port, dial_timeout).await
                                                        }
                                                        sb_core::outbound::OutboundKind::Block => {
                                                            Err(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "blocked by routing rule"))
                                                        }
                                                        _ => {
                                                            warn!("TUN: Outbound kind {:?} not yet supported for probing", kind);
                                                            Err(std::io::Error::new(std::io::ErrorKind::NotFound, "outbound not supported"))
                                                        }
                                                    }
                                                }
                                            };

                                            match tokio::time::timeout(dial_timeout, async {
                                                connection_result
                                            })
                                            .await
                                            {
                                                Ok(Ok(_)) => {
                                                    // 2.3e: 计数；连接会在 block 结束时自动关闭
                                                    TCP_PROBE_OK.fetch_add(1, Ordering::Relaxed);
                                                    debug!(
                                                        "tun probe dial OK -> {}:{} | closed | user={:?} timeout={}ms",
                                                        ip, port, self.cfg.user_tag, self.cfg.timeout_ms
                                                    );
                                                }
                                                Ok(Err(e)) => {
                                                    // 2.3e: 计数
                                                    TCP_PROBE_FAIL.fetch_add(1, Ordering::Relaxed);
                                                    warn!(
                                                        "tun probe dial FAIL -> {}:{} | user={:?} timeout={}ms | {}",
                                                        ip, port, self.cfg.user_tag, self.cfg.timeout_ms, e
                                                    );
                                                }
                                                Err(_elapsed) => {
                                                    warn!(
                                                        "tun probe dial TIMEOUT -> {}:{} | user={:?} timeout={}ms",
                                                        ip, port, self.cfg.user_tag, self.cfg.timeout_ms
                                                    );
                                                }
                                            }
                                        } else {
                                            trace!(
                                                "tun pkt {:?} -> {}:{} | skip probe (UDP/Other)",
                                                pkt.proto,
                                                ip,
                                                port
                                            );
                                        }
                                    }
                                } else {
                                    trace!("tun non-TCP/UDP or no port; drop");
                                }
                            } else {
                                tracing::trace!("tun unknown/short frame len={}", readn);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("open utun({}) fail: {}", self.cfg.name, e);
                    }
                }
            }
        }
        #[cfg(target_os = "linux")]
        {
            tracing::info!(
                "tun(linux): start name={}, mtu={}",
                self.cfg.name,
                self.cfg.mtu
            );
            #[cfg(feature = "tun")]
            {
                use sb_core::net::Address;
                use sb_core::session::ConnectParams;
                use std::os::unix::io::AsRawFd;
                use tokio::io::unix::AsyncFd;
                use tokio::io::Interest;

                match sys_linux::open_tun_device(&self.cfg.name, self.cfg.mtu) {
                    Ok(device) => {
                        let mut buf = vec![0u8; 65536];
                        let router = Arc::clone(&self.router);

                        // Wrap the file descriptor in AsyncFd for async operations
                        let fd = device.as_raw_fd();
                        let async_fd = AsyncFd::with_interest(device, Interest::READABLE)
                            .map_err(io::Error::other)?;

                        loop {
                            let mut guard = async_fd.readable().await?;

                            let n = match guard.try_io(|inner| {
                                use std::io::Read;
                                inner.get_ref().read(&mut buf)
                            }) {
                                Ok(Ok(n)) => n,
                                Ok(Err(e)) => return Err(e),
                                Err(_would_block) => continue,
                            };

                            if n > 0 {
                                if let Some((l4, dst_ip, dst_port)) =
                                    sys_linux::parse_tun_packet(&buf[..n])
                                {
                                    match (l4, dst_ip, dst_port) {
                                        (L4::Tcp, Some(ip), Some(port)) => {
                                            let addr = Address::SocketAddress(
                                                format!("{}:{}", ip, port)
                                                    .parse()
                                                    .expect("valid socket"),
                                            );
                                            let params = ConnectParams {
                                                address: addr,
                                                inbound_tag: Some(self.cfg.name.clone()),
                                            };
                                            let meta = RequestMeta {
                                                destination: format!("{}:{}", ip, port),
                                                network: "tcp".to_string(),
                                                source_addr: None,
                                            };
                                            let _out = router.select(&meta);
                                            tracing::trace!(
                                                "tun: TCP -> {}:{} via {:?}",
                                                ip,
                                                port,
                                                params.inbound_tag
                                            );
                                        }
                                        (L4::Udp, Some(ip), Some(port)) => {
                                            tracing::trace!("tun: UDP -> {}:{} (drop)", ip, port);
                                        }
                                        _ => {
                                            tracing::trace!("tun: other/short packet");
                                        }
                                    }
                                } else {
                                    tracing::trace!("tun: failed to parse packet");
                                }
                            } else {
                                // EOF
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("open tun({}) failed: {}", self.cfg.name, e);
                    }
                }
            }
        }
        #[cfg(target_os = "windows")]
        {
            tracing::info!(
                "tun(windows): start name={}, mtu={}",
                self.cfg.name,
                self.cfg.mtu
            );
            #[cfg(feature = "tun")]
            {
                use sb_core::net::Address;
                use sb_core::session::ConnectParams;

                sys_windows::probe()?;

                match sys_windows::open_wintun_adapter(&self.cfg.name, self.cfg.mtu) {
                    Ok(adapter) => {
                        let session = match adapter.start_session(wintun::MAX_RING_CAPACITY) {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::error!("Failed to start wintun session: {}", e);
                                return Err(io::Error::new(io::ErrorKind::Other, e));
                            }
                        };

                        let router = Arc::clone(&self.router);

                        loop {
                            match session.receive_blocking() {
                                Ok(packet) => {
                                    let bytes = packet.bytes();
                                    if let Some((l4, dst_ip, dst_port)) =
                                        sys_windows::parse_wintun_packet(bytes)
                                    {
                                        match (l4, dst_ip, dst_port) {
                                            (L4::Tcp, Some(ip), Some(port)) => {
                                                let addr = Address::SocketAddress(
                                                    format!("{}:{}", ip, port)
                                                        .parse()
                                                        .expect("valid socket"),
                                                );
                                                let params = ConnectParams {
                                                    address: addr,
                                                    inbound_tag: Some(self.cfg.name.clone()),
                                                };
                                                let meta = RequestMeta {
                                                    destination: format!("{}:{}", ip, port),
                                                    network: "tcp".to_string(),
                                                    source_addr: None,
                                                };
                                                let _out = router.select(&meta);
                                                tracing::trace!(
                                                    "tun: TCP -> {}:{} via {:?}",
                                                    ip,
                                                    port,
                                                    params.inbound_tag
                                                );
                                            }
                                            (L4::Udp, Some(ip), Some(port)) => {
                                                tracing::trace!(
                                                    "tun: UDP -> {}:{} (drop)",
                                                    ip,
                                                    port
                                                );
                                            }
                                            _ => {
                                                tracing::trace!("tun: other/short packet");
                                            }
                                        }
                                    } else {
                                        tracing::trace!("tun: failed to parse packet");
                                    }
                                }
                                Err(e) => {
                                    tracing::error!("wintun receive error: {}", e);
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("open wintun({}) failed: {}", self.cfg.name, e);
                    }
                }
            }
            #[cfg(not(feature = "tun"))]
            {
                sys_windows::probe()?;
                tracing::info!("tun inbound: Windows TUN feature not enabled");
            }
        }
        #[cfg(all(
            not(target_os = "macos"),
            not(target_os = "windows"),
            not(target_os = "linux")
        ))]
        {
            // Not implemented for this OS
            tracing::info!("tun inbound: this OS is not currently supported");
        }
        Ok(())
    }

    /// 直接从 JSON 生成 TunInbound（不改变默认行为；仅在显式配置中使用）
    pub fn from_json(v: &Value, router: Arc<RouterHandle>) -> io::Result<Self> {
        let cfg: TunInboundConfig = serde_json::from_value(v.clone())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(Self::new(cfg, router))
    }

    /// 执行直接连接探测，用于验证目标可达性
    async fn probe_direct_connection(
        ip: &str,
        port: u16,
        timeout: std::time::Duration,
    ) -> Result<(), std::io::Error> {
        use tokio::net::TcpStream;

        let target_addr = format!("{}:{}", ip, port);

        match tokio::time::timeout(timeout, TcpStream::connect(&target_addr)).await {
            Ok(Ok(stream)) => {
                debug!("TUN: Direct connection probe successful to {}", target_addr);
                // 立即关闭连接，这只是一个可达性测试
                drop(stream);
                Ok(())
            }
            Ok(Err(e)) => {
                debug!(
                    "TUN: Direct connection probe failed to {}: {}",
                    target_addr, e
                );
                Err(e)
            }
            Err(_timeout_err) => {
                debug!("TUN: Direct connection probe timeout to {}", target_addr);
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("Connection timeout to {}", target_addr),
                ))
            }
        }
    }
}

#[cfg(test)]
impl TunInbound {
    /// 注入一帧到内存 feeder（仅测试路径）
    pub fn inject_test_frame(&self, data: &[u8]) {
        let _ = self.feeder.sender().try_send(data.to_vec());
    }
}

// -------------------
// Platform stubs
// -------------------
#[cfg(target_os = "macos")]
mod sys_macos {
    // libc not available, using stub
    use std::io;
    #[cfg(feature = "tun")]
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    #[cfg(feature = "tun")]
    use std::{
        ffi::CString,
        os::fd::{FromRawFd, RawFd},
    };
    #[cfg(feature = "tun")]
    use tokio::io::unix::AsyncFd;
    #[cfg(feature = "tun")]
    use tokio::io::Interest;
    #[cfg(feature = "tun")]
    #[allow(dead_code)]
    pub async fn open_and_pump_stub(_name: &str, _mtu: u32) -> io::Result<()> {
        Ok(())
    }
    #[allow(dead_code)]
    pub fn probe() -> io::Result<()> {
        // Future: verify presence of /dev/utunX or NetworkExtension availability.
        Ok(())
    }

    // ===== feature=utun: 真实 utun 打开 + 非阻塞读丢弃 =====
    /// 打开 utun 并返回 AsyncFd；由上层执行读循环以便访问 router / ConnectParams
    #[cfg(feature = "tun")]
    pub async fn open_async_fd(name_hint: &str, mtu: u32) -> io::Result<AsyncFd<std::fs::File>> {
        // SAFETY:
        // - 不变量：open_utun 执行系统调用并返回有效的文件描述符
        // - 并发/别名：fd 是新分配的，无数据竞争
        // - FFI/平台契约：系统调用错误已正确处理
        let fd = unsafe { open_utun(name_hint)? };
        set_nonblocking(fd)?;
        tracing::info!("utun opened fd={}, mtu={}", fd, mtu);
        // SAFETY:
        // - 不变量：fd 是有效的文件描述符，from_raw_fd 转移所有权
        // - 并发/别名：AsyncFd 将管理文件描述符生命周期
        // - FFI/平台契约：文件描述符所有权正确转移
        let async_fd =
            unsafe { AsyncFd::with_interest(std::fs::File::from_raw_fd(fd), Interest::READABLE) }
                .map_err(io::Error::other)?;
        Ok(async_fd)
    }

    #[cfg(feature = "tun")]
    // SAFETY: Performs system calls to open utun device; caller must ensure fd is properly managed
    unsafe fn open_utun(_name_hint: &str) -> io::Result<RawFd> {
        // 参考: utun via PF_SYSTEM/SYSPROTO_CONTROL
        // 1) socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)
        let fd = libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // 2) ctl_id by UTUN_CONTROL_NAME
        #[repr(C)]
        struct CtlInfo {
            ctl_id: u32,
            ctl_name: [libc::c_char; 96],
        }
        let mut info = CtlInfo {
            ctl_id: 0,
            ctl_name: [0; 96],
        };
        let name = CString::new("com.apple.net.utun_control")
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid control name"))?;
        // strncpy
        for (i, b) in name.as_bytes_with_nul().iter().enumerate() {
            if i < info.ctl_name.len() {
                info.ctl_name[i] = *b as libc::c_char;
            }
        }
        const CTLIOCGINFO: libc::c_ulong = 0xC0644E03; // _IOWR('N', 3, struct ctl_info)
        let r = libc::ioctl(fd, CTLIOCGINFO, &mut info);
        if r < 0 {
            let e = io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        // 3) connect 到 kernel control
        #[repr(C)]
        struct SockaddrCtl {
            sc_len: u8,
            sc_family: u8,
            ss_sysaddr: u16,
            sc_id: u32,
            sc_unit: u32,
            sc_reserved: [u32; 5],
        }
        const AF_SYSTEM: u8 = 32;
        const AF_SYS_CONTROL: u16 = 2;
        let addr = SockaddrCtl {
            sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
            sc_family: AF_SYSTEM,
            ss_sysaddr: AF_SYS_CONTROL,
            sc_id: info.ctl_id,
            sc_unit: 0, // 0: 让内核分配 utunN
            sc_reserved: [0; 5],
        };
        let r = libc::connect(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<SockaddrCtl>() as u32,
        );
        if r < 0 {
            let e = io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        Ok(fd)
    }

    #[cfg(feature = "tun")]
    fn set_nonblocking(fd: RawFd) -> io::Result<()> {
        // SAFETY:
        // - 不变量：fd 是有效的文件描述符，F_GETFL 是标准 fcntl 操作
        // - 并发/别名：fd 由当前线程独占访问
        // - FFI/平台契约：fcntl 系统调用在 Unix 系统上是安全的
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY:
        // - 不变量：fd 是有效的文件描述符，flags 为有效的标志位组合
        // - 并发/别名：fd 由当前线程独占访问
        // - FFI/平台契约：F_SETFL 设置非阻塞模式是标准操作
        let r = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    // ====== 解析 ======
    /// 简化后的 L4 协议枚举（无扩展头处理）
    #[cfg(feature = "tun")]
    #[derive(Debug, Clone, Copy)]
    // 枚举用作协议标识占位，暂不读取 u8 具体值；保持信息位，不为"未读字段"而改类型
    #[allow(dead_code)]
    pub enum L4 {
        Tcp,
        Udp,
        Other(u8),
    }

    /// 从 utun 帧解析出的摘要（仅目标地址和端口）
    #[cfg(feature = "tun")]
    #[derive(Debug, Clone)]
    pub struct Parsed {
        #[allow(dead_code)]
        pub af: u32,
        pub proto: L4,
        pub dst_ip: Option<IpAddr>,
        pub dst_port: Option<u16>,
        /// First bytes of L4 payload (if available), capped for cheap sniffing
        pub payload_head: Option<Vec<u8>>,
    }

    #[cfg(feature = "tun")]
    impl Parsed {
        pub fn dst_socket(&self) -> Option<(IpAddr, u16)> {
            match (self.dst_ip, self.dst_port) {
                (Some(ip), Some(port)) => Some((ip, port)),
                _ => None,
            }
        }
    }

    /// 解析 utun 帧（前 4 字节 AF 前缀；后跟 IP 数据包）
    #[cfg(feature = "tun")]
    pub fn parse_frame(buf: &[u8]) -> Option<Parsed> {
        if buf.len() < 4 {
            return None;
        }
        let af = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let pkt = &buf[4..];
        match af as i32 {
            libc::AF_INET => parse_ipv4(pkt).map(|(proto, ip, port, head)| Parsed {
                af,
                proto,
                dst_ip: ip,
                dst_port: port,
                payload_head: head,
            }),
            libc::AF_INET6 => parse_ipv6(pkt).map(|(proto, ip, port, head)| Parsed {
                af,
                proto,
                dst_ip: ip,
                dst_port: port,
                payload_head: head,
            }),
            _ => Some(Parsed {
                af,
                proto: L4::Other(0xff),
                dst_ip: None,
                dst_port: None,
                payload_head: None,
            }),
        }
    }

    #[cfg(feature = "tun")]
    #[allow(clippy::type_complexity)] // Return tuple is explicit and used in parsing pipeline
    fn parse_ipv4(pkt: &[u8]) -> Option<(L4, Option<IpAddr>, Option<u16>, Option<Vec<u8>>)> {
        if pkt.len() < 20 {
            return None;
        }
        let ihl = (pkt[0] & 0x0f) as usize * 4;
        if ihl < 20 || pkt.len() < ihl {
            return None;
        }
        let proto = pkt[9];
        let dst = IpAddr::V4(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]));
        match proto {
            6 /* TCP */ | 17 /* UDP */ => {
                if pkt.len() < ihl + 4 { return Some((L4::Other(proto), Some(dst), None, None)); }
                let port = u16::from_be_bytes([pkt[ihl+2], pkt[ihl+3]]);
                let l4 = if proto == 6 { L4::Tcp } else { L4::Udp };
                // compute payload head for TCP/UDP
                let head = if proto == 6 {
                    // TCP data offset in 32-bit words at offset 12 high nibble
                    if pkt.len() >= ihl + 13 {
                        let doff_words = (pkt[ihl + 12] >> 4) as usize;
                        let tcp_header_len = doff_words * 4;
                        let start = ihl + tcp_header_len;
                        if start < pkt.len() {
                            let rem = pkt.len() - start;
                            let cap = rem.min(1024);
                            Some(pkt[start..start+cap].to_vec())
                        } else { None }
                    } else { None }
                } else {
                    // UDP header is fixed 8 bytes
                    let start = ihl + 8;
                    if start < pkt.len() {
                        let rem = pkt.len() - start;
                        let cap = rem.min(1024);
                        Some(pkt[start..start+cap].to_vec())
                    } else { None }
                };
                Some((l4, Some(dst), Some(port), head))
            }
            x => Some((L4::Other(x), Some(dst), None, None)),
        }
    }

    #[cfg(feature = "tun")]
    #[allow(clippy::type_complexity)] // Return tuple is explicit and used in parsing pipeline
    fn parse_ipv6(pkt: &[u8]) -> Option<(L4, Option<IpAddr>, Option<u16>, Option<Vec<u8>>)> {
        if pkt.len() < 40 {
            return None;
        }
        let next = pkt[6];
        let dst = {
            let mut a = [0u8; 16];
            a.copy_from_slice(&pkt[24..40]);
            IpAddr::V6(Ipv6Addr::from(a))
        };
        match next {
            6 /* TCP */ | 17 /* UDP */ => {
                // 简化：不处理扩展头，仅当 L4 紧随 IPv6 基本头时取端口
                if pkt.len() < 40 + 4 { return Some((L4::Other(next), Some(dst), None, None)); }
                let port = u16::from_be_bytes([pkt[40+2], pkt[40+3]]);
                let l4 = if next == 6 { L4::Tcp } else { L4::Udp };
                // payload head
                let head = if next == 6 {
                    if pkt.len() >= 40 + 13 {
                        let doff_words = (pkt[40 + 12] >> 4) as usize;
                        let tcp_header_len = doff_words * 4;
                        let start = 40 + tcp_header_len;
                        if start < pkt.len() {
                            let rem = pkt.len() - start;
                            let cap = rem.min(1024);
                            Some(pkt[start..start+cap].to_vec())
                        } else { None }
                    } else { None }
                } else {
                    let start = 40 + 8;
                    if start < pkt.len() {
                        let rem = pkt.len() - start;
                        let cap = rem.min(1024);
                        Some(pkt[start..start+cap].to_vec())
                    } else { None }
                };
                Some((l4, Some(dst), Some(port), head))
            }
            x => Some((L4::Other(x), Some(dst), None, None)),
        }
    }
}

#[cfg(target_os = "linux")]
mod sys_linux {
    use std::io;
    #[cfg(feature = "tun")]
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[allow(dead_code)]
    pub fn probe() -> io::Result<()> {
        // Check if /dev/net/tun exists and is accessible
        std::fs::metadata("/dev/net/tun").map(|_| ()).map_err(|e| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("TUN device not available: {}", e),
            )
        })
    }

    /// Open Linux TUN device and return async device
    #[cfg(feature = "tun")]
    pub fn open_tun_device(name_hint: &str, mtu: u32) -> io::Result<tun::platform::Device> {
        let mut config = tun::Configuration::default();

        config.name(name_hint).mtu(mtu as i32).up();

        // Configure as TUN (layer 3) not TAP (layer 2)
        #[cfg(target_os = "linux")]
        config.platform(|config| {
            config.packet_information(false);
        });

        let dev = tun::create(&config)?;

        tracing::info!("Linux TUN opened: {} (mtu={})", name_hint, mtu);
        Ok(dev)
    }

    /// Parse IP packet from TUN device (similar to macOS implementation)
    /// Returns (L4 protocol, destination IP, destination port)
    #[cfg(feature = "tun")]
    pub fn parse_tun_packet(pkt: &[u8]) -> Option<(super::L4, Option<IpAddr>, Option<u16>)> {
        if pkt.is_empty() {
            return None;
        }

        let version = (pkt[0] >> 4) & 0xF;
        match version {
            4 => parse_ipv4(pkt),
            6 => parse_ipv6(pkt),
            _ => None,
        }
    }

    #[cfg(feature = "tun")]
    fn parse_ipv4(pkt: &[u8]) -> Option<(super::L4, Option<IpAddr>, Option<u16>)> {
        if pkt.len() < 20 {
            return None;
        }

        let proto = pkt[9];
        let dst = IpAddr::V4(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]));

        // Get header length in bytes
        let ihl = ((pkt[0] & 0x0F) as usize) * 4;
        if pkt.len() < ihl + 4 {
            return Some((super::L4::Other(proto), Some(dst), None));
        }

        match proto {
            6 => {
                // TCP: destination port at offset ihl+2
                let port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
                Some((super::L4::Tcp, Some(dst), Some(port)))
            }
            17 => {
                // UDP: destination port at offset ihl+2
                let port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
                Some((super::L4::Udp, Some(dst), Some(port)))
            }
            _ => Some((super::L4::Other(proto), Some(dst), None)),
        }
    }

    #[cfg(feature = "tun")]
    fn parse_ipv6(pkt: &[u8]) -> Option<(super::L4, Option<IpAddr>, Option<u16>)> {
        if pkt.len() < 40 {
            return None;
        }

        let next = pkt[6];
        let dst = {
            let mut a = [0u8; 16];
            a.copy_from_slice(&pkt[24..40]);
            IpAddr::V6(Ipv6Addr::from(a))
        };

        match next {
            6 | 17 => {
                // TCP or UDP: check if we have L4 header
                if pkt.len() < 40 + 4 {
                    return Some((super::L4::Other(next), Some(dst), None));
                }
                let port = u16::from_be_bytes([pkt[42], pkt[43]]);
                let l4 = if next == 6 {
                    super::L4::Tcp
                } else {
                    super::L4::Udp
                };
                Some((l4, Some(dst), Some(port)))
            }
            _ => Some((super::L4::Other(next), Some(dst), None)),
        }
    }
}

#[cfg(target_os = "windows")]
mod sys_windows {
    use std::io;
    #[cfg(feature = "tun")]
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    #[cfg(feature = "tun")]
    use std::sync::Arc;

    #[allow(dead_code)]
    pub fn probe() -> io::Result<()> {
        // Check if wintun.dll is available in the system
        #[cfg(feature = "tun")]
        {
            // Try to load wintun library - will fail if not installed
            match wintun::load() {
                Ok(_) => {
                    tracing::info!("Wintun driver detected and loaded successfully");
                    Ok(())
                }
                Err(e) => Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Wintun driver not available: {}", e),
                )),
            }
        }
        #[cfg(not(feature = "tun"))]
        Ok(())
    }

    /// Open Windows wintun adapter
    #[cfg(feature = "tun")]
    pub fn open_wintun_adapter(name_hint: &str, mtu: u32) -> io::Result<Arc<wintun::Adapter>> {
        let wintun = wintun::load().map_err(|e| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("Failed to load wintun: {}", e),
            )
        })?;

        // Create adapter with a GUID (you may want to make this configurable)
        let adapter = wintun::Adapter::create(
            &wintun, name_hint, "SingBox", None, // Let wintun generate a GUID
        )
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to create adapter: {}", e),
            )
        })?;

        // Set MTU (wintun doesn't have direct MTU setting in the API,
        // but we can note it for packet handling)
        tracing::info!(
            "Windows wintun adapter opened: {} (requested mtu={})",
            name_hint,
            mtu
        );

        Ok(adapter)
    }

    /// Parse IP packet from wintun (similar to Linux/macOS)
    #[cfg(feature = "tun")]
    pub fn parse_wintun_packet(pkt: &[u8]) -> Option<(super::L4, Option<IpAddr>, Option<u16>)> {
        if pkt.is_empty() {
            return None;
        }

        let version = (pkt[0] >> 4) & 0xF;
        match version {
            4 => parse_ipv4(pkt),
            6 => parse_ipv6(pkt),
            _ => None,
        }
    }

    #[cfg(feature = "tun")]
    fn parse_ipv4(pkt: &[u8]) -> Option<(super::L4, Option<IpAddr>, Option<u16>)> {
        if pkt.len() < 20 {
            return None;
        }

        let proto = pkt[9];
        let dst = IpAddr::V4(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]));

        let ihl = ((pkt[0] & 0x0F) as usize) * 4;
        if pkt.len() < ihl + 4 {
            return Some((super::L4::Other(proto), Some(dst), None));
        }

        match proto {
            6 => {
                let port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
                Some((super::L4::Tcp, Some(dst), Some(port)))
            }
            17 => {
                let port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
                Some((super::L4::Udp, Some(dst), Some(port)))
            }
            _ => Some((super::L4::Other(proto), Some(dst), None)),
        }
    }

    #[cfg(feature = "tun")]
    fn parse_ipv6(pkt: &[u8]) -> Option<(super::L4, Option<IpAddr>, Option<u16>)> {
        if pkt.len() < 40 {
            return None;
        }

        let next = pkt[6];
        let dst = {
            let mut a = [0u8; 16];
            a.copy_from_slice(&pkt[24..40]);
            IpAddr::V6(Ipv6Addr::from(a))
        };

        match next {
            6 | 17 => {
                if pkt.len() < 40 + 4 {
                    return Some((super::L4::Other(next), Some(dst), None));
                }
                let port = u16::from_be_bytes([pkt[42], pkt[43]]);
                let l4 = if next == 6 {
                    super::L4::Tcp
                } else {
                    super::L4::Udp
                };
                Some((l4, Some(dst), Some(port)))
            }
            _ => Some((super::L4::Other(next), Some(dst), None)),
        }
    }
}

// -------------------
// Tests
// -------------------
#[cfg(test)]
mod tests {
    use super::*;

    // use sb_core::router::RequestMeta; // Using local placeholder
    use serde_json::json;

    /// Create a dummy router handle for testing
    fn create_dummy_router() -> Arc<RouterHandle> {
        // Create a minimal RouterHandle for testing using from_env
        // This will initialize with default/empty rules
        Arc::new(RouterHandle::from_env())
    }

    #[tokio::test]
    async fn tun_phase1_skeleton_starts() {
        let cfg = TunInboundConfig::default();
        let router = create_dummy_router();
        let inbound = TunInbound::new(cfg, router);
        inbound.serve().await.unwrap();
    }

    #[tokio::test]
    async fn tun_from_json_and_feeder_works() {
        let router = create_dummy_router();
        let v = json!({
            "platform": "mac",
            "name": "utun9",
            "mtu": 1500
        });
        let inbound = TunInbound::from_json(&v, router).expect("from_json");
        inbound.serve().await.expect("serve");
        // 向内存 feeder 注入一帧（只在 test 构建下可用）
        inbound.inject_test_frame(&[0u8; 60]); // 伪造一帧
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    #[test]
    fn config_defaults_2_3c() {
        let d = TunInboundConfig::default();
        assert_eq!(d.dry_run, true);
        assert!(d.user_tag.is_none());
        assert!(d.timeout_ms >= 5_000); // 默认应为一个合理超时
    }

    #[test]
    fn config_from_json_2_3c() {
        let v = serde_json::json!({
            "platform": "mac",
            "name": "utun5",
            "mtu": 1400,
            "dry_run": false,
            "user_tag": "alice",
            "timeout_ms": 8000
        });
        let cfg: TunInboundConfig = serde_json::from_value(v).unwrap();
        assert_eq!(cfg.name, "utun5");
        assert_eq!(cfg.mtu, 1400);
        assert_eq!(cfg.dry_run, false);
        assert_eq!(cfg.user_tag.as_deref(), Some("alice"));
        assert_eq!(cfg.timeout_ms, 8000);
    }
}

// -------------------
// Test-only in-memory feeder
// -------------------
#[cfg(test)]
struct MemFeeder {
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    rx: tokio::sync::Mutex<Option<tokio::sync::mpsc::Receiver<Vec<u8>>>>,
}

#[cfg(test)]
impl MemFeeder {
    fn new() -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        Self {
            tx,
            rx: tokio::sync::Mutex::new(Some(rx)),
        }
    }
    fn sender(&self) -> tokio::sync::mpsc::Sender<Vec<u8>> {
        self.tx.clone()
    }
    async fn take_rx(&self) -> Option<tokio::sync::mpsc::Receiver<Vec<u8>>> {
        self.rx.lock().await.take()
    }
}
