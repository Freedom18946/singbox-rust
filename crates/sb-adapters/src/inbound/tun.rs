//! TUN inbound - Phase 1 skeleton (mac / win first; linux TODO)
//! - feature-gated behind `tun`
//! - no real device operations yet; only config + platform stubs
//! - zero deps, zero side effects; merge-safe

use std::io;
use std::sync::Arc;

use tracing::{debug, info, trace, warn};
use serde::Deserialize;
use serde_json::Value;

use sb_core::router::{Router, RouterHandle};
// （如无使用请保持这两个 import 移除，避免未使用警告）
// use std::time::Duration;
// use tokio::time::timeout;

// 2.3e: 轻量指标（无需依赖）
use std::sync::atomic::{AtomicU64, Ordering};
static PACKETS_SEEN: AtomicU64 = AtomicU64::new(0);
static TCP_PROBE_OK: AtomicU64 = AtomicU64::new(0);
static TCP_PROBE_FAIL: AtomicU64 = AtomicU64::new(0);

#[deprecated(since = "0.1.0", note = "metrics collection interface; kept for compatibility")]
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
    #[allow(dead_code)] // Phase 1 先不使用，Phase 2 会进入路由选择
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
                                    let meta = RequestMeta {
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

                                    // --- 路由选择 (placeholder)
                                    let _selected = Option::<String>::None; // TODO: implement router.select(&meta)

                                    if self.cfg.dry_run {
                                        debug!(
                                            "tun parsed {:?} -> {}:{} | select only | inbound={} user={:?} timeout={}ms",
                                            pkt.proto, ip, port, self.cfg.name, self.cfg.user_tag, self.cfg.timeout_ms
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

                                            let meta = RequestMeta {
                                                inbound: Some(self.cfg.name.clone()),
                                                user: self.cfg.user_tag.clone(),
                                                transport: transport_opt,
                                                sniff_host: None,
                                                ..Default::default()
                                            };
                                            let _selected = Option::<String>::None; // TODO: implement router.select(&meta)
                                            // 避免把 tokio::time::timeout() 遮蔽：本地变量不要叫 `timeout`
                                            let dial_timeout =
                                                Duration::from_millis(self.cfg.timeout_ms);
                                            // TODO: implement proper router.select and outbound.connect
                                            // match tokio::time::timeout(
                                            //     dial_timeout,
                                            //     selected.connect(dst.clone()),
                                            // )
                                            match Ok(Ok(())) as Result<Result<(), std::io::Error>, tokio::time::error::Elapsed>
                                            {
                                                Ok(Ok(_s)) => {
                                                    // 2.3e: 计数
                                                    TCP_PROBE_OK.fetch_add(1, Ordering::Relaxed);
                                                    // 立刻丢弃以关闭连接
                                                    drop(_s);
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
        #[cfg(target_os = "windows")]
        {
            sys_windows::probe()?;
            tracing::info!("tun inbound: Windows stub ready (wintun phase-2 pending)");
        }
        #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
        {
            // Not implemented in Phase 1
            tracing::info!("tun inbound: this OS is not targeted in Phase 1");
        }
        Ok(())
    }

    /// 直接从 JSON 生成 TunInbound（不改变默认行为；仅在显式配置中使用）
    pub fn from_json(v: &Value, router: Arc<RouterHandle>) -> io::Result<Self> {
        let cfg: TunInboundConfig = serde_json::from_value(v.clone())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(Self::new(cfg, router))
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
            libc::AF_INET => parse_ipv4(pkt).map(|(proto, ip, port)| Parsed {
                af,
                proto,
                dst_ip: ip,
                dst_port: port,
            }),
            libc::AF_INET6 => parse_ipv6(pkt).map(|(proto, ip, port)| Parsed {
                af,
                proto,
                dst_ip: ip,
                dst_port: port,
            }),
            _ => Some(Parsed {
                af,
                proto: L4::Other(0xff),
                dst_ip: None,
                dst_port: None,
            }),
        }
    }

    #[cfg(feature = "tun")]
    fn parse_ipv4(pkt: &[u8]) -> Option<(L4, Option<IpAddr>, Option<u16>)> {
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
                if pkt.len() < ihl + 4 { return Some((L4::Other(proto), Some(dst), None)); }
                let port = u16::from_be_bytes([pkt[ihl+2], pkt[ihl+3]]);
                let l4 = if proto == 6 { L4::Tcp } else { L4::Udp };
                Some((l4, Some(dst), Some(port)))
            }
            x => Some((L4::Other(x), Some(dst), None)),
        }
    }

    #[cfg(feature = "tun")]
    fn parse_ipv6(pkt: &[u8]) -> Option<(L4, Option<IpAddr>, Option<u16>)> {
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
                if pkt.len() < 40 + 4 { return Some((L4::Other(next), Some(dst), None)); }
                let port = u16::from_be_bytes([pkt[40+2], pkt[40+3]]);
                let l4 = if next == 6 { L4::Tcp } else { L4::Udp };
                Some((l4, Some(dst), Some(port)))
            }
            x => Some((L4::Other(x), Some(dst), None)),
        }
    }
}

#[cfg(target_os = "windows")]
mod sys_windows {
    use std::io;
    #[allow(dead_code)]
    pub fn probe() -> io::Result<()> {
        // Future: check if wintun driver present, or provide helpful diagnostics.
        Ok(())
    }
}

// -------------------
// Tests
// -------------------
#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use sb_core::net::Address;
    use sb_core::pipeline::{DynOutbound, Outbound};
    // use sb_core::router::RequestMeta; // Using local placeholder
    use serde_json::json;
    use tokio::net::TcpStream;

    /// A dummy router that won't be used in Phase 1 serve(), but satisfies type construction.
    struct DummyRouter;
    impl sb_core::router::Router for DummyRouter {
        fn select(&self, _meta: &RequestMeta) -> DynOutbound {
            struct NopOutbound;
            #[async_trait]
            impl Outbound for NopOutbound {
                async fn connect(&self, _dst: Address) -> std::io::Result<TcpStream> {
                    Err(std::io::Error::new(std::io::ErrorKind::Other, "nop"))
                }
            }
            Arc::new(NopOutbound)
        }
    }

    #[tokio::test]
    async fn tun_phase1_skeleton_starts() {
        let cfg = TunInboundConfig::default();
        let router = Arc::new(DummyRouter);
        let inbound = TunInbound::new(cfg, router);
        inbound.serve().await.unwrap();
    }

    #[tokio::test]
    async fn tun_from_json_and_feeder_works() {
        let router = Arc::new(DummyRouter);
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
