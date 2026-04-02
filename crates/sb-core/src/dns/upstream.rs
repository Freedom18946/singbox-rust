//! DNS 上游服务器实现
//!
//! 提供各种 DNS 传输协议的上游实现：
//! - UDP 上游
//! - DNS-over-TLS (`DoT`) 上游
//! - DNS-over-HTTPS (`DoH`) 上游
//! - 系统解析器上游

use anyhow::{Context, Result};
use async_trait::async_trait;
use parking_lot::{Mutex, RwLock};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

#[cfg(feature = "metrics")]
use super::metrics;
#[cfg(test)]
use super::upstream_pool::discover_nameservers_from_file;
use super::upstream_pool::{
    load_udp_upstreams_from_file, record_upstream_fallback, FileBackedUpstreamPool,
};
use super::{DnsAnswer, DnsUpstream, RecordType};
use crate::dns::message::inject_edns0_client_subnet;
use crate::dns::transport::{DnsTransport, LocalTransport};

#[cfg(feature = "service_resolved")]
use crate::dns::transport::resolved::{ResolvedTransport, ResolvedTransportConfig};

// Helper: parse EDNS0 Client Subnet from env (global default)
fn parse_client_subnet_env() -> Option<(u16, u8, u8, Vec<u8>)> {
    let s = std::env::var("SB_DNS_CLIENT_SUBNET").ok()?;
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (ip_str, prefix_opt) = if let Some((a, p)) = s.split_once('/') {
        (a, p.parse::<u8>().ok())
    } else {
        (s, None)
    };
    if let Ok(ipv4) = ip_str.parse::<std::net::Ipv4Addr>() {
        let prefix = prefix_opt.unwrap_or(24).min(32);
        let mut b = ipv4.octets();
        mask_prefix(&mut b, prefix);
        let addr_len = (prefix as usize).div_ceil(8);
        return Some((1, prefix, 0, b[..addr_len].to_vec()));
    }
    if let Ok(ipv6) = ip_str.parse::<std::net::Ipv6Addr>() {
        let prefix = prefix_opt.unwrap_or(56).min(128);
        let mut b = ipv6.octets();
        mask_prefix(&mut b, prefix);
        let addr_len = (prefix as usize).div_ceil(8);
        return Some((2, prefix, 0, b[..addr_len].to_vec()));
    }
    None
}

fn mask_prefix(bytes: &mut [u8], prefix: u8) {
    let full = (prefix / 8) as usize;
    let rem = (prefix % 8) as usize;
    if full < bytes.len() {
        for item in bytes.iter_mut().skip(full + 1) {
            *item = 0;
        }
        if rem > 0 {
            let mask = (!0u8) << (8 - rem);
            bytes[full] &= mask;
        }
    }
}

#[cfg(feature = "dns_dhcp")]
fn parse_dhcp_spec(spec: &str) -> (Option<String>, PathBuf) {
    let mut path = std::env::var("SB_DNS_DHCP_RESOLV_CONF")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DhcpUpstream::DEFAULT_RESOLV_PATH));

    if spec.eq_ignore_ascii_case("dhcp") {
        return (None, path);
    }

    if let Some(rest) = spec.strip_prefix("dhcp://") {
        if rest.starts_with('/') {
            return (None, PathBuf::from(rest));
        }

        let (before_query, query) = rest.split_once('?').unwrap_or((rest, ""));
        let mut iface = None;
        let mut override_path = None;

        if !before_query.is_empty() {
            if before_query.starts_with('/') {
                override_path = Some(PathBuf::from(before_query));
            } else if let Some((if_part, path_part)) = before_query.split_once('/') {
                if !if_part.is_empty() {
                    iface = Some(if_part.to_string());
                }
                if !path_part.is_empty() {
                    let normalized = if path_part.starts_with('/') {
                        path_part.to_string()
                    } else {
                        format!("/{path_part}")
                    };
                    override_path = Some(PathBuf::from(normalized));
                }
            } else {
                iface = Some(before_query.trim_matches('/').to_string());
            }
        }

        for pair in query.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                if key == "resolv" && !value.is_empty() {
                    override_path = Some(PathBuf::from(value));
                }
            }
        }

        if let Some(p) = override_path {
            path = p;
        }
        return (iface, path);
    }

    (None, path)
}

#[cfg(feature = "dns_resolved")]
fn parse_resolved_spec(spec: &str) -> PathBuf {
    let mut path = std::env::var("SB_DNS_RESOLVED_STUB")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(ResolvedUpstream::DEFAULT_STUB));

    if spec.eq_ignore_ascii_case("resolved") {
        return path;
    }

    if let Some(rest) = spec.strip_prefix("resolved://") {
        if rest.starts_with('/') {
            return PathBuf::from(rest);
        }

        let mut override_path = None;
        if let Some((before_query, query)) = rest.split_once('?') {
            if before_query.starts_with('/') && !before_query.is_empty() {
                override_path = Some(PathBuf::from(before_query));
            }
            for pair in query.split('&') {
                if let Some((key, value)) = pair.split_once('=') {
                    if key == "resolv" && !value.is_empty() {
                        override_path = Some(PathBuf::from(value));
                    }
                }
            }
        } else if rest.starts_with('/') {
            override_path = Some(PathBuf::from(rest));
        }

        if let Some(p) = override_path {
            path = p;
        }
    }

    path
}

fn parse_nameserver_addr(token: &str) -> Option<SocketAddr> {
    if let Ok(sa) = token.parse::<SocketAddr>() {
        return Some(sa);
    }
    if let Ok(ipv4) = token.parse::<Ipv4Addr>() {
        return Some(SocketAddr::new(IpAddr::V4(ipv4), 53));
    }
    if let Ok(ipv6) = token.parse::<Ipv6Addr>() {
        return Some(SocketAddr::new(IpAddr::V6(ipv6), 53));
    }
    if let Some((addr_part, port_part)) = token.rsplit_once(':') {
        if let Ok(port) = port_part.parse::<u16>() {
            let normalized = if addr_part.contains(':') && !addr_part.starts_with('[') {
                format!("[{addr_part}]")
            } else {
                addr_part.to_string()
            };
            if let Ok(sa) = format!("{normalized}:{port}").parse::<SocketAddr>() {
                return Some(sa);
            }
        }
    }
    None
}

#[cfg(feature = "dns_tailscale")]
#[allow(dead_code)]
pub(crate) fn parse_tailscale_spec(
    spec: &str,
    tag: Option<&str>,
) -> Result<(String, Vec<SocketAddr>)> {
    let mut raw = Vec::new();
    let name = tag
        .map(|t| format!("tailscale::{t}"))
        .unwrap_or_else(|| "tailscale".to_string());

    if let Some(rest) = spec.strip_prefix("tailscale://") {
        let (before_query, query) = rest.split_once('?').unwrap_or((rest, ""));
        if !before_query.trim().is_empty() {
            raw.push(before_query.trim().to_string());
        }
        for pair in query.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                if key == "servers" && !value.is_empty() {
                    raw.extend(
                        value
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty()),
                    );
                }
            }
        }
    }

    if raw.is_empty() {
        if let Ok(env_value) = std::env::var("SB_TAILSCALE_DNS_ADDRS") {
            raw.extend(
                env_value
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
            );
        }
    }

    let addrs: Vec<SocketAddr> = raw
        .into_iter()
        .filter_map(|token| parse_nameserver_addr(&token))
        .collect();

    if addrs.is_empty() {
        tracing::warn!(
            target: "sb_core::dns",
            upstream = %name,
            spec = spec,
            env = %std::env::var("SB_TAILSCALE_DNS_ADDRS").unwrap_or_default(),
            "tailscale DNS upstream requires explicit address (e.g. tailscale://100.64.0.2:53) or env SB_TAILSCALE_DNS_ADDRS"
        );
        #[cfg(feature = "metrics")]
        metrics::inc_resolve_err("tailscale_no_addrs");
        Err(anyhow::anyhow!(
            "tailscale DNS upstream requires explicit address (e.g. tailscale://100.64.0.2:53) or env SB_TAILSCALE_DNS_ADDRS"
        ))
    } else {
        Ok((name, addrs))
    }
}

/// UDP DNS 上游实现
pub struct UdpUpstream {
    /// 上游服务器地址
    server: SocketAddr,
    /// 查询超时时间
    timeout: Duration,
    /// 重试次数
    retries: usize,
    /// 上游名称
    name: String,
    /// EDNS Client Subnet
    client_subnet: Option<String>,
}

impl UdpUpstream {
    /// 创建新的 UDP 上游
    pub fn new(server: SocketAddr) -> Self {
        let timeout = Duration::from_millis(
            std::env::var("SB_DNS_UDP_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(2000),
        );

        let retries = std::env::var("SB_DNS_UDP_RETRIES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(2);

        Self {
            server,
            timeout,
            retries,
            name: format!("udp://{server}"),
            client_subnet: None,
        }
    }

    /// 设置超时时间
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// 设置重试次数
    pub const fn with_retries(mut self, retries: usize) -> Self {
        self.retries = retries;
        self
    }

    /// 设置 EDNS Client Subnet
    pub fn with_client_subnet(mut self, client_subnet: Option<String>) -> Self {
        self.client_subnet = client_subnet;
        self
    }

    /// 执行单次 UDP DNS 查询
    async fn query_once(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {
        use tokio::net::UdpSocket;
        use tokio::time::timeout;

        // 构建 DNS 查询包
        let query_packet = self.build_query_packet(domain, record_type)?;

        // 创建 UDP socket
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(self.server).await?;

        // 发送查询
        socket.send(&query_packet).await?;

        // 接收响应
        let mut response_buf = vec![0u8; 512];
        let response_len = timeout(self.timeout, socket.recv(&mut response_buf))
            .await
            .map_err(|_| anyhow::anyhow!("DNS query timeout"))?
            .map_err(|e| anyhow::anyhow!("Failed to receive DNS response: {e}"))?;

        response_buf.truncate(response_len);

        // 解析响应
        self.parse_response(&response_buf, record_type)
    }

    /// 构建 DNS 查询包
    fn build_query_packet(&self, domain: &str, record_type: RecordType) -> Result<Vec<u8>> {
        let mut packet = Vec::new();

        // DNS Header (12 bytes)
        let transaction_id_val: u16 =
            match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                Ok(d) => d.as_nanos() as u16,
                Err(_) => 0,
            };
        let transaction_id = transaction_id_val.to_be_bytes();

        packet.extend_from_slice(&transaction_id); // Transaction ID
        packet.extend_from_slice(&[0x01, 0x00]); // Flags: Standard query, recursion desired
        packet.extend_from_slice(&[0x00, 0x01]); // Questions: 1
        packet.extend_from_slice(&[0x00, 0x00]); // Answer RRs: 0
        packet.extend_from_slice(&[0x00, 0x00]); // Authority RRs: 0
        packet.extend_from_slice(&[0x00, 0x00]); // Additional RRs: 0

        // Question section
        // QNAME: domain name in label format
        for label in domain.trim_end_matches('.').split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(anyhow::anyhow!("Invalid domain label: {label}"));
            }
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0); // Root label

        // QTYPE and QCLASS
        packet.extend_from_slice(&record_type.as_u16().to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes()); // IN class

        // Optional EDNS0 Client Subnet:
        // - prefer per-upstream ECS, else fall back to global env.
        let ecs = self
            .client_subnet
            .clone()
            .or_else(|| std::env::var("SB_DNS_CLIENT_SUBNET").ok());
        if let Some(ecs) = ecs {
            let _ = inject_edns0_client_subnet(&mut packet, ecs.trim());
        }

        Ok(packet)
    }

    /// 解析 DNS 响应包
    fn parse_response(&self, packet: &[u8], expected_type: RecordType) -> Result<DnsAnswer> {
        if packet.len() < 12 {
            return Err(anyhow::anyhow!("DNS response too short"));
        }

        // 解析 header
        let answer_count = u16::from_be_bytes([packet[6], packet[7]]) as usize;
        if answer_count == 0 {
            return Err(anyhow::anyhow!("No answers in DNS response"));
        }

        // 跳过 question section
        let mut offset = 12;
        offset = self.skip_question_section(packet, offset)?;

        // 解析 answer section
        let mut ips = Vec::new();
        let mut min_ttl: Option<u32> = None;

        for _ in 0..answer_count {
            let (ip_opt, ttl, new_offset) =
                self.parse_answer_record(packet, offset, expected_type)?;
            offset = new_offset;

            if let Some(ip) = ip_opt {
                ips.push(ip);
                min_ttl = Some(min_ttl.map_or(ttl, |current| current.min(ttl)));
            }
        }

        if ips.is_empty() {
            return Err(anyhow::anyhow!("No valid IP addresses in DNS response"));
        }

        Ok(DnsAnswer::new(
            ips,
            Duration::from_secs(u64::from(min_ttl.unwrap_or(300))),
            super::cache::Source::Upstream,
            super::cache::Rcode::NoError,
        ))
    }

    /// 跳过 question section
    fn skip_question_section(&self, packet: &[u8], mut offset: usize) -> Result<usize> {
        // 跳过 QNAME
        while offset < packet.len() {
            let label_len = packet[offset] as usize;
            offset += 1;

            if label_len == 0 {
                break; // End of QNAME
            }

            if (label_len & 0xC0) == 0xC0 {
                // Compression pointer
                offset += 1;
                break;
            }

            offset += label_len;
        }

        // 跳过 QTYPE 和 QCLASS
        offset += 4;

        Ok(offset)
    }

    /// 解析单个 answer record
    fn parse_answer_record(
        &self,
        packet: &[u8],
        mut offset: usize,
        expected_type: RecordType,
    ) -> Result<(Option<std::net::IpAddr>, u32, usize)> {
        // 跳过 NAME (可能是压缩指针)
        if offset >= packet.len() {
            return Err(anyhow::anyhow!("Unexpected end of packet"));
        }

        if (packet[offset] & 0xC0) == 0xC0 {
            // Compression pointer
            offset += 2;
        } else {
            // Full name
            while offset < packet.len() {
                let label_len = packet[offset] as usize;
                offset += 1;
                if label_len == 0 {
                    break;
                }
                offset += label_len;
            }
        }

        if offset + 10 > packet.len() {
            return Err(anyhow::anyhow!("Insufficient data for answer record"));
        }

        // 解析 TYPE, CLASS, TTL, RDLENGTH
        let rtype = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let _class = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
        let ttl = u32::from_be_bytes([
            packet[offset + 4],
            packet[offset + 5],
            packet[offset + 6],
            packet[offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        offset += 10;

        if offset + rdlength > packet.len() {
            return Err(anyhow::anyhow!("Insufficient data for RDATA"));
        }

        let rdata = &packet[offset..offset + rdlength];
        offset += rdlength;

        // 解析 IP 地址，只处理期望的记录类型
        let ip = match (rtype, expected_type) {
            (1, RecordType::A) if rdlength == 4 => {
                // A record
                Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    rdata[0], rdata[1], rdata[2], rdata[3],
                )))
            }
            (28, RecordType::AAAA) if rdlength == 16 => {
                // AAAA record
                let mut addr = [0u8; 16];
                addr.copy_from_slice(rdata);
                Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(addr)))
            }
            _ => None, // 其他记录类型忽略
        };

        Ok((ip, ttl, offset))
    }
}

#[async_trait]
impl DnsUpstream for UdpUpstream {
    async fn query(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {
        let mut last_error = None;

        for attempt in 0..=self.retries {
            match self.query_once(domain, record_type).await {
                Ok(answer) => {
                    tracing::debug!(
                        "UDP DNS query successful: server={}, domain={}, attempt={}",
                        self.server,
                        domain,
                        attempt
                    );
                    return Ok(answer);
                }
                Err(e) => {
                    last_error = Some(e);
                    if attempt < self.retries {
                        tracing::debug!(
                            "UDP DNS query failed, retrying: server={}, domain={}, attempt={}, error={}",
                            self.server,
                            domain,
                            attempt,
                            // Log the latest error without risking panic on None
                            last_error.as_ref().map_or_else(|| "unknown".to_string(), std::string::ToString::to_string)
                        );
                        // 短暂延迟后重试
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }

        match last_error {
            Some(err) => Err(err),
            None => Err(anyhow::anyhow!("All UDP DNS queries failed")),
        }
    }

    async fn exchange(&self, packet: &[u8]) -> Result<Vec<u8>> {
        use tokio::net::UdpSocket;
        use tokio::time::timeout;

        let mut last_error: Option<anyhow::Error> = None;

        for attempt in 0..=self.retries {
            let mut req = packet.to_vec();
            if let Some(ecs) = &self.client_subnet {
                let _ = inject_edns0_client_subnet(&mut req, ecs.trim());
            }

            let res = async {
                let socket = UdpSocket::bind("0.0.0.0:0").await?;
                socket.connect(self.server).await?;
                socket.send(&req).await?;

                // EDNS0 can exceed 512; use a larger buffer.
                let mut buf = vec![0u8; 4096];
                let n = timeout(self.timeout, socket.recv(&mut buf))
                    .await
                    .map_err(|_| anyhow::anyhow!("DNS exchange timeout"))??;
                buf.truncate(n);
                Ok::<_, anyhow::Error>(buf)
            }
            .await;

            match res {
                Ok(resp) => return Ok(resp),
                Err(err) => {
                    last_error = Some(err);
                    if attempt < self.retries {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("UDP DNS exchange failed")))
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn health_check(&self) -> bool {
        // 简单的健康检查：尝试查询一个已知域名
        matches!(
            tokio::time::timeout(
                Duration::from_secs(5),
                self.query_once("dns.google", RecordType::A),
            )
            .await,
            Ok(Ok(_))
        )
    }
}

/// DHCP-backed upstream that discovers resolver IPs from `/etc/resolv.conf` (or similar).
#[cfg(feature = "dns_dhcp")]
pub struct DhcpUpstream {
    interface: Option<String>,
    pool: FileBackedUpstreamPool,
    transport: Option<Arc<crate::dns::transport::DhcpTransport>>,
}

#[cfg(feature = "dns_dhcp")]
impl std::fmt::Debug for DhcpUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DhcpUpstream")
            .field("name", &self.pool.name())
            .field("interface", &self.interface)
            .field("resolv_path", &self.pool.path())
            .finish()
    }
}

#[cfg(feature = "dns_dhcp")]
impl DhcpUpstream {
    const DEFAULT_RESOLV_PATH: &'static str = "/etc/resolv.conf";

    /// Create a new DHCP upstream from an address spec (`dhcp`, `dhcp://eth0`, etc.).
    pub fn from_spec(spec: &str, tag: Option<&str>) -> Result<Self> {
        let (iface, resolv_path) = parse_dhcp_spec(spec);
        let name = tag
            .map(|t| format!("dhcp::{t}"))
            .or_else(|| iface.as_ref().map(|ifn| format!("dhcp://{ifn}")))
            .unwrap_or_else(|| "dhcp://auto".to_string());
        let pool = FileBackedUpstreamPool::new(
            "dhcp",
            name.clone(),
            resolv_path,
            Arc::new(SystemUpstream::new()),
            load_udp_upstreams_from_file,
        );

        let transport = if iface.is_some() {
            Some(Arc::new(crate::dns::transport::DhcpTransport::new(
                iface.clone(),
            )))
        } else {
            None
        };

        if let Some(t) = &transport {
            Self::start_transport_if_runtime_available(&name, t);
        }

        Ok(Self {
            interface: iface,
            pool,
            transport,
        })
    }

    fn start_transport_if_runtime_available(
        name: &str,
        transport: &Arc<crate::dns::transport::DhcpTransport>,
    ) {
        if tokio::runtime::Handle::try_current().is_ok() {
            let upstream = name.to_string();
            let transport = Arc::clone(transport);
            tokio::spawn(async move {
                if let Err(error) = transport
                    .start(crate::dns::transport::DnsStartStage::Start)
                    .await
                {
                    tracing::warn!(
                        target: "sb_core::dns",
                        upstream = %upstream,
                        error = %error,
                        "failed to start DHCP transport background loop"
                    );
                }
            });
        } else {
            tracing::debug!(
                target: "sb_core::dns",
                upstream = %name,
                "deferring DHCP transport startup until async query because no Tokio runtime is active"
            );
        }
    }

    async fn ensure_transport_started(&self) {
        if let Some(transport) = &self.transport {
            if let Err(error) = transport
                .start(crate::dns::transport::DnsStartStage::Start)
                .await
            {
                tracing::warn!(
                    target: "sb_core::dns",
                    upstream = %self.pool.name(),
                    error = %error,
                    "failed to start DHCP transport on demand"
                );
            }
        }
    }

    fn snapshot(&self) -> Vec<Arc<dyn DnsUpstream>> {
        let mut list = self.pool.snapshot();
        if let Some(t) = &self.transport {
            let servers = t.servers();
            if !servers.is_empty() {
                for addr in servers {
                    list.push(Arc::new(UdpUpstream::new(addr)));
                }
            }
        }
        if list.is_empty() {
            vec![self.pool.fallback()]
        } else {
            list
        }
    }

    /// Reload nameservers from resolv.conf file
    pub fn reload_servers(&self) -> Result<()> {
        self.pool.reload_servers()
    }

    /// Check file modification and reload if needed
    pub fn maybe_reload(&self) {
        self.pool.maybe_reload();
    }
}

#[cfg(feature = "dns_dhcp")]
#[async_trait]
impl DnsUpstream for DhcpUpstream {
    async fn query(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {
        self.ensure_transport_started().await;
        for attempt in 0..2 {
            let upstreams = self.snapshot();
            if upstreams.is_empty() {
                if attempt == 0 {
                    // Try one immediate reload if empty, just in case watcher missed it or initial load failed
                    let _ = self.pool.reload_servers();
                    if self.snapshot().is_empty() {
                        tracing::warn!(
                            target: "sb_core::dns",
                            upstream = %self.pool.name(),
                            "DHCP upstream has no servers; delegating to system resolver"
                        );
                        record_upstream_fallback("dhcp", self.pool.name(), "empty");
                        return self.pool.fallback().query(domain, record_type).await;
                    }
                    continue;
                }
                return self.pool.fallback().query(domain, record_type).await;
            }

            let start = self.pool.next_start();
            for offset in 0..upstreams.len() {
                let idx = (start + offset) % upstreams.len();
                match upstreams[idx].query(domain, record_type).await {
                    Ok(answer) => return Ok(answer),
                    Err(err) => {
                        tracing::debug!(
                            target: "sb_core::dns",
                            upstream = %self.pool.name(),
                            member = %upstreams[idx].name(),
                            error = %err,
                            "DHCP upstream member failed; trying next"
                        );
                    }
                }
            }

            // If all members failed, force a reload and retry once
            if attempt == 0 {
                let _ = self.pool.reload_servers();
            }
        }

        tracing::warn!(
            target: "sb_core::dns",
            upstream = %self.pool.name(),
            "All DHCP upstream members failed; using system resolver fallback"
        );
        record_upstream_fallback("dhcp", self.pool.name(), "members_failed");
        self.pool.fallback().query(domain, record_type).await
    }

    async fn exchange(&self, packet: &[u8]) -> Result<Vec<u8>> {
        self.ensure_transport_started().await;
        for attempt in 0..2 {
            let upstreams = self.snapshot();
            if upstreams.is_empty() {
                if attempt == 0 {
                    let _ = self.pool.reload_servers();
                    if self.snapshot().is_empty() {
                        tracing::warn!(
                            target: "sb_core::dns",
                            upstream = %self.pool.name(),
                            "DHCP upstream has no servers; cannot raw-exchange via system resolver"
                        );
                        record_upstream_fallback("dhcp", self.pool.name(), "empty_exchange");
                        return Err(anyhow::anyhow!(
                            "dhcp upstream {} has no servers for raw exchange",
                            self.pool.name()
                        ));
                    }
                    continue;
                }
                return Err(anyhow::anyhow!(
                    "dhcp upstream {} has no servers for raw exchange",
                    self.pool.name()
                ));
            }

            let start = self.pool.next_start();
            let mut last_error: Option<anyhow::Error> = None;
            for offset in 0..upstreams.len() {
                let idx = (start + offset) % upstreams.len();
                match upstreams[idx].exchange(packet).await {
                    Ok(resp) => return Ok(resp),
                    Err(err) => {
                        tracing::debug!(
                            target: "sb_core::dns",
                            upstream = %self.pool.name(),
                            member = %upstreams[idx].name(),
                            error = %err,
                            "DHCP upstream member raw exchange failed; trying next"
                        );
                        last_error = Some(err);
                    }
                }
            }

            if attempt == 0 {
                let _ = self.pool.reload_servers();
            }

            if let Some(err) = last_error {
                // keep the most recent error for context if second attempt also fails
                if attempt == 1 {
                    return Err(err.context(format!(
                        "dhcp upstream {} exhausted {} members for raw exchange",
                        self.pool.name(),
                        upstreams.len()
                    )));
                }
            }
        }

        Err(anyhow::anyhow!(
            "dhcp upstream {} raw exchange exhausted members",
            self.pool.name()
        ))
    }

    fn name(&self) -> &str {
        self.pool.name()
    }

    async fn health_check(&self) -> bool {
        self.ensure_transport_started().await;
        let snapshot = self.snapshot();
        if let Some(up) = snapshot.first() {
            up.health_check().await
        } else {
            self.pool.fallback().health_check().await
        }
    }
}

/// Static multi-endpoint upstream (round-robin over a fixed list).
pub struct StaticMultiUpstream {
    name: String,
    members: Vec<Arc<dyn DnsUpstream>>,
    index: AtomicUsize,
}

impl StaticMultiUpstream {
    pub fn new(name: String, addrs: Vec<SocketAddr>) -> Self {
        let members = addrs
            .into_iter()
            .map(|addr| Arc::new(UdpUpstream::new(addr)) as Arc<dyn DnsUpstream>)
            .collect();
        Self {
            name,
            members,
            index: AtomicUsize::new(0),
        }
    }

    #[cfg(test)]
    pub fn from_members_for_test(name: String, members: Vec<Arc<dyn DnsUpstream>>) -> Self {
        Self {
            name,
            members,
            index: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl DnsUpstream for StaticMultiUpstream {
    async fn query(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {
        if self.members.is_empty() {
            tracing::warn!(
                target: "sb_core::dns",
                upstream = %self.name,
                kind = "tailscale",
                "tailscale upstream has no members; set SB_TAILSCALE_DNS_ADDRS or use tailscale://host:port"
            );
            #[cfg(feature = "metrics")]
            metrics::inc_resolve_err("tailscale_empty");
            return Err(anyhow::anyhow!(
                "tailscale upstream {} has no nameserver addresses (set SB_TAILSCALE_DNS_ADDRS or configure tailscale://host:port)",
                self.name
            ));
        }
        let start = self.index.fetch_add(1, Ordering::Relaxed);
        let mut last_error = None;
        for offset in 0..self.members.len() {
            let idx = (start + offset) % self.members.len();
            match self.members[idx].query(domain, record_type).await {
                Ok(ans) => return Ok(ans),
                Err(err) => {
                    tracing::debug!(
                        target: "sb_core::dns",
                        upstream = %self.name,
                        member = %self.members[idx].name(),
                        error = %err,
                        "tailscale upstream member failed"
                    );
                    last_error = Some(err);
                }
            }
        }
        #[cfg(feature = "metrics")]
        metrics::inc_resolve_err("tailscale_members_failed");
        if let Some(err) = last_error {
            tracing::warn!(
                target: "sb_core::dns",
                upstream = %self.name,
                attempts = self.members.len(),
                error = %err,
                "all tailscale upstream members failed"
            );
            Err(err.context(format!(
                "tailscale upstream {} exhausted {} members",
                self.name,
                self.members.len()
            )))
        } else {
            Err(anyhow::anyhow!(
                "tailscale upstream {} has no reachable members",
                self.name
            ))
        }
    }

    async fn exchange(&self, packet: &[u8]) -> Result<Vec<u8>> {
        if self.members.is_empty() {
            #[cfg(feature = "metrics")]
            metrics::inc_resolve_err("tailscale_empty_exchange");
            return Err(anyhow::anyhow!(
                "tailscale upstream {} has no nameserver addresses for raw exchange",
                self.name
            ));
        }
        let start = self.index.fetch_add(1, Ordering::Relaxed);
        let mut last_error: Option<anyhow::Error> = None;
        for offset in 0..self.members.len() {
            let idx = (start + offset) % self.members.len();
            match self.members[idx].exchange(packet).await {
                Ok(resp) => return Ok(resp),
                Err(err) => {
                    tracing::debug!(
                        target: "sb_core::dns",
                        upstream = %self.name,
                        member = %self.members[idx].name(),
                        error = %err,
                        "tailscale upstream member raw exchange failed"
                    );
                    last_error = Some(err);
                }
            }
        }
        #[cfg(feature = "metrics")]
        metrics::inc_resolve_err("tailscale_members_failed_exchange");
        Err(last_error.unwrap_or_else(|| {
            anyhow::anyhow!(
                "tailscale upstream {} has no reachable members for raw exchange",
                self.name
            )
        }))
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn health_check(&self) -> bool {
        if let Some(member) = self.members.first() {
            member.health_check().await
        } else {
            false
        }
    }
}

/// systemd-resolved upstream backed by stub resolv.conf.
#[cfg(feature = "dns_resolved")]
pub struct ResolvedUpstream {
    pool: FileBackedUpstreamPool,
}

#[cfg(feature = "dns_resolved")]
impl std::fmt::Debug for ResolvedUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedUpstream")
            .field("name", &self.pool.name())
            .field("resolv_path", &self.pool.path())
            .finish()
    }
}

#[cfg(feature = "dns_resolved")]
impl ResolvedUpstream {
    const DEFAULT_STUB: &'static str = "/run/systemd/resolve/stub-resolv.conf";

    pub fn from_spec(spec: &str, tag: Option<&str>) -> Result<Self> {
        let resolv_path = parse_resolved_spec(spec);
        let name = tag
            .map(|t| format!("resolved::{t}"))
            .unwrap_or_else(|| format!("resolved://{}", resolv_path.display()));
        Ok(Self {
            pool: FileBackedUpstreamPool::new(
                "resolved",
                name,
                resolv_path,
                Arc::new(SystemUpstream::new()),
                load_udp_upstreams_from_file,
            ),
        })
    }

    fn snapshot(&self) -> Vec<Arc<dyn DnsUpstream>> {
        self.pool.snapshot()
    }

    /// Reload nameservers from systemd-resolved stub file
    pub fn reload_servers(&self) -> Result<()> {
        self.pool.reload_servers()
    }

    /// Check file modification and reload if needed
    pub fn maybe_reload(&self) {
        self.pool.maybe_reload();
    }
}

#[cfg(feature = "dns_resolved")]
#[async_trait]
impl DnsUpstream for ResolvedUpstream {
    async fn query(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {
        for attempt in 0..2 {
            let upstreams = self.snapshot();
            if upstreams.is_empty() {
                if attempt == 0 {
                    let _ = self.pool.reload_servers();
                    if self.snapshot().is_empty() {
                        record_upstream_fallback("resolved", self.pool.name(), "empty");
                        return self.pool.fallback().query(domain, record_type).await;
                    }
                    continue;
                }
                record_upstream_fallback("resolved", self.pool.name(), "empty");
                return self.pool.fallback().query(domain, record_type).await;
            }
            let start = self.pool.next_start();
            for offset in 0..upstreams.len() {
                let idx = (start + offset) % upstreams.len();
                match upstreams[idx].query(domain, record_type).await {
                    Ok(answer) => return Ok(answer),
                    Err(err) => tracing::debug!(
                        target: "sb_core::dns",
                        upstream = %self.pool.name(),
                        member = %upstreams[idx].name(),
                        error = %err,
                        "resolved upstream member failed"
                    ),
                }
            }
            if attempt == 0 {
                let _ = self.pool.reload_servers();
            }
        }
        tracing::warn!(
            target: "sb_core::dns",
            upstream = %self.pool.name(),
            "all resolved upstream members failed; falling back to system resolver"
        );
        record_upstream_fallback("resolved", self.pool.name(), "members_failed");
        self.pool.fallback().query(domain, record_type).await
    }

    async fn exchange(&self, packet: &[u8]) -> Result<Vec<u8>> {
        for attempt in 0..2 {
            let upstreams = self.snapshot();
            if upstreams.is_empty() {
                if attempt == 0 {
                    let _ = self.pool.reload_servers();
                    continue;
                }
                record_upstream_fallback("resolved", self.pool.name(), "empty_exchange");
                return Err(anyhow::anyhow!(
                    "resolved upstream {} has no nameservers for raw exchange",
                    self.pool.name()
                ));
            }

            let start = self.pool.next_start();
            let mut last_error: Option<anyhow::Error> = None;
            for offset in 0..upstreams.len() {
                let idx = (start + offset) % upstreams.len();
                match upstreams[idx].exchange(packet).await {
                    Ok(resp) => return Ok(resp),
                    Err(err) => {
                        tracing::debug!(
                            target: "sb_core::dns",
                            upstream = %self.pool.name(),
                            member = %upstreams[idx].name(),
                            error = %err,
                            "resolved upstream member raw exchange failed"
                        );
                        last_error = Some(err);
                    }
                }
            }

            if attempt == 0 {
                let _ = self.pool.reload_servers();
            }
            if attempt == 1 {
                return Err(last_error.unwrap_or_else(|| {
                    anyhow::anyhow!(
                        "resolved upstream {} members failed for raw exchange",
                        self.pool.name()
                    )
                }));
            }
        }

        Err(anyhow::anyhow!(
            "resolved upstream {} raw exchange exhausted members",
            self.pool.name()
        ))
    }

    fn name(&self) -> &str {
        self.pool.name()
    }

    async fn health_check(&self) -> bool {
        let snapshot = self.snapshot();
        if let Some(up) = snapshot.first() {
            up.health_check().await
        } else {
            self.pool.fallback().health_check().await
        }
    }
}

/// DNS upstream backed by `ResolvedTransport` (Go parity: DNS server `type: "resolved"`).
///
/// This consumes link configuration from `RESOLVED_STATE` (populated by the
/// Resolved service's D-Bus Manager implementation).
#[cfg(feature = "service_resolved")]
pub struct ResolvedTransportUpstream {
    name: String,
    transport: Arc<ResolvedTransport>,
}

#[cfg(feature = "service_resolved")]
impl ResolvedTransportUpstream {
    pub fn new(tag: String, config: ResolvedTransportConfig) -> Self {
        let transport = Arc::new(ResolvedTransport::new(tag.clone(), config));
        Self {
            name: format!("resolved-transport::{tag}"),
            transport,
        }
    }
}

#[cfg(feature = "service_resolved")]
#[async_trait]
impl DnsUpstream for ResolvedTransportUpstream {
    async fn query(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {
        let qtype = record_type.as_u16();
        let req = crate::dns::udp::build_query(domain.trim_end_matches('.'), qtype)?;
        let resp = self.transport.query(&req).await?;
        let (ips, ttl) = crate::dns::udp::parse_answers(&resp, qtype)?;
        let ttl = ttl
            .map(|s| Duration::from_secs(u64::from(s)))
            .unwrap_or(Duration::from_secs(60));
        Ok(DnsAnswer::new(
            ips,
            ttl,
            super::cache::Source::Upstream,
            super::cache::Rcode::NoError,
        ))
    }

    async fn exchange(&self, packet: &[u8]) -> Result<Vec<u8>> {
        self.transport.query(packet).await
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn health_check(&self) -> bool {
        matches!(
            tokio::time::timeout(
                Duration::from_secs(5),
                self.query("dns.google", RecordType::A)
            )
            .await,
            Ok(Ok(_))
        )
    }

    async fn start(&self, stage: crate::dns::transport::DnsStartStage) -> Result<()> {
        self.transport.start(stage).await
    }

    async fn close(&self) -> Result<()> {
        self.transport.close().await
    }
}

/// DNS-over-TLS (`DoT`) 上游实现
pub struct DotUpstream {
    server: SocketAddr,
    server_name: String,
    timeout: Duration,
    name: String,
    extra_ca_paths: Vec<String>,
    extra_ca_pem: Vec<String>,
    skip_verify: bool,
    ecs: Option<String>,
    transport: Option<Arc<dyn DnsTransport>>,
}

impl DotUpstream {
    /// 创建新的 `DoT` 上游
    pub fn new(server: SocketAddr, server_name: String) -> Self {
        Self::new_with_tls(server, server_name, Vec::new(), Vec::new(), false, None)
    }

    pub fn new_with_tls(
        server: SocketAddr,
        server_name: String,
        extra_ca_paths: Vec<String>,
        extra_ca_pem: Vec<String>,
        skip_verify: bool,
        transport: Option<Arc<dyn DnsTransport>>,
    ) -> Self {
        let timeout = Duration::from_millis(
            std::env::var("SB_DNS_DOT_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(5000),
        );

        Self {
            server,
            server_name: server_name.clone(),
            timeout,
            name: format!("dot://{server_name}@{server}"),
            extra_ca_paths,
            extra_ca_pem,
            skip_verify,
            ecs: None,
            transport,
        }
    }

    pub fn with_client_subnet(mut self, ecs: Option<String>) -> Self {
        self.ecs = ecs;
        self
    }
}

#[async_trait]
impl DnsUpstream for DotUpstream {
    async fn query(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {
        let _ = (&self.server, &self.server_name, &self.timeout);
        // DoT 实现需要 TLS 支持，这里提供基础框架
        // 实际实现需要使用 rustls 或其他 TLS 库
        #[cfg(feature = "dns_dot")]
        {
            if let Some(t) = &self.transport {
                let id = fastrand::u16(..);
                // Note: We need to use build_dns_query method which is likely private or cfg guarded.
                // Assuming it is available in this scope or moved to utility.
                // It is defined in DotUpstream impl, but might be guarded by cfg(feature="dns_dot").
                // Since this block is guarded by cfg(feature="dns_dot"), we can call methods in that impl block.
                let req = self.build_dns_query(id, domain, record_type)?;
                let resp = t.query(&req).await?;
                self.parse_dns_response(&resp, id)
            } else {
                self.query_dot(domain, record_type).await
            }
        }
        #[cfg(not(feature = "dns_dot"))]
        {
            let _ = (domain, record_type);
            Err(anyhow::anyhow!("DoT support requires dns_dot feature"))
        }
    }

    async fn exchange(&self, packet: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "dns_dot")]
        {
            let mut req = packet.to_vec();
            if let Some(ecs) = &self.ecs {
                let _ = inject_edns0_client_subnet(&mut req, ecs.trim());
            }

            if let Some(t) = &self.transport {
                return tokio::time::timeout(self.timeout, t.query(&req))
                    .await
                    .map_err(|_| anyhow::anyhow!("DoT exchange timeout"))?;
            }

            let transport = crate::dns::transport::DotTransport::new_with_tls(
                self.server,
                self.server_name.clone(),
                self.extra_ca_paths.clone(),
                self.extra_ca_pem.clone(),
                self.skip_verify,
            )?;
            return tokio::time::timeout(self.timeout, transport.query(&req))
                .await
                .map_err(|_| anyhow::anyhow!("DoT exchange timeout"))?;
        }
        #[cfg(not(feature = "dns_dot"))]
        {
            let _ = packet;
            Err(anyhow::anyhow!("DoT support requires dns_dot feature"))
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn health_check(&self) -> bool {
        #[cfg(feature = "dns_dot")]
        {
            matches!(
                tokio::time::timeout(
                    Duration::from_secs(5),
                    self.query("dns.google", RecordType::A),
                )
                .await,
                Ok(Ok(_))
            )
        }
        #[cfg(not(feature = "dns_dot"))]
        {
            false
        }
    }
}

#[cfg(feature = "dns_dot")]
impl DotUpstream {
    async fn query_dot(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {
        use rustls::pki_types::ServerName;
        use std::sync::Arc;
        use tokio::net::TcpStream;
        use tokio_rustls::TlsConnector;

        crate::tls::ensure_rustls_crypto_provider();

        // Create TLS configuration using global roots + per-upstream extras
        let mut roots = crate::tls::global::base_root_store();
        for p in &self.extra_ca_paths {
            if let Ok(bytes) = std::fs::read(p) {
                let mut rd = std::io::BufReader::new(&bytes[..]);
                for der in rustls_pemfile::certs(&mut rd).flatten() {
                    let _ = roots.add(der);
                }
            }
        }
        for pem in &self.extra_ca_pem {
            let mut rd = std::io::BufReader::new(pem.as_bytes());
            for der in rustls_pemfile::certs(&mut rd).flatten() {
                let _ = roots.add(der);
            }
        }
        let mut cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        if self.skip_verify {
            let v = crate::tls::danger::NoVerify::new();
            cfg.dangerous().set_certificate_verifier(Arc::new(v));
        }
        let connector = TlsConnector::from(Arc::new(cfg));

        // Connect to DoT server
        let tcp_stream = TcpStream::connect(self.server).await?;
        let server_name = ServerName::try_from(self.server_name.clone())
            .map_err(|e| anyhow::anyhow!("Invalid server name: {e}"))?;

        let mut tls_stream = connector.connect(server_name, tcp_stream).await?;

        // Build DNS query packet
        let query_id = fastrand::u16(..);
        let query_packet = self.build_dns_query(query_id, domain, record_type)?;

        // Send query with length prefix (DoT uses TCP-style length-prefixed messages)
        let length = query_packet.len() as u16;
        let mut full_packet = Vec::with_capacity(2 + query_packet.len());
        full_packet.extend_from_slice(&length.to_be_bytes());
        full_packet.extend_from_slice(&query_packet);

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        tls_stream.write_all(&full_packet).await?;

        // Read response length
        let mut length_buf = [0u8; 2];
        tls_stream.read_exact(&mut length_buf).await?;
        let response_length = u16::from_be_bytes(length_buf) as usize;

        // Read response data
        let mut response_buf = vec![0u8; response_length];
        tls_stream.read_exact(&mut response_buf).await?;

        // Parse DNS response
        self.parse_dns_response(&response_buf, query_id)
    }

    fn build_dns_query(&self, id: u16, domain: &str, record_type: RecordType) -> Result<Vec<u8>> {
        let qtype = match record_type {
            RecordType::A => 1u16,
            RecordType::AAAA => 28u16,
            RecordType::CNAME => 5u16,
            RecordType::MX => 15u16,
            RecordType::TXT => 16u16,
        };

        let id_bytes = id.to_be_bytes();
        let mut packet = vec![
            id_bytes[0],
            id_bytes[1], // ID
            0x01,
            0x00, // RD=1, standard query
            0x00,
            0x01, // QDCOUNT=1
            0x00,
            0x00, // ANCOUNT=0
            0x00,
            0x00, // NSCOUNT=0
            0x00,
            0x00, // ARCOUNT=0
        ];

        // Build QNAME
        for label in domain.trim_end_matches('.').split('.') {
            let label_bytes = label.as_bytes();
            if label_bytes.is_empty() || label_bytes.len() > 63 {
                return Err(anyhow::anyhow!("Invalid domain label: {label}"));
            }
            packet.push(label_bytes.len() as u8);
            packet.extend_from_slice(label_bytes);
        }
        packet.push(0); // Root label terminator

        // QTYPE and QCLASS
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes()); // IN class

        // Optional EDNS0 Client Subnet (global env-driven)
        if let Some((family, src_prefix, scope_prefix, addr_bytes)) = parse_client_subnet_env() {
            // Increase ARCOUNT to 1
            packet[10] = 0;
            packet[11] = 1;
            // OPT RR
            packet.push(0); // NAME root
            packet.extend_from_slice(&41u16.to_be_bytes()); // TYPE=OPT
            packet.extend_from_slice(&4096u16.to_be_bytes()); // CLASS=udp size
            packet.extend_from_slice(&0u32.to_be_bytes()); // TTL
                                                           // ECS option
            let mut opt = Vec::new();
            opt.extend_from_slice(&8u16.to_be_bytes()); // OPTION-CODE=8
            let data_len = 4u16 + (addr_bytes.len() as u16);
            opt.extend_from_slice(&data_len.to_be_bytes());
            opt.extend_from_slice(&family.to_be_bytes());
            opt.push(src_prefix);
            opt.push(scope_prefix);
            opt.extend_from_slice(&addr_bytes);
            // RDLEN + OPT data
            packet.extend_from_slice(&(opt.len() as u16).to_be_bytes());
            packet.extend_from_slice(&opt);
        }

        Ok(packet)
    }

    fn parse_dns_response(&self, response: &[u8], expected_id: u16) -> Result<DnsAnswer> {
        if response.len() < 12 {
            return Err(anyhow::anyhow!("DNS response too short"));
        }

        // Check response ID
        let response_id = u16::from_be_bytes([response[0], response[1]]);
        if response_id != expected_id {
            return Err(anyhow::anyhow!("DNS response ID mismatch"));
        }

        // Check response flags
        let flags = u16::from_be_bytes([response[2], response[3]]);
        if (flags & 0x8000) == 0 {
            return Err(anyhow::anyhow!("Not a DNS response"));
        }

        let rcode = flags & 0x000F;
        if rcode != 0 {
            return Err(anyhow::anyhow!("DNS server returned error code: {rcode}"));
        }

        let qdcount = u16::from_be_bytes([response[4], response[5]]);
        let ancount = u16::from_be_bytes([response[6], response[7]]);

        let mut offset = 12;

        // Skip questions
        for _ in 0..qdcount {
            offset = self.skip_name(response, offset)?;
            offset += 4; // QTYPE + QCLASS
        }

        // Parse answers
        let mut ips = Vec::new();
        for _ in 0..ancount {
            offset = self.skip_name(response, offset)?;

            if offset + 10 > response.len() {
                break;
            }

            let rtype = u16::from_be_bytes([response[offset], response[offset + 1]]);
            let rdlength = u16::from_be_bytes([response[offset + 8], response[offset + 9]]);
            offset += 10;

            if offset + rdlength as usize > response.len() {
                break;
            }

            match rtype {
                1 if rdlength == 4 => {
                    // A record
                    let ip = std::net::Ipv4Addr::new(
                        response[offset],
                        response[offset + 1],
                        response[offset + 2],
                        response[offset + 3],
                    );
                    ips.push(std::net::IpAddr::V4(ip));
                }
                28 if rdlength == 16 => {
                    // AAAA record
                    let mut ipv6_bytes = [0u8; 16];
                    ipv6_bytes.copy_from_slice(&response[offset..offset + 16]);
                    let ip = std::net::Ipv6Addr::from(ipv6_bytes);
                    ips.push(std::net::IpAddr::V6(ip));
                }
                _ => {}
            }

            offset += rdlength as usize;
        }

        Ok(DnsAnswer::new(
            ips,
            Duration::from_secs(300), // Default 5 minutes TTL
            crate::dns::cache::Source::Upstream,
            crate::dns::cache::Rcode::NoError,
        ))
    }

    fn skip_name(&self, data: &[u8], mut offset: usize) -> Result<usize> {
        loop {
            if offset >= data.len() {
                return Err(anyhow::anyhow!("Invalid name compression"));
            }

            let len = data[offset];
            if len == 0 {
                return Ok(offset + 1);
            }

            if (len & 0xC0) == 0xC0 {
                // Compression pointer
                return Ok(offset + 2);
            }

            offset += 1 + len as usize;
        }
    }
}

/// DNS-over-QUIC (`DoQ`) 上游实现
pub struct DoqUpstream {
    server: SocketAddr,
    server_name: String,
    timeout: Duration,
    name: String,
    extra_ca_paths: Vec<String>,
    extra_ca_pem: Vec<String>,
    skip_verify: bool,
    ecs: Option<String>,
    transport: Option<Arc<dyn DnsTransport>>,
}

impl DoqUpstream {
    pub fn new(server: SocketAddr, server_name: String) -> Self {
        Self::new_with_tls(server, server_name, Vec::new(), Vec::new(), false, None)
    }

    pub fn new_with_tls(
        server: SocketAddr,
        server_name: String,
        extra_ca_paths: Vec<String>,
        extra_ca_pem: Vec<String>,
        skip_verify: bool,
        transport: Option<Arc<dyn DnsTransport>>,
    ) -> Self {
        let timeout = Duration::from_millis(
            std::env::var("SB_DNS_DOQ_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(5000),
        );
        Self {
            server,
            server_name: server_name.clone(),
            timeout,
            name: format!("doq://{server_name}@{server}"),
            extra_ca_paths,
            extra_ca_pem,
            skip_verify,
            ecs: None,
            transport,
        }
    }
}

#[async_trait]
impl DnsUpstream for DoqUpstream {
    async fn query(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {
        #[cfg(feature = "dns_doq")]
        {
            let qtype = record_type.as_u16();
            // Build DNS wire-format query
            let req_bytes = {
                // Reuse UDP builder to include ECS if configured on this upstream
                let addr = "0.0.0.0:53".parse().unwrap();
                let up = UdpUpstream::new(addr).with_client_subnet(self.ecs.clone());
                up.build_query_packet(domain, record_type)?
            };
            // Use shared transport if available, otherwise create temporary one
            let resp_bytes = if let Some(t) = &self.transport {
                t.query(&req_bytes).await?
            } else {
                // Build separate DoQ transport with per-upstream extras
                let transport = crate::dns::transport::DoqTransport::new_with_tls(
                    self.server,
                    self.server_name.clone(),
                    self.extra_ca_paths.clone(),
                    self.extra_ca_pem.clone(),
                    self.skip_verify,
                )?;
                tokio::time::timeout(self.timeout, transport.query(&req_bytes)).await??
            };
            let (ips, ttl) = crate::dns::udp::parse_answers(&resp_bytes, qtype)?;
            let ttl = ttl
                .map(|s| Duration::from_secs(u64::from(s)))
                .unwrap_or(Duration::from_secs(60));
            return Ok(DnsAnswer::new(
                ips,
                ttl,
                super::cache::Source::Upstream,
                super::cache::Rcode::NoError,
            ));
        }
        #[cfg(not(feature = "dns_doq"))]
        {
            let _ = (domain, record_type);
            return Err(anyhow::anyhow!("DoQ support requires dns_doq feature"));
        }
    }

    async fn exchange(&self, packet: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "dns_doq")]
        {
            let mut req = packet.to_vec();
            if let Some(ecs) = &self.ecs {
                let _ = inject_edns0_client_subnet(&mut req, ecs.trim());
            }

            if let Some(t) = &self.transport {
                return tokio::time::timeout(self.timeout, t.query(&req))
                    .await
                    .map_err(|_| anyhow::anyhow!("DoQ exchange timeout"))?;
            }

            let transport = crate::dns::transport::DoqTransport::new_with_tls(
                self.server,
                self.server_name.clone(),
                self.extra_ca_paths.clone(),
                self.extra_ca_pem.clone(),
                self.skip_verify,
            )?;
            return tokio::time::timeout(self.timeout, transport.query(&req))
                .await
                .map_err(|_| anyhow::anyhow!("DoQ exchange timeout"))?;
        }
        #[cfg(not(feature = "dns_doq"))]
        {
            let _ = packet;
            Err(anyhow::anyhow!("DoQ support requires dns_doq feature"))
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn health_check(&self) -> bool {
        #[cfg(feature = "dns_doq")]
        {
            matches!(
                tokio::time::timeout(
                    Duration::from_secs(5),
                    self.query("dns.google", RecordType::A),
                )
                .await,
                Ok(Ok(_))
            )
        }
        #[cfg(not(feature = "dns_doq"))]
        {
            false
        }
    }
}

impl DoqUpstream {
    /// Attach per-upstream ECS string
    pub fn with_client_subnet(mut self, ecs: Option<String>) -> Self {
        self.ecs = ecs;
        self
    }
}

/// DNS-over-HTTPS (`DoH`) 上游实现
pub struct DohUpstream {
    url: String,
    timeout: Duration,
    name: String,
    #[cfg(feature = "dns_doh")]
    client: std::sync::Arc<reqwest::Client>,
    ecs: Option<String>,
}

impl DohUpstream {
    /// 创建新的 `DoH` 上游
    pub fn new(url: String) -> Result<Self> {
        Self::new_with_tls(url, Vec::new(), Vec::new(), false)
    }

    /// 带 TLS 扩展的构造：支持追加 CA 与跳过校验（测试用途）
    pub fn new_with_tls(
        url: String,
        ca_paths: Vec<String>,
        ca_pem: Vec<String>,
        skip_verify: bool,
    ) -> Result<Self> {
        let timeout = Duration::from_millis(
            std::env::var("SB_DNS_DOH_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(5000),
        );

        #[cfg(feature = "dns_doh")]
        let client = {
            use reqwest::Certificate;
            use std::io::Read as _;
            let mut builder = reqwest::Client::builder().timeout(timeout);
            // Append per-upstream CA files
            for p in ca_paths {
                if let Ok(mut f) = std::fs::File::open(&p) {
                    let mut buf = Vec::new();
                    if f.read_to_end(&mut buf).is_ok() {
                        if let Ok(cert) = Certificate::from_pem(&buf) {
                            builder = builder.add_root_certificate(cert);
                        }
                    }
                }
            }
            // Append inline CA
            for pem in ca_pem {
                if let Ok(cert) = Certificate::from_pem(pem.as_bytes()) {
                    builder = builder.add_root_certificate(cert);
                }
            }
            if skip_verify {
                builder = builder.danger_accept_invalid_certs(true);
            }
            let client = builder
                .build()
                .map_err(|e| anyhow::anyhow!("Failed to create HTTP client: {e}"))?;
            std::sync::Arc::new(client)
        };

        Ok(Self {
            url: url.clone(),
            timeout,
            name: format!("doh://{url}"),
            #[cfg(feature = "dns_doh")]
            client,
            ecs: None,
        })
    }
}

#[async_trait]
impl DnsUpstream for DohUpstream {
    async fn query(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {
        let _ = (&self.url, &self.timeout);
        #[cfg(feature = "dns_doh")]
        {
            self.query_doh(domain, record_type).await
        }
        #[cfg(not(feature = "dns_doh"))]
        {
            let _ = (domain, record_type);
            Err(anyhow::anyhow!("DoH support requires dns_doh feature"))
        }
    }

    async fn exchange(&self, packet: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "dns_doh")]
        {
            let mut req = packet.to_vec();
            if let Some(ecs) = &self.ecs {
                let _ = inject_edns0_client_subnet(&mut req, ecs.trim());
            }

            let resp = self
                .client
                .post(&self.url)
                .header("Content-Type", "application/dns-message")
                .header("Accept", "application/dns-message")
                .body(req)
                .send()
                .await
                .map_err(|e| anyhow::anyhow!("DoH request failed: {e}"))?;

            if !resp.status().is_success() {
                return Err(anyhow::anyhow!(
                    "DoH request failed with status: {}",
                    resp.status()
                ));
            }

            let body = resp
                .bytes()
                .await
                .map_err(|e| anyhow::anyhow!("Failed to read DoH response: {e}"))?;
            Ok(body.to_vec())
        }
        #[cfg(not(feature = "dns_doh"))]
        {
            let _ = packet;
            Err(anyhow::anyhow!("DoH support requires dns_doh feature"))
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn health_check(&self) -> bool {
        #[cfg(feature = "dns_doh")]
        {
            matches!(
                tokio::time::timeout(
                    Duration::from_secs(5),
                    self.query("dns.google", RecordType::A),
                )
                .await,
                Ok(Ok(_))
            )
        }
        #[cfg(not(feature = "dns_doh"))]
        {
            false
        }
    }
}

#[cfg(feature = "dns_doh")]
impl DohUpstream {
    async fn query_doh(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {
        // 构建 DNS 查询包
        let temp_upstream = {
            let addr = "0.0.0.0:53"
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid DoH bind address: {e}"))?;
            UdpUpstream::new(addr).with_client_subnet(self.ecs.clone())
        };
        let query_packet = temp_upstream.build_query_packet(domain, record_type)?;

        // 发送 DoH 请求
        let response = self
            .client
            .post(&self.url)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .body(query_packet)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("DoH request failed: {e}"))?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "DoH request failed with status: {}",
                response.status()
            ));
        }

        let response_body = response
            .bytes()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read DoH response: {e}"))?;

        // 解析响应
        temp_upstream.parse_response(&response_body, record_type)
    }
}

impl DohUpstream {
    /// Attach per-upstream ECS string
    pub fn with_client_subnet(mut self, ecs: Option<String>) -> Self {
        self.ecs = ecs;
        self
    }
}

/// DNS-over-HTTP/3 (`DoH3`) 上游实现
pub struct Doh3Upstream {
    server: std::net::SocketAddr,
    server_name: String,
    path: String,
    timeout: Duration,
    name: String,
    #[cfg(feature = "dns_doh3")]
    transport: std::sync::Arc<crate::dns::transport::Doh3Transport>,
    ecs: Option<String>,
}

impl Doh3Upstream {
    /// 创建新的 `DoH3` 上游
    pub fn new(server: std::net::SocketAddr, server_name: String, path: String) -> Result<Self> {
        Self::new_with_tls(server, server_name, path, Vec::new(), Vec::new(), false)
    }

    /// 带 TLS 扩展的构造：支持追加 CA 与跳过校验（测试用途）
    pub fn new_with_tls(
        server: std::net::SocketAddr,
        server_name: String,
        path: String,
        _ca_paths: Vec<String>,
        _ca_pem: Vec<String>,
        _skip_verify: bool,
    ) -> Result<Self> {
        let timeout = Duration::from_millis(
            std::env::var("SB_DNS_DOH3_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(5000),
        );

        #[cfg(feature = "dns_doh3")]
        let transport = {
            let t = crate::dns::transport::Doh3Transport::new_with_tls(
                server,
                server_name.clone(),
                path.clone(),
                _ca_paths,
                _ca_pem,
                _skip_verify,
            )
            .map_err(|e| anyhow::anyhow!("Failed to create DoH3 transport: {e}"))?;
            std::sync::Arc::new(t)
        };

        Ok(Self {
            server,
            server_name: server_name.clone(),
            path: path.clone(),
            timeout,
            name: format!("doh3://{}:{}{}", server_name, server.port(), path),
            #[cfg(feature = "dns_doh3")]
            transport,
            ecs: None,
        })
    }

    /// Attach per-upstream ECS string
    pub fn with_client_subnet(mut self, ecs: Option<String>) -> Self {
        self.ecs = ecs;
        self
    }
}

/// Load a TTL in seconds from the first non-empty environment variable in `candidates`.
/// Falls back to `default_secs` when none are set or parsing fails.
fn ttl_from_env(candidates: &[&str], default_secs: u64) -> Duration {
    for var in candidates {
        if let Ok(raw) = std::env::var(var) {
            if let Ok(secs) = raw.trim().parse::<u64>() {
                return Duration::from_secs(secs);
            }
        }
    }

    Duration::from_secs(default_secs)
}

#[async_trait]
impl DnsUpstream for Doh3Upstream {
    async fn query(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {
        let _ = (&self.server, &self.server_name, &self.path, &self.timeout);
        #[cfg(feature = "dns_doh3")]
        {
            self.query_doh3(domain, record_type).await
        }
        #[cfg(not(feature = "dns_doh3"))]
        {
            let _ = (domain, record_type);
            Err(anyhow::anyhow!("DoH3 support requires dns_doh3 feature"))
        }
    }

    async fn exchange(&self, packet: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "dns_doh3")]
        {
            use crate::dns::transport::DnsTransport as _;
            let mut req = packet.to_vec();
            if let Some(ecs) = &self.ecs {
                let _ = inject_edns0_client_subnet(&mut req, ecs.trim());
            }
            tokio::time::timeout(self.timeout, self.transport.query(&req))
                .await
                .map_err(|_| anyhow::anyhow!("DoH3 exchange timeout"))?
        }
        #[cfg(not(feature = "dns_doh3"))]
        {
            let _ = packet;
            Err(anyhow::anyhow!("DoH3 support requires dns_doh3 feature"))
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn health_check(&self) -> bool {
        #[cfg(feature = "dns_doh3")]
        {
            matches!(
                tokio::time::timeout(
                    Duration::from_secs(5),
                    self.query("dns.google", RecordType::A),
                )
                .await,
                Ok(Ok(_))
            )
        }
        #[cfg(not(feature = "dns_doh3"))]
        {
            false
        }
    }
}

#[cfg(feature = "dns_doh3")]
impl Doh3Upstream {
    async fn query_doh3(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {
        // 构建 DNS 查询包
        let temp_upstream = {
            let addr = "0.0.0.0:53"
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid DoH3 bind address: {e}"))?;
            UdpUpstream::new(addr).with_client_subnet(self.ecs.clone())
        };
        let query_packet = temp_upstream.build_query_packet(domain, record_type)?;

        // 发送 DoH3 请求通过 QUIC/HTTP3 传输
        use crate::dns::transport::DnsTransport;
        let response_body = self
            .transport
            .query(&query_packet)
            .await
            .map_err(|e| anyhow::anyhow!("DoH3 request failed: {e}"))?;

        // 解析响应
        temp_upstream.parse_response(&response_body, record_type)
    }
}

/// 系统解析器上游实现
pub struct SystemUpstream {
    default_ttl: Duration,
    name: String,
}

impl SystemUpstream {
    /// 创建新的系统解析器上游
    pub fn new() -> Self {
        let default_ttl = ttl_from_env(&["SB_DNS_SYSTEM_TTL_S"], 60);

        Self {
            default_ttl,
            name: "system".to_string(),
        }
    }
}

impl Default for SystemUpstream {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DnsUpstream for SystemUpstream {
    async fn query(&self, domain: &str, _record_type: RecordType) -> Result<DnsAnswer> {
        // 使用系统解析器
        let addrs: Vec<std::net::IpAddr> = tokio::net::lookup_host((domain, 0))
            .await
            .map_err(|e| anyhow::anyhow!("System DNS resolution failed: {e}"))?
            .map(|addr| addr.ip())
            .collect();

        if addrs.is_empty() {
            return Err(anyhow::anyhow!(
                "No addresses resolved for domain: {domain}"
            ));
        }

        Ok(DnsAnswer::new(
            addrs,
            self.default_ttl,
            super::cache::Source::Upstream,
            super::cache::Rcode::NoError,
        ))
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn health_check(&self) -> bool {
        // 系统解析器通常总是可用的
        true
    }
}

/// Local DNS upstream backed by the system resolver, with a DNS wire-format
/// fallback for environments that expect the `local` transport.
pub struct LocalUpstream {
    name: String,
    transport: LocalTransport,
    helper: UdpUpstream,
    fallback: SystemUpstream,
    ttl: Duration,
}

impl LocalUpstream {
    pub fn new(tag: Option<&str>) -> Self {
        let name = tag
            .map(|t| format!("local::{t}"))
            .unwrap_or_else(|| "local".to_string());

        // Helper upstream only constructs/parses DNS wire packets; address is unused.
        let helper = UdpUpstream::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 53))).with_retries(0);

        Self {
            name,
            transport: LocalTransport::new(),
            helper,
            fallback: SystemUpstream::new(),
            ttl: ttl_from_env(&["SB_DNS_LOCAL_TTL_S", "SB_DNS_SYSTEM_TTL_S"], 60),
        }
    }

    async fn query_local(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {
        let packet = self
            .helper
            .build_query_packet(domain, record_type)
            .context("build local DNS query packet")?;
        let response = self
            .transport
            .query(&packet)
            .await
            .context("local DNS transport failed")?;
        let mut answer = self
            .helper
            .parse_response(&response, record_type)
            .context("parse local DNS response")?;
        answer.ttl = self.ttl;
        Ok(answer)
    }
}

impl Default for LocalUpstream {
    fn default() -> Self {
        Self::new(None)
    }
}

#[async_trait]
impl DnsUpstream for LocalUpstream {
    async fn query(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {
        match self.query_local(domain, record_type).await {
            Ok(answer) => Ok(answer),
            Err(err) => {
                tracing::debug!(
                    target: "sb_core::dns::local",
                    %domain,
                    ?record_type,
                    error = %err,
                    "local DNS query failed, falling back to system",
                );
                let mut fallback = self.fallback.query(domain, record_type).await?;
                fallback.ttl = self.ttl;
                Ok(fallback)
            }
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn health_check(&self) -> bool {
        self.query("localhost", RecordType::A).await.is_ok()
    }
}

/// Tailscale upstream that dynamically checks local Tailscale status.
#[cfg(feature = "dns_tailscale")]
pub struct TailscaleLocalUpstream {
    name: String,
    upstreams: RwLock<Vec<Arc<dyn DnsUpstream>>>,
    last_refresh: Mutex<Instant>,
    refresh_interval: Duration,
    fallback: Arc<dyn DnsUpstream>,
}

#[cfg(feature = "dns_tailscale")]
impl TailscaleLocalUpstream {
    pub fn new(tag: Option<&str>) -> Self {
        let name = tag
            .map(|t| format!("tailscale::{t}"))
            .unwrap_or_else(|| "tailscale://local".to_string());
        let upstream = Self {
            name,
            upstreams: RwLock::new(Vec::new()),
            last_refresh: Mutex::new(Instant::now() - Duration::from_secs(60)),
            refresh_interval: Duration::from_secs(30),
            fallback: Arc::new(SystemUpstream::new()),
        };
        let _ = upstream.refresh();
        upstream
    }

    fn refresh(&self) -> Result<()> {
        // Run tailscale status --json
        let output = std::process::Command::new("tailscale")
            .arg("status")
            .arg("--json")
            .output();

        let output = match output {
            Ok(o) => o,
            Err(e) => {
                tracing::debug!(target: "sb_core::dns", upstream = %self.name, error = %e, "failed to run tailscale command");
                return Err(e.into());
            }
        };

        if !output.status.success() {
            tracing::debug!(target: "sb_core::dns", upstream = %self.name, status = ?output.status, "tailscale status command failed");
            return Err(anyhow::anyhow!("tailscale status failed"));
        }

        let v: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        let backend_state = v.get("BackendState").and_then(|v| v.as_str()).unwrap_or("");

        if backend_state == "Running" {
            // Tailscale is running. Use 100.100.100.100
            let addr: SocketAddr = "100.100.100.100:53"
                .parse()
                .map_err(|error| anyhow::anyhow!("invalid built-in tailscale DNS addr: {error}"))?;
            let up = Arc::new(UdpUpstream::new(addr));
            *self.upstreams.write() = vec![up];
            tracing::debug!(target: "sb_core::dns", upstream = %self.name, "tailscale is running, using 100.100.100.100");
        } else {
            tracing::warn!(target: "sb_core::dns", upstream = %self.name, state = %backend_state, "tailscale not running");
            self.upstreams.write().clear();
        }
        *self.last_refresh.lock() = Instant::now();
        Ok(())
    }

    fn maybe_refresh(&self) {
        let need = { self.last_refresh.lock().elapsed() >= self.refresh_interval };
        if need {
            let _ = self.refresh();
        }
    }
}

#[cfg(feature = "dns_tailscale")]
#[async_trait]
impl DnsUpstream for TailscaleLocalUpstream {
    async fn query(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {
        self.maybe_refresh();
        let upstreams = self.upstreams.read().clone();
        if let Some(up) = upstreams.first() {
            up.query(domain, record_type).await
        } else {
            // Fallback to system if Tailscale is not running
            self.fallback.query(domain, record_type).await
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn health_check(&self) -> bool {
        self.maybe_refresh();
        !self.upstreams.read().is_empty()
    }
}

// ============================================================================
// FakeIP Upstream (L2.10.9)
// ============================================================================

/// FakeIP upstream: allocates fake IPs from the global FakeIP pool.
/// Implements DnsUpstream so it can be routed to by DNS rules.
#[derive(Debug)]
pub struct FakeIpUpstream {
    tag_name: String,
    // Kept for introspection/debugging and to make config->runtime mapping observable.
    // Range overrides are applied via env vars in `new()`.
    inet4_range: Option<String>,
    inet6_range: Option<String>,
}

impl FakeIpUpstream {
    /// Create a new FakeIP upstream.
    ///
    /// If inet4_range/inet6_range are provided, they override the global defaults.
    /// The FakeIP pool itself is managed by `crate::dns::fakeip`.
    pub fn new(tag: String, inet4_range: Option<String>, inet6_range: Option<String>) -> Self {
        // Apply range overrides to global FakeIP pool if provided
        if let Some(ref v4) = inet4_range {
            if let Some((base, mask)) = parse_cidr_v4(v4) {
                std::env::set_var("SB_FAKEIP_V4_BASE", base.to_string());
                std::env::set_var("SB_FAKEIP_V4_MASK", mask.to_string());
            }
        }
        if let Some(ref v6) = inet6_range {
            if let Some((base, mask)) = parse_cidr_v6(v6) {
                std::env::set_var("SB_FAKEIP_V6_BASE", base.to_string());
                std::env::set_var("SB_FAKEIP_V6_MASK", mask.to_string());
            }
        }
        Self {
            tag_name: tag,
            inet4_range,
            inet6_range,
        }
    }
}

fn parse_cidr_v4(cidr: &str) -> Option<(Ipv4Addr, u8)> {
    let (addr_str, mask_str) = cidr.split_once('/')?;
    let addr: Ipv4Addr = addr_str.parse().ok()?;
    let mask: u8 = mask_str.parse().ok()?;
    Some((addr, mask))
}

fn parse_cidr_v6(cidr: &str) -> Option<(Ipv6Addr, u8)> {
    let (addr_str, mask_str) = cidr.split_once('/')?;
    let addr: Ipv6Addr = addr_str.parse().ok()?;
    let mask: u8 = mask_str.parse().ok()?;
    Some((addr, mask))
}

#[async_trait]
impl DnsUpstream for FakeIpUpstream {
    async fn query(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {
        use crate::dns::fakeip;
        // Touch stored config so fields aren't dead-code, and so debuggers/logging can inspect.
        let _ = (self.inet4_range.as_deref(), self.inet6_range.as_deref());
        match record_type {
            RecordType::A => {
                let ip = fakeip::allocate_v4(domain);
                Ok(DnsAnswer::new(
                    vec![ip],
                    Duration::from_secs(600),
                    super::cache::Source::Static,
                    super::cache::Rcode::NoError,
                ))
            }
            RecordType::AAAA => {
                let ip = fakeip::allocate_v6(domain);
                Ok(DnsAnswer::new(
                    vec![ip],
                    Duration::from_secs(600),
                    super::cache::Source::Static,
                    super::cache::Rcode::NoError,
                ))
            }
            _ => {
                // For Any/CNAME/MX/TXT, return both v4 and v6
                let v4 = fakeip::allocate_v4(domain);
                let v6 = fakeip::allocate_v6(domain);
                Ok(DnsAnswer::new(
                    vec![v4, v6],
                    Duration::from_secs(600),
                    super::cache::Source::Static,
                    super::cache::Rcode::NoError,
                ))
            }
        }
    }

    fn name(&self) -> &str {
        &self.tag_name
    }

    async fn health_check(&self) -> bool {
        // FakeIP upstream is always available — it generates addresses locally
        true
    }
}

// ============================================================================
// Hosts Upstream (L2.10.10)
// ============================================================================

/// Hosts upstream: returns predefined domain->IP mappings.
/// Supports loading from /etc/hosts format files and predefined JSON entries.
#[derive(Debug)]
pub struct HostsUpstream {
    tag_name: String,
    entries: std::collections::HashMap<String, Vec<IpAddr>>,
}

impl HostsUpstream {
    /// Create from predefined map and optional hosts file paths.
    pub fn new(
        tag: String,
        predefined: std::collections::HashMap<String, Vec<IpAddr>>,
        hosts_paths: &[String],
    ) -> Self {
        let mut entries = predefined;
        for path in hosts_paths {
            if let Ok(content) = std::fs::read_to_string(path) {
                Self::parse_hosts_file(&content, &mut entries);
            } else {
                tracing::warn!(path = %path, "Failed to read hosts file");
            }
        }
        Self {
            tag_name: tag,
            entries,
        }
    }

    /// Parse /etc/hosts format: "IP domain [domain ...]" lines
    fn parse_hosts_file(content: &str, map: &mut std::collections::HashMap<String, Vec<IpAddr>>) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let Some(ip_str) = parts.next() else {
                continue;
            };
            let Ok(ip) = ip_str.parse::<IpAddr>() else {
                continue;
            };
            for domain in parts {
                let domain = domain.to_ascii_lowercase();
                map.entry(domain).or_default().push(ip);
            }
        }
    }

    /// Create from a serde_json::Value of predefined entries.
    /// Expected format: {"domain": "ip"} or {"domain": ["ip1", "ip2"]}
    pub fn from_json_predefined(
        tag: String,
        predefined: Option<&serde_json::Value>,
        hosts_paths: &[String],
    ) -> Self {
        let mut entries = std::collections::HashMap::new();
        if let Some(serde_json::Value::Object(map)) = predefined {
            for (domain, value) in map {
                let domain = domain.to_ascii_lowercase();
                let mut ips = Vec::new();
                match value {
                    serde_json::Value::String(s) => {
                        if let Ok(ip) = s.parse::<IpAddr>() {
                            ips.push(ip);
                        }
                    }
                    serde_json::Value::Array(arr) => {
                        for v in arr {
                            if let Some(s) = v.as_str() {
                                if let Ok(ip) = s.parse::<IpAddr>() {
                                    ips.push(ip);
                                }
                            }
                        }
                    }
                    _ => {}
                }
                if !ips.is_empty() {
                    entries.insert(domain, ips);
                }
            }
        }
        Self::new(tag, entries, hosts_paths)
    }
}

#[async_trait]
impl DnsUpstream for HostsUpstream {
    async fn query(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {
        let domain_lower = domain.to_ascii_lowercase();
        match self.entries.get(&domain_lower) {
            Some(ips) => {
                let filtered: Vec<IpAddr> = ips
                    .iter()
                    .filter(|ip| match record_type {
                        RecordType::A => ip.is_ipv4(),
                        RecordType::AAAA => ip.is_ipv6(),
                        _ => true,
                    })
                    .copied()
                    .collect();
                if filtered.is_empty() {
                    Ok(DnsAnswer::new(
                        Vec::new(),
                        Duration::from_secs(3600),
                        super::cache::Source::Static,
                        super::cache::Rcode::NoError,
                    ))
                } else {
                    Ok(DnsAnswer::new(
                        filtered,
                        Duration::from_secs(3600),
                        super::cache::Source::Static,
                        super::cache::Rcode::NoError,
                    ))
                }
            }
            None => Ok(DnsAnswer::new(
                Vec::new(),
                Duration::from_secs(0),
                super::cache::Source::Static,
                super::cache::Rcode::NxDomain,
            )),
        }
    }

    fn name(&self) -> &str {
        &self.tag_name
    }

    async fn health_check(&self) -> bool {
        // Hosts upstream is always available -- it serves from an in-memory map
        true
    }
}

#[cfg(test)]
mod hosts_upstream_tests {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn hosts_returns_predefined_ipv4() {
        let mut entries = HashMap::new();
        entries.insert("example.com".to_string(), vec!["1.2.3.4".parse().unwrap()]);
        let upstream = HostsUpstream::new("hosts".to_string(), entries, &[]);
        let answer = upstream.query("example.com", RecordType::A).await.unwrap();
        assert_eq!(answer.ips.len(), 1);
        assert_eq!(answer.ips[0], "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn hosts_nxdomain_for_unknown() {
        let upstream = HostsUpstream::new("hosts".to_string(), HashMap::new(), &[]);
        let answer = upstream.query("unknown.com", RecordType::A).await.unwrap();
        assert!(answer.ips.is_empty());
        assert_eq!(answer.rcode, super::super::cache::Rcode::NxDomain);
    }

    #[tokio::test]
    async fn hosts_filters_by_record_type() {
        let mut entries = HashMap::new();
        entries.insert(
            "dual.com".to_string(),
            vec!["1.2.3.4".parse().unwrap(), "2001:db8::1".parse().unwrap()],
        );
        let upstream = HostsUpstream::new("hosts".to_string(), entries, &[]);

        let a_answer = upstream.query("dual.com", RecordType::A).await.unwrap();
        assert_eq!(a_answer.ips.len(), 1);
        assert!(a_answer.ips[0].is_ipv4());

        let aaaa_answer = upstream.query("dual.com", RecordType::AAAA).await.unwrap();
        assert_eq!(aaaa_answer.ips.len(), 1);
        assert!(aaaa_answer.ips[0].is_ipv6());
    }

    #[test]
    fn hosts_parse_file() {
        let content =
            "# Comment\n127.0.0.1 localhost\n::1 localhost\n10.0.0.1 my.host other.host\n";
        let mut map = HashMap::new();
        HostsUpstream::parse_hosts_file(content, &mut map);
        assert!(map.contains_key("localhost"));
        assert_eq!(map["localhost"].len(), 2);
        assert!(map.contains_key("my.host"));
        assert!(map.contains_key("other.host"));
    }

    #[test]
    fn hosts_upstream_name() {
        let upstream = HostsUpstream::new("my-hosts".to_string(), HashMap::new(), &[]);
        assert_eq!(upstream.name(), "my-hosts");
    }

    #[test]
    fn hosts_from_json_predefined_single() {
        let json = serde_json::json!({
            "example.com": "10.0.0.1",
            "dual.example.com": ["10.0.0.2", "2001:db8::2"]
        });
        let upstream =
            HostsUpstream::from_json_predefined("json-hosts".to_string(), Some(&json), &[]);
        assert!(upstream.entries.contains_key("example.com"));
        assert_eq!(upstream.entries["example.com"].len(), 1);
        assert!(upstream.entries.contains_key("dual.example.com"));
        assert_eq!(upstream.entries["dual.example.com"].len(), 2);
    }

    #[tokio::test]
    async fn hosts_case_insensitive_lookup() {
        let mut entries = HashMap::new();
        entries.insert("example.com".to_string(), vec!["1.2.3.4".parse().unwrap()]);
        let upstream = HostsUpstream::new("hosts".to_string(), entries, &[]);
        let answer = upstream.query("EXAMPLE.COM", RecordType::A).await.unwrap();
        assert_eq!(answer.ips.len(), 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    #[allow(dead_code)]
    #[derive(Clone)]
    enum DummyOutcome {
        Ok(DnsAnswer),
        Err(&'static str),
    }

    #[derive(Clone)]
    struct DummyUpstream {
        name: &'static str,
        outcome: DummyOutcome,
    }

    impl DummyUpstream {
        fn err(name: &'static str, msg: &'static str) -> Self {
            Self {
                name,
                outcome: DummyOutcome::Err(msg),
            }
        }
    }

    #[async_trait]
    impl DnsUpstream for DummyUpstream {
        async fn query(&self, _domain: &str, _record_type: RecordType) -> Result<DnsAnswer> {
            match &self.outcome {
                DummyOutcome::Ok(ans) => Ok(ans.clone()),
                DummyOutcome::Err(msg) => Err(anyhow::anyhow!(*msg)),
            }
        }

        fn name(&self) -> &str {
            self.name
        }

        async fn health_check(&self) -> bool {
            matches!(self.outcome, DummyOutcome::Ok(_))
        }
    }

    #[test]
    fn dot_upstream_name_contains_sni_and_addr() {
        let sa: SocketAddr = "1.1.1.1:853".parse().unwrap();
        let up = DotUpstream::new_with_tls(
            sa,
            "cloudflare-dns.com".to_string(),
            vec![],
            vec![],
            false,
            None,
        );
        assert!(up.name().contains("cloudflare-dns.com"));
        assert!(up.name().contains("1.1.1.1:853"));
    }

    #[test]
    fn doq_upstream_name_contains_sni_and_addr() {
        let sa: SocketAddr = "1.0.0.1:853".parse().unwrap();
        let up = DoqUpstream::new_with_tls(
            sa,
            "one.one.one.one".to_string(),
            vec![],
            vec![],
            false,
            None,
        );
        assert!(up.name().contains("one.one.one.one"));
        assert!(up.name().contains("1.0.0.1:853"));
    }

    #[test]
    fn doh_upstream_name_contains_url() {
        let up = match std::panic::catch_unwind(|| {
            DohUpstream::new_with_tls(
                "https://1.1.1.1/dns-query".to_string(),
                vec![],
                vec![],
                false,
            )
        }) {
            Ok(Ok(up)) => up,
            Ok(Err(err)) => panic!("doh upstream: {err}"),
            Err(_) => {
                eprintln!("skipping DoH upstream test: system configuration unavailable");
                return;
            }
        };
        assert!(up.name().contains("https://1.1.1.1/dns-query"));
    }

    #[test]
    fn dot_upstream_tls_fields_set() {
        let sa: SocketAddr = "9.9.9.9:853".parse().unwrap();
        let up = DotUpstream::new_with_tls(
            sa,
            "dns.quad9.net".to_string(),
            vec!["/etc/ssl/certs/quad9.pem".to_string()],
            vec!["-----BEGIN CERTIFICATE-----...".to_string()],
            true,
            None,
        );
        // Access private fields within the same module
        assert_eq!(up.server_name, "dns.quad9.net");
        assert_eq!(up.extra_ca_paths.len(), 1);
        assert_eq!(up.extra_ca_pem.len(), 1);
        assert!(up.skip_verify);
    }

    #[test]
    fn doq_upstream_tls_fields_set() {
        let sa: SocketAddr = "9.9.9.11:853".parse().unwrap();
        let up = DoqUpstream::new_with_tls(
            sa,
            "dns.quad9.net".to_string(),
            vec!["/etc/ssl/certs/quad9.pem".to_string()],
            vec![],
            true,
            None,
        );
        assert_eq!(up.server_name, "dns.quad9.net");
        assert_eq!(up.extra_ca_paths.len(), 1);
        assert!(up.skip_verify);
    }

    #[tokio::test]
    async fn test_udp_upstream_creation() {
        let server = SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 53));
        let upstream = UdpUpstream::new(server);

        assert_eq!(upstream.name(), "udp://8.8.8.8:53");
        assert_eq!(upstream.server, server);
    }

    #[tokio::test]
    async fn test_system_upstream() {
        let upstream = SystemUpstream::new();
        assert_eq!(upstream.name(), "system");

        // 系统解析器应该总是健康的
        assert!(upstream.health_check().await);
    }

    #[tokio::test]
    async fn local_upstream_resolves_localhost() {
        let upstream = LocalUpstream::new(None);
        let answer = upstream
            .query("localhost", RecordType::A)
            .await
            .expect("local upstream should resolve localhost");

        assert!(answer.ips.iter().any(|ip| ip.is_ipv4()));
        assert_eq!(upstream.name(), "local");
        assert!(answer.ttl > Duration::ZERO);
    }

    #[tokio::test]
    async fn local_upstream_uses_tag_in_name() {
        let upstream = LocalUpstream::new(Some("home"));
        assert_eq!(upstream.name(), "local::home");
        // Ensure it still functions
        assert!(upstream.query("localhost", RecordType::A).await.is_ok());
    }

    #[test]
    fn test_query_packet_building() {
        let server = SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 53));
        let upstream = UdpUpstream::new(server);

        let packet_res = upstream.build_query_packet("example.com", RecordType::A);
        assert!(packet_res.is_ok(), "failed to build query packet");
        let packet = match packet_res {
            Ok(p) => p,
            Err(e) => {
                // Use assert! to surface the error without relying on panic!/unwrap/expect
                panic!("error: {}", e);
            }
        };

        // 验证包的基本结构
        assert!(packet.len() > 12); // 至少包含 header
        assert_eq!(packet[4], 0x00); // QDCOUNT high byte
        assert_eq!(packet[5], 0x01); // QDCOUNT low byte (1 question)
    }

    #[test]
    fn test_build_query_packet_invalid_label() {
        let server = SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 53));
        let upstream = UdpUpstream::new(server);

        // Test with domain label > 63 chars (DNS protocol limit)
        let long_label = "a".repeat(64);
        let domain = format!("{}.example.com", long_label);

        let result = upstream.build_query_packet(&domain, RecordType::A);
        assert!(result.is_err(), "should reject labels > 63 chars");

        if let Err(e) = result {
            let msg = e.to_string();
            assert!(
                msg.contains("Invalid domain label"),
                "error should mention invalid domain label: {}",
                msg
            );
        }
    }

    #[test]
    fn test_parse_response_too_short() {
        let server = SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 53));
        let upstream = UdpUpstream::new(server);

        // DNS response must be at least 12 bytes (header)
        let short_packet = vec![0u8; 10];

        let result = upstream.parse_response(&short_packet, RecordType::A);
        assert!(result.is_err(), "should reject packets < 12 bytes");

        if let Err(e) = result {
            let msg = e.to_string();
            assert!(
                msg.contains("too short") || msg.contains("short"),
                "error should mention packet too short: {}",
                msg
            );
        }
    }

    #[tokio::test]
    async fn test_system_upstream_nonexistent_domain() {
        let upstream = SystemUpstream::new();

        // Query a domain that should not exist
        let result = upstream
            .query("invalid-nonexistent-domain-12345.local", RecordType::A)
            .await;

        // Should fail with appropriate error
        assert!(result.is_err(), "should fail on nonexistent domain");

        if let Err(e) = result {
            let msg = e.to_string();
            assert!(
                msg.contains("failed") || msg.contains("resolution") || msg.contains("not found"),
                "error should indicate DNS failure: {}",
                msg
            );
        }
    }

    #[test]
    fn parse_dhcp_spec_supports_interface_and_path() {
        let (iface, path) = parse_dhcp_spec("dhcp://eth0?resolv=/run/dhcp/resolv.conf");
        assert_eq!(iface.as_deref(), Some("eth0"));
        assert_eq!(path.display().to_string(), "/run/dhcp/resolv.conf");

        let (iface2, path2) = parse_dhcp_spec("dhcp:///custom/resolv.conf");
        assert_eq!(iface2, None);
        assert_eq!(path2.display().to_string(), "/custom/resolv.conf");
    }

    #[cfg(feature = "dns_dhcp")]
    #[test]
    fn dhcp_upstream_with_transport_builds_without_tokio_runtime() {
        let dir = tempfile::tempdir().expect("tempdir");
        let resolv = dir.path().join("resolv.conf");
        std::fs::write(&resolv, "nameserver 1.1.1.1\n").expect("write resolv.conf");

        let spec = format!("dhcp://eth0?resolv={}", resolv.display());
        let upstream =
            DhcpUpstream::from_spec(&spec, Some("dhcp_transport")).expect("build dhcp upstream");

        assert_eq!(upstream.name(), "dhcp::dhcp_transport");
    }

    #[cfg(unix)]
    #[test]
    fn discover_nameservers_reads_resolv_conf() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            "\
nameserver 8.8.8.8
nameserver 2001:4860:4860::8888
# comment
"
        )
        .unwrap();
        let addrs = discover_nameservers_from_file(tmp.path()).unwrap();
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0], "8.8.8.8:53".parse::<SocketAddr>().unwrap());
        assert_eq!(
            addrs[1],
            "[2001:4860:4860::8888]:53".parse::<SocketAddr>().unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn dhcp_upstream_reload_uses_resolv_conf_content() {
        use std::io::Write;
        use std::thread::sleep;
        use tempfile::NamedTempFile;

        let mut tmp = NamedTempFile::new().expect("temp resolv.conf");
        writeln!(tmp, "nameserver 127.0.0.1").unwrap();
        let spec = format!("dhcp://{}", tmp.path().display());
        let upstream =
            DhcpUpstream::from_spec(&spec, Some("dhcp_test")).expect("dhcp upstream from spec");

        assert_eq!(
            upstream.pool.snapshot().len(),
            1,
            "expected DHCP upstream to load one nameserver"
        );

        std::fs::write(tmp.path(), "").expect("truncate resolv.conf");
        upstream.reload_servers().expect("reload after truncate");
        assert_eq!(
            upstream.pool.snapshot().len(),
            0,
            "empty resolv.conf should clear DHCP upstream members"
        );

        // Update mtime to trigger reload without waiting for interval
        std::fs::write(tmp.path(), "nameserver 1.1.1.1").expect("rewrite resolv.conf");
        sleep(std::time::Duration::from_millis(5));
        upstream.maybe_reload();
        let snap = upstream.snapshot();
        assert_eq!(snap.len(), 1);
        assert!(
            snap[0].name().contains("1.1.1.1"),
            "expected DHCP reload to pick new nameserver, got {}",
            snap[0].name()
        );
    }

    #[test]
    fn parse_tailscale_spec_with_inline_servers() {
        let (name, addrs) = parse_tailscale_spec("tailscale://100.64.0.2:53", Some("ts")).unwrap();
        assert_eq!(name, "tailscale::ts");
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], "100.64.0.2:53".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn parse_tailscale_spec_uses_env_fallback() {
        let old = std::env::var("SB_TAILSCALE_DNS_ADDRS").ok();
        std::env::set_var("SB_TAILSCALE_DNS_ADDRS", "100.64.0.10");
        let (_, addrs) = parse_tailscale_spec("tailscale://", None).unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], "100.64.0.10:53".parse::<SocketAddr>().unwrap());
        if let Some(val) = old {
            std::env::set_var("SB_TAILSCALE_DNS_ADDRS", val);
        } else {
            std::env::remove_var("SB_TAILSCALE_DNS_ADDRS");
        }
    }

    #[test]
    fn parse_tailscale_spec_errors_without_addrs() {
        let old = std::env::var("SB_TAILSCALE_DNS_ADDRS").ok();
        std::env::remove_var("SB_TAILSCALE_DNS_ADDRS");
        let err = parse_tailscale_spec("tailscale://", Some("ts")).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("SB_TAILSCALE_DNS_ADDRS"),
            "error should hint env configuration, got: {msg}"
        );
        if let Some(val) = old {
            std::env::set_var("SB_TAILSCALE_DNS_ADDRS", val);
        }
    }

    #[tokio::test]
    async fn tailscale_upstream_empty_members_returns_hint() {
        let up = StaticMultiUpstream::from_members_for_test("tailscale::test".into(), Vec::new());
        let err = up
            .query("example.com", RecordType::A)
            .await
            .expect_err("tailscale upstream should error when empty");
        let msg = err.to_string();
        assert!(
            msg.contains("SB_TAILSCALE_DNS_ADDRS"),
            "error should hint env configuration, got: {msg}"
        );
        assert!(
            msg.contains("tailscale upstream tailscale::test"),
            "error should include upstream name, got: {msg}"
        );
    }

    #[tokio::test]
    async fn tailscale_upstream_reports_member_failures() {
        let member = Arc::new(DummyUpstream::err("ts1", "boom"));
        let up = StaticMultiUpstream::from_members_for_test(
            "tailscale::test".into(),
            vec![member.clone(), member],
        );
        let err = up
            .query("example.com", RecordType::A)
            .await
            .expect_err("tailscale upstream should bubble member errors");
        let msg = err.to_string();
        assert!(
            msg.contains("exhausted"),
            "error should indicate exhaustion, got: {msg}"
        );
        assert!(
            msg.contains("tailscale::test"),
            "error should include upstream name, got: {msg}"
        );
        let debug = format!("{err:?}");
        assert!(
            debug.contains("boom"),
            "error chain should preserve member failure, got: {debug}"
        );
    }

    #[test]
    fn parse_resolved_spec_supports_absolute_and_query() {
        let path = parse_resolved_spec("resolved:///run/systemd/resolve/resolv.conf");
        assert_eq!(
            path.display().to_string(),
            "/run/systemd/resolve/resolv.conf"
        );

        let path2 = parse_resolved_spec("resolved://?resolv=/tmp/custom.conf");
        assert_eq!(path2.display().to_string(), "/tmp/custom.conf");
    }

    #[cfg(unix)]
    #[test]
    fn resolved_upstream_uses_stub_file() {
        use std::io::Write;
        use std::thread::sleep;
        use tempfile::NamedTempFile;

        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "nameserver 127.0.0.53").unwrap();
        let up = ResolvedUpstream::from_spec(
            &format!("resolved://{}", tmp.path().display()),
            Some("test"),
        )
        .unwrap();
        assert_eq!(up.snapshot().len(), 1);

        std::fs::write(tmp.path(), "").expect("truncate resolved stub");
        up.reload_servers().expect("reload after truncate");
        assert!(
            up.snapshot().is_empty(),
            "resolved upstream should clear members after empty stub"
        );

        // Update stub and ensure reload is picked up immediately
        std::fs::write(tmp.path(), "nameserver 9.9.9.9").expect("rewrite resolved stub");
        sleep(std::time::Duration::from_millis(5));
        up.maybe_reload();
        let snap = up.snapshot();
        assert_eq!(snap.len(), 1);
        assert!(
            snap[0].name().contains("9.9.9.9"),
            "expected resolved reload to pick new nameserver, got {}",
            snap[0].name()
        );
    }

    #[test]
    fn file_backed_upstream_pool_owner_lives_in_upstream_pool_module() {
        let pool_source = include_str!("upstream_pool.rs");
        let upstream_source = include_str!("upstream.rs");

        assert!(pool_source.contains("struct FileBackedUpstreamPool"));
        assert!(upstream_source.contains("pool: FileBackedUpstreamPool"));
        assert!(upstream_source.contains("load_udp_upstreams_from_file"));
    }

    #[tokio::test]
    async fn fakeip_upstream_allocates_v4() {
        let upstream = FakeIpUpstream::new("fakeip".to_string(), None, None);
        let answer = upstream
            .query("test.example.com", RecordType::A)
            .await
            .unwrap();
        assert_eq!(answer.ips.len(), 1);
        assert!(answer.ips[0].is_ipv4());
        assert_eq!(answer.rcode, crate::dns::cache::Rcode::NoError);
        assert_eq!(answer.ttl, Duration::from_secs(600));
    }

    #[tokio::test]
    async fn fakeip_upstream_allocates_v6() {
        let upstream = FakeIpUpstream::new("fakeip".to_string(), None, None);
        let answer = upstream
            .query("test.example.com", RecordType::AAAA)
            .await
            .unwrap();
        assert_eq!(answer.ips.len(), 1);
        assert!(answer.ips[0].is_ipv6());
    }

    #[test]
    fn fakeip_upstream_tag() {
        let upstream = FakeIpUpstream::new("my-fakeip".to_string(), None, None);
        assert_eq!(upstream.name(), "my-fakeip");
    }

    #[tokio::test]
    async fn fakeip_upstream_health_check_always_true() {
        let upstream = FakeIpUpstream::new("fakeip".to_string(), None, None);
        assert!(upstream.health_check().await);
    }
}
