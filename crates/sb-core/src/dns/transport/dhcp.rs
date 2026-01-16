//! DHCP DNS Transport
//!
//! Active discovery of DNS servers via DHCP DISCOVER/INFORM.
//! Mirrors Go's `dns/transport/dhcp` lifecycle: interface auto-detect, TTL/backoff,
//! multi-server exchange.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use futures::future::select_ok;
use futures::FutureExt;
use parking_lot::RwLock;
use sb_platform::system_proxy::get_default_interface_name;
use smoltcp::wire::{DhcpMessageType, DhcpPacket, DhcpRepr, Ipv4Address};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, Notify};

use super::{DnsStartStage, DnsTransport};

const DHCP_CLIENT_PORT: u16 = 68;
const DHCP_SERVER_PORT: u16 = 67;
/// Go `constant.DHCPTimeout` (1 minute). Used as an upper bound for a DHCP exchange.
const DHCP_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Per-receive timeout inside a single probe.
const DHCP_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);
/// Go `constant.DHCPTTL` (1 hour). After this we refresh.
const DHCP_TTL: Duration = Duration::from_secs(3600);
/// How often to check TTL/interface changes in the background.
const DHCP_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
/// Frequency to re-check default interface when auto-detect is enabled.
const INTERFACE_CHECK_INTERVAL: Duration = Duration::from_secs(15);
/// DNS query timeout when talking to discovered servers.
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(4);
/// DHCP option code for domain name (string).
const OPT_DOMAIN_NAME: u8 = 15;
/// DHCP option code for domain search list (RFC 3397).
const OPT_DOMAIN_SEARCH: u8 = 119;

#[derive(Debug, Clone, Default)]
struct DhcpProbeResult {
    servers: Vec<SocketAddr>,
    /// DHCP search list (option 119/15). Currently informational; reserved for future
    /// search/ndots expansion.
    search: Vec<String>,
    /// ndots hint (Go defaults to 1).
    ndots: u8,
}

#[derive(Debug, Clone)]
pub struct DhcpTransport {
    interface: Arc<RwLock<Option<String>>>,
    servers: Arc<RwLock<Vec<SocketAddr>>>,
    search_domains: Arc<RwLock<Vec<String>>>,
    ndots: Arc<AtomicU8>,
    updated_at: Arc<RwLock<Option<Instant>>>,
    force_probe: Arc<AtomicBool>,
    started: Arc<AtomicBool>,
    close_notify: Arc<Notify>,
    probe_lock: Arc<Mutex<()>>,
    auto_detect: bool,
}

impl DhcpTransport {
    pub fn new(interface: Option<String>) -> Self {
        Self {
            auto_detect: interface.is_none(),
            interface: Arc::new(RwLock::new(interface)),
            servers: Arc::new(RwLock::new(Vec::new())),
            search_domains: Arc::new(RwLock::new(Vec::new())),
            ndots: Arc::new(AtomicU8::new(1)),
            updated_at: Arc::new(RwLock::new(None)),
            force_probe: Arc::new(AtomicBool::new(false)),
            started: Arc::new(AtomicBool::new(false)),
            close_notify: Arc::new(Notify::new()),
            probe_lock: Arc::new(Mutex::new(())),
        }
    }

    /// Get cached DNS servers (does not trigger refresh).
    pub fn servers(&self) -> Vec<SocketAddr> {
        self.servers.read().clone()
    }

    fn should_probe(&self) -> bool {
        if self.force_probe.swap(false, Ordering::SeqCst) {
            return true;
        }
        let servers_empty = self.servers.read().is_empty();
        let expired = self
            .updated_at
            .read()
            .map(|t| t.elapsed() >= DHCP_TTL)
            .unwrap_or(true);
        servers_empty || expired
    }

    fn current_interface(&self) -> Option<String> {
        let configured = self.interface.read().clone();
        if configured.is_some() {
            return configured;
        }
        get_default_interface_name()
    }

    fn update_interface_if_changed(&self) {
        if !self.auto_detect {
            return;
        }
        if let Some(default_iface) = get_default_interface_name() {
            let mut iface_guard = self.interface.write();
            if iface_guard.as_deref() != Some(default_iface.as_str()) {
                *iface_guard = Some(default_iface.clone());
                self.force_probe.store(true, Ordering::SeqCst);
                tracing::info!(interface = %default_iface, "DHCP: default interface changed, scheduling probe");
            }
        }
    }

    async fn refresh_if_needed(&self, reason: &str) -> Result<()> {
        if !self.should_probe() {
            return Ok(());
        }

        let _guard = self.probe_lock.lock().await;
        // Re-check under lock to avoid duplicate probes.
        if !self.should_probe() {
            return Ok(());
        }

        let iface = self.current_interface();
        match Self::probe_once(iface.as_deref()).await {
            Ok(result) if !result.servers.is_empty() => {
                {
                    let mut servers = self.servers.write();
                    *servers = result.servers.clone();
                }
                *self.search_domains.write() = result.search;
                self.ndots.store(result.ndots, Ordering::SeqCst);
                *self.updated_at.write() = Some(Instant::now());
                tracing::info!(
                    interface = iface.as_deref().unwrap_or("auto"),
                    servers = ?result.servers,
                    reason,
                    "DHCP: refreshed DNS servers"
                );
                Ok(())
            }
            Ok(_) => Err(anyhow!("DHCP: no DNS servers in response")),
            Err(e) => Err(e).context("DHCP probe failed"),
        }
    }

    async fn run_background(self: Arc<Self>) {
        tracing::debug!("DHCP probe loop started");
        let mut refresh_tick = tokio::time::interval(DHCP_REFRESH_INTERVAL);
        refresh_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut iface_tick = tokio::time::interval(INTERFACE_CHECK_INTERVAL);
        iface_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = self.close_notify.notified() => {
                    tracing::debug!("DHCP probe loop stopped");
                    break;
                }
                _ = refresh_tick.tick() => {
                    if let Err(e) = self.refresh_if_needed("ttl/periodic").await {
                        tracing::warn!(error = %e, "DHCP periodic refresh failed");
                    }
                }
                _ = iface_tick.tick(), if self.auto_detect => {
                    self.update_interface_if_changed();
                }
            }
        }
    }

    async fn probe_once(interface: Option<&str>) -> Result<DhcpProbeResult> {
        // Build MAC (prefer real if available).
        let mac = if let Some(iface) = interface {
            match Self::get_mac_address(iface) {
                Ok(m) => m,
                Err(e) => {
                    tracing::debug!("DHCP: failed to read MAC for {}: {e}, using random", iface);
                    Self::random_mac()
                }
            }
        } else {
            Self::random_mac()
        };

        // Create socket
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_broadcast(true)?;
        socket.set_reuse_address(true)?;

        #[cfg(target_os = "linux")]
        if let Some(iface) = interface {
            socket.bind_device(Some(iface.as_bytes()))?;
        }

        let addr = SocketAddr::from(([0, 0, 0, 0], DHCP_CLIENT_PORT));
        socket.bind(&addr.into())?;
        socket.set_nonblocking(true)?;

        let udp_socket = UdpSocket::from_std(socket.into())?;

        // Construct DHCP DISCOVER with DNS/search options requested (6, 15, 119).
        let xid = fastrand::u32(..);
        let mut buffer = vec![0u8; 300];
        let repr = DhcpRepr {
            message_type: DhcpMessageType::Discover,
            transaction_id: xid,
            client_hardware_address: mac,
            client_ip: Ipv4Address::UNSPECIFIED,
            your_ip: Ipv4Address::UNSPECIFIED,
            server_ip: Ipv4Address::UNSPECIFIED,
            relay_agent_ip: Ipv4Address::UNSPECIFIED,
            broadcast: true,
            // Options
            router: None,
            subnet_mask: None,
            requested_ip: None,
            client_identifier: Some(mac),
            server_identifier: None,
            parameter_request_list: Some(&[6, 15, 119]),
            dns_servers: None,
            lease_duration: None,
            renew_duration: None,
            rebind_duration: None,
            secs: 0,
            max_size: Some(1500),
            additional_options: &[],
        };

        let mut packet = DhcpPacket::new_unchecked(&mut buffer);
        repr.emit(&mut packet)?;

        let target = SocketAddr::from(([255, 255, 255, 255], DHCP_SERVER_PORT));
        udp_socket
            .send_to(packet.into_inner(), target)
            .await
            .context("send DHCP discover")?;

        // Wait for OFFER/ACK
        let mut recv_buf = vec![0u8; 1500];
        let start = Instant::now();

        loop {
            let elapsed = start.elapsed();
            if elapsed >= DHCP_REQUEST_TIMEOUT {
                return Err(anyhow!("DHCP probe timeout"));
            }

            let timeout_dur = DHCP_RESPONSE_TIMEOUT.min(DHCP_REQUEST_TIMEOUT - elapsed);
            let res = tokio::time::timeout(timeout_dur, udp_socket.recv_from(&mut recv_buf)).await;
            match res {
                Ok(Ok((len, _peer))) => {
                    let data = &recv_buf[..len];
                    if let Ok(packet) = DhcpPacket::new_checked(data) {
                        let repr = DhcpRepr::parse(&packet)?;
                        if repr.transaction_id != xid {
                            continue;
                        }
                        if repr.message_type != DhcpMessageType::Offer
                            && repr.message_type != DhcpMessageType::Ack
                        {
                            continue;
                        }

                        let (search, ndots) = Self::parse_search_and_ndots(&packet);
                        if let Some(dns_servers) = repr.dns_servers {
                            let addrs = dns_servers
                                .iter()
                                .map(|ip| SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip.0)), 53))
                                .collect::<Vec<_>>();
                            return Ok(DhcpProbeResult {
                                servers: addrs,
                                search,
                                ndots,
                            });
                        }
                    }
                }
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => continue, // timeout; keep waiting until overall timeout
            }
        }
    }

    /// Get MAC address for an interface using platform-native APIs.
    ///
    /// Delegates to `sb_platform::network::get_interface_mac()` which uses:
    /// - Linux: `/sys/class/net/{iface}/address`
    /// - macOS/BSD: `getifaddrs()` with `AF_LINK`
    /// - Windows: `GetAdaptersAddresses()` API (Go parity)
    fn get_mac_address(iface: &str) -> Result<smoltcp::wire::EthernetAddress> {
        sb_platform::network::get_interface_mac(iface)
            .map(smoltcp::wire::EthernetAddress)
            .map_err(|e| anyhow!("{e}"))
    }

    /// Parse DHCP options for search domains (option 119 / 15) and ndots hint.
    fn parse_search_and_ndots(packet: &DhcpPacket<&[u8]>) -> (Vec<String>, u8) {
        let mut search = Vec::new();
        let mut domain_name = None;

        for opt in packet.options() {
            match opt.kind {
                OPT_DOMAIN_SEARCH if !opt.data.is_empty() => {
                    if let Ok(list) = decode_domain_search(opt.data) {
                        search = list;
                    }
                }
                OPT_DOMAIN_NAME if !opt.data.is_empty() => {
                    if let Ok(s) = std::str::from_utf8(opt.data) {
                        let trimmed = s.trim_end_matches('.');
                        if !trimmed.is_empty() {
                            domain_name = Some(trimmed.to_string());
                        }
                    }
                }
                _ => {}
            }
        }

        if search.is_empty() {
            if let Some(dom) = domain_name {
                search.push(dom);
            }
        }

        // Go default ndots is 1; DHCP option 119 does not carry ndots so keep default.
        (search, 1)
    }

    fn random_mac() -> smoltcp::wire::EthernetAddress {
        let mut bytes = [0u8; 6];
        fastrand::fill(&mut bytes);
        bytes[0] &= 0xfe; // unicast
        bytes[0] |= 0x02; // local admin
        smoltcp::wire::EthernetAddress(bytes)
    }

    /// Expand DNS packet with search/ndots rules (Go nameList equivalent).
    ///
    /// Input: raw DNS wire packet (first question name assumed).
    /// Output: vector of wire packets with adjusted QNAMEs according to search/ndots.
    fn expand_search(&self, packet: &[u8]) -> Result<Vec<Vec<u8>>> {
        // Minimal DNS parser: read QNAME from the first question.
        if packet.len() < 12 {
            return Err(anyhow!("invalid DNS packet: too short"));
        }
        let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
        if qdcount == 0 {
            return Err(anyhow!("DNS packet missing questions"));
        }

        // Parse QNAME labels.
        let mut labels = Vec::new();
        let mut idx = 12usize;
        while idx < packet.len() {
            let len = packet[idx] as usize;
            idx += 1;
            if len == 0 {
                break;
            }
            if idx + len > packet.len() {
                return Err(anyhow!("DNS packet QNAME truncated"));
            }
            let label = std::str::from_utf8(&packet[idx..idx + len])
                .map_err(|e| anyhow!("invalid QNAME utf8: {e}"))?;
            labels.push(label.to_string());
            idx += len;
        }

        if idx >= packet.len() {
            return Err(anyhow!("DNS packet missing question fields"));
        }

        // Collect suffix after QNAME (QTYPE/QCLASS and rest).
        let suffix = packet[idx..].to_vec();
        let name = labels.join(".");
        let rooted = name.ends_with('.');
        let search_list = self.search_domains.read().clone();
        let ndots = self.ndots.load(Ordering::SeqCst).max(1) as usize;

        // Helper to build packet with given fqdn.
        let build_packet =
            |fqdn: &str, qname_and_suffix: &[u8], original: &[u8]| -> Result<Vec<u8>> {
                let mut out = Vec::with_capacity(original.len() + fqdn.len());
                out.extend_from_slice(&original[..12]); // header unchanged
                                                        // rebuild QNAME
                for part in fqdn.trim_end_matches('.').split('.') {
                    if part.is_empty() {
                        continue;
                    }
                    let len = part.len();
                    if len > 63 {
                        return Err(anyhow!("label too long in fqdn"));
                    }
                    out.push(len as u8);
                    out.extend_from_slice(part.as_bytes());
                }
                out.push(0); // end of QNAME
                out.extend_from_slice(qname_and_suffix);
                Ok(out)
            };

        let fqdn_rooted = format!("{name}.");
        let has_ndots = name.matches('.').count() >= ndots;
        let mut out = Vec::new();

        if rooted {
            if !avoid_dns(&fqdn_rooted) {
                out.push(build_packet(&fqdn_rooted, &suffix, packet)?);
            }
            return Ok(out);
        }

        // Start with trailing dot version of the base name
        let base = format!("{name}.");
        if has_ndots && !avoid_dns(&base) {
            out.push(build_packet(&base, &suffix, packet)?);
        }

        for suffix_domain in &search_list {
            let fqdn = format!("{name}.{}", suffix_domain.trim_end_matches('.'));
            if !avoid_dns(&fqdn) && fqdn.len() <= 254 {
                out.push(build_packet(&fqdn, &suffix, packet)?);
            }
        }

        if !has_ndots && !avoid_dns(&base) {
            out.push(build_packet(&base, &suffix, packet)?);
        }

        if out.is_empty() {
            // fallback: original packet
            out.push(packet.to_vec());
        }

        Ok(out)
    }
}

/// Decode RFC 3397 domain search list (option 119).
///
/// Supports standard DNS label encoding with optional compression pointers.
fn decode_domain_search(data: &[u8]) -> Result<Vec<String>> {
    let mut result = Vec::new();
    let mut pos = 0usize;

    while pos < data.len() {
        let (name, next) = decode_name(data, pos, 0)?;
        if !name.is_empty() {
            result.push(name);
        }
        pos = next;
    }

    Ok(result)
}

fn decode_name(data: &[u8], mut pos: usize, depth: u8) -> Result<(String, usize)> {
    if depth > 8 {
        return Err(anyhow!("domain search name compression depth exceeded"));
    }

    let mut labels: Vec<String> = Vec::new();
    let mut jumped = false;
    let mut jump_end = pos;

    loop {
        let len = *data.get(pos).ok_or_else(|| anyhow!("truncated label"))?;
        // Zero-length label marks end.
        if len == 0 {
            pos += 1;
            if !jumped {
                jump_end = pos;
            }
            break;
        }

        // Compression pointer: two bytes, top two bits set.
        if len & 0b1100_0000 == 0b1100_0000 {
            let next_byte = *data
                .get(pos + 1)
                .ok_or_else(|| anyhow!("truncated compression pointer"))?;
            let offset = (((len & 0b0011_1111) as usize) << 8) | (next_byte as usize);
            let (suffix, _) = decode_name(data, offset, depth + 1)?;
            labels.push(suffix);
            pos += 2;
            if !jumped {
                jump_end = pos;
            }
            jumped = true;
            break;
        }

        let label_len = len as usize;
        pos += 1;
        let label_bytes = data
            .get(pos..pos + label_len)
            .ok_or_else(|| anyhow!("truncated label data"))?;
        let label =
            std::str::from_utf8(label_bytes).map_err(|e| anyhow!("invalid label utf8: {e}"))?;
        labels.push(label.to_string());
        pos += label_len;
    }

    let name = labels.join(".");
    let next = if jumped { jump_end } else { pos };
    Ok((name, next))
}

fn avoid_dns(name: &str) -> bool {
    if name.is_empty() {
        return true;
    }
    let trimmed = name.trim_end_matches('.');
    trimmed.ends_with(".onion")
}

#[allow(dead_code)]
fn parse_mac_str(raw: &str) -> Option<[u8; 6]> {
    let cleaned = raw.trim().trim_matches('"');
    let parts: Vec<&str> = cleaned
        .split(['-', ':', ' '])
        .filter(|s| !s.is_empty())
        .collect();
    if parts.len() != 6 {
        return None;
    }
    let mut bytes = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        if let Ok(b) = u8::from_str_radix(part, 16) {
            bytes[i] = b;
        } else {
            return None;
        }
    }
    Some(bytes)
}

#[async_trait::async_trait]
impl DnsTransport for DhcpTransport {
    fn name(&self) -> &'static str {
        "dhcp"
    }

    async fn start(&self, stage: DnsStartStage) -> Result<()> {
        if stage != DnsStartStage::Start {
            return Ok(());
        }
        if self.started.swap(true, Ordering::SeqCst) {
            return Ok(());
        }

        // Prime once on start; failure is non-fatal (will retry in background).
        if let Err(e) = self.refresh_if_needed("start").await {
            tracing::warn!(error = %e, "DHCP initial probe failed");
        }

        let cloned = Arc::new(self.clone());
        tokio::spawn(cloned.run_background());
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        if self.started.swap(false, Ordering::SeqCst) {
            self.close_notify.notify_waiters();
        }
        Ok(())
    }

    async fn query(&self, packet: &[u8]) -> Result<Vec<u8>> {
        // Ensure we have fresh servers (stale TTL triggers refresh).
        self.refresh_if_needed("query").await?;
        let servers = self.servers();
        if servers.is_empty() {
            return Err(anyhow!("No DHCP DNS servers discovered"));
        }

        // Expand queries according to search/ndots like Go's nameList.
        let queries = self.expand_search(packet)?;

        // Race all queries across all servers; return first success.
        let futs = queries.into_iter().flat_map(|q| {
            servers.iter().cloned().map(move |target| {
                let pkt = q.clone();
                async move {
                    let socket = UdpSocket::bind("0.0.0.0:0").await?;
                    socket.connect(target).await?;
                    socket.send(&pkt).await?;

                    let mut buf = vec![0u8; 1500];
                    let len =
                        tokio::time::timeout(DNS_QUERY_TIMEOUT, socket.recv(&mut buf)).await??;
                    buf.truncate(len);
                    Ok::<Vec<u8>, anyhow::Error>(buf)
                }
                .boxed()
            })
        });

        match select_ok(futs).await {
            Ok((bytes, _pending)) => Ok(bytes),
            Err(e) => Err(anyhow!(e)).context("all DHCP DNS servers failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_probe_on_empty_or_expired() {
        let t = DhcpTransport::new(None);
        assert!(t.should_probe()); // empty
        {
            *t.servers.write() = vec![SocketAddr::from(([1, 1, 1, 1], 53))];
            *t.updated_at.write() = Some(Instant::now() - DHCP_TTL - Duration::from_secs(1));
        }
        assert!(t.should_probe()); // expired
    }

    #[test]
    fn force_probe_flag_triggers_once() {
        let t = DhcpTransport::new(None);
        t.force_probe.store(true, Ordering::SeqCst);
        assert!(t.should_probe());
        // Next call should fall back to empty/expired check (still true here).
        assert!(t.should_probe());
    }

    #[test]
    fn decode_domain_search_plain_labels() {
        // "example.com." encoded as labels: 7 example 3 com 0
        let data = [
            7u8, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];
        let res = decode_domain_search(&data).unwrap();
        assert_eq!(res, vec!["example.com".to_string()]);
    }

    #[test]
    fn expand_search_respects_ndots_and_search() {
        // Build a minimal DNS query for "foo"
        let mut packet = vec![0u8; 12];
        // Set QDCOUNT = 1
        packet[4] = 0;
        packet[5] = 1;
        packet.extend_from_slice(&[3, b'f', b'o', b'o', 0]); // QNAME "foo."
        packet.extend_from_slice(&[0, 1, 0, 1]); // QTYPE A, QCLASS IN

        let transport = DhcpTransport {
            interface: Arc::new(RwLock::new(None)),
            servers: Arc::new(RwLock::new(vec![SocketAddr::from(([1, 1, 1, 1], 53))])),
            search_domains: Arc::new(RwLock::new(vec!["example.com".to_string()])),
            ndots: Arc::new(AtomicU8::new(1)),
            updated_at: Arc::new(RwLock::new(None)),
            force_probe: Arc::new(AtomicBool::new(false)),
            started: Arc::new(AtomicBool::new(false)),
            close_notify: Arc::new(Notify::new()),
            probe_lock: Arc::new(Mutex::new(())),
            auto_detect: true,
        };

        let expanded = transport.expand_search(&packet).unwrap();
        // Expect two queries: foo.example.com. and foo.
        assert_eq!(expanded.len(), 2);
        let qnames: Vec<String> = expanded
            .iter()
            .map(|pkt| extract_qname(pkt).unwrap())
            .collect();
        assert!(qnames.contains(&"foo.example.com".to_string()));
        assert!(qnames.contains(&"foo".to_string()));
    }

    fn extract_qname(packet: &[u8]) -> Result<String> {
        let mut idx = 12usize;
        let mut labels = Vec::new();
        loop {
            let len = *packet.get(idx).ok_or_else(|| anyhow!("short"))? as usize;
            idx += 1;
            if len == 0 {
                break;
            }
            let label = packet
                .get(idx..idx + len)
                .ok_or_else(|| anyhow!("short label"))?;
            labels.push(std::str::from_utf8(label)?.to_string());
            idx += len;
        }
        Ok(labels.join("."))
    }

    #[test]
    fn parse_mac_str_variants() {
        assert_eq!(
            parse_mac_str("aa-bb-cc-dd-ee-ff"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert_eq!(
            parse_mac_str("aa:bb:cc:dd:ee:ff"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert_eq!(
            parse_mac_str("aa bb cc dd ee ff"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert!(parse_mac_str("not-a-mac").is_none());
    }
}
