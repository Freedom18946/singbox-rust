//! D-Bus server interface for org.freedesktop.resolve1.Manager.
//!
//! This module implements the D-Bus server side of systemd-resolved,
//! allowing external programs to configure per-link DNS settings.
//!
//! Mirrors Go's `service/resolved/resolve1.go`.

use std::sync::Arc;
#[cfg(not(all(target_os = "linux", feature = "service_resolved")))]
use tracing::warn;
#[cfg(all(target_os = "linux", feature = "service_resolved"))]
use tracing::{debug, info, warn};

use sb_core::dns::transport::resolved::Resolve1ManagerState;

// D-Bus interface implementation (zbus)
#[cfg(all(target_os = "linux", feature = "service_resolved"))]
pub mod dbus_server {
    use super::*;
    use sb_core::dns::message::{parse_answer_records, pack_rr_uncompressed};
    use sb_core::dns::transport::resolved::{LinkDNS, LinkDNSEx, LinkDomainConfig};
    use sb_core::dns::udp;
    use sb_core::dns::{DnsQueryContext, DnsRouter};
    use std::net::IpAddr;
    use zbus::{interface, Connection, Result as ZbusResult};

    /// D-Bus interface for org.freedesktop.resolve1.Manager.
    ///
    /// This struct wraps the shared state and exposes D-Bus methods.
    pub struct Resolve1Manager {
        state: Arc<Resolve1ManagerState>,
        system_bus: Connection,
    }

    impl Resolve1Manager {
        /// Create a new Resolve1Manager.
        pub fn new(state: Arc<Resolve1ManagerState>, system_bus: Connection) -> Self {
            Self { state, system_bus }
        }

        async fn get_sender_pid(&self, sender: &str) -> Option<u32> {
            let proxy = zbus::ProxyBuilder::new_bare(&self.system_bus)
                .destination("org.freedesktop.DBus")
                .ok()?
                .path("/org/freedesktop/DBus")
                .ok()?
                .interface("org.freedesktop.DBus")
                .ok()?
                .build()
                .await
                .ok()?;
            proxy.call("GetConnectionUnixProcessID", &(sender)).await.ok()
        }

        fn lookup_username(uid: u32) -> Option<String> {
            let content = std::fs::read_to_string("/etc/passwd").ok()?;
            for line in content.lines() {
                if line.starts_with('#') || line.trim().is_empty() {
                    continue;
                }
                let mut it = line.split(':');
                let name = it.next()?;
                let _pw = it.next()?;
                let uid_field = it.next()?;
                if uid_field.parse::<u32>().ok()? == uid {
                    return Some(name.to_string());
                }
            }
            None
        }

        async fn build_query_context(
            &self,
            transport: &'static str,
            sender: Option<&str>,
        ) -> DnsQueryContext {
            let mut ctx = DnsQueryContext::new()
                .with_inbound(self.state.get_service_tag())
                .with_transport(transport);

            let sender = match sender {
                Some(s) => s,
                None => return ctx,
            };

            let Some(pid) = self.get_sender_pid(sender).await else {
                return ctx;
            };

            // process path/name
            let proc_exe = format!("/proc/{pid}/exe");
            if let Ok(p) = std::fs::read_link(&proc_exe) {
                if let Some(s) = p.to_str() {
                    ctx = ctx.with_process_path(s.to_string());
                    if let Some(base) = std::path::Path::new(s).file_name().and_then(|f| f.to_str())
                    {
                        ctx = ctx.with_process_name(base.to_string());
                    }
                }
            } else if let Ok(comm) = std::fs::read_to_string(format!("/proc/{pid}/comm")) {
                let comm = comm.trim();
                if !comm.is_empty() {
                    ctx = ctx.with_process_name(comm.to_string());
                }
            }

            // user id/name
            if let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) {
                for line in status.lines() {
                    let line = line.trim();
                    if let Some(rest) = line.strip_prefix("Uid:") {
                        let fields: Vec<&str> = rest.split_whitespace().collect();
                        if let Some(uid_s) = fields.first() {
                            if let Ok(uid) = uid_s.parse::<u32>() {
                                ctx = ctx.with_user_id(uid);
                                if let Some(user) = Self::lookup_username(uid) {
                                    ctx = ctx.with_user(user);
                                }
                            }
                        }
                        break;
                    }
                }
            }

            ctx
        }

        fn canonical_name(s: &str) -> String {
            let mut out = s.trim().to_ascii_lowercase();
            if out.is_empty() {
                return ".".to_string();
            }
            if !out.ends_with('.') {
                out.push('.');
            }
            out
        }

        fn ensure_fqdn(s: &str) -> String {
            let s = s.trim();
            if s.is_empty() {
                return ".".to_string();
            }
            if s.ends_with('.') {
                s.to_string()
            } else {
                format!("{s}.")
            }
        }

        fn parse_uncompressed_name(mut data: &[u8]) -> Option<String> {
            let mut labels: Vec<String> = Vec::new();
            loop {
                if data.is_empty() {
                    return None;
                }
                let len = data[0] as usize;
                data = &data[1..];
                if len == 0 {
                    break;
                }
                if len > 63 || data.len() < len {
                    return None;
                }
                let s = std::str::from_utf8(&data[..len]).ok()?;
                labels.push(s.to_string());
                data = &data[len..];
            }
            Some(Self::ensure_fqdn(&labels.join(".")))
        }

        fn rcode(resp: &[u8]) -> Option<u8> {
            if resp.len() < 4 {
                return None;
            }
            let flags = u16::from_be_bytes([resp[2], resp[3]]);
            Some((flags & 0x0F) as u8)
        }

        fn build_query_with_class(name: &str, qtype: u16, qclass: u16) -> anyhow::Result<Vec<u8>> {
            use std::time::{SystemTime, UNIX_EPOCH};
            let name = name.trim_end_matches('.');
            let id: u16 = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u16)
                .unwrap_or(0);
            let mut out = Vec::with_capacity(512);
            out.extend_from_slice(&id.to_be_bytes()); // ID
            out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
            out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
            out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
            out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
            out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
            for label in name.split('.') {
                if label.is_empty() {
                    continue;
                }
                let b = label.as_bytes();
                out.push(b.len() as u8);
                out.extend_from_slice(b);
            }
            out.push(0);
            out.extend_from_slice(&qtype.to_be_bytes());
            out.extend_from_slice(&qclass.to_be_bytes());
            Ok(out)
        }
    }

    #[interface(name = "org.freedesktop.resolve1.Manager")]
    impl Resolve1Manager {
        /// Set DNS servers for a link (simple format).
        async fn set_link_dns(
            &self,
            if_index: i32,
            addresses: Vec<(i32, Vec<u8>)>,
        ) -> ZbusResult<()> {
            let if_name = get_interface_name(if_index);
            let mut link = self.state.get_or_create_link(if_index, &if_name);

            link.addresses = addresses
                .into_iter()
                .map(|(family, address)| LinkDNS { family, address })
                .collect();

            if !link.addresses.is_empty() {
                info!(
                    if_name = %link.if_name,
                    "SetLinkDNS: {}",
                    link.addresses
                        .iter()
                        .filter_map(|a| a.to_ip_addr())
                        .map(|ip| ip.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            } else {
                debug!(if_name = %link.if_name, "SetLinkDNS: (empty)");
            }

            self.state
                .update_link(link)
                .map_err(|e| zbus::Error::Failure(e))?;
            Ok(())
        }

        /// Set DNS servers for a link (extended format with port and SNI).
        async fn set_link_dns_ex(
            &self,
            if_index: i32,
            addresses: Vec<(i32, Vec<u8>, u16, String)>,
        ) -> ZbusResult<()> {
            let if_name = get_interface_name(if_index);
            let mut link = self.state.get_or_create_link(if_index, &if_name);

            link.addresses_ex = addresses
                .into_iter()
                .map(|(family, address, port, server_name)| LinkDNSEx {
                    family,
                    address,
                    port,
                    server_name,
                })
                .collect();

            if !link.addresses_ex.is_empty() {
                info!(
                    if_name = %link.if_name,
                    "SetLinkDNSEx: {}",
                    link.addresses_ex
                        .iter()
                        .filter_map(|a| {
                            a.to_ip_addr().map(|ip| {
                                if a.port == 0 {
                                    ip.to_string()
                                } else {
                                    format!("{}:{}", ip, a.port)
                                }
                            })
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            } else {
                debug!(if_name = %link.if_name, "SetLinkDNSEx: (empty)");
            }

            self.state
                .update_link(link)
                .map_err(|e| zbus::Error::Failure(e))?;
            Ok(())
        }

        /// Set search/routing domains for a link.
        async fn set_link_domains(
            &self,
            if_index: i32,
            domains: Vec<(String, bool)>,
        ) -> ZbusResult<()> {
            let if_name = get_interface_name(if_index);
            let mut link = self.state.get_or_create_link(if_index, &if_name);

            link.domains = domains
                .into_iter()
                .map(|(domain, routing_only)| LinkDomainConfig {
                    domain,
                    routing_only,
                })
                .collect();

            if !link.domains.is_empty() {
                info!(
                    if_name = %link.if_name,
                    "SetLinkDomains: {}",
                    link.domains
                        .iter()
                        .map(|d| if d.routing_only {
                            format!("~{}", d.domain)
                        } else {
                            d.domain.clone()
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            } else {
                debug!(if_name = %link.if_name, "SetLinkDomains: (empty)");
            }

            self.state
                .update_link(link)
                .map_err(|e| zbus::Error::Failure(e))?;
            Ok(())
        }

        /// Set whether this link is a default route for DNS.
        async fn set_link_default_route(
            &self,
            if_index: i32,
            default_route: bool,
        ) -> ZbusResult<()> {
            let if_name = get_interface_name(if_index);
            let mut link = self.state.get_or_create_link(if_index, &if_name);
            link.default_route = default_route;

            // Update default route sequence
            {
                let mut seq = self.state.default_route_sequence.write();
                seq.retain(|&idx| idx != if_index);
                if default_route {
                    seq.push(if_index);
                }
            }

            info!(
                if_name = %link.if_name,
                "SetLinkDefaultRoute: {}",
                if default_route { "yes" } else { "no" }
            );

            self.state
                .update_link(link)
                .map_err(|e| zbus::Error::Failure(e))?;
            Ok(())
        }

        /// Set DNS-over-TLS mode for a link.
        async fn set_link_dns_over_tls(&self, if_index: i32, dot_mode: &str) -> ZbusResult<()> {
            let if_name = get_interface_name(if_index);
            let mut link = self.state.get_or_create_link(if_index, &if_name);

            link.dns_over_tls = match dot_mode {
                "yes" => true,
                "" | "no" | "opportunistic" => false,
                _ => {
                    warn!(if_name = %link.if_name, "Unknown DoT mode: {}", dot_mode);
                    false
                }
            };

            info!(
                if_name = %link.if_name,
                "SetLinkDNSOverTLS: {}",
                if link.dns_over_tls { "yes" } else { "no" }
            );

            self.state
                .update_link(link)
                .map_err(|e| zbus::Error::Failure(e))?;
            Ok(())
        }

        /// Stub implementations for unused methods.
        async fn set_link_llmnr(&self, _if_index: i32, _mode: &str) -> ZbusResult<()> {
            Ok(())
        }

        async fn set_link_multicast_dns(&self, _if_index: i32, _mode: &str) -> ZbusResult<()> {
            Ok(())
        }

        async fn set_link_dnssec(&self, _if_index: i32, _mode: &str) -> ZbusResult<()> {
            Ok(())
        }

        async fn set_link_dnssec_negative_trust_anchors(
            &self,
            _if_index: i32,
            _domains: Vec<String>,
        ) -> ZbusResult<()> {
            Ok(())
        }

        /// Revert link configuration.
        async fn revert_link(&self, if_index: i32) -> ZbusResult<()> {
            let if_name = get_interface_name(if_index);
            info!(if_name = %if_name, "RevertLink");
            self.state.delete_link(if_index);
            Ok(())
        }

        /// Flush DNS caches (wired to DNS router).
        async fn flush_caches(&self) -> ZbusResult<()> {
            info!("FlushCaches");
            self.state.clear_cache();
            Ok(())
        }

        /// Reset server features (no-op).
        async fn reset_server_features(&self) -> ZbusResult<()> {
            Ok(())
        }

        /// Reset statistics (no-op).
        async fn reset_statistics(&self) -> ZbusResult<()> {
            Ok(())
        }

        #[zbus(name = "ResolveHostname")]
        async fn resolve_hostname(
            &self,
            if_index: i32,
            hostname: &str,
            family: i32,
            _flags: u64,
            #[zbus(header)] header: zbus::MessageHeader<'_>,
        ) -> ZbusResult<(Vec<(i32, i32, Vec<u8>)>, String, u64)> {
            let sender = header.sender().map(|s| s.to_string());
            let ctx = self.build_query_context("dbus", sender.as_deref()).await;

            let router = self
                .state
                .dns_router
                .read()
                .as_ref()
                .cloned()
                .ok_or_else(|| zbus::Error::Failure("resolved: dns_router not wired".into()))?;

            let ips = router
                .lookup(&ctx, hostname)
                .await
                .map_err(|e| zbus::Error::Failure(format!("ResolveHostname failed: {e}")))?;

            let mut addrs = Vec::new();
            for ip in ips {
                match (family, ip) {
                    (libc::AF_INET, IpAddr::V4(v4)) => {
                        addrs.push((if_index, libc::AF_INET, v4.octets().to_vec()));
                    }
                    (libc::AF_INET6, IpAddr::V6(v6)) => {
                        addrs.push((if_index, libc::AF_INET6, v6.octets().to_vec()));
                    }
                    (libc::AF_UNSPEC, IpAddr::V4(v4)) => {
                        addrs.push((if_index, libc::AF_INET, v4.octets().to_vec()));
                    }
                    (libc::AF_UNSPEC, IpAddr::V6(v6)) => {
                        addrs.push((if_index, libc::AF_INET6, v6.octets().to_vec()));
                    }
                    _ => {}
                }
            }

            Ok((addrs, Self::canonical_name(hostname), 0))
        }

        #[zbus(name = "ResolveAddress")]
        async fn resolve_address(
            &self,
            if_index: i32,
            family: i32,
            address: Vec<u8>,
            _flags: u64,
            #[zbus(header)] header: zbus::MessageHeader<'_>,
        ) -> ZbusResult<(Vec<(i32, String)>, u64)> {
            let sender = header.sender().map(|s| s.to_string());
            let ctx = self.build_query_context("dbus", sender.as_deref()).await;

            let router = self
                .state
                .dns_router
                .read()
                .as_ref()
                .cloned()
                .ok_or_else(|| zbus::Error::Failure("resolved: dns_router not wired".into()))?;

            // Go parity: build reverse domain by nibbles (even for IPv4).
            let mut nibbles: Vec<String> = Vec::with_capacity(address.len() * 2);
            for b in address.iter().rev() {
                nibbles.push(format!("{:x}", b & 0x0F));
                nibbles.push(format!("{:x}", b >> 4));
            }
            let suffix = if family == libc::AF_INET {
                "in-addr.arpa."
            } else {
                "ip6.arpa."
            };
            let ptr_domain = format!("{}.{}", nibbles.join("."), suffix);

            let req = udp::build_query(ptr_domain.trim_end_matches('.'), 12)
                .map_err(|e| zbus::Error::Failure(format!("build PTR query failed: {e}")))?;

            let resp = match router.exchange(&ctx, &req).await {
                Ok(r) => r,
                Err(err) => {
                    // fallback reverse mapping cache
                    let ip = if family == libc::AF_INET && address.len() == 4 {
                        let b: [u8; 4] = address[..4].try_into().unwrap();
                        IpAddr::V4(b.into())
                    } else if family == libc::AF_INET6 && address.len() == 16 {
                        let b: [u8; 16] = address[..16].try_into().unwrap();
                        IpAddr::V6(b.into())
                    } else {
                        return Err(zbus::Error::Failure(format!("invalid address bytes: {err}").into()));
                    };
                    if let Some(name) = router.lookup_reverse_mapping(&ip) {
                        return Ok((vec![(if_index, Self::ensure_fqdn(&name))], 0));
                    }
                    return Err(zbus::Error::Failure(format!("ResolveAddress exchange failed: {err}").into()));
                }
            };

            if Self::rcode(&resp).unwrap_or(2) != 0 {
                return Err(zbus::Error::Failure("ResolveAddress: upstream returned error rcode".into()));
            }

            let mut names = Vec::new();
            if let Some(records) = parse_answer_records(&resp) {
                for rr in records {
                    if rr.rtype == 12 {
                        if let Some(name) = Self::parse_uncompressed_name(&rr.data) {
                            names.push((if_index, name));
                        }
                    }
                }
            }
            Ok((names, 0))
        }

        #[zbus(name = "ResolveRecord")]
        async fn resolve_record(
            &self,
            if_index: i32,
            hostname: &str,
            qclass: u16,
            qtype: u16,
            _flags: u64,
            #[zbus(header)] header: zbus::MessageHeader<'_>,
        ) -> ZbusResult<(Vec<(i32, u16, u16, Vec<u8>)>, u64)> {
            let sender = header.sender().map(|s| s.to_string());
            let ctx = self.build_query_context("dbus", sender.as_deref()).await;

            let router = self
                .state
                .dns_router
                .read()
                .as_ref()
                .cloned()
                .ok_or_else(|| zbus::Error::Failure("resolved: dns_router not wired".into()))?;

            let req = Self::build_query_with_class(hostname, qtype, qclass)
                .map_err(|e| zbus::Error::Failure(format!("build query failed: {e}")))?;
            let resp = router
                .exchange(&ctx, &req)
                .await
                .map_err(|e| zbus::Error::Failure(format!("ResolveRecord exchange failed: {e}")))?;

            if Self::rcode(&resp).unwrap_or(2) != 0 {
                return Err(zbus::Error::Failure("ResolveRecord: upstream returned error rcode".into()));
            }

            let mut records = Vec::new();
            if let Some(ans) = parse_answer_records(&resp) {
                for rr in ans {
                    let data = pack_rr_uncompressed(&rr.name, rr.rtype, rr.class, rr.ttl, &rr.data)
                        .ok_or_else(|| {
                            zbus::Error::Failure("ResolveRecord: rtype not supported for packing".into())
                        })?;
                    records.push((if_index, rr.rtype as u16, rr.class as u16, data));
                }
            }
            Ok((records, 0))
        }

        #[zbus(name = "ResolveService")]
        async fn resolve_service(
            &self,
            if_index: i32,
            hostname: &str,
            s_type: &str,
            domain: &str,
            family: i32,
            _flags: u64,
            #[zbus(header)] header: zbus::MessageHeader<'_>,
        ) -> ZbusResult<(
            Vec<(u16, u16, u16, String, Vec<(i32, i32, Vec<u8>)>, String)>,
            Vec<Vec<u8>>,
            String,
            String,
            String,
            u64,
        )> {
            let sender = header.sender().map(|s| s.to_string());
            let ctx = self.build_query_context("dbus", sender.as_deref()).await;

            let router = self
                .state
                .dns_router
                .read()
                .as_ref()
                .cloned()
                .ok_or_else(|| zbus::Error::Failure("resolved: dns_router not wired".into()))?;

            let mut service_name = hostname.to_string();
            if !service_name.is_empty() && !service_name.ends_with('.') {
                service_name.push('.');
            }
            service_name.push_str(s_type);
            if !service_name.ends_with('.') {
                service_name.push('.');
            }
            service_name.push_str(domain);
            if !service_name.ends_with('.') {
                service_name.push('.');
            }

            let srv_req = udp::build_query(service_name.trim_end_matches('.'), 33)
                .map_err(|e| zbus::Error::Failure(format!("build SRV query failed: {e}")))?;
            let srv_resp = router
                .exchange(&ctx, &srv_req)
                .await
                .map_err(|e| zbus::Error::Failure(format!("SRV exchange failed: {e}")))?;
            if Self::rcode(&srv_resp).unwrap_or(2) != 0 {
                return Err(zbus::Error::Failure("ResolveService: SRV rcode != 0".into()));
            }

            let txt_req = udp::build_query(service_name.trim_end_matches('.'), 16)
                .map_err(|e| zbus::Error::Failure(format!("build TXT query failed: {e}")))?;
            let txt_resp = router
                .exchange(&ctx, &txt_req)
                .await
                .map_err(|e| zbus::Error::Failure(format!("TXT exchange failed: {e}")))?;

            let srv_records = parse_answer_records(&srv_resp).unwrap_or_default();
            let txt_records = parse_answer_records(&txt_resp).unwrap_or_default();

            let mut srv_out = Vec::new();
            for rr in &srv_records {
                if rr.rtype != 33 || rr.data.len() < 7 {
                    continue;
                }
                let pri = u16::from_be_bytes([rr.data[0], rr.data[1]]);
                let w = u16::from_be_bytes([rr.data[2], rr.data[3]]);
                let port = u16::from_be_bytes([rr.data[4], rr.data[5]]);
                let target = Self::parse_uncompressed_name(&rr.data[6..]).unwrap_or_else(|| ".".to_string());

                let mut addrs: Vec<(i32, i32, Vec<u8>)> = Vec::new();
                if target != "." {
                    let lookup_name = target.trim_end_matches('.');
                    if !lookup_name.is_empty() {
                        if let Ok(ips) = router.lookup(&ctx, lookup_name).await {
                        for ip in ips {
                            match (family, ip) {
                                (libc::AF_INET, IpAddr::V4(v4)) => addrs.push((
                                    if_index,
                                    libc::AF_INET,
                                    v4.octets().to_vec(),
                                )),
                                (libc::AF_INET6, IpAddr::V6(v6)) => addrs.push((
                                    if_index,
                                    libc::AF_INET6,
                                    v6.octets().to_vec(),
                                )),
                                (libc::AF_UNSPEC, IpAddr::V4(v4)) => addrs.push((
                                    if_index,
                                    libc::AF_INET,
                                    v4.octets().to_vec(),
                                )),
                                (libc::AF_UNSPEC, IpAddr::V6(v6)) => addrs.push((
                                    if_index,
                                    libc::AF_INET6,
                                    v6.octets().to_vec(),
                                )),
                                _ => {}
                            }
                        }
                        }
                    }
                }

                // CNAME: find a CNAME where NAME == target
                let want = target.trim_end_matches('.').to_ascii_lowercase();
                let mut cname = String::new();
                for a in &srv_records {
                    if a.rtype == 5 && a.name.trim_end_matches('.').eq_ignore_ascii_case(&want) {
                        if let Some(t) = Self::parse_uncompressed_name(&a.data) {
                            cname = t;
                            break;
                        }
                    }
                }

                srv_out.push((pri, w, port, target, addrs, cname));
            }

            let mut txt_out: Vec<Vec<u8>> = Vec::new();
            for rr in &txt_records {
                if rr.rtype != 16 {
                    continue;
                }
                if let Some(data) = pack_rr_uncompressed(&rr.name, rr.rtype, rr.class, rr.ttl, &rr.data) {
                    txt_out.push(data);
                }
            }

            Ok((
                srv_out,
                txt_out,
                Self::canonical_name(hostname),
                Self::canonical_name(s_type),
                Self::canonical_name(domain),
                0,
            ))
        }
    }

    /// Get interface name from index (fallback to index if not found).
    fn get_interface_name(if_index: i32) -> String {
        #[cfg(target_os = "linux")]
        {
            use std::ffi::CStr;
            let mut buf = [0u8; libc::IF_NAMESIZE];
            let result =
                unsafe { libc::if_indextoname(if_index as u32, buf.as_mut_ptr() as *mut i8) };
            if !result.is_null() {
                if let Ok(name) = unsafe { CStr::from_ptr(result) }.to_str() {
                    return name.to_string();
                }
            }
        }
        format!("if{}", if_index)
    }

    /// Start the D-Bus server and export the resolve1 Manager.
    pub async fn start_dbus_server(
        state: Arc<Resolve1ManagerState>,
    ) -> Result<Connection, Box<dyn std::error::Error + Send + Sync>> {
        let connection = Connection::system().await?;

        // Export the interface
        let manager = Resolve1Manager::new(state, connection.clone());
        connection
            .object_server()
            .at("/org/freedesktop/resolve1", manager)
            .await?;

        // Request the well-known name
        use zbus::fdo::{RequestNameFlags, RequestNameReply};
        let reply = connection
            .request_name_with_flags("org.freedesktop.resolve1", RequestNameFlags::DoNotQueue)
            .await?;
        match reply {
            RequestNameReply::PrimaryOwner => {}
            RequestNameReply::Exists => {
                return Err(
                    "D-Bus object already exists; stop/disable systemd-resolved and retry"
                        .into(),
                );
            }
            other => {
                return Err(format!("unexpected request name reply: {other:?}").into());
            }
        }

        info!("D-Bus server started: org.freedesktop.resolve1");
        Ok(connection)
    }
}

// Non-Linux stub
#[cfg(not(all(target_os = "linux", feature = "service_resolved")))]
pub mod dbus_server {
    use super::*;

    /// Stub implementation for non-Linux platforms.
    pub async fn start_dbus_server(
        _state: Arc<Resolve1ManagerState>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        warn!("D-Bus server not supported on this platform");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Resolve1ManagerState;
    use sb_core::dns::transport::resolved::{LinkDNS, TransportLink};
    use std::net::IpAddr;

    #[test]
    fn test_transport_link_default() {
        let link = TransportLink::default();
        assert_eq!(link.if_index, 0);
        assert!(!link.default_route);
        assert!(!link.dns_over_tls);
        assert!(link.addresses.is_empty());
        assert!(link.domains.is_empty());
    }

    #[test]
    fn test_link_dns_to_ip() {
        let ipv4 = LinkDNS {
            family: 2,
            address: vec![192, 168, 1, 1],
        };
        assert_eq!(ipv4.to_ip_addr(), Some(IpAddr::V4([192, 168, 1, 1].into())));

        let ipv6 = LinkDNS {
            family: 10,
            address: vec![
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
            ],
        };
        assert!(ipv6.to_ip_addr().is_some());
    }

    #[test]
    fn test_state_get_or_create_link() {
        let state = Resolve1ManagerState::new();
        let link = state.get_or_create_link(1, "eth0");
        assert_eq!(link.if_index, 1);
        assert_eq!(link.if_name, "eth0");

        // Should return same link
        let link2 = state.get_or_create_link(1, "eth0");
        assert_eq!(link2.if_index, 1);
    }

    #[test]
    fn test_state_default_route_sequence() {
        let state = Resolve1ManagerState::new();

        // Create links with default routes
        let mut link1 = state.get_or_create_link(1, "eth0");
        link1.default_route = true;
        state.update_link(link1).unwrap();
        state.default_route_sequence.write().push(1);

        let mut link2 = state.get_or_create_link(2, "wlan0");
        link2.default_route = true;
        state.update_link(link2).unwrap();
        state.default_route_sequence.write().push(2);

        // Most recent is last
        let def = default_route_link(&state);
        assert!(def.is_some());
        assert_eq!(def.unwrap().if_index, 2);

        // Delete link 2
        state.delete_link(2);
        let def = default_route_link(&state);
        assert!(def.is_some());
        assert_eq!(def.unwrap().if_index, 1);
    }

    fn default_route_link(state: &Resolve1ManagerState) -> Option<TransportLink> {
        let seq = state.default_route_sequence.read();
        let links = state.links.read();
        for &if_index in seq.iter().rev() {
            if let Some(link) = links.get(&if_index) {
                return Some(link.clone());
            }
        }
        None
    }
}
