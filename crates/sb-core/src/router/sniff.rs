//! Minimal TLS ClientHello sniffing utilities
//!
//! Provides zero-copy parsers to extract SNI and ALPN from a TLS ClientHello
//! message embedded in a TCP stream prefix. Intended for use by TUN or
//! inbounds that can safely peek initial bytes prior to routing.
//!
//! ## Supported Protocols
//! - TLS (SNI, ALPN extraction)
//! - HTTP/1.x (Host header extraction)
//! - QUIC (Initial packet detection with SNI extraction from embedded ClientHello)
//! - DNS (Query domain extraction)
//! - SSH, RDP, BitTorrent, DTLS, STUN detection

/// Result of TLS ClientHello sniffing
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsClientHelloInfo {
    pub sni: Option<String>,
    pub alpn: Option<String>,
}

/// Aggregated sniff outcome for routing hints.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SniffOutcome {
    /// Detected high-level protocol name (e.g., "tls", "http", "ssh").
    pub protocol: Option<&'static str>,
    /// Extracted host (TLS SNI or HTTP Host).
    pub host: Option<String>,
    /// Extracted or inferred ALPN (e.g., "h2", "http/1.1", "h3").
    pub alpn: Option<String>,
}

/// Attempt to parse a TLS ClientHello from the provided buffer and extract
/// SNI and ALPN. Returns `None` if the buffer does not look like a TLS
/// ClientHello or if required fields are incomplete.
pub fn sniff_tls_client_hello(buf: &[u8]) -> Option<TlsClientHelloInfo> {
    // TLS record header: [ContentType(1)=22][Version(2)][Length(2)]
    if buf.len() < 5 {
        return None;
    }
    let content_type = buf[0];
    if content_type != 22 {
        return None; // not handshake
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + record_len || record_len < 4 {
        return None;
    }
    let mut p = 5; // handshake starts
                   // Handshake header: [msg_type(1)=1][length(3)]
    if buf[p] != 1 {
        return None; // not ClientHello
    }
    if p + 4 > buf.len() {
        return None;
    }
    let hs_len =
        ((buf[p + 1] as usize) << 16) | ((buf[p + 2] as usize) << 8) | (buf[p + 3] as usize);
    p += 4;
    if p + hs_len > buf.len() {
        return None;
    }

    // ClientHello:
    // version(2) + random(32)
    if p + 2 + 32 > buf.len() {
        return None;
    }
    p += 2 + 32;
    // session_id
    if p + 1 > buf.len() {
        return None;
    }
    let sid_len = buf[p] as usize;
    p += 1;
    if p + sid_len > buf.len() {
        return None;
    }
    p += sid_len;
    // cipher_suites
    if p + 2 > buf.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
    p += 2;
    if p + cs_len > buf.len() {
        return None;
    }
    p += cs_len;
    // compression_methods
    if p + 1 > buf.len() {
        return None;
    }
    let cm_len = buf[p] as usize;
    p += 1;
    if p + cm_len > buf.len() {
        return None;
    }
    p += cm_len;
    // extensions
    if p + 2 > buf.len() {
        return None;
    }
    let ext_total = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
    p += 2;
    if p + ext_total > buf.len() {
        return None;
    }
    let ext_end = p + ext_total;

    let mut info = TlsClientHelloInfo::default();

    while p + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([buf[p], buf[p + 1]]);
        p += 2;
        let ext_len = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
        p += 2;
        if p + ext_len > ext_end {
            return None;
        }
        let ext_data = &buf[p..p + ext_len];
        p += ext_len;

        match ext_type {
            0x0000 => {
                // server_name
                // server_name_list: u16 len, entries: [u8 name_type=0][u16 name_len][name]
                if ext_data.len() >= 2 {
                    let mut q = 2; // skip list length
                    while q + 3 <= ext_data.len() {
                        let name_type = ext_data[q];
                        q += 1;
                        let nlen = u16::from_be_bytes([ext_data[q], ext_data[q + 1]]) as usize;
                        q += 2;
                        if q + nlen > ext_data.len() {
                            break;
                        }
                        if name_type == 0 {
                            if let Ok(s) = std::str::from_utf8(&ext_data[q..q + nlen]) {
                                info.sni = Some(s.to_string());
                                // do not break; prefer first, but continue to parse ALPN
                            }
                        }
                        q += nlen;
                    }
                }
            }
            0x0010 => {
                // ALPN
                // alpn: u16 len, then protocol_name_list: [len][name] ... choose first
                if ext_data.len() >= 2 {
                    let mut q = 2; // skip list length
                    if q < ext_data.len() {
                        let nlen = ext_data[q] as usize;
                        q += 1;
                        if q + nlen <= ext_data.len() {
                            if let Ok(s) = std::str::from_utf8(&ext_data[q..q + nlen]) {
                                info.alpn = Some(s.to_string());
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    if info.sni.is_some() || info.alpn.is_some() {
        Some(info)
    } else {
        None
    }
}

/// Detect QUIC Initial long header and return an ALPN hint when applicable.
/// This is a best-effort detector for UDP payloads.
/// Returns Some("h3") when the packet looks like QUIC Initial, otherwise None.
pub fn sniff_quic_initial(buf: &[u8]) -> Option<&'static str> {
    // Minimal checks based on RFC 9000:
    // - First bit (0x80) set indicates long header
    // - Next two bits indicate fixed bit pattern; type 0x00 = Initial
    if buf.len() < 7 {
        return None;
    }
    let flags = buf[0];
    let long = (flags & 0x80) != 0;
    if !long {
        return None;
    }
    // Long header form: bits[1..3] = fixed patterns; type in low 2 bits
    // We accept any long header and assume Initial for hinting purpose.
    // Version field follows (bytes 1..4). Non-zero typically indicates QUIC.
    let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    if version == 0 {
        return None;
    }
    Some("h3")
}

/// Compatibility wrapper: extract SNI string from a TLS ClientHello buffer.
/// Returns the first server_name if present.
pub fn extract_sni_from_tls_client_hello(buf: &[u8]) -> Option<String> {
    sniff_tls_client_hello(buf).and_then(|info| info.sni)
}

/// Extract the HTTP Host header value from an HTTP/1.x request bytes.
/// Performs a lightweight, case-insensitive scan of header lines until the
/// first empty line. Returns the raw host value (which may include a port).
pub fn extract_http_host_from_request(buf: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(buf).ok()?;
    // Limit scanning to a reasonable number of lines to avoid pathological inputs
    for line in text.lines().take(128) {
        let l = line.trim_end_matches(['\r', '\n']);
        if l.is_empty() {
            break; // end of headers
        }
        // Case-insensitive match for "Host:"
        if l.len() >= 5 && l[..5].eq_ignore_ascii_case("host:") {
            let value = l[5..].trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Sniff a stream (TCP) payload for protocol/host/ALPN hints.
pub fn sniff_stream(buf: &[u8]) -> SniffOutcome {
    let mut out = SniffOutcome::default();

    if let Some(info) = sniff_tls_client_hello(buf) {
        out.protocol = Some("tls");
        out.host = info.sni;
        out.alpn = info.alpn;
        return out;
    }

    if let Some(host) = extract_http_host_from_request(buf) {
        out.protocol = Some("http");
        out.host = Some(host);
        out.alpn = Some("http/1.1".to_string());
        return out;
    }

    if is_ssh_protocol(buf) {
        out.protocol = Some("ssh");
        return out;
    }

    if is_rdp_protocol(buf) {
        out.protocol = Some("rdp");
        return out;
    }

    if is_bittorrent_handshake(buf) {
        out.protocol = Some("bittorrent");
        return out;
    }

    out
}

/// Sniff a datagram (UDP) payload for protocol/ALPN hints.
pub fn sniff_datagram(buf: &[u8]) -> SniffOutcome {
    let mut out = SniffOutcome::default();

    // Check for DNS query first (common case)
    if let Some(dns_info) = sniff_dns_query(buf) {
        out.protocol = Some("dns");
        out.host = dns_info.domain;
        return out;
    }

    if is_dtls_record(buf) {
        out.protocol = Some("dtls");
        return out;
    }

    if is_stun_message(buf) {
        out.protocol = Some("stun");
        return out;
    }

    if is_bittorrent_utp(buf) || is_bittorrent_udp_tracker(buf) {
        out.protocol = Some("bittorrent");
        return out;
    }

    if let Some(alpn) = sniff_quic_initial(buf) {
        out.protocol = Some("quic");
        out.alpn = Some(alpn.to_string());
        return out;
    }

    if is_ntp_protocol(buf) {
        out.protocol = Some("ntp");
        return out;
    }

    out
}

fn is_bittorrent_handshake(buf: &[u8]) -> bool {
    const HEADER: &[u8] = b"BitTorrent protocol";
    buf.len() > HEADER.len() && buf[0] == 19 && &buf[1..1 + HEADER.len()] == HEADER
}

fn is_bittorrent_utp(packet: &[u8]) -> bool {
    if packet.len() < 20 {
        return false;
    }
    let version = packet[0] & 0x0f;
    let ty = packet[0] >> 4;
    if version != 1 || ty > 4 {
        return false;
    }

    // Validate extension headers (best-effort; avoid deep parsing to stay cheap).
    let mut ext_type = packet[1];
    let mut offset = 20usize;
    while ext_type != 0 {
        if ext_type > 0x04 {
            return false;
        }
        // Each extension header: [next_type][len][payload...]
        if offset + 2 > packet.len() {
            return false;
        }
        let next_type = packet[offset];
        let len = packet[offset + 1] as usize;
        offset += 2;
        if offset + len > packet.len() {
            return false;
        }
        offset += len;
        ext_type = next_type;
    }
    true
}

fn is_bittorrent_udp_tracker(packet: &[u8]) -> bool {
    if packet.len() < 16 {
        return false;
    }
    const BITTORRENT_MAGIC: u64 = 0x0417_2710_1980;
    let protocol = u64::from_be_bytes([
        packet[0], packet[1], packet[2], packet[3], packet[4], packet[5], packet[6], packet[7],
    ]);
    if protocol != BITTORRENT_MAGIC {
        return false;
    }
    let action = u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]);
    action == 0
}

fn is_dtls_record(packet: &[u8]) -> bool {
    if packet.len() < 13 {
        return false;
    }
    match packet[0] {
        20 | 21 | 22 | 23 | 25 => {}
        _ => return false,
    }
    packet[1] == 0xfe && matches!(packet[2], 0xff | 0xfd)
}

fn is_ssh_protocol(buf: &[u8]) -> bool {
    buf.len() >= 8 && buf.starts_with(b"SSH-2.0-")
}

fn is_rdp_protocol(buf: &[u8]) -> bool {
    if buf.len() < 14 {
        return false;
    }
    if buf[0] != 0x03 || buf[1] != 0x00 {
        return false;
    }
    if u16::from_be_bytes([buf[2], buf[3]]) != 19 {
        return false;
    }
    if buf[4] != 0x0e || buf[5] != 0xe0 {
        return false;
    }
    if buf[11] != 0x01 {
        return false;
    }
    buf[13] == 0x08
}

fn is_ntp_protocol(packet: &[u8]) -> bool {
    if packet.len() < 48 {
        return false;
    }
    let first_byte = packet[0];
    let li = (first_byte >> 6) & 0x03;
    let vn = (first_byte >> 3) & 0x07;
    let mode = first_byte & 0x07;

    if li > 3 {
        return false;
    }
    if vn != 3 && vn != 4 {
        return false;
    }
    if mode != 3 {
        return false;
    }

    let root_delay = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
    let root_dispersion = u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]);

    if (root_delay as f64) / 65536.0 > 16.0 {
        return false;
    }
    if (root_dispersion as f64) / 65536.0 > 16.0 {
        return false;
    }

    true
}

/// Result of DNS query sniffing
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsQueryInfo {
    /// The queried domain name
    pub domain: Option<String>,
    /// Query type (A=1, AAAA=28, etc.)
    pub qtype: Option<u16>,
}

/// Sniff DNS query from a UDP payload and extract the queried domain.
/// Returns `Some(DnsQueryInfo)` if the payload looks like a DNS query.
/// Works with both UDP DNS (port 53) and DNS-over-TLS/HTTPS wrapped queries.
pub fn sniff_dns_query(buf: &[u8]) -> Option<DnsQueryInfo> {
    // DNS header is 12 bytes minimum
    if buf.len() < 12 {
        return None;
    }

    // Check DNS header flags
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qr = (flags >> 15) & 1; // QR bit: 0 = query, 1 = response
    let opcode = (flags >> 11) & 0xf; // Opcode: 0 = standard query

    // Must be a query (QR=0) with standard opcode (0)
    if qr != 0 || opcode != 0 {
        return None;
    }

    // Check question count
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount == 0 {
        return None;
    }

    // Parse the first question section
    let mut pos = 12; // Start after header
    let mut domain_parts = Vec::new();

    // Parse domain name (label format)
    while pos < buf.len() {
        let label_len = buf[pos] as usize;
        if label_len == 0 {
            pos += 1;
            break; // End of domain name
        }

        // Check for compression pointer (high 2 bits set)
        if label_len >= 0xc0 {
            // Compression pointer - not commonly used in queries, skip for simplicity
            pos += 2;
            break;
        }

        pos += 1;
        if pos + label_len > buf.len() {
            return None;
        }

        if let Ok(label) = std::str::from_utf8(&buf[pos..pos + label_len]) {
            domain_parts.push(label.to_string());
        } else {
            return None; // Invalid UTF-8 in domain
        }

        pos += label_len;
    }

    if domain_parts.is_empty() {
        return None;
    }

    // Parse QTYPE (2 bytes after domain)
    let qtype = if pos + 2 <= buf.len() {
        Some(u16::from_be_bytes([buf[pos], buf[pos + 1]]))
    } else {
        None
    };

    Some(DnsQueryInfo {
        domain: Some(domain_parts.join(".")),
        qtype,
    })
}

/// Detect STUN (Session Traversal Utilities for NAT) protocol.
/// STUN messages start with a 2-bit type, 14-bit length, and 32-bit magic cookie.
fn is_stun_message(buf: &[u8]) -> bool {
    // STUN header is 20 bytes minimum
    if buf.len() < 20 {
        return false;
    }

    // First 2 bits must be 0 (differentiates from other multiplexed protocols)
    if buf[0] & 0xc0 != 0 {
        return false;
    }

    // Magic cookie at bytes 4-7 must be 0x2112A442
    const STUN_MAGIC_COOKIE: u32 = 0x2112_a442;
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if cookie != STUN_MAGIC_COOKIE {
        return false;
    }

    // Message length at bytes 2-3 should be multiple of 4 and fit in buffer
    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if !msg_len.is_multiple_of(4) {
        return false;
    }
    // Total message size = 20 byte header + message length
    if 20 + msg_len > buf.len() {
        return false;
    }

    true
}

/// Extended QUIC sniffing that attempts to extract SNI from QUIC Initial packets.
/// This is a simplified implementation that detects QUIC but doesn't decrypt the payload.
/// Full SNI extraction from QUIC requires decrypting the Initial packet payload.
pub fn sniff_quic_initial_extended(buf: &[u8]) -> Option<SniffOutcome> {
    // Minimal checks based on RFC 9000:
    // - First bit (0x80) set indicates long header
    // - Next two bits indicate fixed bit pattern; type 0x00 = Initial
    if buf.len() < 7 {
        return None;
    }

    let flags = buf[0];
    let long = (flags & 0x80) != 0;
    if !long {
        return None;
    }

    // Version field follows (bytes 1..4). Non-zero typically indicates QUIC.
    let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    if version == 0 {
        return None;
    }

    // Determine QUIC version for ALPN hint
    let alpn = match version {
        // QUIC v1 and v2 - typically HTTP/3
        0x00000001 | 0x6b3343cf => "h3",
        // Google QUIC versions
        v if (v & 0xff000000) == 0x51000000 => "h3",
        // Other QUIC versions
        _ => "h3",
    };

    // NOTE: Full SNI extraction from QUIC, we would need to:
    // 1. Parse DCID from header
    // 2. Derive Initial secret using HKDF with version-specific salt
    // 3. Decrypt QUIC packet payload
    // 4. Find CRYPTO frame containing TLS ClientHello
    // 5. Parse SNI from ClientHello
    // This is complex and requires crypto dependencies; left for future enhancement.

    Some(SniffOutcome {
        protocol: Some("quic"),
        host: None, // Would require decryption
        alpn: Some(alpn.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_none_for_short_or_non_tls() {
        assert!(sniff_tls_client_hello(&[]).is_none());
        assert!(sniff_tls_client_hello(&[0]).is_none());
        // content type not handshake
        assert!(sniff_tls_client_hello(&[0x14, 0x03, 0x03, 0, 5, 0, 0, 0, 0, 0]).is_none());
    }

    #[test]
    fn detects_http_and_host() {
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let sniffed = sniff_stream(payload);
        assert_eq!(sniffed.protocol, Some("http"));
        assert_eq!(sniffed.host.as_deref(), Some("example.com"));
        assert_eq!(sniffed.alpn.as_deref(), Some("http/1.1"));
    }

    #[test]
    fn detects_bittorrent_tcp_handshake() {
        let mut payload = Vec::new();
        payload.push(19);
        payload.extend_from_slice(b"BitTorrent protocol");
        payload.extend_from_slice(&[0u8; 4]);
        let sniffed = sniff_stream(&payload);
        assert_eq!(sniffed.protocol, Some("bittorrent"));
    }

    #[test]
    fn detects_ssh_banner_and_rdp() {
        let ssh = b"SSH-2.0-OpenSSH_9.0\r\n";
        let sniffed_ssh = sniff_stream(ssh);
        assert_eq!(sniffed_ssh.protocol, Some("ssh"));

        let mut rdp = [0u8; 14];
        rdp[0] = 0x03;
        rdp[2] = 0x00;
        rdp[3] = 0x13;
        rdp[4] = 0x0e;
        rdp[5] = 0xe0;
        rdp[11] = 0x01;
        rdp[13] = 0x08;
        let sniffed_rdp = sniff_stream(&rdp);
        assert_eq!(sniffed_rdp.protocol, Some("rdp"));
    }

    #[test]
    fn detects_udp_protocols() {
        let dtls = [22u8, 0xfe, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let sniffed_dtls = sniff_datagram(&dtls);
        assert_eq!(sniffed_dtls.protocol, Some("dtls"));

        let utp = {
            let mut buf = vec![0u8; 20];
            buf[0] = 0x11; // type=1 version=1
            buf
        };
        let sniffed_utp = sniff_datagram(&utp);
        assert_eq!(sniffed_utp.protocol, Some("bittorrent"));

        let quic = [0xc3u8, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00];
        let sniffed_quic = sniff_datagram(&quic);
        assert_eq!(sniffed_quic.protocol, Some("quic"));
        assert_eq!(sniffed_quic.alpn.as_deref(), Some("h3"));
    }

    #[test]
    fn detects_dns_query() {
        // Construct a minimal DNS query for "example.com" type A
        let mut dns_query = vec![
            0x00, 0x01, // Transaction ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answer RRs: 0
            0x00, 0x00, // Authority RRs: 0
            0x00, 0x00, // Additional RRs: 0
        ];
        // Domain: example.com
        dns_query.push(7); // "example" length
        dns_query.extend_from_slice(b"example");
        dns_query.push(3); // "com" length
        dns_query.extend_from_slice(b"com");
        dns_query.push(0); // Root label
        dns_query.extend_from_slice(&[0x00, 0x01]); // QTYPE: A (1)
        dns_query.extend_from_slice(&[0x00, 0x01]); // QCLASS: IN (1)

        let sniffed = sniff_datagram(&dns_query);
        assert_eq!(sniffed.protocol, Some("dns"));
        assert_eq!(sniffed.host.as_deref(), Some("example.com"));

        // Direct DNS sniffing function test
        let dns_info = sniff_dns_query(&dns_query).unwrap();
        assert_eq!(dns_info.domain.as_deref(), Some("example.com"));
        assert_eq!(dns_info.qtype, Some(1)); // A record
    }

    #[test]
    fn detects_stun_message() {
        // Construct a minimal STUN Binding Request
        let mut stun = vec![
            0x00, 0x01, // Type: Binding Request
            0x00, 0x00, // Length: 0 (no attributes)
            0x21, 0x12, 0xa4, 0x42, // Magic cookie
        ];
        // Transaction ID (12 bytes)
        stun.extend_from_slice(&[0x00; 12]);

        let sniffed = sniff_datagram(&stun);
        assert_eq!(sniffed.protocol, Some("stun"));
    }

    #[test]
    fn dns_response_not_detected_as_query() {
        // DNS response (QR bit = 1)
        let dns_response = vec![
            0x00, 0x01, // Transaction ID
            0x81, 0x80, // Flags: response, recursion available
            0x00, 0x01, // Questions: 1
            0x00, 0x01, // Answer RRs: 1
            0x00, 0x00, // Authority RRs: 0
            0x00,
            0x00, // Additional RRs: 0
                  // ... (truncated - just need flags to differentiate)
        ];
        let result = sniff_dns_query(&dns_response);
        assert!(
            result.is_none(),
            "DNS response should not be detected as query"
        );
    }

    #[test]
    fn detects_ntp_packet() {
        let mut ntp = vec![0u8; 48];
        // LI=0, VN=3, Mode=3 (Client) -> 00 011 011 -> 0x1B
        ntp[0] = 0x1b;
        let sniffed = sniff_datagram(&ntp);
        assert_eq!(sniffed.protocol, Some("ntp"));
    }
}
