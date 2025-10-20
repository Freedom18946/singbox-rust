//! Stage 1: protocol sniffing stubs
//!
//! Provides types and no-op functions for protocol/domain sniffing so that
//! inbounds and routing can wire the plumbing without behavior changes.

use std::fmt;

/// Known application protocols that can be inferred by lightweight sniffing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SniffProtocol {
    Tls,
    Http,
    Quic,
    Dns,
    Stun,
    Ssh,
    Rdp,
    Bittorrent,
    Utp,
    UdpTracker,
    Dtls,
}

impl fmt::Display for SniffProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            SniffProtocol::Tls => "tls",
            SniffProtocol::Http => "http",
            SniffProtocol::Quic => "quic",
            SniffProtocol::Dns => "dns",
            SniffProtocol::Stun => "stun",
            SniffProtocol::Ssh => "ssh",
            SniffProtocol::Rdp => "rdp",
            SniffProtocol::Bittorrent => "bittorrent",
            SniffProtocol::Utp => "utp",
            SniffProtocol::UdpTracker => "udp-tracker",
            SniffProtocol::Dtls => "dtls",
        };
        f.write_str(s)
    }
}

/// Result of a sniff attempt from stream peek or UDP packet inspection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SniffResult {
    /// Server Name Indication from TLS ClientHello, if present.
    pub sni: Option<String>,
    /// HTTP Host header or authority, if present.
    pub http_host: Option<String>,
    /// Application-Layer Protocol Negotiation hint (e.g., h2, http/1.1).
    pub alpn: Option<String>,
    /// Protocol classification (best-effort).
    pub protocol: Option<SniffProtocol>,
}

/// Configuration for sniff operations.
#[derive(Debug, Clone)]
pub struct SniffConfig {
    /// Whether sniffing is enabled for the connection.
    pub enabled: bool,
    /// Upper bound for sniffing work in milliseconds.
    pub timeout_ms: u64,
    /// Max number of bytes to peek for stream sniffing.
    pub max_peek: usize,
}

impl Default for SniffConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            timeout_ms: 100,
            max_peek: 1024,
        }
    }
}

/// Perform stream-based sniffing by peeking initial bytes.
///
/// Attempts to extract TLS SNI, HTTP Host, and ALPN from stream data.
pub async fn sniff_stream_peek<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    cfg: &SniffConfig,
) -> SniffResult {
    if !cfg.enabled {
        return SniffResult::default();
    }

    use tokio::io::AsyncReadExt;
    use tokio::time::{timeout, Duration};

    let mut buf = vec![0u8; cfg.max_peek];

    // Try to peek data with timeout
    let read_fut = reader.read(&mut buf);
    let n = match timeout(Duration::from_millis(cfg.timeout_ms), read_fut).await {
        Ok(Ok(n)) => n,
        _ => return SniffResult::default(),
    };

    if n == 0 {
        return SniffResult::default();
    }

    let data = &buf[..n];

    // Try TLS first (most common encrypted protocol)
    if data.len() >= 5 && data[0] == 0x16 {
        // TLS Handshake record
        if let Some(sni) = extract_sni_from_tls_client_hello(data) {
            // Also try to extract ALPN from the same ClientHello
            let alpn = extract_alpn_from_tls_client_hello(data);
            return SniffResult {
                sni: Some(sni),
                http_host: None,
                alpn,
                protocol: Some(SniffProtocol::Tls),
            };
        }
    }

    // Try HTTP if it looks like ASCII
    if data.len() >= 16 {
        if let Some(host) = extract_http_host_from_request(data) {
            return SniffResult {
                sni: None,
                http_host: Some(host),
                alpn: Some("http/1.1".to_string()),
                protocol: Some(SniffProtocol::Http),
            };
        }
    }

    SniffResult::default()
}

/// Inspect a UDP datagram for quick protocol hints.
///
/// Attempts to detect QUIC and extract ALPN from QUIC ClientHello.
pub fn sniff_udp_datagram(packet: &[u8], cfg: &SniffConfig) -> SniffResult {
    if !cfg.enabled || packet.is_empty() {
        return SniffResult::default();
    }

    // Try QUIC detection
    if is_quic_packet(packet) {
        if let Some(alpn) = extract_quic_alpn(packet) {
            return SniffResult {
                sni: None,
                http_host: None,
                alpn: Some(alpn),
                protocol: Some(SniffProtocol::Quic),
            };
        }
        return SniffResult {
            sni: None,
            http_host: None,
            alpn: None,
            protocol: Some(SniffProtocol::Quic),
        };
    }

    // Try DNS
    if packet.len() >= 12 && is_dns_packet(packet) {
        return SniffResult {
            sni: None,
            http_host: None,
            alpn: None,
            protocol: Some(SniffProtocol::Dns),
        };
    }

    SniffResult::default()
}

/// Parse a TLS ClientHello record and extract SNI if present.
/// Returns `Some(host)` when a valid SNI (host_name) is found.
/// The input should begin at TLS record header.
pub fn extract_sni_from_tls_client_hello(data: &[u8]) -> Option<String> {
    // Minimum TLS record header: 5 bytes
    if data.len() < 5 {
        return None;
    }
    // ContentType(1)=22 for Handshake
    if data[0] != 22 {
        // 0x16
        return None;
    }
    // Record length
    let rec_len = ((data[3] as usize) << 8) | (data[4] as usize);
    if data.len() < 5 + rec_len {
        return None;
    }
    let mut off = 5;
    // HandshakeType(1)=1 for ClientHello
    if off + 4 > data.len() || data[off] != 1 {
        return None;
    }
    // Handshake length (3 bytes)
    let hs_len = ((data[off + 1] as usize) << 16)
        | ((data[off + 2] as usize) << 8)
        | (data[off + 3] as usize);
    off += 4;
    if off + hs_len > data.len() {
        return None;
    }
    // client_version(2) + random(32)
    if off + 2 + 32 > data.len() {
        return None;
    }
    off += 2 + 32;
    // session_id
    if off + 1 > data.len() {
        return None;
    }
    let sid_len = data[off] as usize;
    off += 1 + sid_len;
    if off > data.len() {
        return None;
    }
    // cipher_suites
    if off + 2 > data.len() {
        return None;
    }
    let cs_len = ((data[off] as usize) << 8) | (data[off + 1] as usize);
    off += 2 + cs_len;
    if off > data.len() {
        return None;
    }
    // compression_methods
    if off + 1 > data.len() {
        return None;
    }
    let cm_len = data[off] as usize;
    off += 1 + cm_len;
    if off > data.len() {
        return None;
    }
    // extensions (optional)
    if off + 2 > data.len() {
        return None;
    }
    let ext_total = ((data[off] as usize) << 8) | (data[off + 1] as usize);
    off += 2;
    if off + ext_total > data.len() {
        return None;
    }
    let mut ext_off = off;
    while ext_off + 4 <= off + ext_total {
        let ext_type = ((data[ext_off] as u16) << 8) | (data[ext_off + 1] as u16);
        let ext_len = ((data[ext_off + 2] as usize) << 8) | (data[ext_off + 3] as usize);
        ext_off += 4;
        if ext_off + ext_len > off + ext_total {
            break;
        }
        if ext_type == 0x0000 {
            // server_name
            if ext_len < 2 {
                break;
            }
            let mut sn_off = ext_off;
            let list_len = ((data[sn_off] as usize) << 8) | (data[sn_off + 1] as usize);
            sn_off += 2;
            if sn_off + list_len > ext_off + ext_len {
                break;
            }
            // iterate names
            let mut cur = sn_off;
            while cur + 3 <= sn_off + list_len {
                let name_type = data[cur];
                let name_len = ((data[cur + 1] as usize) << 8) | (data[cur + 2] as usize);
                cur += 3;
                if cur + name_len > sn_off + list_len {
                    break;
                }
                if name_type == 0 {
                    // host_name
                    if let Ok(s) = std::str::from_utf8(&data[cur..cur + name_len]) {
                        return Some(s.to_string());
                    }
                }
                cur += name_len;
            }
        }
        ext_off += ext_len;
    }
    None
}

/// Parse HTTP/1.1 request bytes and extract Host header if present.
/// Accepts a slice starting at the beginning of the request (start-line).
/// Returns `Some(host)` (without port) when a valid Host header is found.
pub fn extract_http_host_from_request(data: &[u8]) -> Option<String> {
    // Look for end of headers (\r\n\r\n) within a reasonable window
    let window = data.get(..2048).unwrap_or(data);
    let text = std::str::from_utf8(window).ok()?;
    let mut lines = text.split("\r\n");
    // Skip request line
    lines.next()?;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(rest) = line
            .strip_prefix("Host:")
            .or_else(|| line.strip_prefix("host:"))
            .or_else(|| line.strip_prefix("HOST:"))
        {
            let host = rest.trim();
            // Strip optional :port
            let host_only = host.split(':').next().unwrap_or(host).trim();
            if !host_only.is_empty() {
                return Some(host_only.to_string());
            }
        }
    }
    None
}

/// Parse ALPN extension from TLS ClientHello record.
/// Returns the first ALPN protocol if present.
pub fn extract_alpn_from_tls_client_hello(data: &[u8]) -> Option<String> {
    // Minimum TLS record header: 5 bytes
    if data.len() < 5 || data[0] != 22 {
        return None;
    }
    let rec_len = ((data[3] as usize) << 8) | (data[4] as usize);
    if data.len() < 5 + rec_len {
        return None;
    }
    let mut off = 5;
    // HandshakeType(1)=1 for ClientHello
    if off + 4 > data.len() || data[off] != 1 {
        return None;
    }
    // Handshake length (3 bytes)
    let hs_len = ((data[off + 1] as usize) << 16)
        | ((data[off + 2] as usize) << 8)
        | (data[off + 3] as usize);
    off += 4;
    if off + hs_len > data.len() {
        return None;
    }
    // client_version(2) + random(32)
    if off + 2 + 32 > data.len() {
        return None;
    }
    off += 2 + 32;
    // session_id
    if off + 1 > data.len() {
        return None;
    }
    let sid_len = data[off] as usize;
    off += 1 + sid_len;
    if off > data.len() {
        return None;
    }
    // cipher_suites
    if off + 2 > data.len() {
        return None;
    }
    let cs_len = ((data[off] as usize) << 8) | (data[off + 1] as usize);
    off += 2 + cs_len;
    if off > data.len() {
        return None;
    }
    // compression_methods
    if off + 1 > data.len() {
        return None;
    }
    let cm_len = data[off] as usize;
    off += 1 + cm_len;
    if off > data.len() {
        return None;
    }
    // extensions (optional)
    if off + 2 > data.len() {
        return None;
    }
    let ext_total = ((data[off] as usize) << 8) | (data[off + 1] as usize);
    off += 2;
    if off + ext_total > data.len() {
        return None;
    }
    let mut ext_off = off;
    while ext_off + 4 <= off + ext_total {
        let ext_type = ((data[ext_off] as u16) << 8) | (data[ext_off + 1] as u16);
        let ext_len = ((data[ext_off + 2] as usize) << 8) | (data[ext_off + 3] as usize);
        ext_off += 4;
        if ext_off + ext_len > off + ext_total {
            break;
        }
        if ext_type == 0x0010 {
            // ALPN extension
            if ext_len < 2 {
                break;
            }
            let mut alpn_off = ext_off;
            let list_len = ((data[alpn_off] as usize) << 8) | (data[alpn_off + 1] as usize);
            alpn_off += 2;
            if alpn_off + list_len > ext_off + ext_len {
                break;
            }
            // Read first ALPN protocol
            if alpn_off < ext_off + ext_len {
                let proto_len = data[alpn_off] as usize;
                alpn_off += 1;
                if alpn_off + proto_len <= ext_off + ext_len {
                    if let Ok(s) = std::str::from_utf8(&data[alpn_off..alpn_off + proto_len]) {
                        return Some(s.to_string());
                    }
                }
            }
        }
        ext_off += ext_len;
    }
    None
}

/// Check if a UDP packet looks like QUIC (initial packet).
fn is_quic_packet(packet: &[u8]) -> bool {
    if packet.len() < 5 {
        return false;
    }
    // QUIC v1/v2 initial packet: first byte has long header bit set (0x80)
    let first_byte = packet[0];
    (first_byte & 0x80) != 0
}

/// Extract ALPN from QUIC Initial packet (simplified heuristic).
/// This is a best-effort extraction - full QUIC parsing is complex.
fn extract_quic_alpn(packet: &[u8]) -> Option<String> {
    // QUIC Initial packets may contain TLS ClientHello in the payload
    // after the QUIC header. This is a simplified heuristic.
    if packet.len() < 20 {
        return None;
    }
    // Skip QUIC long header (variable length, typically 17+ bytes)
    // Look for TLS handshake starting with 0x16 in the payload
    for i in 10..packet.len().saturating_sub(20) {
        if packet[i] == 0x16 {
            // Might be TLS handshake record
            return extract_alpn_from_tls_client_hello(&packet[i..]);
        }
    }
    None
}

/// Check if packet looks like DNS query.
fn is_dns_packet(packet: &[u8]) -> bool {
    if packet.len() < 12 {
        return false;
    }
    // DNS header: QR bit (bit 15 of flags) should be 0 for query
    let flags = ((packet[2] as u16) << 8) | (packet[3] as u16);
    let qr = (flags >> 15) & 1;
    let qdcount = ((packet[4] as u16) << 8) | (packet[5] as u16);
    qr == 0 && qdcount > 0
}

#[cfg(test)]
mod sniff_http_tests {
    use super::*;

    #[test]
    fn parse_http_host_simple() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: t\r\n\r\n";
        assert_eq!(
            extract_http_host_from_request(req),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn parse_http_host_with_port() {
        let req = b"GET /p HTTP/1.1\r\nhost: example.com:8080\r\n\r\n";
        assert_eq!(
            extract_http_host_from_request(req),
            Some("example.com".to_string())
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn sniff_stream_noop_returns_empty() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut cursor = std::io::Cursor::new(data.to_vec());
        let mut buf = [0u8; 4];
        // read a bit to ensure function doesn't depend on exact position
        let _ = cursor.read(&mut buf).await.unwrap();
        let res = sniff_stream_peek(&mut cursor, &SniffConfig::default()).await;
        assert_eq!(res, SniffResult::default());
    }

    #[test]
    fn sniff_udp_noop_returns_empty() {
        let pkt = [0u8; 16];
        let res = sniff_udp_datagram(&pkt, &SniffConfig::default());
        assert_eq!(res, SniffResult::default());
    }

    #[test]
    fn extract_sni_rejects_invalid() {
        // Not a TLS handshake
        assert_eq!(extract_sni_from_tls_client_hello(&[0u8; 8]), None);
    }

    #[test]
    fn test_alpn_extraction() {
        // Build a minimal TLS ClientHello with ALPN extension
        let mut ch = build_client_hello_with_alpn("h2");
        let alpn = extract_alpn_from_tls_client_hello(&ch);
        assert_eq!(alpn, Some("h2".to_string()));

        ch = build_client_hello_with_alpn("http/1.1");
        let alpn = extract_alpn_from_tls_client_hello(&ch);
        assert_eq!(alpn, Some("http/1.1".to_string()));
    }

    #[test]
    fn test_quic_detection() {
        // QUIC initial packet starts with long header (0x80 bit set)
        let quic_pkt = vec![0xc0, 0x00, 0x00, 0x00, 0x01];
        assert!(is_quic_packet(&quic_pkt));

        // Non-QUIC packet
        let non_quic = vec![0x16, 0x03, 0x03];
        assert!(!is_quic_packet(&non_quic));
    }

    #[test]
    fn test_dns_detection() {
        // Minimal DNS query header
        let dns = vec![
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answers: 0
            0x00, 0x00, // Authority: 0
            0x00, 0x00, // Additional: 0
        ];
        assert!(is_dns_packet(&dns));
    }

    // Helper to build ClientHello with ALPN
    fn build_client_hello_with_alpn(alpn_proto: &str) -> Vec<u8> {
        let mut hs: Vec<u8> = Vec::new();
        hs.push(0x01); // Handshake type: ClientHello
        hs.extend_from_slice(&[0, 0, 0]); // Length placeholder
        hs.extend_from_slice(&[0x03, 0x03]); // Version TLS 1.2
        hs.extend_from_slice(&[0u8; 32]); // Random
        hs.push(0); // Session ID length
        hs.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]); // Cipher suites
        hs.push(1);
        hs.push(0); // Compression methods

        // Extensions
        let ext_len_pos = hs.len();
        hs.extend_from_slice(&[0x00, 0x00]); // Extensions length placeholder

        // ALPN extension (0x0010)
        let mut ext: Vec<u8> = Vec::new();
        ext.extend_from_slice(&[0x00, 0x10]); // Extension type: ALPN
        let ext_data_len_pos = ext.len();
        ext.extend_from_slice(&[0x00, 0x00]); // Extension data length placeholder
        let list_len_pos = ext.len();
        ext.extend_from_slice(&[0x00, 0x00]); // ALPN list length placeholder

        // ALPN protocol
        let proto_bytes = alpn_proto.as_bytes();
        ext.push(proto_bytes.len() as u8);
        ext.extend_from_slice(proto_bytes);

        // Fill lengths
        let list_len = (1 + proto_bytes.len()) as u16;
        ext[list_len_pos..list_len_pos + 2].copy_from_slice(&list_len.to_be_bytes());
        let ext_data_len = (2 + list_len as usize) as u16;
        ext[ext_data_len_pos..ext_data_len_pos + 2].copy_from_slice(&ext_data_len.to_be_bytes());

        hs.extend_from_slice(&ext);
        let final_ext_len = ext.len() as u16;
        hs[ext_len_pos..ext_len_pos + 2].copy_from_slice(&final_ext_len.to_be_bytes());

        // Fill handshake length
        let hs_body_len = (hs.len() - 4) as u32;
        hs[1..4].copy_from_slice(&[
            (hs_body_len >> 16) as u8,
            (hs_body_len >> 8) as u8,
            hs_body_len as u8,
        ]);

        // TLS record wrapper
        let mut rec = Vec::new();
        rec.push(0x16); // Handshake
        rec.extend_from_slice(&[0x03, 0x03]); // Version
        let rec_len = hs.len() as u16;
        rec.extend_from_slice(&rec_len.to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }
}
