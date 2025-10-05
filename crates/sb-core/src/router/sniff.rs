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
/// Stage 1 returns a default (empty) result to avoid any behavior changes.
pub async fn sniff_stream_peek<R: tokio::io::AsyncRead + Unpin>(
    _reader: &mut R,
    _cfg: &SniffConfig,
) -> SniffResult {
    SniffResult::default()
}

/// Inspect a UDP datagram for quick protocol hints.
///
/// Stage 1 returns a default (empty) result to avoid any behavior changes.
pub fn sniff_udp_datagram(_packet: &[u8], _cfg: &SniffConfig) -> SniffResult {
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
    if data[0] != 22 { // 0x16
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
        if line.is_empty() { break; }
        if let Some(rest) = line.strip_prefix("Host:")
            .or_else(|| line.strip_prefix("host:"))
            .or_else(|| line.strip_prefix("HOST:"))
        {
            let host = rest.trim();
            // Strip optional :port
            let host_only = host.split(':').next().unwrap_or(host).trim();
            if !host_only.is_empty() { return Some(host_only.to_string()); }
        }
    }
    None
}

#[cfg(test)]
mod sniff_http_tests {
    use super::*;

    #[test]
    fn parse_http_host_simple() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: t\r\n\r\n";
        assert_eq!(extract_http_host_from_request(req), Some("example.com".to_string()));
    }

    #[test]
    fn parse_http_host_with_port() {
        let req = b"GET /p HTTP/1.1\r\nhost: example.com:8080\r\n\r\n";
        assert_eq!(extract_http_host_from_request(req), Some("example.com".to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn sniff_stream_noop_returns_empty() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut cursor = tokio::io::Cursor::new(data.to_vec());
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
}
