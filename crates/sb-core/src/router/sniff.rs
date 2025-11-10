//! Minimal TLS ClientHello sniffing utilities
//!
//! Provides zero-copy parsers to extract SNI and ALPN from a TLS ClientHello
//! message embedded in a TCP stream prefix. Intended for use by TUN or
//! inbounds that can safely peek initial bytes prior to routing.

/// Result of TLS ClientHello sniffing
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsClientHelloInfo {
    pub sni: Option<String>,
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
    let hs_len = ((buf[p + 1] as usize) << 16) | ((buf[p + 2] as usize) << 8) | (buf[p + 3] as usize);
    p += 4;
    if p + hs_len > buf.len() { return None; }

    // ClientHello:
    // version(2) + random(32)
    if p + 2 + 32 > buf.len() { return None; }
    p += 2 + 32;
    // session_id
    if p + 1 > buf.len() { return None; }
    let sid_len = buf[p] as usize; p += 1;
    if p + sid_len > buf.len() { return None; }
    p += sid_len;
    // cipher_suites
    if p + 2 > buf.len() { return None; }
    let cs_len = u16::from_be_bytes([buf[p], buf[p+1]]) as usize; p += 2;
    if p + cs_len > buf.len() { return None; }
    p += cs_len;
    // compression_methods
    if p + 1 > buf.len() { return None; }
    let cm_len = buf[p] as usize; p += 1;
    if p + cm_len > buf.len() { return None; }
    p += cm_len;
    // extensions
    if p + 2 > buf.len() { return None; }
    let ext_total = u16::from_be_bytes([buf[p], buf[p+1]]) as usize; p += 2;
    if p + ext_total > buf.len() { return None; }
    let ext_end = p + ext_total;

    let mut info = TlsClientHelloInfo::default();

    while p + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([buf[p], buf[p+1]]); p += 2;
        let ext_len = u16::from_be_bytes([buf[p], buf[p+1]]) as usize; p += 2;
        if p + ext_len > ext_end { return None; }
        let ext_data = &buf[p..p+ext_len];
        p += ext_len;

        match ext_type {
            0x0000 => { // server_name
                // server_name_list: u16 len, entries: [u8 name_type=0][u16 name_len][name]
                if ext_data.len() >= 2 {
                    let mut q = 2; // skip list length
                    while q + 3 <= ext_data.len() {
                        let name_type = ext_data[q]; q += 1;
                        let nlen = u16::from_be_bytes([ext_data[q], ext_data[q+1]]) as usize; q += 2;
                        if q + nlen > ext_data.len() { break; }
                        if name_type == 0 {
                            if let Ok(s) = std::str::from_utf8(&ext_data[q..q+nlen]) {
                                info.sni = Some(s.to_string());
                                // do not break; prefer first, but continue to parse ALPN
                            }
                        }
                        q += nlen;
                    }
                }
            }
            0x0010 => { // ALPN
                // alpn: u16 len, then protocol_name_list: [len][name] ... choose first
                if ext_data.len() >= 2 {
                    let mut q = 2; // skip list length
                    if q < ext_data.len() {
                        let nlen = ext_data[q] as usize; q += 1;
                        if q + nlen <= ext_data.len() {
                            if let Ok(s) = std::str::from_utf8(&ext_data[q..q+nlen]) {
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
    if !long { return None; }
    // Long header form: bits[1..3] = fixed patterns; type in low 2 bits
    // We accept any long header and assume Initial for hinting purpose.
    // Version field follows (bytes 1..4). Non-zero typically indicates QUIC.
    let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    if version == 0 { return None; }
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
}
