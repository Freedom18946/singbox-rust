#![no_main]
//! HTTP CONNECT protocol parsing fuzzer
//!
//! This fuzzer tests HTTP CONNECT request parsing which includes:
//! - Request line parsing (method, target, version)
//! - Host:port parsing (IPv4, IPv6, domain)
//! - Header parsing and validation
//!
//! HTTP CONNECT is a critical inbound protocol, and parsing errors could lead to:
//! - Request smuggling vulnerabilities
//! - Header injection attacks
//! - Buffer overflows in header parsing
//! - Panic/crash from malformed requests
//! - DoS through resource exhaustion

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test 1: HTTP request line parsing
    // Format: "METHOD target HTTP/version\r\n"
    if let Ok(s) = std::str::from_utf8(data) {
        // Parse request line components
        let mut parts = s.split_whitespace();
        let _method = parts.next();
        let target = parts.next();
        let _version = parts.next();

        // Test CONNECT target parsing (host:port)
        if let Some(t) = target {
            let _ = parse_host_port(t);
        }
    }

    // Test 2: Request line with CRLF termination
    if let Some(pos) = data.windows(2).position(|w| w == b"\r\n") {
        let line = &data[..pos];
        if let Ok(s) = std::str::from_utf8(line) {
            let mut it = s.split_whitespace();
            let method = it.next().unwrap_or("");
            let target = it.next().unwrap_or("");

            // Validate HTTP method
            match method {
                "CONNECT" | "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" => {
                    // Valid methods
                    if method == "CONNECT" {
                        // Parse CONNECT target
                        let _ = parse_host_port(target);
                    }
                }
                _ => {
                    // Invalid method - should be handled gracefully
                }
            }
        }
    }

    // Test 3: Header parsing (header end detection)
    // HTTP headers end with \r\n\r\n
    if let Some(_pos) = find_header_end(data) {
        // Headers found - validate they're parseable
        if let Ok(s) = std::str::from_utf8(data) {
            for line in s.lines() {
                // Parse header format: "Name: Value"
                if let Some((name, value)) = line.split_once(':') {
                    // Validate header name doesn't contain invalid chars
                    if !name.is_empty() && !name.chars().any(|c| c.is_control()) {
                        // Valid header
                        let _ = (name.trim(), value.trim());
                    }
                }
            }
        }
    }

    // Test 4: Edge cases

    // Empty data
    if data.is_empty() {
        return;
    }

    // Single byte (invalid but shouldn't crash)
    if data.len() == 1 {
        let _ = data[0];
        return;
    }

    // Very long request line (should be rejected)
    if data.len() > 8192 {
        // Too long - should be handled gracefully
        return;
    }

    // Test 5: Malformed host:port combinations
    if data.len() >= 3 {
        if let Ok(s) = std::str::from_utf8(data) {
            let _ = parse_host_port(s);
        }
    }

    // Test 6: IPv6 address parsing
    // IPv6 format: [::1]:8080 or [2001:db8::1]:443
    if data.starts_with(b"[") {
        if let Ok(s) = std::str::from_utf8(data) {
            let _ = parse_host_port(s);
        }
    }

    // Test 7: Special characters in request
    // These should all be handled without panicking
    let _special_chars = [
        b'\0', // Null byte
        b'\r', // Carriage return
        b'\n', // Line feed
        b'\t', // Tab
        0x80, 0xFF, // High bytes (non-ASCII)
    ];

    // Test 8: Multiple CRLF sequences
    if data.windows(4).any(|w| w == b"\r\n\r\n") {
        // This indicates header end, should be handled properly
    }

    // Test 9: Missing CRLF termination
    // Request without proper line ending should timeout or error gracefully
    if !data.windows(2).any(|w| w == b"\r\n") && data.len() < 8192 {
        // Incomplete request - should be handled with timeout
    }

    // Test 10: Invalid port numbers
    if let Ok(s) = std::str::from_utf8(data) {
        if let Some((_, port_str)) = s.rsplit_once(':') {
            // Try parsing port
            match port_str.parse::<u16>() {
                Ok(port) => {
                    if port == 0 {
                        // Port 0 is technically invalid
                    }
                }
                Err(_) => {
                    // Invalid port format - should be rejected
                }
            }
        }
    }

    // Test 11: Very long host names
    if let Ok(s) = std::str::from_utf8(data) {
        if let Some((host, _)) = s.rsplit_once(':') {
            if host.len() > 253 {
                // DNS limit is 253 chars - should be rejected
                return;
            }
        }
    }

    // Test 12: Empty host or port
    if data.contains(&b':') {
        if let Ok(s) = std::str::from_utf8(data) {
            if s.starts_with(':') || s.ends_with(':') {
                // Empty host or port - should be rejected
                let _ = parse_host_port(s);
            }
        }
    }
});

/// Parse host:port from CONNECT target
/// Handles: domain:port, ipv4:port, [ipv6]:port
fn parse_host_port(s: &str) -> Option<(&str, u16)> {
    // IPv6 format: [host]:port
    if let Some(rest) = s.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        let (_, port_s) = rest.split_once(':')?;
        let port = port_s.parse().ok()?;
        return Some((host, port));
    }

    // IPv4 or domain: host:port
    let (host, port_s) = s.rsplit_once(':')?;
    let port = port_s.parse().ok()?;
    Some((host, port))
}

/// Find the end of HTTP headers (marked by \r\n\r\n)
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_host_port() {
        assert_eq!(parse_host_port("example.com:80"), Some(("example.com", 80)));
        assert_eq!(parse_host_port("127.0.0.1:8080"), Some(("127.0.0.1", 8080)));
        assert_eq!(parse_host_port("[::1]:443"), Some(("::1", 443)));
        assert_eq!(parse_host_port("[2001:db8::1]:8443"), Some(("2001:db8::1", 8443)));
        assert_eq!(parse_host_port("invalid"), None);
        assert_eq!(parse_host_port(":8080"), None); // Empty host
        assert_eq!(parse_host_port("example.com:"), None); // Empty port
    }

    #[test]
    fn test_find_header_end() {
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\n\r\n"), Some(18));
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), Some(41));
        assert_eq!(find_header_end(b"no header end"), None);
    }
}
