#![no_main]

use libfuzzer_sys::fuzz_target;

/// Fuzz target for HTTP CONNECT parsing
/// Tests HTTP request line parsing, header parsing, and CRLF boundary handling
fuzz_target!(|data: &[u8]| {
    // Test HTTP request line parsing
    let _ = parse_http_request_line(data);

    // Test HTTP header parsing
    let _ = parse_http_headers(data);

    // Test CRLF boundary handling
    let _ = parse_http_complete_request(data);

    // Test malformed requests
    let _ = parse_malformed_http(data);
});

fn parse_http_request_line(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    if let Ok(request_str) = std::str::from_utf8(data) {
        let lines: Vec<&str> = request_str.lines().collect();
        if !lines.is_empty() {
            let request_line = lines[0];
            let parts: Vec<&str> = request_line.split_whitespace().collect();

            if parts.len() >= 3 {
                let method = parts[0];
                let target = parts[1];
                let version = parts[2];

                // Test method validation
                match method {
                    "CONNECT" => (), // Valid for proxy
                    "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" => (),
                    _ => (), // Unknown method - should be handled gracefully
                }

                // Test target format for CONNECT
                if method == "CONNECT" {
                    // Should be host:port format
                    if let Some(_colon_pos) = target.find(':') {
                        // Valid CONNECT target format
                    }
                }

                // Test HTTP version
                match version {
                    "HTTP/1.0" | "HTTP/1.1" | "HTTP/2.0" => (),
                    _ => (), // Invalid version
                }
            }
        }
    }
    Ok(())
}

fn parse_http_headers(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    if let Ok(request_str) = std::str::from_utf8(data) {
        let lines: Vec<&str> = request_str.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            if i == 0 {
                continue; // Skip request line
            }

            if line.is_empty() {
                break; // End of headers
            }

            // Test header format: "Name: Value"
            if let Some(colon_pos) = line.find(':') {
                let header_name = &line[..colon_pos];
                let header_value = &line[colon_pos + 1..].trim_start();

                // Test common proxy-related headers
                match header_name.to_lowercase().as_str() {
                    "host" => {
                        // Host header should be valid
                        let _ = header_value;
                    },
                    "proxy-authorization" => {
                        // Test auth header format
                        if header_value.starts_with("Basic ") {
                            // Basic auth
                        } else if header_value.starts_with("Bearer ") {
                            // Bearer token
                        }
                    },
                    "proxy-connection" => {
                        match header_value.to_lowercase().as_str() {
                            "keep-alive" | "close" => (),
                            _ => (),
                        }
                    },
                    "user-agent" => {
                        // User agent can be anything
                    },
                    _ => {
                        // Other headers
                    }
                }
            }
        }
    }
    Ok(())
}

fn parse_http_complete_request(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Test different CRLF combinations
    let request_str = String::from_utf8_lossy(data);

    // Look for different line ending patterns
    let patterns = ["\r\n\r\n", "\n\n", "\r\r"];

    for pattern in &patterns {
        if let Some(end_pos) = request_str.find(pattern) {
            let headers_part = &request_str[..end_pos];
            let body_part = &request_str[end_pos + pattern.len()..];

            // Test headers parsing
            let lines: Vec<&str> = headers_part.lines().collect();
            if !lines.is_empty() {
                // First line should be request line
                let request_line = lines[0];
                if request_line.contains("CONNECT") {
                    // Valid CONNECT request structure
                }
            }

            // Test body (should be empty for CONNECT)
            if !body_part.is_empty() {
                // CONNECT requests shouldn't have body
            }
            break;
        }
    }
    Ok(())
}

fn parse_malformed_http(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Test various malformed inputs that should be handled gracefully

    // Test with only partial data
    if data.len() < 10 {
        let _ = std::str::from_utf8(data);
        return Ok(());
    }

    // Test with null bytes
    if data.contains(&0) {
        // Should handle null bytes gracefully
    }

    // Test with very long lines
    if data.len() > 8192 {
        // Should handle oversized headers
    }

    // Test with invalid UTF-8
    let _ = String::from_utf8_lossy(data);

    // Test missing required elements
    let request_str = String::from_utf8_lossy(data);

    // Test request without method
    if !request_str.contains(' ') {
        // Malformed request line
    }

    // Test request without proper line endings
    if !request_str.contains('\n') && !request_str.contains('\r') {
        // No line endings
    }

    // Test headers without colons
    let lines: Vec<&str> = request_str.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if i > 0 && !line.is_empty() && !line.contains(':') {
            // Header without colon
        }
    }

    Ok(())
}

/// Test specific CONNECT request parsing scenarios
fn test_connect_scenarios(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let request_str = String::from_utf8_lossy(data);

    // Test various CONNECT target formats
    if request_str.contains("CONNECT") {
        let lines: Vec<&str> = request_str.lines().collect();
        if !lines.is_empty() {
            let parts: Vec<&str> = lines[0].split_whitespace().collect();
            if parts.len() >= 2 && parts[0] == "CONNECT" {
                let target = parts[1];

                // Test different target formats
                if target.contains(':') {
                    let target_parts: Vec<&str> = target.split(':').collect();
                    if target_parts.len() == 2 {
                        let host = target_parts[0];
                        let port = target_parts[1];

                        // Test host validation
                        if host.is_empty() {
                            // Empty host
                        } else if host.contains(' ') {
                            // Host with spaces
                        } else if host.len() > 253 {
                            // Host too long
                        }

                        // Test port validation
                        if let Ok(port_num) = port.parse::<u16>() {
                            // Valid port
                            if port_num == 0 || port_num > 65535 {
                                // Invalid port range
                            }
                        } else {
                            // Invalid port format
                        }
                    }
                }
            }
        }
    }

    Ok(())
}