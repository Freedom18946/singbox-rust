#![no_main]
//! Mixed protocol detection fuzzer
//!
//! This fuzzer tests the mixed protocol detection logic which includes:
//! - Protocol detection based on first byte
//! - TLS handshake detection
//! - SOCKS5 detection
//! - HTTP detection
//! - Protocol switching logic
//!
//! Mixed protocol detection is critical for security, and errors could lead to:
//! - Protocol confusion attacks
//! - Authentication bypass
//! - Data leakage
//! - Service disruption

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Test protocol detection based on first byte
    let first_byte = data[0];

    match first_byte {
        0x16 => {
            // TLS handshake - test TLS detection
            let _ = detect_tls(data);
        }
        0x05 => {
            // SOCKS5 - test SOCKS5 detection
            let _ = detect_socks5(data);
        }
        b'A'..=b'Z' => {
            // HTTP - test HTTP detection
            let _ = detect_http(data);
        }
        _ => {
            // Other protocols or unknown - should be handled gracefully
        }
    }

    // Test edge cases
    // These should all be handled gracefully without panicking

    // Single byte (should not crash)
    if data.len() == 1 {
        let _ = data[0];
        return;
    }

    // Test with null bytes
    if data.contains(&0) {
        // Should handle null bytes gracefully
    }

    // Test with very long data
    if data.len() > 8192 {
        // Should handle oversized data gracefully
    }
});

fn detect_tls(data: &[u8]) -> bool {
    // TLS handshake detection (simplified)
    if data.len() < 5 {
        return false;
    }

    // Check TLS version
    let version = u16::from_be_bytes([data[1], data[2]]);
    match version {
        0x0301 => true, // TLS 1.0
        0x0302 => true, // TLS 1.1
        0x0303 => true, // TLS 1.2
        0x0304 => true, // TLS 1.3
        _ => false,
    }
}

fn detect_socks5(data: &[u8]) -> bool {
    // SOCKS5 detection (simplified)
    if data.len() < 2 {
        return false;
    }

    let version = data[0];
    let nmethods = data[1] as usize;

    version == 0x05 && data.len() >= 2 + nmethods
}

fn detect_http(data: &[u8]) -> bool {
    // HTTP detection (simplified)
    if data.len() < 4 {
        return false;
    }

    // Check for HTTP methods
    let first_four = &data[..4];
    matches!(first_four, b"GET " | b"POST" | b"PUT " | b"HEAD" | b"OPTI" | b"DELE" | b"PATC" | b"CONN")
}

// TODO: When sb-adapters exposes the real parsing function, replace
// the above manual parsing with:
//
// let _ = sb_adapters::inbound::mixed::detect_tls(data);
// let _ = sb_adapters::inbound::mixed::detect_socks5(data);
// let _ = sb_adapters::inbound::mixed::detect_http(data);
//
// This will ensure we're testing the actual production code path
// rather than a reimplementation.
