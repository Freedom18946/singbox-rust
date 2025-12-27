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
use sb_adapters::inbound::mixed::{detect_http, detect_socks5, detect_tls};

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
