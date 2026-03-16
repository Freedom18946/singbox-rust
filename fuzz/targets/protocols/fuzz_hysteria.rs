#![no_main]
//! Hysteria v1/v2 protocol parsing fuzzer
//!
//! The Hysteria protocol operates over QUIC (via the quinn crate). All parsing
//! functions in the inbound/outbound modules are async and require a QUIC
//! connection or stream, making them inaccessible from a synchronous fuzz harness.
//!
//! What IS fuzzable:
//! - Address parsing via `parse_ss_addr()` — Hysteria uses the same SOCKS5-style
//!   address encoding for target addresses in its connect/packet commands.
//!
//! What is NOT directly fuzzable without an async runtime + QUIC stack:
//! - QUIC handshake and authentication
//! - Hysteria-specific frame parsing (requires quinn::RecvStream)
//! - Speed/bandwidth negotiation

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Exercise real address parsing — Hysteria target address uses SOCKS5-like format
    let _ = sb_adapters::inbound::shadowsocks::parse_ss_addr(data);

    // Exercise Trojan request parsing for cross-protocol address coverage
    let _ = sb_adapters::inbound::trojan::parse_trojan_request(data);
});
