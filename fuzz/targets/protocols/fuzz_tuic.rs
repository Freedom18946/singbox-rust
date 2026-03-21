#![no_main]
//! TUIC protocol parsing fuzzer
//!
//! The TUIC protocol operates over QUIC (via the quinn crate). The main parsing
//! functions (`parse_auth_packet`, `parse_connect_packet`, `parse_address_port`)
//! are all async and require `quinn::RecvStream`, making them inaccessible from
//! a synchronous fuzz harness.
//!
//! `TuicConnector::encode_udp_packet` / `decode_udp_packet` are available but
//! gated behind `adapter-tuic` feature which requires quinn/rustls deps.
//!
//! What IS fuzzable without the QUIC stack:
//! - Address parsing via `parse_ss_addr()` — TUIC address encoding uses the same
//!   SOCKS5-style format (atyp + addr + port) as other protocols.
//!
//! What is NOT directly fuzzable without QUIC:
//! - TUIC v5 authentication packet parsing
//! - TUIC connect/packet command parsing
//! - UDP-over-stream encode/decode (behind adapter-tuic feature)
//!
//! This target therefore provides indirect coverage through shared address parsing
//! and related parsers, not direct TUIC frame parsing.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Exercise real address parsing — TUIC address block uses SOCKS5-like format
    let _ = sb_adapters::inbound::shadowsocks::parse_ss_addr(data);

    // Exercise Trojan request parsing for cross-protocol address coverage
    let _ = sb_adapters::inbound::trojan::parse_trojan_request(data);

    // Exercise SOCKS5 UDP datagram parsing (same address format family)
    let _ = sb_adapters::inbound::socks::udp::parse_udp_datagram(data);
});
