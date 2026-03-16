#![no_main]
//! HTTP CONNECT protocol parsing fuzzer
//!
//! The HTTP inbound's parsing functions (`split_host_port`, `parse_request_line`,
//! `find_header_end`, `read_request_head`) are all private (`fn`, not `pub fn`)
//! and/or async. They cannot be called directly from the fuzz crate.
//!
//! What IS fuzzable:
//! - The shared address parsing via `parse_ss_addr()` and `parse_trojan_request()`
//!   for cross-protocol coverage.
//! - SOCKS5 UDP datagram parsing (exercises address parsing from a different angle).
//!
//! What is NOT directly fuzzable from outside the crate:
//! - `split_host_port()` — private fn in http.rs
//! - `parse_request_line()` — private fn in http.rs
//! - `find_header_end()` — private fn in http.rs
//! - `read_request_head()` — private async fn in http.rs
//! - `serve_conn()` — public but requires full async runtime + RouterHandle + etc.
//!
//! To enable direct fuzzing of HTTP parsing, these functions would need to be
//! exposed via `pub` (or `#[cfg(fuzzing)] pub`) visibility.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Exercise real production parsing code for cross-protocol coverage.
    // HTTP CONNECT target addresses (host:port) share validation patterns with
    // the SOCKS5-style address parsers used by other protocols.

    // Test 1: SOCKS5-style address parsing (shared address format family)
    let _ = sb_adapters::inbound::shadowsocks::parse_ss_addr(data);

    // Test 2: SOCKS5 UDP datagram parsing (exercises address type validation)
    let _ = sb_adapters::inbound::socks::udp::parse_udp_datagram(data);

    // Test 3: Trojan request parsing (exercises hash + CRLF + address parsing)
    let _ = sb_adapters::inbound::trojan::parse_trojan_request(data);
});
