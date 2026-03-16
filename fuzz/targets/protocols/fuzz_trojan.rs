#![no_main]
//! Trojan protocol parsing fuzzer
//!
//! Exercises real production parsing code from sb-adapters:
//! - `parse_trojan_request()` — full Trojan request header parser
//!   Format: SHA224_hash(56 hex bytes) + CRLF + command(1) + address_block + CRLF
//!
//! Also exercises `parse_ss_addr()` since Trojan's address block uses the same
//! SOCKS5-style encoding.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test 1: Full Trojan request parsing via real production code
    let _ = sb_adapters::inbound::trojan::parse_trojan_request(data);

    // Test 2: Exercise the address parsing component independently
    // Trojan address block starts after: hash(56) + CRLF(2) + command(1) = offset 59
    if data.len() > 59 {
        let addr_portion = &data[59..];
        let _ = sb_adapters::inbound::shadowsocks::parse_ss_addr(addr_portion);
    }

    // Test 3: Direct address parsing for cross-protocol coverage
    let _ = sb_adapters::inbound::shadowsocks::parse_ss_addr(data);
});
