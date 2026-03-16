#![no_main]
//! VLESS protocol parsing fuzzer
//!
//! Exercises real production parsing code from sb-adapters:
//! - `parse_ss_addr()` for SOCKS5-style address parsing (VLESS uses the same format)
//!
//! The VLESS inbound's `parse_vless_address()` is async and requires a tokio AsyncRead
//! stream, so we cannot call it directly from the synchronous fuzz harness. Instead we
//! exercise the address parsing component via `parse_ss_addr()` which uses the identical
//! wire format: atyp(1) + addr(variable) + port(2).
//!
//! VLESS request format:
//!   version(1) + UUID(16) + additional_len(1) + [additional_data] + command(1) + address_block
//! The address_block is the fuzzable parsing surface.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test 1: Direct address parsing via parse_ss_addr (same format as VLESS address block)
    let _ = sb_adapters::inbound::shadowsocks::parse_ss_addr(data);

    // Test 2: Simulate VLESS request layout and parse the address portion
    // VLESS minimum header: version(1) + UUID(16) + additional_len(1) + command(1) = 19 bytes
    // If additional_len > 0, add that many bytes before command.
    if data.len() >= 19 {
        let additional_len = data[17] as usize;
        let addr_offset = 19 + additional_len;
        if data.len() > addr_offset {
            let addr_portion = &data[addr_offset..];
            let _ = sb_adapters::inbound::shadowsocks::parse_ss_addr(addr_portion);
        }
    }

    // Test 3: Fuzz the address block at the minimum header offset (no additional data)
    // This is the most common case: additional_len = 0
    if data.len() > 19 {
        let _ = sb_adapters::inbound::shadowsocks::parse_ss_addr(&data[19..]);
    }

    // Test 4: Trojan also uses the same address format; exercise parse_trojan_request
    // to get cross-protocol coverage from the same fuzz corpus
    let _ = sb_adapters::inbound::trojan::parse_trojan_request(data);
});
