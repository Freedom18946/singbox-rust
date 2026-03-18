#![no_main]
//! VMess protocol parsing fuzzer
//!
//! Exercises real production parsing code from sb-adapters:
//! - `parse_vmess_request()` for the full VMess decrypted request header
//! - `parse_ss_addr()` for SOCKS5-style address parsing (shared encoding)
//!
//! The VMess request parser handles: version(1) + IV(16) + key(16) +
//! response_auth(1) + options(1) + security(1) + reserved(1) + command(1)
//! + address_block (atyp + addr + port).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test 1: Exercise the real VMess request parser directly.
    // This parses the full decrypted VMess request header including
    // version, IV, key, options, security, command, and address fields.
    let _ = sb_adapters::inbound::vmess::parse_vmess_request(data);

    // Test 2: Exercise address parsing via parse_ss_addr.
    // VMess address block uses the same SOCKS5-like encoding as Shadowsocks:
    // atyp(1) + addr(variable) + port(2)
    let _ = sb_adapters::inbound::shadowsocks::parse_ss_addr(data);

    // Test 3: Parse the address portion at the correct VMess offset (byte 38).
    // After the fixed 38-byte header, the address block begins.
    if data.len() > 38 {
        let addr_portion = &data[38..];
        let _ = sb_adapters::inbound::shadowsocks::parse_ss_addr(addr_portion);
    }

    // Test 4: Fuzz with various offsets to exercise parse_ss_addr
    // with different starting points (simulates misaligned or truncated requests)
    for start in [1, 10, 20, 56] {
        if data.len() > start {
            let _ = sb_adapters::inbound::shadowsocks::parse_ss_addr(&data[start..]);
        }
    }
});
