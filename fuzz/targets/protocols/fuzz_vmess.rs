#![no_main]
//! VMess protocol parsing fuzzer
//!
//! Exercises real production parsing code from sb-adapters:
//! - `parse_ss_addr()` for SOCKS5-style address parsing (shared with VMess request body)
//! - VMess uses the same address type encoding (0x01=IPv4, 0x02=Domain, 0x03=IPv6)
//!
//! The VMess inbound's `parse_vmess_request()` is private (requires decrypted request
//! bytes after AEAD decryption), so we cannot call it directly. Instead we exercise
//! the address parsing component which is the main parsing surface exposed to
//! attacker-controlled bytes after decryption.
//!
//! The HMAC authentication and AEAD decryption layers are tested implicitly through
//! the crypto dependencies (aes-gcm, chacha20poly1305, hmac, sha2) which have their
//! own fuzz coverage.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test 1: Exercise real address parsing via parse_ss_addr
    // VMess request body contains address in SOCKS5-like format after the fixed header fields.
    // parse_ss_addr handles: atyp(1) + addr(variable) + port(2)
    let _ = sb_adapters::inbound::shadowsocks::parse_ss_addr(data);

    // Test 2: Simulate the VMess request body layout and parse the address portion.
    // VMess decrypted request format:
    //   version(1) + IV(16) + key(16) + response_auth(1) + options(1) + security(1)
    //   + reserved(1) + command(1) + address_block
    // The address_block starts at offset 38 and uses SOCKS5-like encoding.
    if data.len() > 38 {
        let addr_portion = &data[38..];
        let _ = sb_adapters::inbound::shadowsocks::parse_ss_addr(addr_portion);
    }

    // Test 3: Fuzz with various offsets into the data to exercise parse_ss_addr
    // with different starting points (simulates misaligned or truncated requests)
    for start in [0, 1, 10, 20, 38, 56] {
        if data.len() > start {
            let _ = sb_adapters::inbound::shadowsocks::parse_ss_addr(&data[start..]);
        }
    }
});
