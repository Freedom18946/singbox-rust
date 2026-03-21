#![no_main]
//! Shadowsocks protocol parsing fuzzer
//!
//! Exercises real production parsing code from sb-adapters:
//! - `parse_ss_addr()` — the core SOCKS5-style address parser used by Shadowsocks
//!   for both TCP request headers and UDP packet addressing.
//!
//! The AEAD encryption/decryption layer is handled by aes-gcm / chacha20poly1305
//! crates which have their own security auditing. After decryption, the first
//! meaningful parsing operation is `parse_ss_addr()` on the plaintext payload.
//!
//! parse_ss_addr format: atyp(1) + addr(variable) + port(2)
//!   atyp=1: IPv4 (4 bytes)
//!   atyp=3: Domain (1 byte length + N bytes)
//!   atyp=4: IPv6 (16 bytes) — note: Shadowsocks uses 4 for IPv6, not 3

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test 1: Real Shadowsocks address parser — the primary parsing surface
    let _ = sb_adapters::inbound::shadowsocks::parse_ss_addr(data);

    // Test 2: Parse with various sub-slices to exercise boundary conditions
    // In real usage, the address is embedded after the salt+decrypted payload prefix
    for offset in 0..data.len().min(32) {
        let _ = sb_adapters::inbound::shadowsocks::parse_ss_addr(&data[offset..]);
    }
});
