#![no_main]
//! Mixed protocol detection fuzzer
//!
//! Exercises the mixed inbound's protocol detectors. The base path always feeds
//! every input to the TLS, SOCKS5, and HTTP detectors so coverage does not
//! depend on the first byte matching a specific protocol prefix.

use libfuzzer_sys::fuzz_target;
use sb_adapters::inbound::mixed::{detect_http, detect_socks5, detect_tls};

fuzz_target!(|data: &[u8]| {
    // Always exercise all three protocol detectors on the raw input.
    let _ = detect_tls(data);
    let _ = detect_socks5(data);
    let _ = detect_http(data);

    // Targeted prefixes to push inputs down more specific branches.
    if !data.is_empty() {
        let mut tls_like = data.to_vec();
        tls_like[0] = 0x16;
        let _ = detect_tls(&tls_like);

        let mut socks_like = data.to_vec();
        socks_like[0] = 0x05;
        let _ = detect_socks5(&socks_like);
    }

    if data.len() >= 2 {
        static HTTP_PREFIXES: &[&[u8]] = &[
            b"GET / HTTP/1.1\r\n",
            b"CONNECT example.com:443 HTTP/1.1\r\n",
            b"POST / HTTP/1.1\r\n",
        ];
        let prefix = HTTP_PREFIXES[data[0] as usize % HTTP_PREFIXES.len()];
        let mut http_like = Vec::with_capacity(prefix.len() + data.len().saturating_sub(1));
        http_like.extend_from_slice(prefix);
        http_like.extend_from_slice(&data[1..]);
        let _ = detect_http(&http_like);
    }
});
