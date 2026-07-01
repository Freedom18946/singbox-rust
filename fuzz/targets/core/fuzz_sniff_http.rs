#![no_main]
//! Dedicated HTTP Host header extraction fuzzer
//!
//! Deeply exercises the HTTP/1.x Host header parser in
//! sb-core::router::sniff::extract_http_host_from_request. This parser
//! processes raw TCP stream prefixes from untrusted sources and must never
//! panic on any input.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // --- Full-buffer parsing ---

    // Exercise HTTP Host extraction on the raw fuzzer input.
    let _ = sb_core::router::sniff::extract_http_host_from_request(data);

    // Exercise sniff_stream which tries HTTP after TLS fails.
    let _ = sb_core::router::sniff::sniff_stream(data);

    // --- HTTP method prefix variations ---
    // Prepend common HTTP methods to fuzzer data to exercise the Host header
    // parsing path more frequently (the parser requires valid UTF-8 first).
    static METHODS: &[&[u8]] = &[
        b"GET / HTTP/1.1\r\n",
        b"POST / HTTP/1.1\r\n",
        b"HEAD / HTTP/1.1\r\n",
        b"PUT / HTTP/1.1\r\n",
        b"DELETE / HTTP/1.1\r\n",
        b"CONNECT ",
        b"OPTIONS / HTTP/1.1\r\n",
        b"PATCH / HTTP/1.1\r\n",
    ];

    if data.len() >= 2 {
        // Use first byte to select method prefix, rest as header content.
        let method_idx = data[0] as usize % METHODS.len();
        let prefix = METHODS[method_idx];
        let rest = &data[1..];

        let mut buf = Vec::with_capacity(prefix.len() + rest.len());
        buf.extend_from_slice(prefix);
        buf.extend_from_slice(rest);
        let _ = sb_core::router::sniff::extract_http_host_from_request(&buf);
        let _ = sb_core::router::sniff::sniff_stream(&buf);
    }

    // --- Host header injection patterns ---
    // Construct requests with "Host:" header using fuzzer-controlled values
    // to exercise the case-insensitive Host header scan.
    if data.len() >= 4 {
        let host_value = &data[2..];
        // Try various Host: casings
        static HOST_VARIANTS: &[&[u8]] = &[b"Host: ", b"host: ", b"HOST: ", b"hOsT: ", b"Host:"];
        let variant_idx = data[0] as usize % HOST_VARIANTS.len();

        let mut request = Vec::with_capacity(64 + host_value.len());
        request.extend_from_slice(b"GET / HTTP/1.1\r\n");
        request.extend_from_slice(HOST_VARIANTS[variant_idx]);
        request.extend_from_slice(host_value);
        request.extend_from_slice(b"\r\n\r\n");
        let _ = sb_core::router::sniff::extract_http_host_from_request(&request);
    }

    // --- Pathological line patterns ---
    // Exercise the line scanning limit (128 lines) with many short lines.
    if data.len() >= 8 {
        let mut many_lines = Vec::with_capacity(data.len() * 3);
        many_lines.extend_from_slice(b"GET / HTTP/1.1\r\n");
        // Generate many header-like lines from fuzzer data.
        for chunk in data.chunks(4) {
            many_lines.extend_from_slice(b"X-Fuzz: ");
            many_lines.extend_from_slice(chunk);
            many_lines.extend_from_slice(b"\r\n");
        }
        // Append a Host header at the end to test late-in-headers detection.
        many_lines.extend_from_slice(b"Host: late.example.com\r\n\r\n");
        let _ = sb_core::router::sniff::extract_http_host_from_request(&many_lines);
    }

    // --- UTF-8 boundary testing ---
    // The HTTP parser calls from_utf8 first. Exercise with mixed valid/invalid
    // UTF-8 sequences to ensure no panics on partial multi-byte characters.
    if data.len() >= 6 {
        let mut mixed = Vec::with_capacity(32 + data.len());
        mixed.extend_from_slice(b"GET / HTTP/1.1\r\nHost: ");
        mixed.extend_from_slice(data);
        mixed.extend_from_slice(b"\r\n\r\n");
        let _ = sb_core::router::sniff::extract_http_host_from_request(&mixed);
    }

    // --- Truncated requests ---
    if data.len() > 5 {
        for trim in 1..std::cmp::min(data.len(), 8) {
            let truncated = &data[..data.len() - trim];
            let _ = sb_core::router::sniff::extract_http_host_from_request(truncated);
        }
    }
});
