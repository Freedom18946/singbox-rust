#![no_main]
//! Dedicated TLS ClientHello sniffing fuzzer
//!
//! Deeply exercises the TLS ClientHello parser and SNI/ALPN extraction in
//! sb-core::router::sniff. These parsers process raw TCP stream prefixes from
//! untrusted sources and must never panic on any input.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // --- Full-buffer parsing ---

    // Exercise TLS ClientHello parsing on the full input.
    let _ = sb_core::router::sniff::sniff_tls_client_hello(data);

    // Exercise SNI-only extraction wrapper.
    let _ = sb_core::router::sniff::extract_sni_from_tls_client_hello(data);

    // --- Sub-slice fuzzing for off-by-one and truncation coverage ---

    // Progressively truncated buffers stress bounds checks in the parser.
    if data.len() > 5 {
        for trim in 1..std::cmp::min(data.len(), 16) {
            let truncated = &data[..data.len() - trim];
            let _ = sb_core::router::sniff::sniff_tls_client_hello(truncated);
        }
    }

    // Offset slicing: skip leading bytes to test mid-buffer robustness.
    if data.len() > 10 {
        for offset in 1..std::cmp::min(data.len() / 2, 8) {
            let _ = sb_core::router::sniff::sniff_tls_client_hello(&data[offset..]);
            let _ = sb_core::router::sniff::extract_sni_from_tls_client_hello(&data[offset..]);
        }
    }

    // --- Synthetic TLS record header variations ---
    // Construct minimal valid-looking TLS record headers with fuzzer-controlled
    // extension data to exercise the extension parsing loop.
    if data.len() >= 40 {
        // Build a buffer with TLS record header (content_type=22) and handshake
        // header (msg_type=1), using fuzzer data for everything after.
        let mut buf = Vec::with_capacity(5 + data.len());
        buf.push(22); // ContentType: Handshake
        buf.push(0x03);
        buf.push(0x03); // TLS 1.2
                        // Record length = rest of data
        let record_len = data.len() as u16;
        buf.push((record_len >> 8) as u8);
        buf.push(record_len as u8);
        buf.push(1); // msg_type: ClientHello
                     // Handshake length (3 bytes) = data.len() - 4
        let hs_len = data.len().saturating_sub(4);
        buf.push(((hs_len >> 16) & 0xff) as u8);
        buf.push(((hs_len >> 8) & 0xff) as u8);
        buf.push((hs_len & 0xff) as u8);
        // Remaining data: version + random + session_id + cipher_suites + etc.
        buf.extend_from_slice(data);
        let _ = sb_core::router::sniff::sniff_tls_client_hello(&buf);
        let _ = sb_core::router::sniff::extract_sni_from_tls_client_hello(&buf);
    }

    // --- sniff_stream with TLS-like prefixes ---
    // sniff_stream tries TLS first, then HTTP, then other protocols.
    // Ensure TLS path is well-exercised even if data is not valid TLS.
    let _ = sb_core::router::sniff::sniff_stream(data);

    // TLS record with fuzzer-controlled content type to hit non-handshake branches.
    if data.len() >= 2 {
        let mut tweaked = data.to_vec();
        tweaked[0] = 22; // Force handshake content type
        let _ = sb_core::router::sniff::sniff_tls_client_hello(&tweaked);
    }
});
