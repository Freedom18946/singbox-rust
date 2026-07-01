#![no_main]
//! Route decision / protocol sniffing fuzzer
//!
//! Feeds arbitrary bytes to the protocol sniffing functions in
//! sb-core::router::sniff. These functions process raw TCP/UDP payloads
//! from untrusted sources and must never panic on any input.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Exercise TCP stream sniffing (TLS, HTTP, SSH, RDP, BitTorrent detection).
    let _ = sb_core::router::sniff::sniff_stream(data);

    // Exercise UDP datagram sniffing (DNS, QUIC, DTLS, STUN, NTP detection).
    let _ = sb_core::router::sniff::sniff_datagram(data);

    // Exercise TLS ClientHello parsing directly.
    let _ = sb_core::router::sniff::sniff_tls_client_hello(data);

    // Exercise HTTP Host header extraction.
    let _ = sb_core::router::sniff::extract_http_host_from_request(data);

    // Exercise SNI extraction from TLS ClientHello.
    let _ = sb_core::router::sniff::extract_sni_from_tls_client_hello(data);

    // Exercise QUIC Initial detection.
    let _ = sb_core::router::sniff::sniff_quic_initial(data);

    // Exercise skip_sniff with arbitrary port values derived from input.
    if data.len() >= 2 {
        let port = u16::from_be_bytes([data[0], data[1]]);
        let _ = sb_core::router::sniff::skip_sniff(port);
    }

    // Exercise multi-packet QUIC sniffing.
    let (outcome, quic_state) = sb_core::router::sniff::sniff_datagram_multi(data);
    let _ = outcome;

    // If we got a QUIC reassembly context, try feeding more data.
    if let Some(ctx) = quic_state {
        if data.len() > 4 {
            let (result, _) = sb_core::router::sniff::sniff_datagram_continue(&data[2..], ctx);
            let _ = result;
        }
    }

    // Exercise DNS query sniffing.
    let _ = sb_core::router::sniff::sniff_dns_query(data);
});
