#![no_main]
//! Dedicated QUIC Initial packet sniffing fuzzer
//!
//! Deeply exercises the QUIC Initial packet detection, full QUIC SNI extraction
//! (AES-128-GCM decryption + CRYPTO frame reassembly), and multi-packet
//! reassembly in sb-core::router::sniff. These parsers process raw UDP payloads
//! from untrusted sources and must never panic on any input.
//!
//! This target benefits from the T1-01 fix that replaced `unreachable!()` with
//! a safe `return None` in the QUIC varint parser.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // --- QUIC Initial detection (lightweight check) ---
    let _ = sb_core::router::sniff::sniff_quic_initial(data);

    // --- Full datagram sniffing (triggers full QUIC SNI extraction path) ---
    // sniff_datagram calls sniff_quic::sniff_quic_sni internally, exercising
    // the full decryption + CRYPTO frame parsing + TLS ClientHello extraction.
    let _ = sb_core::router::sniff::sniff_datagram(data);

    // --- Multi-packet QUIC reassembly ---
    // First packet: may return NeedMoreData with reassembly state.
    let (outcome, quic_state) = sb_core::router::sniff::sniff_datagram_multi(data);
    let _ = outcome;

    if let Some(ctx) = quic_state {
        // Feed the same data as a "second packet" (unlikely to match DCID but
        // exercises the continuation path and error handling).
        let (result, ctx2) = sb_core::router::sniff::sniff_datagram_continue(data, ctx);
        let _ = result;

        // Feed sub-slices as additional packets to exercise more code paths.
        if let Some(ctx2) = ctx2 {
            if data.len() > 4 {
                let (r, _) = sb_core::router::sniff::sniff_datagram_continue(&data[2..], ctx2);
                let _ = r;
            }
        }
    }

    // --- QUIC long header variations ---
    // Construct buffers with valid-looking QUIC long header flags to increase
    // the chance of reaching deeper parsing code.
    if data.len() >= 20 {
        // QUIC v1 Initial header
        let mut v1_buf = Vec::with_capacity(data.len() + 6);
        v1_buf.push(0xc3); // Long header + fixed bit + Initial type
        v1_buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Version 1
        v1_buf.extend_from_slice(data);
        let _ = sb_core::router::sniff::sniff_quic_initial(&v1_buf);
        let _ = sb_core::router::sniff::sniff_datagram(&v1_buf);
        let (_, state) = sb_core::router::sniff::sniff_datagram_multi(&v1_buf);
        if let Some(ctx) = state {
            if data.len() > 10 {
                let _ = sb_core::router::sniff::sniff_datagram_continue(&data[5..], ctx);
            }
        }

        // QUIC v2 Initial header (type bits swapped: Initial = 0x02)
        let mut v2_buf = Vec::with_capacity(data.len() + 6);
        v2_buf.push(0xe3); // Long header + fixed bit + type 2 (Initial for v2)
        v2_buf.extend_from_slice(&[0x6b, 0x33, 0x43, 0xcf]); // Version 2
        v2_buf.extend_from_slice(data);
        let _ = sb_core::router::sniff::sniff_quic_initial(&v2_buf);
        let _ = sb_core::router::sniff::sniff_datagram(&v2_buf);
        let (_, state) = sb_core::router::sniff::sniff_datagram_multi(&v2_buf);
        if let Some(ctx) = state {
            if data.len() > 10 {
                let _ = sb_core::router::sniff::sniff_datagram_continue(&data[5..], ctx);
            }
        }

        // Draft-29 header
        let mut d29_buf = Vec::with_capacity(data.len() + 6);
        d29_buf.push(0xc3); // Long header + fixed bit + Initial type
        d29_buf.extend_from_slice(&[0xff, 0x00, 0x00, 0x1d]); // Draft-29 version
        d29_buf.extend_from_slice(data);
        let _ = sb_core::router::sniff::sniff_quic_initial(&d29_buf);
        let _ = sb_core::router::sniff::sniff_datagram(&d29_buf);
        let (_, state) = sb_core::router::sniff::sniff_datagram_multi(&d29_buf);
        if let Some(ctx) = state {
            if data.len() > 10 {
                let _ = sb_core::router::sniff::sniff_datagram_continue(&data[5..], ctx);
            }
        }
    }

    // --- DCID length variations ---
    // Exercise various DCID lengths (1-20 bytes) to cover the key derivation path.
    if data.len() >= 30 {
        for dcid_len in [1u8, 4, 8, 16, 20] {
            let mut pkt = Vec::with_capacity(7 + dcid_len as usize + data.len());
            pkt.push(0xc3); // QUIC v1 Initial flags
            pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Version 1
            pkt.push(dcid_len); // DCID length
                                // Use fuzzer data for DCID and remaining packet
            let available = std::cmp::min(dcid_len as usize, data.len());
            pkt.extend_from_slice(&data[..available]);
            // Pad DCID if fuzzer data is shorter
            let pad = dcid_len as usize - available;
            pkt.extend(std::iter::repeat_n(0u8, pad));
            if available < data.len() {
                pkt.extend_from_slice(&data[available..]);
            }
            let _ = sb_core::router::sniff::sniff_datagram(&pkt);
            let (_, state) = sb_core::router::sniff::sniff_datagram_multi(&pkt);
            drop(state);
        }
    }

    // --- Sub-slice and truncation ---
    if data.len() > 10 {
        for trim in 1..std::cmp::min(data.len(), 8) {
            let truncated = &data[..data.len() - trim];
            let _ = sb_core::router::sniff::sniff_quic_initial(truncated);
            let _ = sb_core::router::sniff::sniff_datagram(truncated);
        }
    }
});
