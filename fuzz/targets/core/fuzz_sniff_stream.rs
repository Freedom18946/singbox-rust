#![no_main]
//! Dedicated stream/datagram sniff entry point fuzzer
//!
//! Deeply exercises the top-level protocol sniffing functions:
//! - sniff_stream (TCP): TLS, HTTP, SSH, RDP, BitTorrent detection
//! - sniff_datagram (UDP): DNS, QUIC, DTLS, STUN, BitTorrent, NTP detection
//! - sniff_dns_query: DNS query domain extraction
//! - skip_sniff: server-first port check
//!
//! These are the main entry points that inbounds call on raw network data.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // --- Top-level entry points ---

    // TCP stream sniffing: tries TLS, HTTP, SSH, RDP, BitTorrent in order.
    let _ = sb_core::router::sniff::sniff_stream(data);

    // UDP datagram sniffing: tries DNS, DTLS, STUN, BitTorrent, QUIC, NTP.
    let _ = sb_core::router::sniff::sniff_datagram(data);

    // DNS query extraction.
    let _ = sb_core::router::sniff::sniff_dns_query(data);

    // --- skip_sniff with ports derived from input ---
    if data.len() >= 2 {
        let port = u16::from_be_bytes([data[0], data[1]]);
        let _ = sb_core::router::sniff::skip_sniff(port);
    }

    // --- Multi-packet datagram sniffing ---
    let (outcome, quic_state) = sb_core::router::sniff::sniff_datagram_multi(data);
    let _ = outcome;
    if let Some(ctx) = quic_state {
        // Feed sub-slices as continuation packets.
        if data.len() > 4 {
            let (result, ctx2) = sb_core::router::sniff::sniff_datagram_continue(&data[2..], ctx);
            let _ = result;
            if let Some(ctx2) = ctx2 {
                if data.len() > 8 {
                    let (r, _) = sb_core::router::sniff::sniff_datagram_continue(&data[4..], ctx2);
                    let _ = r;
                }
            }
        }
    }

    // --- Protocol-specific prefix patterns for deeper coverage ---

    // SSH banner prefix to exercise is_ssh_protocol.
    if data.len() >= 4 {
        let mut ssh_buf = Vec::with_capacity(8 + data.len());
        ssh_buf.extend_from_slice(b"SSH-2.0-");
        ssh_buf.extend_from_slice(data);
        let _ = sb_core::router::sniff::sniff_stream(&ssh_buf);
    }

    // RDP-like prefix to exercise is_rdp_protocol.
    if data.len() >= 14 {
        let mut rdp_buf = vec![0u8; 14];
        rdp_buf[0] = 0x03;
        rdp_buf[1] = 0x00;
        rdp_buf[2] = 0x00;
        rdp_buf[3] = 0x13;
        rdp_buf[4] = 0x0e;
        rdp_buf[5] = 0xe0;
        rdp_buf[11] = 0x01;
        rdp_buf[13] = 0x08;
        // Append fuzzer data
        rdp_buf.extend_from_slice(data);
        let _ = sb_core::router::sniff::sniff_stream(&rdp_buf);

        // Also test with fuzzer-modified RDP header bytes
        let mut rdp_fuzz = data[..14].to_vec();
        rdp_fuzz[0] = 0x03;
        rdp_fuzz[1] = 0x00;
        rdp_fuzz.extend_from_slice(&data[14..]);
        let _ = sb_core::router::sniff::sniff_stream(&rdp_fuzz);
    }

    // BitTorrent TCP handshake prefix.
    if data.len() >= 4 {
        let mut bt_buf = Vec::with_capacity(20 + data.len());
        bt_buf.push(19);
        bt_buf.extend_from_slice(b"BitTorrent protocol");
        bt_buf.extend_from_slice(data);
        let _ = sb_core::router::sniff::sniff_stream(&bt_buf);
    }

    // BitTorrent uTP (UDP) prefix.
    if data.len() >= 20 {
        let mut utp_buf = vec![0u8; 20];
        utp_buf[0] = 0x11; // type=1 version=1
        utp_buf[1..std::cmp::min(20, data.len())]
            .copy_from_slice(&data[..std::cmp::min(19, data.len() - 1)]);
        utp_buf[0] = 0x11; // Ensure type/version are correct
        utp_buf.extend_from_slice(data);
        let _ = sb_core::router::sniff::sniff_datagram(&utp_buf);
    }

    // DTLS record prefix.
    if data.len() >= 10 {
        let mut dtls_buf = Vec::with_capacity(13 + data.len());
        dtls_buf.push(22); // ContentType: Handshake
        dtls_buf.push(0xfe);
        dtls_buf.push(0xff); // DTLS 1.0
        dtls_buf.extend_from_slice(&[0; 10]); // Epoch + seq + length
        dtls_buf.extend_from_slice(data);
        let _ = sb_core::router::sniff::sniff_datagram(&dtls_buf);
    }

    // STUN message prefix.
    if data.len() >= 12 {
        let mut stun_buf = Vec::with_capacity(20 + data.len());
        stun_buf.extend_from_slice(&[0x00, 0x01]); // Binding Request
                                                   // Message length (multiple of 4)
        let msg_len = (data.len() & !3) as u16;
        stun_buf.push((msg_len >> 8) as u8);
        stun_buf.push(msg_len as u8);
        stun_buf.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]); // Magic cookie
        stun_buf.extend_from_slice(&[0; 12]); // Transaction ID
        stun_buf.extend_from_slice(data);
        let _ = sb_core::router::sniff::sniff_datagram(&stun_buf);
    }

    // NTP client packet prefix.
    if data.len() >= 48 {
        let mut ntp_buf = vec![0u8; 48];
        ntp_buf[0] = 0x1b; // LI=0, VN=3, Mode=3
                           // Copy fuzzer data into the NTP fields
        let copy_len = std::cmp::min(47, data.len());
        ntp_buf[1..1 + copy_len].copy_from_slice(&data[..copy_len]);
        ntp_buf[0] = 0x1b; // Ensure mode/version bits are correct
        ntp_buf.extend_from_slice(data);
        let _ = sb_core::router::sniff::sniff_datagram(&ntp_buf);
    }

    // --- DNS query with fuzzer-controlled domain ---
    if data.len() >= 8 {
        let mut dns_buf = vec![
            0x00, 0x01, // Transaction ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answer RRs
            0x00, 0x00, // Authority RRs
            0x00, 0x00, // Additional RRs
        ];
        // Append fuzzer data as domain labels + QTYPE/QCLASS
        dns_buf.extend_from_slice(data);
        let _ = sb_core::router::sniff::sniff_dns_query(&dns_buf);
        let _ = sb_core::router::sniff::sniff_datagram(&dns_buf);
    }

    // --- Sub-slice and truncation of both stream and datagram ---
    if data.len() > 8 {
        for trim in 1..std::cmp::min(data.len(), 6) {
            let truncated = &data[..data.len() - trim];
            let _ = sb_core::router::sniff::sniff_stream(truncated);
            let _ = sb_core::router::sniff::sniff_datagram(truncated);
            let _ = sb_core::router::sniff::sniff_dns_query(truncated);
        }
    }
});
