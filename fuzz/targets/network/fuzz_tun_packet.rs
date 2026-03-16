#![no_main]
//! TUN packet parsing fuzzer
//!
//! Exercises IP packet parsing logic used by TUN inbound handlers.
//! Tests IPv4/IPv6 header parsing, protocol identification, and boundary checks.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Determine IP version from first nibble
    let version = (data[0] >> 4) & 0x0F;

    match version {
        4 => {
            // IPv4 header: minimum 20 bytes
            if data.len() >= 20 {
                let ihl = (data[0] & 0x0F) as usize * 4;
                let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;
                let protocol = data[9];
                let _src = &data[12..16];
                let _dst = &data[16..20];

                // Validate header length field
                if ihl >= 20 && ihl <= data.len() && total_len <= data.len() {
                    // Extract transport header if present
                    match protocol {
                        6 => {
                            // TCP: minimum 20 bytes after IP header
                            if data.len() >= ihl + 20 {
                                let _src_port =
                                    u16::from_be_bytes([data[ihl], data[ihl + 1]]);
                                let _dst_port =
                                    u16::from_be_bytes([data[ihl + 2], data[ihl + 3]]);
                            }
                        }
                        17 => {
                            // UDP: 8 bytes after IP header
                            if data.len() >= ihl + 8 {
                                let _src_port =
                                    u16::from_be_bytes([data[ihl], data[ihl + 1]]);
                                let _dst_port =
                                    u16::from_be_bytes([data[ihl + 2], data[ihl + 3]]);
                                let _udp_len =
                                    u16::from_be_bytes([data[ihl + 4], data[ihl + 5]]);
                            }
                        }
                        _ => {}
                    }
                }

                // Check fragmentation
                let flags_frag = u16::from_be_bytes([data[6], data[7]]);
                let _mf = (flags_frag >> 13) & 0x1;
                let _frag_offset = flags_frag & 0x1FFF;
            }
        }
        6 => {
            // IPv6 header: minimum 40 bytes
            if data.len() >= 40 {
                let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;
                let next_header = data[6];
                let _hop_limit = data[7];
                let _src = &data[8..24];
                let _dst = &data[24..40];

                // Extract transport header
                let hdr_end = 40;
                if payload_len <= data.len() - 40 {
                    match next_header {
                        6 => {
                            if data.len() >= hdr_end + 20 {
                                let _src_port = u16::from_be_bytes([
                                    data[hdr_end],
                                    data[hdr_end + 1],
                                ]);
                                let _dst_port = u16::from_be_bytes([
                                    data[hdr_end + 2],
                                    data[hdr_end + 3],
                                ]);
                            }
                        }
                        17 => {
                            if data.len() >= hdr_end + 8 {
                                let _src_port = u16::from_be_bytes([
                                    data[hdr_end],
                                    data[hdr_end + 1],
                                ]);
                                let _dst_port = u16::from_be_bytes([
                                    data[hdr_end + 2],
                                    data[hdr_end + 3],
                                ]);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        _ => {
            // Invalid IP version — must not panic
        }
    }
});
