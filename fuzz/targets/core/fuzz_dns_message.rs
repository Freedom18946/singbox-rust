#![no_main]
//! DNS message parsing fuzzer
//!
//! Feeds arbitrary bytes to the lightweight DNS wire-format parsers in
//! sb-core::dns::message. These parsers handle untrusted network data and
//! must never panic on malformed input.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Exercise question key extraction (query parsing).
    let _ = sb_core::dns::message::parse_question_key(data);

    // Exercise minimum TTL scanning (response parsing).
    let _ = sb_core::dns::message::parse_min_ttl(data);

    // Exercise answer record parsing with name decompression.
    let _ = sb_core::dns::message::parse_answer_records(data);

    // Exercise A/AAAA IP extraction from answers.
    let _ = sb_core::dns::message::parse_all_answer_ips(data);

    // Exercise transaction ID extraction.
    let _ = sb_core::dns::message::get_query_id(data);

    // Exercise RCODE extraction.
    let _ = sb_core::dns::message::extract_rcode(data);

    // Exercise EDNS0 Client Subnet parsing.
    let _ = sb_core::dns::message::parse_edns0_client_subnet(data);

    // Exercise DNS response building (use data as a fake query).
    let ips = sb_core::dns::message::parse_all_answer_ips(data);
    if !ips.is_empty() {
        let _ = sb_core::dns::message::build_dns_response(data, &ips, 60, 0);
    } else {
        // Try building with empty IPs (NXDOMAIN case).
        let _ = sb_core::dns::message::build_dns_response(data, &[], 0, 3);
    }

    // Exercise ECS injection on a mutable copy.
    if data.len() >= 12 {
        let mut msg = data.to_vec();
        let _ = sb_core::dns::message::inject_edns0_client_subnet(&mut msg, "1.2.3.0/24");
    }

    // Exercise subnet string parsing with arbitrary data as string.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = sb_core::dns::message::parse_subnet(s);
    }
});
