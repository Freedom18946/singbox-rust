#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = sb_core::dns::message::parse_question_key(data);
    let _ = sb_core::dns::message::parse_min_ttl(data);
});

