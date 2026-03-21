#![no_main]
//! V2Ray API request parsing fuzzer
//!
//! Exercises deserialization of the real simplified V2Ray API request types
//! used by `sb_api::v2ray::simple`.

use libfuzzer_sys::fuzz_target;
use sb_api::v2ray::simple::{SimpleQueryStatsRequest, SimpleStatsRequest};

fuzz_target!(|data: &[u8]| {
    // Exercise the real request structs from arbitrary JSON bytes.
    let _ = serde_json::from_slice::<SimpleStatsRequest>(data);
    let _ = serde_json::from_slice::<SimpleQueryStatsRequest>(data);

    // Also exercise the string-based path for the same request structs.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<SimpleStatsRequest>(s);
        let _ = serde_json::from_str::<SimpleQueryStatsRequest>(s);
    }
});
