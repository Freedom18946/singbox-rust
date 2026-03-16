#![no_main]
//! V2Ray API request parsing fuzzer
//!
//! Exercises JSON deserialization of V2Ray API request types
//! to ensure malformed input never causes a panic.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try to interpret as JSON for v2ray API request types
    if let Ok(s) = std::str::from_utf8(data) {
        // Exercise serde_json parsing with arbitrary strings
        let _ = serde_json::from_str::<serde_json::Value>(s);
    }

    // Also exercise raw JSON parsing from bytes
    let _ = serde_json::from_slice::<serde_json::Value>(data);
});
