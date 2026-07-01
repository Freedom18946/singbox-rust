#![no_main]
//! Config parsing fuzzer
//!
//! Feeds arbitrary bytes as JSON to the sb-config parsing pipeline to ensure
//! robust error handling on malformed input. Exercises the full path:
//! serde_json parse -> migrate_to_v2 -> validate_v2 -> Config::from_value -> validate.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Attempt to parse arbitrary bytes as a JSON Value.
    // Most fuzz inputs will fail here, which is expected.
    let Ok(raw) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };

    // Exercise the full config parsing pipeline (migration + validation + IR).
    // This must never panic regardless of the JSON structure.
    let _ = sb_config::config_from_raw_value(raw.clone());

    // Also exercise the lighter-weight path that skips strict validation.
    let _ = sb_config::Config::from_value(raw.clone());

    // Exercise compatibility migration independently.
    let (migrated, _diags) = sb_config::compat::migrate_to_v2(&raw);

    // Exercise schema validation on the migrated value.
    let _issues = sb_config::validator::v2::validate_v2(&migrated, false);

    // Exercise IR conversion.
    let _ir = sb_config::validator::v2::to_ir_v1(&raw);
});
