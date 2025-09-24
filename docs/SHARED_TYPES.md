# Shared Types (sb-types)

## Goal
Break cycles between `sb-config` and `sb-core` by putting *only* stable contracts
into a small crate `sb-types`. Currently it contains:
- `IssueCode` (serde-enabled, SCREAMING_SNAKE_CASE),
- optional `IssuePayload` helper struct.

## Migration
- Replace imports `use sb_core::error_map::IssueCode` with `use sb_types::IssueCode`.
- Keep JSON contracts unchanged (field names and values intact).
- `sb-core/src/error_map.rs` remains as a light re-export for back-compat.

## Do/Don't
- Do keep `sb-types` minimal (no IR, no runtime structs).
- Don't move behavior here. Only stable *data* contracts that multiple crates need.