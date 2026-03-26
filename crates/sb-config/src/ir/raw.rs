//! Raw (serde-facing) configuration types — **skeleton only**.
//!
//! ## Purpose
//!
//! This module will hold the **Raw** configuration types that map 1:1 to the
//! on-disk JSON/YAML schema. All Raw types will derive `Deserialize` with
//! `#[serde(deny_unknown_fields)]` to enforce strict input boundaries.
//!
//! ## Current status (WP-30a)
//!
//! This file is a **doc-first skeleton** created as part of the WP-30a prelude
//! card. It does not yet contain any public types or logic. The existing
//! `outbound.rs` raw types (the Raw/Validated boundary pilot completed earlier)
//! remain in their current location and are not affected.
//!
//! ## Future work
//!
//! - Define `RawConfigRoot` / `RawInbound` / `RawOutbound` / `RawRoute` etc.
//!   with `deny_unknown_fields`
//! - Implement `TryFrom<RawConfigRoot> for ConfigIR` (or equivalent conversion)
//! - Move the serde entry point here so that `ConfigIR` no longer derives
//!   `Deserialize` directly from user input
