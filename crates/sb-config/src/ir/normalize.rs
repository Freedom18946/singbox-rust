//! IR normalization entry point — **skeleton only**.
//!
//! ## Purpose
//!
//! This module will serve as the entry point for IR normalization — the process
//! of canonicalizing, deduplicating, and simplifying an IR tree before it is
//! consumed by downstream layers (validator, planner, runtime builder).
//!
//! ## Current status (WP-30a)
//!
//! This file is a **doc-first skeleton** created as part of the WP-30a prelude
//! card. It does not yet contain any public types or logic.
//!
//! **Important**: The existing `crates/sb-config/src/normalize.rs` module is
//! unrelated to this file and its behavior is not affected by this card. That
//! module handles V1/V2 schema normalization at the JSON level, while this
//! module will handle IR-level normalization in the future.
//!
//! ## Future work
//!
//! - Define normalization passes (e.g. inline rule-set expansion, tag
//!   deduplication, transport chain canonicalization)
//! - Wire into the Raw → Validated → Planned pipeline
//! - Potentially subsume parts of the existing `normalize.rs` once the
//!   three-phase model is complete
