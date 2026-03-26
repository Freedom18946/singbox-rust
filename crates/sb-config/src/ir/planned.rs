//! Planning / RuntimePlan layer — **skeleton only**.
//!
//! ## Purpose
//!
//! This module will hold the **Planned** configuration representation — the
//! output of resolving defaults, verifying tag uniqueness, binding cross-
//! references (e.g. outbound detour → outbound tag), and computing a
//! dependency-ordered startup plan.
//!
//! The planned representation sits between Validated IR and runtime
//! construction:
//!
//! ```text
//! Raw → Validated (ConfigIR) → Planned (RuntimePlan) → Runtime owners
//! ```
//!
//! ## Current status (WP-30a)
//!
//! This file is a **doc-first skeleton** created as part of the WP-30a prelude
//! card. It does not yet contain any public types or logic. No `RuntimePlan`
//! builder exists yet.
//!
//! ## Future work
//!
//! - Define `RuntimePlan` struct holding resolved defaults, unique tag map,
//!   reference graph, and startup order
//! - Implement `RuntimePlan::from_validated(config: &ConfigIR) -> Result<Self>`
//! - Move default-resolution logic (currently scattered in bootstrap/validator)
//!   into this module
