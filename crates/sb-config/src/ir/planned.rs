//! Planning layer preflight contract — **still doc-only after WP-30k**.
//!
//! ## Purpose
//!
//! This module is reserved for the future **Planned** representation that will
//! sit between Validated IR and runtime construction:
//!
//! ```text
//! Raw → Validated (ConfigIR) → Planned (RuntimePlan) → Runtime owners
//! ```
//!
//! ## Current status (WP-30k)
//!
//! WP-30k did **not** implement `RuntimePlan`. It rebuilt the seam inventory
//! from current repository facts and recorded the authoritative map in
//! `agents-only/planned_preflight_inventory.md`.
//!
//! This module still exposes **no public planned-layer API**:
//!
//! - no public `RuntimePlan`
//! - no public `PlannedConfigIR`
//! - no public builder/helper entry point
//!
//! ## Inventory conclusions now pinned in-repo
//!
//! The WP-30k inventory found that the safest first cut is **not** runtime
//! construction or parse-time default migration. The recommended first cut is a
//! private planned seam that derives a tag/reference fact set from existing
//! validated IR, starting from the checks that currently live in
//! `crate::Config::validate()`:
//!
//! - outbound/endpoint shared tag namespace
//! - selector/urltest member references
//! - route rule outbound references
//! - `route.default` existence
//!
//! ## Responsibilities that still stay elsewhere
//!
//! These responsibilities remain with their current owners for now:
//!
//! - `validated.rs`: planning-adjacent IR self-checks such as
//!   selector/urltest non-empty-members and transport conflict validation
//! - `validator/v2/mod.rs`: parse-time compatibility/default materialization
//!   such as Shadowsocks method defaults, URLTest timing defaults, route
//!   `default`/`final` alias fill, and credential ENV resolution
//! - `crate::normalize` / `crate::minimize`: rule token canonicalization and
//!   minimization policy
//! - `crate::present`: legacy IR projection / JSON view helpers
//! - `app::bootstrap` / `app::run_engine`: runtime-side selector binding,
//!   router text emission, DNS env bridging, and other runtime-only derivations
//!
//! ## What the first implementation card should do
//!
//! The next planned-layer implementation should stay intentionally narrow:
//!
//! - introduce a **private** tag/reference inventory helper over `ConfigIR`
//! - reuse existing error surface instead of changing public API
//! - avoid moving validator business logic, runtime builder logic, or
//!   normalize/present/minimize behavior in the same card
