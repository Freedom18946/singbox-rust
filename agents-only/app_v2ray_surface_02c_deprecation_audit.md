# APP-V2RAY-SURFACE-02C - sb-api V2Ray deprecation impact audit

## Scope And Baseline

This card is audit-only. No Rust code, tests, fuzz targets, Cargo files, fixtures, CI files, or
REALITY artifacts were changed.

Pre-audit accepted commits were pushed first:

- `git push origin main`: pushed `ecbe3ffd..28106de7` to `origin/main`.
- Baseline status after push: `## main...origin/main` and `?? agents-only/a0_reality_spike/`.
- Recent commits confirmed: `28106de7 checkpoint: record sb-api v2ray naming bridge`,
  `d4191964 feat(sb-api): add explicit grpc v2ray server alias`,
  `ecbe3ffd checkpoint: propose sb-api v2ray surface redesign`.

## Export Graph

Current sb-api V2Ray public graph:

```text
crates/sb-api/src/v2ray/server.rs
  #[cfg(feature = "v2ray-api")]
  grpc_impl::V2RayApiServer
    -> pub use grpc_impl::V2RayApiServer
       as server::V2RayApiServer
    -> pub use grpc_impl::V2RayApiServer
       as server::GrpcV2RayApiServer

  #[cfg(not(feature = "v2ray-api"))]
  simple_impl::V2RayApiServer
    -> wraps SimpleV2RayApiServer
    -> pub use simple_impl::V2RayApiServer
       as server::V2RayApiServer

crates/sb-api/src/v2ray/mod.rs
  pub use server::V2RayApiServer
    -> sb_api::v2ray::V2RayApiServer
       feature-off/default: Simple wrapper, no TCP bind, no gRPC serve
       feature-on/all-features: tonic gRPC server, TCP bind, gRPC serve

  #[cfg(feature = "v2ray-api")]
  pub use server::GrpcV2RayApiServer
    -> sb_api::v2ray::GrpcV2RayApiServer
       always the feature-on tonic gRPC server

  pub use simple::SimpleV2RayApiServer
    -> sb_api::v2ray::SimpleV2RayApiServer
       legacy-compatible in-memory helper, no TCP bind, no gRPC serve

crates/sb-api/src/lib.rs
  #[cfg(feature = "v2ray-api")]
  pub use v2ray::V2RayApiServer
    -> sb_api::V2RayApiServer
       feature-on only, tonic gRPC server, generic old root name

  #[cfg(feature = "v2ray-api")]
  pub use v2ray::GrpcV2RayApiServer
    -> sb_api::GrpcV2RayApiServer
       feature-on only, explicit stable gRPC name
```

## Calling Radius

Product runtime callers:

- No workspace product runtime caller uses `sb_api::v2ray::V2RayApiServer`.
- No workspace product runtime caller uses `sb_api::V2RayApiServer`.
- No workspace product runtime caller uses `sb_api::v2ray::SimpleV2RayApiServer`.
- App bootstrap uses `sb_core::services::v2ray_api::V2RayApiServer`.
- sb-core supervisor uses `crate::services::v2ray_api::V2RayApiServer`.

Tests:

- `crates/sb-api/tests/v2ray_api_test.rs` uses `SimpleV2RayApiServer` and Simple request structs.
- `crates/sb-api/tests/monitoring_integration_test.rs` uses `SimpleV2RayApiServer`,
  `SimpleStatsRequest`, and `SimpleQueryStatsRequest`.
- `crates/sb-api/tests/v2ray_api_bad_inputs.rs` uses `SimpleStatsRequest`.
- `crates/sb-api/tests/v2ray_public_paths.rs` uses only the new explicit
  `GrpcV2RayApiServer` paths.
- `crates/sb-api/src/v2ray/simple.rs` unit tests use the Simple helper and Simple request structs.

Fuzz:

- `fuzz/targets/api/fuzz_v2ray_api.rs` uses
  `sb_api::v2ray::simple::{SimpleQueryStatsRequest, SimpleStatsRequest}`.
- Fuzz does not use either generic `V2RayApiServer` path or `GrpcV2RayApiServer`.

Docs and history:

- `agents-only/*` contains historical audit/checkpoint references to `SimpleV2RayApiServer`,
  `V2RayApiServer`, and the new `GrpcV2RayApiServer` bridge.
- These are not runtime callers and should not be counted as warning churn.

## Deprecated Attribute Probes

All probes used `/tmp` scratch files with `rustc 1.92.0 (ded5c06cf 2025-12-08)`. No repository
files were modified.

### Probe A - deprecated re-export versus new alias

Model:

```rust
pub struct Server;

#[deprecated(note = "use GrpcServer")]
pub use self::Server as OldServer;

pub use self::Server as GrpcServer;
```

Result:

- `#![deny(deprecated)] use probe::OldServer;` compiled successfully.
- Type-position and constructor-position uses of `OldServer` also compiled successfully.
- `GrpcServer` compiled successfully.

Conclusion: on this toolchain, attaching `#[deprecated]` directly to `pub use ... as ...` is
syntactically accepted but does not produce the compiler warning needed for the migration window.
The implementation card should not rely on deprecated re-export attributes as the warning vehicle.

Control model:

```rust
pub struct Server;

#[deprecated(note = "use GrpcServer")]
pub type OldServer = Server;

pub type GrpcServer = Server;
```

Result:

- `OldServer` failed under `#![deny(deprecated)]`.
- `GrpcServer` passed.

Conclusion: a deprecated type alias produces the intended warning without polluting the new alias.

### Probe B - deprecated underlying type

Model:

```rust
#[deprecated(note = "use GrpcServer")]
pub struct Server;

pub use Server as GrpcServer;
```

Result:

- `#![deny(deprecated)] use probe::GrpcServer;` failed.

Conclusion: do not put `#[deprecated]` on the underlying tonic server struct. That would pollute
`GrpcV2RayApiServer`, which is the desired replacement path.

### Probe C - module-level and crate-root old names

Re-export-only model:

- Deprecated `pub use` on module-level old alias did not warn.
- Deprecated `pub use` on crate-root old alias did not warn.
- Explicit gRPC paths passed.

Type-alias model:

```rust
pub mod v2ray {
    pub use server::GrpcV2RayApiServer;
    #[allow(deprecated)]
    pub use server::V2RayApiServer;
}

pub use v2ray::GrpcV2RayApiServer;

#[deprecated(note = "use GrpcV2RayApiServer")]
pub type V2RayApiServer = v2ray::GrpcV2RayApiServer;
```

with `server::V2RayApiServer` itself defined as a deprecated type alias.

Result:

- `probe::v2ray::V2RayApiServer` failed under `#![deny(deprecated)]`.
- `probe::V2RayApiServer` failed under `#![deny(deprecated)]`.
- `probe::v2ray::GrpcV2RayApiServer` passed.
- `probe::GrpcV2RayApiServer` passed.
- The probe library itself passed under `-D deprecated` only when internal compatibility re-exports
  that mention deprecated aliases used a narrow `#[allow(deprecated)]`, or when the root old name was
  a separate deprecated type alias pointing at the explicit gRPC alias rather than re-exporting the
  deprecated module alias.

Conclusion: both generic paths can be warned without affecting explicit gRPC paths, but the
implementation must handle internal re-export lint carefully.

### Probe D - attribute location and rustdoc

Result:

- `#[deprecated] pub use ... as ...` compiles, but did not create compiler diagnostics for external
  uses and rustdoc did not render a useful Deprecated badge on the re-export item.
- `#[deprecated] pub type OldServer = Server;` both warns at compile time and renders the rustdoc
  deprecation note.

Conclusion: the next implementation card should place deprecation on type aliases for the old
generic public paths, not on the underlying server type and not merely on `pub use`.

## Deprecation Candidate Matrix

| Public path | Current semantics | Workspace callers | Deprecate? | Replacement | Rationale |
| --- | --- | ---: | ---: | --- | --- |
| `sb_api::v2ray::V2RayApiServer` | Feature-dependent compatibility surface: Simple wrapper without `v2ray-api`, tonic gRPC with `v2ray-api` | 0 product/test/fuzz callers found | Yes | `sb_api::v2ray::GrpcV2RayApiServer` for network server; Simple helper for legacy in-memory contract | This is the semantic-drift path and the primary warning target. |
| `sb_api::V2RayApiServer` | Feature-on generic crate-root export of the tonic server | 0 product/test/fuzz callers found | Yes | `sb_api::GrpcV2RayApiServer` | Semantics are stable, but the old generic root name competes with the new explicit root name and would otherwise leave two public root names for the same network capability. Warning churn is zero in workspace. |
| `sb_api::v2ray::SimpleV2RayApiServer` | Legacy-compatible in-memory helper, no TCP bind, no gRPC serve | Tests use it; no product runtime caller found | No | Keep current explicit Simple path | It remains the Simple contract exercised by tests; deprecating it would create avoidable test churn and does not solve the generic-name drift. |
| `SimpleStatsRequest` / `SimpleQueryStatsRequest` | Legacy serde request contract for Simple helper | Tests and fuzz use them | No | Keep current explicit simple request paths | Fuzz relies on these as compatibility input contracts. |
| `sb_api::v2ray::GrpcV2RayApiServer` / `sb_api::GrpcV2RayApiServer` | Explicit feature-gated gRPC server aliases | `v2ray_public_paths` test only | No | Self | These are the stable replacement paths and must not be polluted by deprecated underlying types. |

Expected workspace warning churn after correct implementation:

- Zero product runtime warnings.
- Zero current test/fuzz warnings, because they do not use the two generic old aliases.
- Potential crate-internal warnings only if deprecated aliases are re-exported through old paths
  without local `#[allow(deprecated)]` or root direct type-alias handling. This is an implementation
  detail for APP-V2RAY-SURFACE-02D.

## Route Comparison

| Route | Summary | Impact | Decision |
| --- | --- | --- | --- |
| 1. Docs only | Keep old paths and rely on Rustdoc guidance | Lowest immediate risk, but no compiler migration signal; old generic root and drifting module path remain attractive | Not recommended |
| 2. Deprecate only module-level drifting alias | Warn only `sb_api::v2ray::V2RayApiServer`; keep `sb_api::V2RayApiServer` as docs-only generic root | Precisely targets feature drift, but leaves a generic root alias beside the explicit root alias | Acceptable but incomplete |
| 3. Deprecate both generic aliases | Warn `sb_api::v2ray::V2RayApiServer` and `sb_api::V2RayApiServer`; keep both `GrpcV2RayApiServer` paths and Simple contracts | Clear migration direction, zero workspace caller churn, nonbreaking if implemented as deprecated type aliases | Recommended |
| 4. Deprecate Simple helper and request structs | Warn legacy Simple helper and serde request contracts too | Creates test/fuzz churn and attacks the wrong surface; Simple remains useful as legacy contract | Reject |
| 5. Breaking cleanup | Delete old wrapper or remove feature-off same-name path | Solves the surface immediately but breaks public compatibility; belongs after a deprecation window | Reject for this stage |

## Classification

`B. GENERIC_ALIAS_SET_DEPRECATION_READY`

Reason: both generic `V2RayApiServer` names can enter a nonbreaking deprecation window now. The
module-level path is semantically drifting, and the crate-root path is stable but obsolete now that
`GrpcV2RayApiServer` exists at the same root. The Simple helper and request structs should stay
public and non-deprecated for now.

## Recommended Next Card

`APP-V2RAY-SURFACE-02D - deprecate generic V2RayApiServer compatibility aliases`

Minimum implementation guidance:

- Do not deprecate the underlying tonic struct.
- Do not deprecate `GrpcV2RayApiServer`.
- Do not deprecate `SimpleV2RayApiServer` or Simple request structs.
- Use deprecated type aliases for old generic paths rather than relying on `#[deprecated] pub use`.
- Keep feature conditions unchanged.
- Keep behavior unchanged.
- Handle crate-internal re-export lint explicitly so `cargo clippy -p sb-api --all-features
  --all-targets -- -D warnings` and rustdoc gates do not fail.

`SVC-V2RAY-API-01B` remains `DEFER / POLICY REVIEW`.
