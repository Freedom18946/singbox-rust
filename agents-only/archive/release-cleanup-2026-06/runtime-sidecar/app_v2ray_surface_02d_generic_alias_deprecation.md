# APP-V2RAY-SURFACE-02D - generic V2RayApiServer alias deprecation

## Scope

Implemented the additive deprecation window for the two generic sb-api V2Ray public paths:

- `sb_api::v2ray::V2RayApiServer`
- `sb_api::V2RayApiServer`

No runtime behavior, feature behavior, Cargo files, sb-core/app code, server/simple implementations,
fuzz targets, fixtures, REALITY artifacts, L18 assets, CI files, or `agents-only/a0_reality_spike/`
were changed.

Code commit:

- `60b88414 feat(sb-api): deprecate generic v2ray server aliases`

## Source-compatibility Gate

Pre-change review covered:

- `crates/sb-api/src/lib.rs`
- `crates/sb-api/src/v2ray/mod.rs`
- `crates/sb-api/src/v2ray/server.rs`
- `crates/sb-api/src/v2ray/simple.rs`
- `crates/sb-api/tests/`

Findings:

- Feature-off `server::V2RayApiServer` is a normal named-field struct wrapping
  `SimpleV2RayApiServer`; fields are private.
- Feature-on `grpc_impl::V2RayApiServer` is a normal named-field struct; fields are private.
- Both implementations are constructed through associated functions (`new`; Simple also exposes
  its own explicit helper API).
- Workspace search found no `V2RayApiServer { ... }`, tuple/unit constructor use, enum variant
  constructor use, or public pattern-matching contract for the old generic aliases.

Decision: deprecated type aliases are source-compatible for the retained public paths.

## Implementation

`sb_api::v2ray::V2RayApiServer` is now:

```rust
#[deprecated(
    note = "compatibility alias: use `GrpcV2RayApiServer` for the network gRPC server or `SimpleV2RayApiServer` for the legacy in-memory helper"
)]
pub type V2RayApiServer = server::V2RayApiServer;
```

This keeps the existing feature-dependent target:

- without `v2ray-api`: Simple wrapper, no TCP bind, no gRPC serve
- with `v2ray-api`: tonic gRPC server

`sb_api::V2RayApiServer` is now:

```rust
#[cfg(feature = "v2ray-api")]
#[deprecated(note = "use `sb_api::GrpcV2RayApiServer`")]
pub type V2RayApiServer = v2ray::GrpcV2RayApiServer;
```

The root alias points directly at `GrpcV2RayApiServer`, not at the deprecated module-level alias.

No `allow(deprecated)` was added.

## Public-path Probes

Compile-only `/private/tmp` rustc probes linked against per-feature local `sb-api` artifacts.

Results:

- New explicit gRPC paths:
  - `--no-default-features`: expected E0432
  - default features: expected E0432
  - `--features v2ray-api`: OK under `#![deny(deprecated)]`
  - `--all-features`: OK under `#![deny(deprecated)]`
- Module-level old alias:
  - all four feature modes fail under `#![deny(deprecated)]` with the deprecation diagnostic
  - all four feature modes compile without deny and emit only deprecation warnings
- Crate-root old alias:
  - no-default/default: expected E0432
  - `v2ray-api`/all-features: fail under `#![deny(deprecated)]`
  - `v2ray-api`/all-features: compile without deny and emit only deprecation warnings
- Simple contract:
  - all four feature modes compile under `#![deny(deprecated)]` for
    `SimpleV2RayApiServer`, `SimpleStatsRequest`, and `SimpleQueryStatsRequest`
- Associated constructors:
  - old module alias `V2RayApiServer::new(...)` resolves in all feature modes and emits only warnings
  - old root alias `V2RayApiServer::new(...)` resolves in feature-on modes and emits only warnings
  - new gRPC aliases resolve in feature-on modes under `#![deny(deprecated)]`

## Repository Verification

Passed:

- `cargo fmt -p sb-api --check`
- `cargo check -p sb-api --no-default-features`
- `cargo check -p sb-api`
- `cargo check -p sb-api --features v2ray-api`
- `cargo check -p sb-api --all-features`
- `cargo test -p sb-api --no-default-features --lib v2ray`
- `cargo test -p sb-api --no-default-features --test v2ray_api_test`
- `cargo test -p sb-api --no-default-features --test v2ray_api_bad_inputs`
- `cargo test -p sb-api --features v2ray-api v2ray`
- `cargo test -p sb-api --features v2ray-api --test v2ray_api_bad_inputs`
- `cargo test -p sb-api --features v2ray-api --test v2ray_public_paths`
- `cargo test -p sb-api --all-features v2ray`
- `cargo test -p sb-api --all-features --test v2ray_api_bad_inputs`
- `cargo test -p sb-api --all-features --test v2ray_public_paths`
- `cargo clippy -p sb-api --all-features --all-targets -- -D warnings`
- `cargo check --workspace --all-features`
- `RUSTDOCFLAGS="-D warnings" cargo doc -p sb-api --all-features --no-deps`
- `git diff --check`
- `bash agents-only/06-scripts/verify-consistency.sh`
- `bash agents-only/06-scripts/check-boundaries.sh`

## State

`APP-V2RAY-SURFACE-02D` is DONE.

`SVC-V2RAY-API-01B` remains `DEFER / POLICY REVIEW`.
