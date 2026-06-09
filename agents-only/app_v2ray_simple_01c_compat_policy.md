<!-- tier: B -->
# APP-V2RAY-SIMPLE-01C - sb-api V2Ray compatibility policy

Status: DONE audit report only. No Rust source change.

## Baseline

- Starting status: only `agents-only/a0_reality_spike/` was untracked.
- Recent commits confirmed:
  - `9f847f3d checkpoint: audit orphan simple v2ray api helper`
  - `9939eccb checkpoint: record bootstrap v2ray listener wiring`
  - `a80a0916 fix(app): wire bootstrap v2ray api to real listener`
- `agents-only/a0_reality_spike/` remains unrelated REALITY spike material and was not staged.

## Executive Decision

Unique classification: **C. FEATURE_SURFACE_REDESIGN_REQUIRED**.

`SimpleV2RayApiServer` alone is ready for non-breaking legacy documentation, but that is not enough:
`sb_api::v2ray::V2RayApiServer` is a public same-name type whose implementation changes by feature
mode. Without `sb-api/v2ray-api`, it is a no-network Simple wrapper. With `sb-api/v2ray-api`, it is
a tonic gRPC server that binds and serves. That feature-conditioned semantic drift can mislead crate
users even if `SimpleV2RayApiServer` gets deprecated. The next card should therefore design the
public V2Ray surface first, then implement annotations or renames afterward.

## Feature Definitions

Evidence:

- `crates/sb-api/Cargo.toml`:
  - `default = ["clash-api"]`
  - `clash-api = []`
  - `v2ray-api = ["tonic", "prost", "prost-types", "tokio-stream", "http-body"]`
- `crates/sb-api/src/lib.rs`:
  - `pub mod v2ray;` is unconditional.
  - crate-root `pub use v2ray::V2RayApiServer;` is gated behind `feature = "v2ray-api"`.
- `crates/sb-api/src/v2ray/mod.rs`:
  - `pub mod server;` and `pub mod simple;` are unconditional.
  - `pub use server::V2RayApiServer;` and `pub use simple::SimpleV2RayApiServer;` are unconditional.
  - `services` and generated gRPC-ish modules are gated behind `feature = "v2ray-api"`.
- `crates/sb-api/src/v2ray/server.rs`:
  - `feature = "v2ray-api"` exports `grpc_impl::V2RayApiServer`.
  - `not(feature = "v2ray-api")` exports `simple_impl::V2RayApiServer`, which wraps
    `SimpleV2RayApiServer`.

## Public API Feature Matrix

| Mode | `SimpleV2RayApiServer` public? | `sb_api::v2ray::V2RayApiServer` points to | Binds TCP? | Serves gRPC? |
|---|---:|---|---:|---:|
| `--no-default-features` | Yes: `sb_api::v2ray::SimpleV2RayApiServer` and `sb_api::v2ray::simple::*` | `simple_impl::V2RayApiServer` wrapping `SimpleV2RayApiServer`; crate-root `sb_api::V2RayApiServer` absent | No | No |
| default features | Yes | Same simple wrapper; crate-root `sb_api::V2RayApiServer` absent | No | No |
| `--features v2ray-api` | Yes | `grpc_impl::V2RayApiServer`; crate-root `sb_api::V2RayApiServer` also exported | Yes, inside async `start().await` via tonic `Server::serve` | Yes |
| `--all-features` | Yes | Same gRPC implementation as `--features v2ray-api`; crate-root export present | Yes, inside async `start().await` | Yes |

Important nuance: the sb-api gRPC implementation is real network serving, but it is not the
01A bootstrap path. App bootstrap and run-engine now use `sb_core::services::v2ray_api::V2RayApiServer`.

## Feature Matrix Validation

Check commands:

- `cargo check -p sb-api --no-default-features` - PASS
- `cargo check -p sb-api` - PASS
- `cargo check -p sb-api --features v2ray-api` - PASS
- `cargo check -p sb-api --all-features` - PASS

Requested test command caveat:

- `cargo test -p sb-api --no-default-features v2ray` - FAILS before V2Ray assertions because Cargo
  still compiles all sb-api integration test targets, and multiple Clash tests import
  `sb_api::clash` while `clash-api` is disabled. This is a feature-gating issue in test targets,
  not a Simple V2Ray test failure.

Equivalent V2Ray-only no-default validation:

- `cargo test -p sb-api --no-default-features --lib v2ray` - PASS, 5/5
- `cargo test -p sb-api --no-default-features --test v2ray_api_test` - PASS, 6/6
- `cargo test -p sb-api --no-default-features --test v2ray_api_bad_inputs` - PASS, 2/2

Feature-enabled tests:

- `cargo test -p sb-api --features v2ray-api v2ray` - PASS, matching V2Ray tests: lib 5/5 +
  `v2ray_api_test` 6/6. `v2ray_api_bad_inputs` compiled but its test names do not contain `v2ray`,
  so it was filtered out.
- `cargo test -p sb-api --features v2ray-api --test v2ray_api_bad_inputs` - PASS, 2/2.
- `cargo test -p sb-api --all-features v2ray` - PASS, matching V2Ray tests: lib 5/5 +
  `v2ray_api_test` 6/6. `v2ray_api_bad_inputs` was filtered out by test name.
- `cargo test -p sb-api --all-features --test v2ray_api_bad_inputs` - PASS, 2/2.

## Fuzz Dependency

Evidence:

- `fuzz/Cargo.toml` depends on `sb-api = { path = "../crates/sb-api", default-features = false }`.
- `fuzz/targets/api/fuzz_v2ray_api.rs` imports
  `sb_api::v2ray::simple::{SimpleQueryStatsRequest, SimpleStatsRequest}`.
- The fuzz target validates deserialization of Simple request structs only. It does not depend on
  `SimpleV2RayApiServer`, `sb_api::v2ray::V2RayApiServer`, or `sb-api/v2ray-api`.

## External Compatibility Evidence

Commands used:

- `cargo metadata --format-version 1 --no-deps > /tmp/singbox-cargo-metadata.json`
- `git tag --list | tail -n 40`
- metadata inspection for `sb-api`

Findings:

- `sb-api` does **not** set `publish = false`; cargo metadata reports `"publish": null`.
- `crates/sb-api/Cargo.toml` declares `version = "0.1.0"`, description, workspace license,
  workspace repository, and workspace readme.
- Workspace metadata declares repository, license, readme, and rust-version.
- Git tag scan shows at least `v0.2.0`.
- No root `CHANGELOG*` file was found; docs contain general breaking-change/deprecation guidance,
  but no sb-api-specific semver policy for this surface.

Compatibility conclusion: repository evidence cannot prove any external user exists, but it also
cannot exclude external dependency. Because there is no `publish = false` or explicit internal-only
marker, treat the current public surface as a potential external compatibility surface.

## Object-Specific Policy

### A. `SimpleV2RayApiServer`

- Always public through `sb_api::v2ray::SimpleV2RayApiServer`.
- tests/fuzz dependency: tests use the server and simple request structs; fuzz uses only request
  structs.
- product runtime caller: none found after APP-V2RAY-SIMPLE-01A.
- suitable legacy status: yes. It should be documented as legacy / in-memory / non-network.
- suitable non-breaking `#[deprecated]`: yes for the server type and possibly `start()` /
  `start_with_shutdown()`, provided request structs remain usable or are separately classified.
- direct deletion: no. It would break public symbols, tests, fuzz request imports if moved too
  broadly, and the non-`v2ray-api` wrapper.

### B. `sb_api::v2ray::V2RayApiServer`

- Feature-conditioned implementation: yes.
- Construction shape is mostly consistent (`new(ApiConfig) -> ApiResult<Self>`), but behavior is
  not consistent.
- Startup semantics differ:
  - no `v2ray-api`: `start()` returns after starting a synthetic stats task; no listener exists.
  - with `v2ray-api`: `start().await` runs tonic `Server::serve` on `listen_addr`.
- There is same-name capability drift: no-network stats wrapper vs network gRPC server.
- This can mislead crate users because `sb_api::v2ray::V2RayApiServer` does not name the capability
  boundary and crate-root re-export exists only with `v2ray-api`.
- It needs separate public-surface governance. Annotating only `SimpleV2RayApiServer` leaves the
  same-name wrapper drift unresolved.

### C. tests / fuzz

- Current tests validate the Simple compatibility layer, not current app product runtime.
- Keeping tests/fuzz is useful as legacy contract coverage while public symbols remain.
- If Simple is eventually removed, tests should either move to a public legacy-compat crate/module
  during deprecation, or migrate to sb-core real gRPC tests; fuzz request structs need a replacement
  home before deleting `sb_api::v2ray::simple::*`.

## Route Comparison

| Route | Description | Benefit | Cost / risk | Fit now |
|---|---|---|---|---|
| 1. Maintain status quo | No docs, no annotations, no behavior change | Zero churn | Leaves public same-name drift and non-network Simple semantics misleading | No |
| 2. Non-breaking legacy marking | Keep public surface; document Simple as legacy/non-network; optionally add `#[deprecated]`; retain tests/fuzz as compat contracts | Low risk for Simple itself; useful near-term cleanup | Incomplete alone because `V2RayApiServer` same-name feature drift remains | Partial only |
| 3. Only govern Simple helper | Mark/deprecate `SimpleV2RayApiServer`; leave `sb_api::v2ray::V2RayApiServer` feature behavior unchanged | Smallest implementation card | Half-fix: wrapper still changes network semantics by feature and can still mislead | Not recommended |
| 4. Unify sb-api V2Ray public surface | Redesign names/modules so real listener and simple stats helper are explicit separate surfaces | Addresses root ambiguity | Requires public API design, possible breaking plan or staged aliases | **Recommended next** |
| 5. Next-major removal | Deprecate now, remove helper/wrapper/tests/fuzz compat later in breaking release | Clean long-term endpoint | Requires release/version policy and migration window; not immediate | Later, after route 4 policy |

## Classification

**C. FEATURE_SURFACE_REDESIGN_REQUIRED**

Reason: non-breaking legacy annotation is viable for `SimpleV2RayApiServer`, but it does not resolve
the feature-conditioned semantic drift of `sb_api::v2ray::V2RayApiServer`. The public surface must be
designed before implementing annotations, renames, or removals.

## Recommended Next Card

**APP-V2RAY-SURFACE-02A - sb-api V2Ray feature-surface redesign proposal**

Required output for that card:

- decide public names for real gRPC server vs simple in-memory stats helper;
- decide whether existing names become aliases, deprecated aliases, or breaking removals;
- define test/fuzz migration policy;
- preserve app/runtime behavior and keep `SVC-V2RAY-API-01B` out of scope.

## Validation

Executed:

- `git diff --check` - PASS
- `bash agents-only/06-scripts/verify-consistency.sh` - PASS
- `bash agents-only/06-scripts/check-boundaries.sh` - PASS

`SVC-V2RAY-API-01B` remains **DEFER / POLICY REVIEW**.
