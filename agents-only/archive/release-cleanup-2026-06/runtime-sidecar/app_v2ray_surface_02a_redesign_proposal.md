<!-- tier: B -->
# APP-V2RAY-SURFACE-02A - sb-api V2Ray feature-surface redesign proposal

Status: DONE proposal only. No Rust source, Cargo, tests, or fuzz changes.

## Baseline

- Starting status: only `agents-only/a0_reality_spike/` was untracked.
- Recent commits confirmed:
  - `9a16a13f checkpoint: define sb-api v2ray compatibility policy`
  - `9f847f3d checkpoint: audit orphan simple v2ray api helper`
  - `9939eccb checkpoint: record bootstrap v2ray listener wiring`
  - `a80a0916 fix(app): wire bootstrap v2ray api to real listener`
- `agents-only/a0_reality_spike/` remains unrelated REALITY spike material and was not staged.

## Executive Decision

Unique classification: **A. ADDITIVE_BRIDGE_READY**.

The root invariant is accepted:

```text
The same public type path must not silently switch capability models by feature flag.
```

The least-risk path is a staged, nonbreaking explicit naming bridge:

- keep the current public paths during the migration window;
- add explicit stable paths for legacy in-memory Simple and feature-gated gRPC server;
- move tests/fuzz to explicit legacy/request paths;
- later deprecate ambiguous aliases;
- remove the feature-dependent same-name drift only in a breaking cleanup.

Recommended next card: **APP-V2RAY-SURFACE-02B - sb-api V2Ray additive explicit naming bridge**.

## Current Public Symbol Inventory

Evidence:

- `crates/sb-api/Cargo.toml`: `default = ["clash-api"]`,
  `v2ray-api = ["tonic", "prost", "prost-types", "tokio-stream", "http-body"]`.
- `crates/sb-api/src/lib.rs`: `pub mod v2ray;` is unconditional; crate-root
  `pub use v2ray::V2RayApiServer;` is gated by `feature = "v2ray-api"`.
- `crates/sb-api/src/v2ray/mod.rs`: `pub mod server;`, `pub mod simple;`,
  `pub use server::V2RayApiServer;`, and `pub use simple::SimpleV2RayApiServer;`
  are unconditional. `services` and `generated` are gated by `feature = "v2ray-api"`.
- `crates/sb-api/src/v2ray/server.rs`: feature-off exports a Simple wrapper;
  feature-on exports a tonic gRPC implementation.

| Public path | Feature condition | Actual implementation | Constructor / methods | TCP bind | gRPC serve | Current callers |
|---|---|---|---|---:|---:|---|
| `sb_api::v2ray::simple::SimpleV2RayApiServer` | Always | In-memory Simple server | `new`, `with_monitoring`, `start`, `start_with_shutdown`, `get_stats`, `query_stats`, `update_traffic`, `subscribe_stats`, `get_all_stats` | No | No | sb-api tests |
| `sb_api::v2ray::SimpleV2RayApiServer` | Always | Re-export of `simple::SimpleV2RayApiServer` | Same as above | No | No | sb-api tests |
| `sb_api::v2ray::V2RayApiServer` | Always | Feature-off: `simple_impl::V2RayApiServer` wrapping Simple. Feature-on: `grpc_impl::V2RayApiServer` | Feature-off: `new`, `start`, `inner`. Feature-on: `new`, `start` | Feature-off no; feature-on yes inside tonic `serve` | Feature-off no; feature-on yes | No workspace runtime caller found |
| `sb_api::V2RayApiServer` | `v2ray-api` only | Re-export of feature-on `sb_api::v2ray::V2RayApiServer` | `new`, `start` | Yes | Yes | No workspace runtime caller found |
| `sb_api::v2ray::simple::SimpleStat` | Always | Simple serializable stat value | data struct | No | No | sb-api monitoring reporter |
| `sb_api::v2ray::simple::SimpleStatsRequest` | Always | Simple serde request | data struct | No | No | tests and fuzz |
| `sb_api::v2ray::simple::SimpleStatsResponse` | Always | Simple serde response | data struct | No | No | tests |
| `sb_api::v2ray::simple::SimpleQueryStatsRequest` | Always | Simple serde request | data struct | No | No | tests and fuzz |
| `sb_api::v2ray::simple::SimpleQueryStatsResponse` | Always | Simple serde response | data struct | No | No | tests |
| `sb_api::v2ray::generated::*` request/response structs | `v2ray-api` only | Stub gRPC-ish request surface in `mod.rs` | data structs and service wrappers | By server only | By server only | No app runtime caller found |
| `sb_api::v2ray::services::*` | `v2ray-api` only | sb-api tonic service implementations | service impls and re-exported service traits | By server only | Yes | No app runtime caller found |

Additional generated structs exposed under `v2ray-api`: `InboundHandlerConfig`,
`GetStatsRequest`, `GetStatsResponse`, `QueryStatsRequest`, `QueryStatsResponse`,
`SysStatsRequest`, `SysStatsResponse`, `Stat`, inbound/outbound handler request/response
types, routing request/context types, and logger request/log entry types.

## Feature-Mode Probe Results

The requested `/tmp` Cargo probe crates were created, but direct `cargo check --manifest-path`
was blocked before path checking by offline registry source resolution for `rustls` in the
temporary crate lockfile. No product code was modified.

Equivalent compile-only probes were then run from `/tmp`: build `sb-api` in the requested feature
mode with a temporary `CARGO_TARGET_DIR`, then invoke `rustc` against the generated `sb-api`
`rlib` to check public paths and method sets.

| Mode | `sb_api::v2ray::SimpleV2RayApiServer` | `sb_api::v2ray::V2RayApiServer` | `sb_api::V2RayApiServer` | Method-set evidence | Result |
|---|---|---|---|---|---|
| `--no-default-features` | Exists | Exists; Simple wrapper | Absent | `server.inner()` compiles; root import fails with `E0432`, gated behind `v2ray-api` | PASS as expected |
| default features | Exists | Exists; Simple wrapper | Absent | `server.inner()` compiles; root import fails with `E0432`, gated behind `v2ray-api` | PASS as expected |
| `--features v2ray-api` | Exists | Exists; gRPC server | Exists | root/module type assignment compiles; `server.inner()` fails with `E0599` | PASS as expected |
| `--features clash-api,v2ray-api` | Exists | Exists; gRPC server | Exists | root/module type assignment compiles; `server.inner()` fails with `E0599` | PASS as expected |

Supporting build checks:

- `cargo check -p sb-api --no-default-features` - PASS
- `cargo check -p sb-api` - PASS
- `cargo check -p sb-api --features v2ray-api` - PASS
- `cargo check -p sb-api --features clash-api,v2ray-api` - PASS

Conclusion: the module-level path `sb_api::v2ray::V2RayApiServer` is stable as a symbol but
not stable as a capability model. Feature-off it is a no-network Simple wrapper; feature-on it is
a network gRPC server.

## Runtime Callers

Workspace product runtime does not call `sb_api::v2ray::V2RayApiServer` or
`SimpleV2RayApiServer`.

Current runtime callers use sb-core:

- `app/src/bootstrap_runtime/api_services.rs` constructs
  `sb_core::services::v2ray_api::V2RayApiServer`.
- `app/src/bootstrap.rs` delegates to `start_v2ray_api_server`.
- `crates/sb-core/src/runtime/supervisor.rs` constructs
  `crate::services::v2ray_api::V2RayApiServer`.

## Tests And Fuzz Callers

- `crates/sb-api/tests/v2ray_api_test.rs` uses `SimpleV2RayApiServer` and Simple request structs.
- `crates/sb-api/tests/v2ray_api_bad_inputs.rs` uses `SimpleStatsRequest`.
- `crates/sb-api/tests/monitoring_integration_test.rs` uses `SimpleV2RayApiServer`,
  `SimpleStatsRequest`, and `SimpleQueryStatsRequest`.
- `crates/sb-api/src/v2ray/simple.rs` unit tests exercise Simple server stats behavior.
- `fuzz/targets/api/fuzz_v2ray_api.rs` uses only
  `SimpleStatsRequest` and `SimpleQueryStatsRequest`.

These callers are useful as legacy/request contract coverage, but they are not evidence that
Simple is current product runtime.

## sb-api Versus sb-core Real Listener

The feature-on sb-api tonic implementation and the sb-core real listener are **parallel
implementations**, not the same implementation and not a direct wrapper.

| Dimension | `sb-api` feature-on gRPC server | `sb-core::services::v2ray_api::V2RayApiServer` |
|---|---|---|
| Config type | `sb_api::types::ApiConfig` | `sb_config::ir::V2RayApiIR` |
| Server trait | Plain sb-api type | Implements `sb_core::context::V2RayServer` |
| Listener bind | tonic `Server::serve(self.config.listen_addr).await` | synchronous pre-bind via std `TcpListener`, then tonic incoming stream |
| Startup honesty | bind error occurs in awaited `start()` path, but no pre-bound handle model | bind error surfaces before `start()` returns `Ok` |
| Shutdown | no public `close` or shutdown signal on sb-api server | `close()` sends shutdown and resets started state |
| Stats source | internal `HashMap<String, i64>` in `StatsServiceImpl`; mock/system placeholders | `StatsManager` wired to traffic recorders and standard counters |
| Served services | Stats, Handler, Router, Logger stubs | Stats service only |
| Product runtime use | none found | app bootstrap and run-engine supervisor |

Long-term responsibility judgment:

- `sb-core` should remain the runtime listener authority for app/supervisor lifecycle.
- `sb-api` may retain public API facade/request types and a legacy in-memory Simple stats helper.
- If `sb-api` keeps a network server, it needs an explicit gRPC/runtime name and should not share
  the ambiguous `V2RayApiServer` path with a non-network fallback.
- Directly merging sb-api and sb-core listener implementations is not required for the first
  additive bridge and should remain a separate boundary review.

## Design Routes

| Route | Description | Compatibility | Risk / cost | Decision |
|---|---|---|---|---|
| 1. Maintain status quo | Keep feature-conditioned `sb_api::v2ray::V2RayApiServer` drift | Nonbreaking | Preserves misleading no-network fallback and violates future invariant | Reject |
| 2. Additive explicit naming bridge | Add explicit stable public paths, keep old paths for now | Nonbreaking | Requires docs/tests for new names, but no behavior removal | **Recommended** |
| 3. Feature-on only stable network symbol | Make `sb_api::v2ray::V2RayApiServer` exist only under `v2ray-api` and always mean gRPC | Breaking for feature-off users | Good final state, not safe as first move | Later major cleanup |
| 4. Split legacy stats helper and runtime listener surface | Keep Simple as legacy non-network utility; use explicit `grpc`/runtime naming or sb-core for listener | Can start nonbreaking, may later break ambiguous aliases | May expose sb-api/sb-core duplication; boundary review if reusing sb-core | Fold into route 2 now, revisit boundary later |
| 5. Next major delete Simple contract | Deprecate first, then delete or move Simple after migration | Breaking | Needs semver/release policy and fuzz/test migration | Later only |

Chosen route details for the next implementation card:

- Keep existing paths unchanged in Phase 1.
- Add feature-gated explicit gRPC path such as
  `sb_api::v2ray::grpc::GrpcV2RayApiServer`.
- Add or formalize explicit legacy path such as
  `sb_api::v2ray::legacy::{SimpleV2RayApiServer, SimpleStatsRequest, SimpleQueryStatsRequest}`.
- Continue to expose existing `sb_api::v2ray::simple::*` during the migration window.
- Do not change app/runtime behavior; do not delete or rename the current ambiguous path yet.

## Staged Migration Plan

### Phase 0: Current state freeze

- Goal: prevent new product runtime dependencies on Simple.
- Breaking: no.
- Change scope: policy/doc only.
- Old caller behavior: unchanged.
- New caller guidance: avoid `SimpleV2RayApiServer` for runtime listener semantics.
- Tests/fuzz: unchanged.
- Stop condition: any new app/runtime path attempts to call Simple or feature-off wrapper.

### Phase 1: Nonbreaking additive bridge

- Goal: introduce honest, stable names without removing old paths.
- Breaking: no.
- Change scope: sb-api module exports and docs only; no app, no Cargo feature changes.
- Old caller behavior: unchanged, including ambiguous `sb_api::v2ray::V2RayApiServer`.
- New caller guidance:
  - use explicit legacy/simple path for in-memory stats helper;
  - use explicit `grpc` path under `v2ray-api` for a network gRPC server;
  - use sb-core for app/supervisor runtime lifecycle.
- Tests/fuzz: add compile tests for explicit paths; keep Simple contract tests.
- Stop condition: implementing the bridge requires sb-api/sb-core boundary changes or feature
  rework.

### Phase 2: Deprecation window

- Goal: move callers away from ambiguous aliases.
- Breaking: no, if limited to docs and `#[deprecated]`.
- Change scope: deprecate ambiguous `sb_api::v2ray::V2RayApiServer` compatibility alias and,
  if policy accepts, direct Simple server paths that do not name legacy/non-network semantics.
- Old caller behavior: compiles with warnings.
- New caller guidance: explicit `legacy` or `grpc` paths only.
- Tests/fuzz: migrate fuzz imports to explicit request path; keep compatibility tests for
  deprecated aliases until major cleanup.
- Stop condition: no release policy exists for public deprecation notices.

### Phase 3: Breaking cleanup

- Goal: remove the feature-dependent same-name drift.
- Breaking: yes.
- Change scope: remove feature-off Simple wrapper from `sb_api::v2ray::V2RayApiServer`; either
  make that path feature-on-only gRPC or remove it in favor of `GrpcV2RayApiServer`.
- Old caller behavior: feature-off ambiguous server users must migrate.
- New caller guidance: explicit legacy stats helper or explicit gRPC server.
- Tests/fuzz: remove deprecated alias tests; keep request fuzzing in the final request module or
  migrate to sb-core gRPC request tests.
- Stop condition: external compatibility policy or major-release timing is not approved.

## External Compatibility Risk

- `crates/sb-api/Cargo.toml` has `version = "0.1.0"`, description, license, repository, and
  readme metadata.
- No `publish = false` was found for `sb-api`; previous metadata inspection reported
  `"publish": null`.
- `git tag --list` shows at least `v0.2.0`.
- Repository evidence cannot prove any external user exists, but it also cannot exclude one.

Compatibility policy: treat `sb-api` as a potential external public surface. Do not delete or
rename public V2Ray symbols without a deprecation window or major-release cleanup.

## Classification

**A. ADDITIVE_BRIDGE_READY**

Reason: the next safe move does not require breaking old paths and does not require an sb-api /
sb-core boundary redesign. A nonbreaking bridge can add explicit names first, then later cards can
deprecate and remove the ambiguous same-name drift.

## Recommended Next Card

**APP-V2RAY-SURFACE-02B - sb-api V2Ray additive explicit naming bridge**

Scope for that card:

- implement explicit sb-api legacy/simple and gRPC public paths;
- keep existing paths available;
- add compile-level coverage for the new names across feature modes;
- do not delete old paths and do not alter app/runtime behavior.

## Validation

Executed for this proposal:

- `cargo check -p sb-api --no-default-features` - PASS
- `cargo check -p sb-api` - PASS
- `cargo check -p sb-api --features v2ray-api` - PASS
- `cargo check -p sb-api --features clash-api,v2ray-api` - PASS
- `/tmp` rustc compile-only public-path probes - PASS/expected FAIL as documented above

Final card validation:

- `git diff --check` - PASS
- `bash agents-only/06-scripts/verify-consistency.sh` - PASS
- `bash agents-only/06-scripts/check-boundaries.sh` - PASS

`SVC-V2RAY-API-01B` remains **DEFER / POLICY REVIEW**.
