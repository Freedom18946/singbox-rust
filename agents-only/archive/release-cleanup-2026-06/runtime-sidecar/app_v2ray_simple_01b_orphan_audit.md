<!-- tier: B -->
# APP-V2RAY-SIMPLE-01B - orphan SimpleV2RayApiServer reachability audit

Status: DONE audit report only. No business-source change.

## Baseline

- Starting status: only `agents-only/a0_reality_spike/` was untracked.
- Recent commits confirmed:
  - `9939eccb checkpoint: record bootstrap v2ray listener wiring`
  - `a80a0916 fix(app): wire bootstrap v2ray api to real listener`
- `agents-only/a0_reality_spike/` remains unrelated REALITY spike material and was not staged.

## Executive Decision

Unique classification: **C. ORPHAN_PUBLIC_COMPAT_SURFACE**.

Workspace product runtime no longer calls `sb_api::v2ray::SimpleV2RayApiServer` after
APP-V2RAY-SIMPLE-01A. However, the helper is still part of the public `sb-api` module surface:
`crates/sb-api/src/v2ray/mod.rs` public-reexports `simple::SimpleV2RayApiServer`, and
`sb_api::v2ray::V2RayApiServer` uses a `SimpleV2RayApiServer` wrapper when `sb-api/v2ray-api` is
not enabled. The repository can prove "no workspace product caller"; it cannot prove external
callers do not exist. Therefore deletion or `cfg(test)` contraction needs a compatibility policy
card first.

## Reference Scan Conclusion

Command used:

```text
rg -n "SimpleV2RayApiServer|start_with_shutdown|sb_api::v2ray|V2RayApiServer|V2RayServer" --glob '!target/**' .
```

Findings:

- Product runtime call sites now use sb-core:
  - `app/src/bootstrap_runtime/api_services.rs` constructs
    `sb_core::services::v2ray_api::V2RayApiServer`.
  - `crates/sb-core/src/runtime/supervisor.rs` constructs the same sb-core server.
- `SimpleV2RayApiServer` remains in:
  - `crates/sb-api/src/v2ray/simple.rs`
  - `crates/sb-api/src/v2ray/mod.rs` public re-export
  - `crates/sb-api/src/v2ray/server.rs` non-`v2ray-api` wrapper
  - `crates/sb-api/tests/v2ray_api_test.rs`
  - `crates/sb-api/tests/monitoring_integration_test.rs`
  - `crates/sb-api/tests/v2ray_api_bad_inputs.rs`
  - `fuzz/targets/api/fuzz_v2ray_api.rs`

## Public Surface Evidence

- `crates/sb-api/src/lib.rs` declares `pub mod v2ray;`.
- `crates/sb-api/src/v2ray/mod.rs` declares `pub mod simple;` and
  `pub use simple::SimpleV2RayApiServer;`.
- `crates/sb-api/src/v2ray/server.rs` has two public `V2RayApiServer` implementations:
  - with `feature = "v2ray-api"`: tonic gRPC server using `serve(self.config.listen_addr)`;
  - without `feature = "v2ray-api"`: public wrapper holding `inner: SimpleV2RayApiServer`.
- `crates/sb-api/Cargo.toml` has repository/license metadata and no `publish = false` evidence in
  the crate manifest. Treat it as a public crate surface for compatibility purposes.

Correct risk statement: workspace-internal product callers were not found; repository evidence
cannot prove external callers are absent.

## Runtime And Test Reachability

### Workspace product runtime callers

None found for `SimpleV2RayApiServer`.

Current product paths:

```text
bootstrap:
app/src/bootstrap.rs
  -> app/src/bootstrap_runtime/api_services.rs::start_v2ray_api_server
  -> sb_core::services::v2ray_api::V2RayApiServer
  -> V2RayServer::start()

run-engine:
crates/sb-core/src/runtime/supervisor.rs::wire_experimental_sidecars
  -> sb_core::services::v2ray_api::V2RayApiServer
  -> V2RayServer::start()
```

### Tests, docs, examples, benches, fuzz

- Tests directly using the helper:
  - `crates/sb-api/src/v2ray/simple.rs` in-module tests
  - `crates/sb-api/tests/v2ray_api_test.rs`
  - `crates/sb-api/tests/monitoring_integration_test.rs`
- Tests using simple request structs:
  - `crates/sb-api/tests/v2ray_api_bad_inputs.rs`
- Fuzz target:
  - `fuzz/targets/api/fuzz_v2ray_api.rs` deserializes
    `sb_api::v2ray::simple::{SimpleStatsRequest, SimpleQueryStatsRequest}`.
- Docs:
  - `docs/01-user-guide/configuration/config-reference.md` documents
    `experimental.v2ray_api.listen`, but not `SimpleV2RayApiServer` as a user-facing helper.
  - `fuzz/README.md` documents the simple request structs for fuzzing.
- Examples/benches:
  - No product example or bench caller of `SimpleV2RayApiServer` found by the requested scans.

## Cargo Dependency Direction

Commands used:

```text
cargo tree --workspace -i sb-api
cargo tree --workspace --all-features -i sb-api
cargo tree --workspace -i sb-core
cargo tree --workspace --all-features -i sb-core
cargo tree -p app --all-features
```

Findings:

- Default workspace reverse tree for `sb-api`: only `sb-api` itself.
- All-features workspace reverse tree for `sb-api`: `app` depends on `sb-api` and `xtests`
  reaches it through app dev-dependencies.
- `app --all-features` enables `sb-api` through `clash_api` and `v2ray_api`; after 01A, app
  bootstrap V2Ray runtime uses sb-core, not the simple helper.
- `sb-core` has many workspace reverse deps, including `app`, `sb-api`, `sb-adapters`, benches,
  interop-lab, and xtests.
- `sb-api` depends on `sb-core` directly in `crates/sb-api/Cargo.toml`, so moving sb-core runtime
  API into sb-api or deleting public sb-api types has compatibility and dependency-boundary impact.

## Semantic Comparison

| Dimension | `sb-api::v2ray::SimpleV2RayApiServer` | `sb-core::services::v2ray_api::V2RayApiServer` |
|---|---|---|
| Binds TCP | No. It stores/logs `ApiConfig.listen_addr` but never binds. | Yes when `service_v2ray_api` is enabled; `start()` pre-binds a TCP listener synchronously. |
| Serves tonic gRPC | No. `start()` spawns a synthetic stats loop; `start_with_shutdown()` loops on interval/shutdown. | Yes. It serves tonic `StatsService` over the pre-bound listener. |
| Stats source | In-memory `HashMap<String, i64>` initialized with common counters; synthetic loop mutates mock counters; manual `update_traffic`. | `StatsManager` built from `V2RayApiIR.stats`; integrated with traffic recorder paths and standard counter initialization. |
| Query/reset ability | Direct async helper methods `get_stats`, `query_stats`, `update_traffic`, `subscribe_stats`, `get_all_stats`; reset supported in `get_stats`. | gRPC `GetStats`/`QueryStats`; reset supported through service handlers and `StatsManager`. |
| Shutdown model | `start()` returns after spawning a background task with no retained handle; `start_with_shutdown()` exits on oneshot but no socket lifecycle exists. | `close()` sends stored shutdown signal; serve task exits and drops listener; bootstrap waits for port release. |
| Current product caller | None found after 01A. | Bootstrap and run-engine supervisor. |
| Current test caller | sb-api unit/integration/monitoring tests; fuzz target uses simple request structs. | sb-core v2ray tests, app bootstrap tests, context wiring tests. |
| Public exposure | Yes: `pub mod v2ray`, `pub mod simple`, `pub use simple::SimpleV2RayApiServer`; also non-feature `sb_api::v2ray::V2RayApiServer` wrapper. | Public inside `sb-core`; consumed by app and supervisor under feature wiring. |
| Direct deletion safety | Not safe without policy: breaks public `sb-api` symbols and workspace tests/fuzz. | Not in scope; this is the real product implementation. |

## Classification

**C. ORPHAN_PUBLIC_COMPAT_SURFACE**

Rationale:

- Workspace product runtime caller: none found.
- Test/fuzz callers: present.
- Public exposure: present.
- External use: cannot be disproven from repository evidence.
- Therefore it is not `A` (not private/internal), not `B` (not only test-only because it is public
  and also backs public non-feature `sb_api::v2ray::V2RayApiServer`), not `D` (no workspace product
  path still reaches it), and not `E` (evidence is sufficient).

## Route Comparison

| Route | User-visible/API behavior | Workspace impact | External compatibility risk | Test/fuzz impact | Immediate fit |
|---|---|---|---|---|---|
| 1. Delete helper | Removes misleading simple helper and non-feature wrapper dependency | Breaks sb-api tests/fuzz and public re-export | High: public symbols disappear | Requires rewrites or removals | No |
| 2. Keep public legacy wrapper, mark non-product path | Preserves API while making runtime semantics honest | Low-medium: docs/deprecation attributes/tests can be added | Low: source remains available | Existing tests remain; add policy tests/docs | **Yes, recommended** |
| 3. Move under `cfg(test)` or test utility module | Makes production surface cleaner | Breaks public re-export and non-feature wrapper | High: external callers lose symbols | Tests/fuzz need migration | No until compatibility policy approves break |
| 4. Defer with compatibility review only | No behavior/API change | Low now; leaves misleading surface unresolved | Low now | No test churn | Acceptable if policy bandwidth is not available |

## Recommendation

Recommended next card: **APP-V2RAY-SIMPLE-01C - sb-api SimpleV2Ray compatibility policy**.

Scope should be policy-first, not deletion:

- Decide whether `SimpleV2RayApiServer` remains a public legacy compatibility surface.
- If retained, add explicit docs/deprecation/non-product wording and tests that pin the public
  surface while clearly stating it does not bind or serve.
- If removal is desired, stage it as a breaking API change or migration with test/fuzz rewrites.

Do not delete, rename, `cfg(test)`-shrink, or rewire it directly from this audit.

## Validation

Executed:

- `git diff --check` - PASS
- `bash agents-only/06-scripts/verify-consistency.sh` - PASS
- `bash agents-only/06-scripts/check-boundaries.sh` - PASS
- `git status --short` - expected docs-only state plus `agents-only/a0_reality_spike/`

`SVC-V2RAY-API-01B` remains **DEFER / POLICY REVIEW**.
