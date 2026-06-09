<!-- tier: B -->
# APP-V2RAY-SIMPLE-01 - bootstrap SimpleV2RayApiServer product-semantics audit

Status: PROPOSED audit report only. No business-source change. No public-network run.

## Executive Decision

Unique classification: **B. MISSING_REAL_LISTENER_BUG**.

The bootstrap helper accepts `experimental.v2ray_api.listen`, parses it as a socket address, logs
"Starting V2Ray API server", returns a live-looking `ServiceHandle`, and stores it in the legacy
bootstrap runtime. The underlying `SimpleV2RayApiServer` never binds or serves that address. Go
sing-box treats non-empty `listen` as a real gRPC listening address, and the Rust sb-core
`V2RayApiServer` already has a real pre-bound gRPC listener implementation. Therefore the current
bootstrap simple helper is not an intentional stats-only product surface; it is a missing listener
for a config field whose product meaning is "start a gRPC API listener".

## Evidence Map

- Bootstrap call chain: `app/src/bootstrap.rs:239-248` calls
  `bootstrap_runtime::api_services::start_v2ray_api_server(listen.as_str())` when
  `experimental.v2ray_api.listen` is present.
- Bootstrap helper: `app/src/bootstrap_runtime/api_services.rs:95-137` parses `listen` into
  `SocketAddr`, constructs `sb_api::types::ApiConfig`, creates `SimpleV2RayApiServer`, logs
  startup, spawns `start_with_shutdown()`, then returns `Some(ServiceHandle)`.
- Simple server: `crates/sb-api/src/v2ray/simple.rs:153-194` loops on interval/shutdown and
  updates in-memory counters. There is no `TcpListener`, `tonic::Server`, `serve`, `accept`, or
  HTTP/gRPC endpoint in that path. `listen_addr` is only logged at `:157-160`.
- Config model: `crates/sb-config/src/ir/experimental.rs:58-65` defines
  `V2RayApiIR { listen, stats }`; stats fields are separate at `:96-108`.
- Go semantics: `go_fork_source/sing-box-1.12.14/box.go:139-140` enables V2Ray API only when
  `listen` is non-empty; `experimental/v2rayapi/server.go:55-67` calls `net.Listen("tcp", s.listen)`
  and serves gRPC; docs say `listen` is the "gRPC API listening address" and empty disables it
  (`docs/configuration/experimental/v2ray-api.md:28-30`).
- Rust real listener: `crates/sb-core/src/services/v2ray_api.rs:390-399` pre-binds a listener;
  `:416-506` starts tonic over the pre-bound listener; tests at `:716-955` cover bind conflict,
  successful bind, retry, duplicate start, shutdown, and task-exit state cleanup.
- Run-engine path: `crates/sb-core/src/runtime/supervisor.rs:1167-1176` wires sb-core
  `V2RayApiServer`, not the app bootstrap `SimpleV2RayApiServer`.
- ServiceManager boundary: `Context` carries `v2ray_server` separately from `service_manager`
  (`crates/sb-core/src/context.rs:87-92`); `ServiceManager` health uses registered `Service`
  instances only (`crates/sb-core/src/service.rs:247-331`).

## Semantic Questions

1. **Does SimpleV2RayApiServer really ignore listen address?** Yes for product behavior. The
   app helper validates/parses it and the simple server logs it, but no socket bind or serve uses
   it. Valid but occupied addresses still produce `Some(ServiceHandle)`.
2. **What capability does it actually provide?** It provides an in-memory stats map, query/reset
   helpers, broadcast subscription, and a synthetic interval stats loop. It does **not** provide a
   gRPC API, real compatibility endpoint, network listener, or active metrics adapter in bootstrap.
   It is a placeholder-like in-process stats shim, not a dead path.
3. **What should a user reasonably expect when config enables it?** A reachable V2Ray-compatible
   gRPC StatsService on the configured `listen` address, or a visible startup failure if the
   listener cannot bind.
4. **Does Go reference really listen?** Yes. Non-empty `listen` enables the service; `Start`
   performs `net.Listen("tcp", s.listen)` and serves a gRPC server.
5. **Does sb-core V2RayApiServer already have a reusable real listener?** Yes. With
   `service_v2ray_api`, it pre-binds synchronously, serves tonic `StatsService`, and supports
   close/restart semantics.
6. **Are bootstrap SimpleV2RayApiServer and sb-core sidecar duplicated?** Yes in product intent.
   They both attach to `experimental.v2ray_api`, but only sb-core implements the real listener.
   Bootstrap is legacy; run-engine uses the supervisor/sb-core path.
7. **Is there a feature/dependency boundary blocking direct reuse?** There is a real boundary:
   app feature `v2ray_api` currently enables `sb-api/v2ray-api` only, while the real sb-core sidecar
   requires `sb-core/service_v2ray_api`. Reuse needs explicit feature wiring and tests.
8. **User-visible errors today?** Yes: config can succeed while no port listens; clients cannot
   connect; the "Starting V2Ray API server" log is misleading; stats are synthetic/in-memory and
   not exposed to network clients. Unparsable listen strings are skipped, but valid unbindable
   addresses are silently accepted because no bind happens.
9. **Is there a test proving stats-only is intended?** No. Existing sb-api tests exercise creation,
   in-memory stats, broadcasts, and a startup loop that updates counters. They do not assert that
   the API should be stats-only, and they do not test TCP/gRPC connectivity.
10. **If listen address is invalid, does current code silently succeed?** For unparsable strings
    through the app helper, no: it logs a warning and returns `None`. For bind-invalid runtime
    conditions such as occupied port or unavailable local address after a valid `SocketAddr` parse,
    yes: it returns a handle because it never attempts to bind.

## Route Comparison

| Route | User-visible behavior | Go parity | Scope | Feature/dependency risk | Lifecycle semantics | Test strategy | Immediate fit |
|---|---|---|---|---|---|---|---|
| 1. Reuse sb-core `V2RayApiServer` | Config creates a real gRPC listener; bind failure can return no handle | Highest | Medium: app helper + feature wiring + handle close wrapper | Medium: app `v2ray_api` must enable/require `sb-core/service_v2ray_api` | Good: existing `start()` pre-binds and `close()` shuts down | bind conflict, TCP connect, gRPC StatsService query, shutdown release, invalid listen | **Yes, recommended** |
| 2. Implement real listener in app helper | Real listener from bootstrap only | Medium-high | Medium-high: duplicate tonic/server lifecycle in app/sb-api | Medium-high: duplicates existing sb-core code and may add drift | Must design shutdown/pre-bind/readiness again | same listener and client tests as route 1 | No; duplicates fixed code |
| 3. Remove listen address | No listener; config no longer promises one | Low | Medium: config/schema/docs/migration churn | Low | Simple but degrades feature | config rejection/migration tests | No; contradicts Go field semantics |
| 4. Reject unsupported config | Honest failure/skip instead of false handle | Medium-low | Low-medium | Low | Honest but no feature | config validation + app startup no-handle tests | Acceptable fallback only if real listener is deferred |
| 5. Mark deprecated | Warns users away from bootstrap V2Ray API | Low | Low | Low | Does not fix no-listener behavior by itself | warning/deprecation tests | Not enough alone |
| 6. Keep current behavior, fix docs | Documents stats-only/no listener | Low | Low | Low | Preserves misleading runtime handle | doc-only | No; product semantics remain wrong |
| 7. Delete dead path | Removes bootstrap helper | Depends on callers | Medium | Medium | Cleans legacy only if callers migrate | compile/callsite tests | No; path is still reachable |

## Recommended Next Card

**APP-V2RAY-SIMPLE-01A - bootstrap V2Ray real-listener wiring**

Implement route 1: replace the bootstrap `SimpleV2RayApiServer` helper with sb-core
`V2RayApiServer` under explicit feature wiring, return a `ServiceHandle` only after
`V2RayServer::start()` succeeds, and make shutdown call `close()` before joining. Add local-only
tests for invalid listen, bind conflict/no handle, successful bind/TCP connect, optional gRPC
StatsService query, retry after failed bind, and shutdown port release.

## Boundaries And Deferred Items

- Do not change parity numbers for this audit. This is product/runtime honesty work.
- Do not use public network. All future tests should use loopback ephemeral ports.
- `SVC-V2RAY-API-01B` remains **DEFER / POLICY REVIEW**. It concerns supervisor policy and
  ServiceManager/health projection, not the bootstrap simple-helper bug.
- Deferred hygiene: `TROJAN-FMT` (pre-existing full workspace fmt drift) and `TIDY-A0`
  (`agents-only/a0_reality_spike/` pre-existing untracked).

## Audit Validation Plan

Expected validation for this audit-only proposal:

- `git diff --check`
- `cargo check --workspace --all-features`
- `bash agents-only/06-scripts/verify-consistency.sh`
- `bash agents-only/06-scripts/check-boundaries.sh`
- `git status --short`

Expected source-change boundary: no `app/`, `crates/`, Cargo, fixtures, REALITY, Makefile, L18,
CI, or `.github` changes. Only this agents-only report should be new.
