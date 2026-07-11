<!-- tier: B -->
# MIG-03 WP10 admin_debug census

Date: 2026-07-11
Disposition: ACCEPTED — no endpoint deletion; duplicate HTTP/auth/middleware infrastructure removed.

## Method

Inventory source: `server_extension.rs` route match plus every file under
`app/src/admin_debug/`. Consumption search covered `scripts/`, `app/tests/`, `docs/`,
`agents-only/archive/`, and `GUI_fork_source/`. Blanket lint allow was removed before
classification; `cargo check -p app --features admin_debug` exposed eight actionable
imports/variables, all fixed. Remaining feature-dependent code compiles in acceptance and
all-feature profiles. No endpoint met SUSPECT-DEAD deletion threshold: each has current docs,
tests, scripts, or archived acceptance evidence plus active implementation tests.

## Endpoint inventory

| Method/path | Feature gate | Consumption evidence | Disposition |
|---|---|---|---|
| `GET /__health` | `admin_debug` | `scripts/e2e/subs.sh`; `app/tests/admin_observe.rs`; CLI auth fixtures | KEEP |
| `GET /__metrics` | `admin_debug` | `scripts/e2e/subs.sh`; `scripts/tools/prefetch-heat.sh`; API guide | KEEP |
| `GET /__config` | `admin_debug` | API guide; config endpoint tests | KEEP |
| `PUT /__config` | `admin_debug` | `scripts/tools/config-patch.sh`; audit regression test | KEEP |
| `* /router/geoip*` | `admin_debug` | API guide; `app/tests/admin_observe.rs` | KEEP |
| `* /router/rules/normalize*` | `admin_debug` | API guide; `app/tests/admin_observe.rs` | KEEP |
| `* /subs/fetch*` | any `subs_*` | security E2E suite; archived accepted metrics work | KEEP |
| `* /subs/convert*` | `subs_clash` or `subs_singbox` | endpoint unit/contract tests; `/subs/*` API guide | KEEP |
| `* /subs/parse*` | any `subs_*` | endpoint unit/contract tests; `/subs/*` API guide | KEEP |
| `* /subs/plan*` | any `subs_*` | endpoint unit/contract tests; `/subs/*` API guide | KEEP |
| `* /router/analyze*` | `sbcore_rules_tool` | API guide; rules-capture/endpoint tests | KEEP |
| `* /route/dryrun*` | `route_sandbox` | API guide; endpoint tests | KEEP |

Wildcard methods preserve existing server behavior. Feature-disabled endpoints keep their
existing `501` response rather than disappearing.

## File inventory

| File/group | Role | Liveness/owner |
|---|---|---|
| `mod.rs` | state, lifecycle facade | LIVE; app composition only |
| `server_extension.rs` | app route extension | LIVE; sole app-to-sb-api route bridge |
| `endpoints/{health,metrics,config,geoip,normalize}.rs` | active handlers | LIVE; evidence above |
| `endpoints/{subs,analyze,route_dryrun}.rs` | feature handlers | LIVE; evidence above |
| `endpoints/mod.rs` | handler exports | LIVE |
| `audit.rs` | config mutation audit | LIVE; PUT regression test |
| `breaker.rs` | subscription upstream circuit breaker | LIVE; subs tests/metrics |
| `cache.rs` | subscription fetch cache | LIVE; subs tests/metrics |
| `prefetch.rs` | subscription warming | LIVE; CLI/runtime consumer |
| `reloadable.rs` | admin config store/signal | LIVE; config GET/PUT and reload owner |
| `security.rs`, `security_async.rs` | outbound URL/IP policy | LIVE; security E2E |
| `security_metrics.rs` | subscription security counters | LIVE; health/metrics |
| `http/mod.rs`, `http/redirect.rs` | outbound subscription redirect client | LIVE; not HTTP server infrastructure |
| `http_util.rs` | endpoint response encoding | LIVE; extension handlers |
| former `http_server.rs` | duplicate TCP/TLS/request server | DELETE; replaced by `sb_api::debug::server` |
| former `auth/*`, `middleware/*` | duplicate control-plane auth/rate/request stack | MOVE; unique owner `sb_api::debug` |

## Overlap resolution

| Capability | Before | Canonical owner after WP10 | Proof |
|---|---|---|---|
| TCP/TLS/mTLS HTTP lifecycle | app debug server plus sb-api servers | `sb_api::debug::server` | app holds only lifecycle facade/extension |
| Bearer/HMAC/JWT providers | app | `sb_api::debug::auth` | app reexports auth API for compatibility |
| request auth | app server | `sb_api::debug::server` | live 200/401 contract tests |
| rate limiting | app middleware | `sb_api::debug::middleware` | live 429 contract test and bucket tests |
| request IDs | app middleware | `sb_api::debug::middleware` | middleware tests |
| audit | app endpoint state | app | mutation depends on app-owned reloadable state |
| subscription breaker/cache | app endpoint state | app | domain state, not server infrastructure |

## Measurements

- Baseline app admin_debug: 13,634 Rust LOC.
- Final app admin_debug: 9,830 Rust LOC; app ownership reduced 3,804 LOC.
- New sb-api debug owner: 3,359 Rust LOC.
- Combined: 13,189 Rust LOC, net -445 while retaining every endpoint.
- Blanket module allow: 1 → 0. App-owned server/auth/middleware implementations: 3 → 0.

## Acceptance evidence

- Real HTTP auth/rate contract: `admin_auth_contract` locks 200, 401, and 429 envelopes.
- Audit: config PUT extension test verifies audit entry.
- Route preservation: extension health and config tests plus existing endpoint suites.
- Manual-curl equivalent: contract tests open a real loopback listener and issue reqwest HTTP
  requests; `scripts/e2e/subs.sh` retains operator curl smoke for `/__health` and `/__metrics`.
