<!-- tier: B -->
# P1313-10 V2Ray Stats And Router Tracker

Priority: P1

Status: DONE locally (2026-06-27)

Primary evidence:

- `agents-only/reference/GO_PARITY_MATRIX.md` PX-012
- `go_fork_source/sing-box-1.13.13/experimental/v2rayapi/server.go`
- `go_fork_source/sing-box-1.13.13/experimental/v2rayapi/stats.go`
- `go_fork_source/sing-box-1.13.13/experimental/v2rayapi/stats.proto`
- `go_fork_source/sing-box-1.13.13/option/experimental.go`

## Goal

Finish the router-wide tracking and API policy decisions around the V2Ray StatsService.

## Closed Gap

PX-012's open StatsService items are settled locally for the Rust mainline:
router tracker wiring, Go-shaped stat names, query/reset behavior, and HTTP
endpoint policy are covered below.

## Closure Notes

- Main parity path is `sb-core::services::v2ray_api::V2RayApiServer`; `sb-api`
  simple V2Ray helpers remain Rust-only compatibility/testing surfaces.
- V2Ray StatsService now uses Go-shaped lazy counters only:
  `inbound|outbound|user>>>TAG>>>traffic>>>uplink|downlink`.
  Rust-only `packet` stat names are not created or exposed by this path.
- Configured inbound/outbound/user filters gate recorder creation. Empty query
  patterns return all counters; substring and repeated regex patterns are
  supported; invalid regex now returns gRPC `InvalidArgument`.
- `GetStats(reset=true)` returns the pre-reset value and clears the counter.
  `QueryStats(reset=true)` returns pre-reset values for matched counters.
- `V2RayStatsPortAdapter` now implements router `ConnectionTrackerPort` hooks
  by lazily requesting the matching stats recorder from route metadata. The
  hook creates Go-shaped counters without double-counting; byte accounting stays
  in the existing metered recorder paths.
- HTTP JSON policy: upstream Go 1.13.13 exposes V2Ray StatsService through gRPC
  here. No Go-compatible HTTP JSON V2Ray stats endpoint is claimed; Rust-only
  simple API helpers stay outside the parity path.

## Verification (2026-06-27)

- `cargo test -p sb-core v2ray --features service_v2ray_api`: PASS
- `cargo test -p sb-core --test adapter_surface_contract --features router`: PASS
- `cargo test -p sb-api v2ray`: PASS
- `cargo check -p app --features parity`: PASS
- `cargo check --workspace --all-features`: PASS

## Task Split

1. Config surface.
   - `experimental.v2ray_api.listen`.
   - `stats.enabled`.
   - inbound/outbound/user filter lists.

2. Router-wide tracker.
   - Track TCP and UDP flows from all route paths, not only selected adapter paths.
   - Include TUN and endpoint flows where possible.
   - Avoid double counting when Clash/metrics trackers also subscribe.

3. Stats naming.
   - Match Go stat key patterns for inbound, outbound, user, uplink, and downlink.
   - Document any Rust-only stat names.

4. Query and reset.
   - Pattern/regex matching.
   - Reset behavior.
   - System stats behavior if Go exposes it.

5. HTTP JSON endpoint decision.
   - Either gate/keep Rust HTTP endpoints as explicit extension or remove from parity builds.
   - Document decision in active docs and tests.

6. Tests.
   - gRPC query/reset tests.
   - TCP and UDP byte accounting tests.
   - Filter list tests.
   - Negative tests for disabled stats.

## Acceptance

- `cargo test -p sb-core v2ray`
- `cargo test -p sb-api v2ray`
- `cargo check -p app --features parity`
- API decision documented without implying Go behavior if Rust keeps extensions.

## Non-Goals

- No public v2ray client interoperability test.
- No GUI desktop proof.
