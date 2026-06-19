<!-- tier: B -->
# P1313-10 V2Ray Stats And Router Tracker

Priority: P1

Primary evidence:

- `agents-only/reference/GO_PARITY_MATRIX.md` PX-012
- `go_fork_source/sing-box-1.13.13/experimental/v2rayapi/server.go`
- `go_fork_source/sing-box-1.13.13/experimental/v2rayapi/stats.go`
- `go_fork_source/sing-box-1.13.13/experimental/v2rayapi/stats.proto`
- `go_fork_source/sing-box-1.13.13/option/experimental.go`

## Goal

Finish the router-wide tracking and API policy decisions around the V2Ray StatsService.

## Current Gap

PX-012 says gRPC StatsService and tracking are partly implemented, but router-wide
ConnectionTracker parity and HTTP endpoint policy still need settlement.

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
