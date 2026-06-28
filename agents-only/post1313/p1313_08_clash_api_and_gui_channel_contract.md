<!-- tier: B -->
# P1313-08 Clash API And GUI Channel Contract

Status: DONE (2026-06-27)

Priority: P0

Primary evidence:

- `agents-only/reference/GO_PARITY_MATRIX.md` PX-010
- `go_fork_source/sing-box-1.13.13/experimental/clashapi/*`
- `go_fork_source/sing-box-1.13.13/experimental/clashapi.go`
- `go_fork_source/sing-box-1.13.13/route/rule/rule_item_clash_mode.go`
- `GUI_fork_source/GUI.for.SingBox-1.25.1/frontend/src/api/kernel.ts`
- `GUI_fork_source/GUI.for.SingBox-1.25.1/frontend/src/types/kernel.d.ts`

## Goal

Make the Clash-compatible API shape reliable for GUI 1.25.1 and Go 1.13.13 behavior where
the API is user-visible.

## Current Gap

PX-010 records stubbing/wiring gaps in `/configs`, `/proxies`, `/connections`, cache/history,
mode list, and `clash_mode` integration. GUI 1.25.1 now opens independent lazy WebSocket
channels and passes delay timeout.

## Task Split

1. Controller and auth.
   - Honor `external_controller` host/port including bracketed IPv6.
   - Bearer secret behavior for HTTP and WebSocket.
   - CORS/private-network fields from experimental config.

2. `/configs`.
   - Response fields required by GUI: `port`, `socks-port`, `mixed-port`,
     `interface-name`, `allow-lan`, `mode`, `tun`.
   - PATCH semantics for mode/ports/TUN-ish fields.
   - Preserve documented oracle ignores where dual-kernel spec already accepts divergence.

3. `/proxies`.
   - Group response shape: `type`, `name`, `udp`, `history`, `now`, `all`.
   - Selector and urltest state backed by P1313-07 cache.
   - GLOBAL virtual group semantics.
   - PUT group selection with 204 on success and Go-like error JSON on failure.

4. Delay API.
   - `GET /proxies/{name}/delay?url=&timeout=`.
   - Use full HTTP GET delay, not TCP connect only.
   - Timeout parsing and error shape.

5. WebSockets.
   - `/logs?level=debug`.
   - `/memory`.
   - `/traffic`.
   - `/connections`.
   - Independent connect/disconnect without poisoning shared state.

6. Connections API.
   - REST `/connections` shape for GUI.
   - DELETE `/connections/{id}` cancellation.
   - Rule/rulePayload/chains metadata where available.

7. Clash mode rule integration.
   - ClashServer service exposes current mode.
   - Route rule `clash_mode` consumes that mode.
   - Mode changes trigger consistent routing behavior.

8. Tests.
   - Strict HTTP contract tests.
   - WebSocket independent-channel tests.
   - GUI fixture replay without opening Wails.

## Acceptance

- `cargo test -p sb-api clash`
- `cargo test -p app clash`
- Existing interop-lab `p0_clash_api_contract_strict` remains green with documented oracle
  ignores only.
- Local GUI 1.25.1 API-shape probe may be added, but no desktop automation is required.

## Non-Goals

- Do not resume Wails click automation.
- Do not remove existing documented oracle ignores without a separate parity decision.
- Provider endpoints blocked by Go-fork structural divergence remain out of scope.

## Closure Notes (2026-06-27)

- `/configs` now includes GUI 1.25.1 `interface-name` and derives HTTP/SOCKS/mixed/TUN shape from
  `ConfigIR`.
- Clash API server startup paths now share the runtime `ConnTracker` with inbound/supervisor
  context, so `/connections` observes the same tracker instead of an isolated API tracker.
- `PATCH /configs`, selector `PUT /proxies/{name}`, and proxy delay timeout errors now return
  Go-like JSON messages for invalid request bodies/parameters and selector failures.
- Lazy WebSocket channels remain independent across `/logs`, `/memory`, `/traffic`, and
  `/connections`; disconnecting one channel does not poison the others.
- Dual-kernel oracle ignores `DIV-M-006` through `DIV-M-009` were preserved; no parity-count change
  is claimed.

## Verification (2026-06-27)

- `cargo fmt --check`
- `cargo test -p sb-api --test clash_http_e2e -- --nocapture`
- `cargo test -p sb-api --test clash_websocket_e2e -- --nocapture`
- `cargo test -p sb-api --test connections_snapshot_test -- --nocapture`
- `cargo test -p app clash --features "router clash_api" -- --nocapture`
- `cargo check --workspace --all-features`
- `./agents-only/06-scripts/verify-consistency.sh`
- `make boundaries`
- `cargo run -p interop-lab -- case run p0_clash_api_contract_strict --kernel rust`

Dual-core strict replay was attempted with `cargo run -p interop-lab -- case run
p0_clash_api_contract_strict`; it did not reach diff because the local Go API was not ready at
`http://127.0.0.1:9090/version` within 15000 ms. This is an environment precondition for the Go
kernel, not a Rust contract failure.

## Revalidation (2026-06-28)

- Strict post1313 revalidation is recorded in
  `agents-only/post1313/p1313_strict_revalidation_2026_06_28.md`.
- The two stale `/connections` WebSocket snapshot quarantines were repaired by using the same
  explicit `ConnTracker` for test registration and server state. They are now part of the default
  `clash_websocket_e2e` suite.
- The long-running `/connections` WebSocket soak remains ignored by default but was explicitly run
  and passed in the strict revalidation.
