<!-- tier: B -->
# P1313-09 UDP NAT And Packet Dataplane

Priority: P1

Status: **Closed locally** (2026-06-27)

Primary evidence:

- `agents-only/reference/GO_PARITY_MATRIX.md` PX-005
- `go_fork_source/sing-box-1.13.13/route/conn.go`
- `go_fork_source/sing-box-1.13.13/route/route.go`
- `go_fork_source/sing-box-1.13.13/route/network.go`
- `go_fork_source/sing-box-1.13.13/option/rule_action.go`

## Goal

Close the UDP NAT / packet routing gap that prevents route dataplane parity claims beyond
TCP-heavy scenarios.

## Current Gap

PX-005 states UDP NAT is still stubbed. Go route action options include
`udp_disable_domain_unmapping`, `udp_connect`, and `udp_timeout`.

## Closure Summary

- Route action UDP options now parse through raw IR, v2 lowering, compiled router rules,
  and `RouterHandle::decide_with_meta`.
- SOCKS UDP association now receives the runtime `RouterHandle` and
  `OutboundRegistryHandle` from the app path.
- UDP NAT entries can hold either direct UDP sockets or generic outbound UDP transports.
- SOCKS UDP reply relays honor domain unmapping: domain replies preserve the original
  SOCKS domain target by default, and `udp_disable_domain_unmapping=true` returns the
  actual upstream socket address.
- Per-entry relay idle timeout uses route `udp_timeout` first, then inbound
  `udp_timeout`, protocol defaults, and finally the Go-style default UDP timeout.
- The self-contained large UDP payload interop oracle was promoted from expected
  failure to expected success after the dataplane passed.

No dual-kernel parity movement is claimed here; the dual-core `both` ledger remains
owned by `labs/interop-lab/docs/dual_kernel_golden_spec.md`.

## Task Split

1. Current UDP path audit.
   - Inbound UDP entry points: SOCKS, mixed, TUN, DNS inbound, protocol adapters.
   - Router packet decision path.
   - Outbound UDP connector capabilities.

2. NAT table design.
   - Key by inbound/session/source/destination as Go-compatible behavior requires.
   - Timeout handling from route action or default.
   - Cleanup and close behavior.
   - Metrics and connection tracker hooks.

3. Domain unmapping.
   - Preserve or disable domain unmapping based on route action option.
   - Test domain destination, IP destination, and FakeIP destination cases.

4. UDP connect semantics.
   - Connected UDP for supported outbounds.
   - Packet mode fallback for unsupported outbounds.
   - Error classification for unsupported network.

5. Datagram relay.
   - Concurrent bidirectional relay.
   - Cancellation on connection close or route switch.
   - Backpressure and packet-size handling.

6. Tests.
   - SOCKS UDP association E2E.
   - DNS-over-UDP through route.
   - Timeout cleanup.
   - Rule action option matrix.

## Acceptance

- `cargo fmt --check` — PASS
- `cargo test -p sb-config route` — PASS
- `cargo test -p sb-core udp --features router` — PASS
- `cargo test -p sb-adapters udp --features socks,e2e` — PASS
- `cargo test -p app udp` — PASS
- `cargo run -p interop-lab -- case run p1_rust_core_udp_via_socks --kernel rust` — PASS
  after rebuilding `app` with `--features gui_runtime` so the `target/debug/app`
  binary includes adapters and Clash API.
- `cargo run -p interop-lab -- case run p1_dataplane_large_payload_udp --kernel rust` — PASS
  with oracle promoted to `success=true`.
- No public network dependency.

## Non-Goals

- TUN privileged dataplane proof remains environment-limited.
- QUIC protocol internals are not part of this package unless needed for generic UDP relay
  correctness.
