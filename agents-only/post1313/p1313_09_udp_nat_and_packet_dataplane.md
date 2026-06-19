<!-- tier: B -->
# P1313-09 UDP NAT And Packet Dataplane

Priority: P1

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

- `cargo test -p sb-core udp`
- `cargo test -p sb-adapters udp`
- Relevant interop UDP cases, if self-contained, promoted or extended.
- No public network dependency.

## Non-Goals

- TUN privileged dataplane proof remains environment-limited.
- QUIC protocol internals are not part of this package unless needed for generic UDP relay
  correctness.
