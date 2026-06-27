<!-- tier: B -->
# P1313-11 Service Regression Closeout

Priority: P1
Status: DONE locally (2026-06-28)

Primary evidence:

- `agents-only/reference/GO_PARITY_MATRIX.md` PX-011, PX-014, PX-015
- `go_fork_source/sing-box-1.13.13/service/ssmapi/*`
- `go_fork_source/sing-box-1.13.13/service/derp/*`
- `go_fork_source/sing-box-1.13.13/service/resolved/*`
- post-FABLE package06 service liveness work

## Closed Work

SSMAPI now has a real app-level regression test that starts a managed Shadowsocks inbound,
mutates users through SSMAPI, verifies unauthenticated and bad-request paths, exercises TCP
and UDP through Shadowsocks clients, checks per-user counters, and verifies cache persistence
on service close.

The SSMAPI builder and cache tails gained focused unit coverage for unbound endpoint rejection
and corrupt cache deletion. The Shadowsocks public UDP relay dial path now seeds the relay
target before returning the socket, and Shadowsocks inbound startup now has the same
no-current-Tokio-runtime fallback shape used by SOCKS inbound startup.

DERP resolver coverage now asserts that `domain_resolver.server` is passed into the injected
DNS router for dial-time domain resolution. The stale DERP module comment was updated to match
the implemented relay/probe/mock service surface.

Resolved remains a macOS-local service-status/stub proof. Linux systemd runtime proof is still
an accepted limitation for a Linux host, not a blocker for this package closeout.

## Verification

- `cargo test -p app --features parity --test ssmapi_service_regression_e2e`
- `cargo test -p sb-core --features service_ssmapi ssmapi`
- `cargo test -p sb-core --features service_derp derp`
- `cargo test -p sb-core --features service_resolved dns_forwarder`
- `cargo test -p sb-adapters --features adapter-shadowsocks,service_ssmapi shadowsocks`
- `cargo test -p sb-adapters resolved`
- `cargo check -p app --features parity`
- `cargo check --workspace --all-features`
- `make boundaries`
- `./agents-only/06-scripts/verify-consistency.sh`
- `cargo fmt --check`
- `cargo run -p interop-lab -- case run p1_service_failure_isolation --kernel rust`

## Non-Goals And Limits

- No GitHub workflow automation was added or restored.
- No dual-kernel parity movement is claimed from this service regression work.
- Linux resolved/systemd runtime evidence still requires a Linux host.
