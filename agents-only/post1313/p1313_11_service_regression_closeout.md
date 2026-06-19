<!-- tier: B -->
# P1313-11 Service Regression Closeout

Priority: P1

Primary evidence:

- `agents-only/reference/GO_PARITY_MATRIX.md` PX-011, PX-014, PX-015
- `go_fork_source/sing-box-1.13.13/service/ssmapi/*`
- `go_fork_source/sing-box-1.13.13/service/derp/*`
- `go_fork_source/sing-box-1.13.13/service/resolved/*`
- post-FABLE package06 service liveness work

## Goal

Revalidate the service tails that are mostly implemented but need stronger, current-reference
evidence before they can be considered stable under the 1.13.13 baseline.

## Current Gap

SSMAPI is implemented but calls for stronger E2E Shadowsocks client integration tests.
DERP has optional resolver strategy and HTTP/2/h2c parity tails. Resolved is accepted
limitation for Linux runtime proof but still has platform/stub and bind-failure honesty risks.

## Task Split

1. SSMAPI E2E.
   - Start managed Shadowsocks inbound.
   - Add users through SSMAPI.
   - Verify TCP auth for multiple users.
   - Verify UDP correctness.
   - Verify traffic counters and cache write cadence.

2. SSMAPI failure cases.
   - Bad method/key.
   - Unknown user.
   - Endpoint not bound.
   - Cache corrupt or missing.

3. DERP resolver strategy.
   - Expand `domain_resolver` strategy coverage beyond first-IP minimal behavior if feasible.
   - Verify `verify_client_url` string/object forms.
   - Recheck mesh_with per-peer dial/TLS behavior.
   - Decide whether HTTP/2/h2c differences matter for this repo's target.

4. Resolved service.
   - Keep Linux runtime proof as accepted limitation unless a Linux host is available.
   - Revalidate DNS stub UDP/TCP bind failure status.
   - Confirm non-Linux stubs are loud and machine-readable.

5. Service status honesty.
   - Ensure bind/start failures produce `ServiceStatus::Failed`.
   - Avoid async spawned task failures being reported as started.

6. Tests.
   - Service-specific unit tests.
   - No external network.
   - Optional Linux manual evidence only when environment exists.

## Acceptance

- `cargo test -p sb-core --features service_ssmapi`
- `cargo test -p sb-adapters shadowsocks`
- `cargo test -p sb-core --features service_derp`
- `cargo test -p sb-adapters resolved` where platform allows or stub tests apply.

## Non-Goals

- Do not block package closure on Linux systemd runtime proof on this macOS host.
- Do not claim Go-fork LC-003 parity movement.
