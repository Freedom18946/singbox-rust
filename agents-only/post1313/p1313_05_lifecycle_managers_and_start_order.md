<!-- tier: B -->
# P1313-05 Lifecycle Managers And Start Order

Priority: P0

Status: DONE (2026-06-27)

Primary evidence:

- `agents-only/reference/GO_PARITY_MATRIX.md` PX-006
- `agents-only/reference/GO-DESIGN-REFERENCE.md`
- `go_fork_source/sing-box-1.13.13/box.go`
- `go_fork_source/sing-box-1.13.13/adapter/lifecycle.go`
- `go_fork_source/sing-box-1.13.13/adapter/*/manager.go`

## Goal

Make Rust startup/shutdown semantics explicit and Go-shaped enough that DNS, cache, Clash,
V2Ray, inbound, outbound, endpoint, and service work can rely on deterministic stages.

## Current Gap

PX-006 says Rust managers are still closer to registries than Go lifecycle managers. Go has
staged `Initialize`, `Start`, `PostStart`, and `Started` order, plus internal services.

## Task Split

1. Stage model audit.
   - Map existing Rust lifecycle traits to Go stages.
   - Record which modules already have Initialize/Start/PostStart analogs.
   - Identify registry-only managers that need stage hooks.

2. Manager ordering.
   - PreStart order: logging, internal services, network, DNS transport/router,
     connection manager, router, outbound, inbound, endpoint, service.
   - Start order: outbound, DNS transport/router, network, connection, router,
     then inbound/endpoint/service.
   - PostStart/Started order with internal services.

3. Default outbound and dependency ordering.
   - Align default outbound resolution.
   - Ensure dependency graph order is deterministic.
   - Confirm missing dependency behavior matches Go or is documented.

4. Failure and rollback semantics.
   - Bind/start failures must not be reported as healthy.
   - Preserve existing working listeners on failed reload.
   - Close partially started stages in reverse order.

5. Reload integration.
   - Reuse package05 post-FABLE atomic reload guarantees.
   - Avoid resurrecting same-port unsafe handoff.
   - Keep service health snapshots truthful.

6. Tests.
   - Unit tests for stage order.
   - Failure injection tests for each stage.
   - Reload rollback regression tests.

## Acceptance

- `cargo test -p sb-core lifecycle`
- `cargo test -p app reload`
- Existing package05/package06 regression tests remain green.
- `cargo check --workspace --all-features`

## Implementation Evidence (2026-06-27)

- Added a private `LifecycleCoordinator` in `sb-core` supervisor code. It is not a
  public runtime plan API and does not expose `RuntimePlan` or `PlannedConfigIR`.
- Router and no-router startup/reload now run the same activation transaction
  shape: build context, build DNS runtime, Initialize, build bridge, populate
  managers, StartCore, inbound readiness, StartEdge, PostStart, Started, then
  publish runtime registries and DNS resolver.
- Configured DNS is now part of activation. `build_dns_components` and
  `Resolver::start/close` are used; failed DNS build/start aborts startup/reload.
  Global DNS resolver publication is deferred until commit, so rollback preserves
  the previous resolver.
- Outbound manager gained fallible ordered lifecycle helpers. Legacy connectors
  are still included in tag/dependency/default ordering but skipped for adapter
  lifecycle calls.
- Adapter registry tests that install global snapshots are serialized to avoid
  cross-test registry races exposed by the broader supervisor filter.

## Actual Stage Order

- Initialize: network → DNS → connection → task monitor → platform → outbound →
  inbound → endpoint → service.
- StartCore: outbound → DNS → network → connection → task monitor → platform.
- StartEdge: inbound → endpoint → service.
- PostStart: outbound → network → DNS → connection → task monitor → platform →
  inbound → endpoint → service.
- Started: network → DNS → connection → task monitor → platform → outbound →
  inbound → endpoint → service.
- Close: service → endpoint → inbound → outbound → platform → task monitor →
  connection → DNS → network, with V2Ray sidecar close controlled by the existing
  reload reuse ownership flag.

## Retained Boundaries

- Same-port in-process reload remains rejected; no fd handoff or reuseport work.
- Legacy listener readiness stays owned by supervisor `start_inbounds_until_ready`;
  `InboundManager` remains a shell for this package.
- `EndpointManager` and `ServiceManager` remain lifecycle owners for registered
  endpoint/service objects. ServiceManager fault isolation remains intact.
- Clash/API sidecars stay app/run-engine owned; package5 does not move them into
  `sb-core`.
- No `.github/workflows/*` changes and no dual-kernel parity movement claim.

## Verification (2026-06-27)

- `cargo test -p sb-core lifecycle` — PASS.
- `cargo test -p sb-core --lib reload_atomicity` — PASS.
- `cargo test -p sb-core --lib rollback` — PASS.
- `cargo test -p sb-core --lib supervisor` — PASS.
- `cargo test -p sb-core dns` — PASS.
- `cargo test -p app reload` — PASS; reload integration tests with external run
  binary requirements remain ignored as before.
- `cargo check --workspace --all-features` — PASS.
- `./agents-only/06-scripts/verify-consistency.sh` — PASS.
- `make boundaries` — PASS.
- `cargo fmt --check` and `git diff --check` — PASS.

## Non-Goals

- Do not re-open old MT maintenance line names.
- Do not make Go-fork structural LC-003 parity claims.
- Do not add workflow automation.
