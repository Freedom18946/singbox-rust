<!-- tier: B -->
# P1313-05 Lifecycle Managers And Start Order

Priority: P0

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

## Non-Goals

- Do not re-open old MT maintenance line names.
- Do not make Go-fork structural LC-003 parity claims.
- Do not add workflow automation.
