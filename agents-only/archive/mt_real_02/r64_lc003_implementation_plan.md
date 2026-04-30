<!-- tier: B -->
# R64: BHV-LC-003 implementation breakdown

> Date: 2026-04-30
> Purpose: decompose BHV-LC-003 (Service failure isolation) from an
> effort-L structural gap into half-hour sub-WPs with explicit
> dependencies. R64 ships no code; it ships this plan.

## BHV-LC-003 current gap (precise)

Three concrete facts from the live read of spec, case yaml, Rust
source, and Go source:

1. Go fork side: the Clash API route table mounts `/`, `/logs`,
   `/traffic`, `/version`, `/configs`, `/proxies`, `/rules`,
   `/connections`, `/providers/*`, `/script`, `/profile`, `/cache`,
   and `/dns`, but no `/services/health`; today's comparable Go
   response is therefore a route miss rather than a health payload
   (go_fork_source/sing-box-1.12.14/experimental/clashapi/server.go:114).
   The Go service manager also returns the first service start error
   without a persisted health snapshot
   (go_fork_source/sing-box-1.12.14/adapter/service/manager.go:36).
2. Rust side: `GET /services/health` is routed, but the handler is a
   static stub returning `{"healthy": true, "services": []}`
   (crates/sb-api/src/clash/server.rs:341,
   crates/sb-api/src/clash/handlers.rs:2098). `ServiceManager`
   already has fault-isolated `start_all()` results, but
   `health_status()` maps every registered tag to `Running`
   (crates/sb-core/src/service.rs:256,
   crates/sb-core/src/service.rs:293).
3. Case yaml fact: `p1_service_failure_isolation` is `kernel_mode:
   rust`, only checks `GET /`, and points at
   `rust_core_broken_service.json`
   (labs/interop-lab/cases/p1_service_failure_isolation.yaml:1,
   labs/interop-lab/cases/p1_service_failure_isolation.yaml:24).
   That config has clash API, one mixed inbound, one direct outbound,
   and no `services` array, so the broken service is not actually
   modeled today
   (labs/interop-lab/configs/rust_core_broken_service.json:4).

Spec anchor: BHV-LC-003 is "Concurrent service initialization" with
Rust-only case `p1_service_failure_isolation` and known div DIV-H-006
(labs/interop-lab/docs/dual_kernel_golden_spec.md:139). DIV-H-006 says
the Rust config has no broken service and Rust service health is static
(labs/interop-lab/docs/dual_kernel_golden_spec.md:242).

## What closing BHV-LC-003 actually requires

- Rust records runtime service start outcomes and exposes them through
  an approved service-health API shape.
- Rust and Go fixtures both model a broken service and produce the
  same oracle shape.
- `p1_service_failure_isolation` or a successor runs both kernels with
  equivalent inputs and compares health outputs.
- DIV-H-006 can be retired, and BHV-LC-003 moves to honest
  dual-kernel coverage.

## Sub-WP breakdown

### Sub-WP A: Persist Rust service start outcomes

- **Goal**: Make `ServiceManager` retain per-service status after
  `start_all()`, instead of returning transient results while
  `health_status()` reports every tag as running.
- **Files to touch**: crates/sb-core/src/service.rs.
- **Acceptance criteria**:
  - `cargo test -p sb-core service_manager_persists_failed_start_status` passes.
  - After one good service and one bad service start, `health_status()`
    returns one `Running` and one `Failed(...)`.
  - Existing `test_start_all_fault_isolation` still proves both
    services were attempted.
- **Independent of Go fork?**: yes.
- **Reuses R62 framework?**: no; this is runtime plumbing.
- **Estimated effort**: 25-40 min.
- **Depends on**: none.

### Sub-WP B: Wire service startup into Rust runtime stages

- **Goal**: Ensure services registered from config are actually started
  during runtime stages, with failures isolated and retained.
- **Files to touch**: crates/sb-core/src/context.rs, crates/sb-core/src/runtime/supervisor.rs, crates/sb-core/src/service.rs.
- **Acceptance criteria**:
  - `cargo test -p sb-core service_manager_start_stage_fault_isolation` passes.
  - `ctx.service_manager.start(stage)` attempts registered services
    instead of being a no-op.
  - A failing service records `Failed(...)` and does not prevent admin
    API startup.
- **Independent of Go fork?**: yes.
- **Reuses R62 framework?**: no.
- **Estimated effort**: 30-40 min.
- **Depends on**: Sub-WP A.

### Sub-WP C: Replace Rust service-health static stub

- **Goal**: Connect the existing Rust service-health route, or an
  approved replacement endpoint, to runtime service status.
- **Files to touch**: crates/sb-api/src/clash/server.rs, crates/sb-api/src/clash/handlers.rs, app/src/run_engine_runtime/admin_start.rs, app/src/bootstrap_runtime/api_services.rs.
- **Acceptance criteria**:
  - Before implementation, planner gets user confirmation for endpoint
    path and JSON shape.
  - `cargo test -p sb-api services_health_reports_runtime_status` passes
    against the approved fixture.
  - The approved endpoint returns a failed service entry when
    `ServiceManager` has `Failed(...)`.
  - The static `{"healthy": true, "services": []}` path is no longer
    the app runtime implementation.
- **Independent of Go fork?**: yes.
- **Reuses R62 framework?**: partial; final evidence can use generic
  health comparison, but this sub-WP is API plumbing.
- **Estimated effort**: 30-40 min.
- **Depends on**: Sub-WP A, Sub-WP B.

### Sub-WP D: Make the Rust LC-003 case honest

- **Goal**: Replace the current diagnostic with a Rust-only case/config
  that actually includes a broken service and checks runtime health.
- **Files to touch**: labs/interop-lab/cases/p1_service_failure_isolation.yaml, labs/interop-lab/configs/rust_core_broken_service.json, optional successor fixture under labs/interop-lab/configs/.
- **Acceptance criteria**:
  - The config contains a real `services` array with one service
    expected to fail and one expected to survive, or an approved
    equivalent fixture.
  - The GUI sequence probes the approved service-health endpoint.
  - The case stays `kernel_mode: rust` until Go parity exists.
  - The interop runner passes and asserts the failed-service health entry.
- **Independent of Go fork?**: yes.
- **Reuses R62 framework?**: partial; useful once both kernels exist.
- **Estimated effort**: 25-40 min.
- **Depends on**: Sub-WP C.

### Sub-WP E: Add comparable Go service-health support

- **Goal**: Provide the Go side with an equivalent service-health output
  path for LC-003, or land an explicit blocker note if Go fork edits are
  rejected before implementation.
- **Files to touch**: go_fork_source/sing-box-1.12.14/experimental/clashapi/server.go, go_fork_source/sing-box-1.12.14/adapter/service/manager.go, possible Go handler/test fixture under go_fork_source/.
- **Acceptance criteria**:
  - REVIEW BEFORE MERGE: planner reconfirms with user before editing
    go_fork_source.
  - Go fork exposes the approved service-health shape for the LC-003
    fixture, or the sub-WP lands a documented blocker and stops before
    promotion.
  - A Go-side smoke command or interop probe returns approved
    healthy/failed service fields.
  - Existing Go Clash API routes keep their current behavior.
- **Independent of Go fork?**: no.
- **Reuses R62 framework?**: partial; runtime plumbing is Go-specific,
  but final payload comparison can use R62 evidence primitives.
- **Estimated effort**: 30-40 min spike; may expand if endpoint design is nontrivial.
- **Depends on**: Sub-WP C.

### Sub-WP F: Promote LC-003 to dual-kernel coverage

- **Goal**: Convert LC-003 from Rust-only diagnostic coverage to
  dual-kernel coverage and retire DIV-H-006.
- **Files to touch**: labs/interop-lab/cases/p1_service_failure_isolation.yaml or successor, matching configs, labs/interop-lab/docs/dual_kernel_golden_spec.md, labs/interop-lab/docs/compat_matrix.md.
- **Acceptance criteria**:
  - REVIEW BEFORE MERGE if this depends on Go fork changes from Sub-WP E.
  - LC-003 case uses `kernel_mode: both`.
  - Dual-kernel interop run passes for both kernels with the same
    service-health oracle.
  - `BHV-LC-003` lists the both-kernel case and DIV-H-006 is marked
    retired or closed with evidence pointer.
- **Independent of Go fork?**: no.
- **Reuses R62 framework?**: yes; this is the generic evidence payoff.
- **Estimated effort**: 30-40 min after Sub-WP E is accepted.
- **Depends on**: Sub-WP D, Sub-WP E.

## Dependency DAG

- A blocks B and C.
- B blocks C.
- C blocks D and E.
- D blocks F.
- E blocks F.
- Recommended linear execution order: A -> B -> C -> D -> E -> F.
- A through D are pure Rust/docs/harness work. E and Go-dependent F are
  scheduled only after explicit user confirmation.

## Risk register

- Sub-WP A: status persistence may need interior mutability without regressing `ServiceManager` clone semantics.
- Sub-WP B: isolated service failures could accidentally become fatal.
- Sub-WP C: API state may not carry service manager/runtime health handles into `sb-api`.
- Sub-WP D: deterministic intentional failure may need a tiny test-only fixture.
- Sub-WP E: modifying go_fork_source is policy-sensitive and must be REVIEW BEFORE MERGE.
- Sub-WP F: coverage accounting may be confused by CLAUDE.md 52/60 vs spec 52/56; defer that cleanup.
- Cross-cutting Go risk: Sub-WP E modifies go_fork_source, and Sub-WP F is REVIEW BEFORE MERGE if it relies on those Go changes.

## Sub-WPs that are NOT in this plan

- Work outside LC-003, including REALITY sampler/dataplane work.
- General service framework cleanup unrelated to startup failure health.
- New production service traits beyond strict LC-003 needs.
- CLAUDE.md 52/60 vs spec 52/56 correction; defer to post-LC-003 cleanup.
- R62 framework expansion unless LC-003 evidence proves a missing primitive.

## What R64 deliberately does NOT decide

- Does not commit to runtime health endpoint URL or JSON shape; Sub-WP C must ask the user before implementation.
- Does not commit to Go fork modification; Sub-WP E and Go-dependent F are REVIEW BEFORE MERGE.
- Does not choose whether to keep the existing case ID or create a successor; Sub-WP D should choose the least disruptive path.
- Does not assume R62 primitives are sufficient; any new primitive must land in dual_kernel_verification with byte-equivalence checks.

## Reference pointer reaffirm

- Spec: labs/interop-lab/docs/dual_kernel_golden_spec.md S3 LC.1, S4 DIV-H-006, S5.
- Case: labs/interop-lab/cases/p1_service_failure_isolation.yaml.
- Rust: crates/sb-core/src/services/, crates/sb-core/src/service.rs, crates/sb-core/src/context.rs, crates/sb-core/src/runtime/supervisor.rs, app/src/bootstrap_runtime/api_services.rs, app/src/run_engine.rs, app/src/run_engine_runtime/admin_start.rs, crates/sb-api/src/clash/server.rs, crates/sb-api/src/clash/handlers.rs.
- Go: go_fork_source/sing-box-1.12.14/adapter/service.go, go_fork_source/sing-box-1.12.14/adapter/service/manager.go, go_fork_source/sing-box-1.12.14/experimental/clashapi/server.go.
- CLAUDE.md 52/60 vs spec 52/56 mismatch remains open and deferred to the post-LC-003 cleanup round per user-elected order.
