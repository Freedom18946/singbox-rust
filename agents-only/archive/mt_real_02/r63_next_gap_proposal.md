<!-- tier: B -->
# R63: Next dual-kernel BHV gap proposal

> Date: 2026-04-30
> Purpose: enumerate top candidates to open stage-3 path C after
> MT-REAL-02 stage-2 closure and R62 framework abstraction. No code
> changes proposed in this round; this document lists candidates and
> a recommended order for the planner to choose from.

## Current dual-kernel state

Two denominator snapshots currently coexist:

- CLAUDE.md snapshot: 52/60 closed (86.7%).
- Authoritative golden spec S1/S6: 52/56 closed (92.9%), because
  BHV-SV-001 through BHV-SV-004 were reclassified as harness-only
  subscription parser checks on 2026-03-16.

The 8 not-both-covered IDs under the legacy 60 denominator are:

| BHV-ID | Spec section | Open since | One-line state |
| --- | --- | --- | --- |
| BHV-SV-001 | S3 SV.1 | SV.1 reclass | Harness-only JSON subscription parsing; excluded from current parity denominator. |
| BHV-SV-002 | S3 SV.1 | SV.1 reclass | Harness-only YAML subscription parsing; excluded from current parity denominator. |
| BHV-SV-003 | S3 SV.1 | SV.1 reclass | Harness-only base64 subscription parsing; excluded from current parity denominator. |
| BHV-SV-004 | S3 SV.1 | SV.1 reclass | Harness-only URL subscription parsing; excluded from current parity denominator. |
| BHV-LC-003 | S3 LC.1 | current | Service failure isolation remains structural: no honest broken-service dual-kernel model and Rust service health is not runtime-aggregated. |
| BHV-SV-005 | S3 SV.2 | current | Proxy provider list with real provider entries is Rust-only; Go fork provider endpoint is an empty stub. |
| BHV-SV-006 | S3 SV.2 | current | Rule provider list with real provider entries is Rust-only; Go fork rule provider endpoint is an empty stub/list. |
| BHV-SV-007 | S3 SV.2 | current | Provider healthcheck with a real provider is Rust-only; Go fork named provider lookup always falls through to 404. |

For R64 planning, the current authoritative open parity set is the
last 4 rows only: BHV-LC-003 and BHV-SV-005 through BHV-SV-007.

## Top candidates for R64 starting point

### Candidate 1: BHV-LC-003 service failure isolation

- **What it is**: S3 LC.1 requires multiple configured services to
  initialize concurrently, with failures isolated so the kernel still
  starts and exposes accurate service health.
- **Why it is open**: `p1_service_failure_isolation` is Rust-only.
  Golden spec DIV-H-006 says the current case has no honest broken
  service dual-kernel model, and Rust health reporting is static
  rather than runtime-aggregated.
- **Effort**: L (>3 days), because it likely needs harness modeling,
  runtime health plumbing, and dual-kernel oracle design.
- **Risk**: high. It may need a new Go config that actually creates a
  comparable broken service, and Rust may need a real `/services/health`
  or equivalent runtime snapshot instead of static admin health.
- **Impact**: closes 1 current BHV, but it is the only non-provider
  current gap and would remove the last LC hole.
- **Reuses R62 framework?**: partial. The generic health/run outcome
  primitives can classify repeated dual-kernel service-start attempts,
  but service-health schema would need a new evidence adapter.
- **Reference Go file path**: `go_fork_source/sing-box-1.12.14/service/`
  plus service users under `experimental/clashapi/server.go`.
- **Reference Rust file path**: `crates/sb-core/src/services/`,
  `app/src/bootstrap_runtime/api_services.rs`,
  `labs/interop-lab/cases/p1_service_failure_isolation.yaml`.
- **Spec section anchor**: S3 LC.1 BHV-LC-003; S4 DIV-H-006; S5
  Non-Promotable Cases.

### Candidate 2: BHV-SV-005 proxy provider list with data

- **What it is**: S3 SV.2 requires `GET /providers/proxies` to return
  provider entries with node/provider metadata, not just an empty shell.
- **Why it is open**: Rust has `ProviderManager` and a Rust-only e2e
  test with injected data. The Go fork endpoint currently returns
  `{"providers": {}}` and does not expose real provider data.
- **Effort**: M to L (1-3 days if treated as harness/oracle work; >3
  days if the Go fork must grow provider fixtures).
- **Risk**: medium-high. DIV-H-005 says SV.2 cannot be honest
  dual-kernel tested while Go provider endpoints are stubs.
- **Impact**: closes 1 BHV directly and is prerequisite knowledge for
  the rest of the provider triad.
- **Reuses R62 framework?**: yes for classification, partial for schema.
  Provider-list runs can use generic latest_health/run labels, but the
  provider response shape needs a protocol-specific comparer.
- **Reference Go file path**:
  `go_fork_source/sing-box-1.12.14/experimental/clashapi/provider.go`.
- **Reference Rust file path**: `crates/sb-api/src/clash/handlers.rs`,
  `crates/sb-api/src/managers.rs`,
  `crates/sb-api/tests/clash_http_e2e.rs`.
- **Spec section anchor**: S3 SV.2 BHV-SV-005; S4 DIV-H-005.

### Candidate 3: BHV-SV-006 rule provider list with data

- **What it is**: S3 SV.2 requires `GET /providers/rules` to return
  rule provider entries.
- **Why it is open**: Rust has injected rule-provider data tests, while
  the Go fork rule provider route returns an empty provider list and
  comments out real lookup/update behavior.
- **Effort**: M to L, for the same reason as BHV-SV-005 plus rule
  provider response-shape normalization.
- **Risk**: medium-high. Empty-set shape has already been treated as
  cosmetic, but non-empty provider parity is blocked by Go stub behavior.
- **Impact**: closes 1 BHV and would pair naturally with BHV-SV-005 if
  R64 chooses a provider-triad stage.
- **Reuses R62 framework?**: yes for repeated pass/fail/run-family
  tracking; partial for provider-specific response comparison.
- **Reference Go file path**:
  `go_fork_source/sing-box-1.12.14/experimental/clashapi/ruleprovider.go`.
- **Reference Rust file path**: `crates/sb-api/src/clash/handlers.rs`,
  `crates/sb-api/src/managers.rs`,
  `crates/sb-api/tests/clash_http_e2e.rs`.
- **Spec section anchor**: S3 SV.2 BHV-SV-006; S4 DIV-H-005.

### Candidate 4: BHV-SV-007 provider healthcheck with data

- **What it is**: S3 SV.2 requires `POST /providers/proxies/{name}/healthcheck`
  to produce healthcheck semantics for a real provider.
- **Why it is open**: Rust can inject a provider and returns 204 when
  the healthcheck path succeeds. The Go fork named provider middleware
  is stubbed so named provider routes return 404.
- **Effort**: L (>3 days) unless BHV-SV-005 first establishes a real
  provider fixture for both kernels.
- **Risk**: high. It depends on a provider object existing and on
  comparable healthcheck target semantics; otherwise it tests stubs.
- **Impact**: closes 1 BHV and validates the most operational part of
  provider support, but it should not be first in the provider triad.
- **Reuses R62 framework?**: yes for repeated health/run classification;
  partial for response semantics and provider-health dimensions.
- **Reference Go file path**:
  `go_fork_source/sing-box-1.12.14/experimental/clashapi/provider.go`.
- **Reference Rust file path**: `crates/sb-api/src/clash/handlers.rs`,
  `crates/sb-api/src/managers.rs`,
  `crates/sb-api/tests/clash_http_e2e.rs`.
- **Spec section anchor**: S3 SV.2 BHV-SV-007; S4 DIV-H-004 and DIV-H-005.

## Falsified candidates

- BHV-SV-001 through BHV-SV-004: subscription parsing is harness-side,
  not kernel behavior. Do not reopen as dual-kernel parity work.
- ARCH-LIMIT-REALITY: R45-R60 closed the current REALITY evidence
  regime with no sampler/dataplane signal; do not pick it for R64.
- `p2_bench_socks5_throughput`: S5 marks it pending but coverage-neutral;
  not an open BHV gap.
- BHV-SV-007 before BHV-SV-005: provider healthcheck needs an honest
  provider fixture first.

## Recommended order for R64

1. **Primary recommendation**: Candidate 1, BHV-LC-003. It is the only
   current non-provider structural gap, so solving or decisively
   reclassifying it gives the biggest information gain without getting
   trapped in Go provider stubs.
2. **Backup if primary blocked**: Candidate 2, BHV-SV-005. Start with
   proxy provider list because it is the first prerequisite for any
   provider-triad closure and has the clearest Rust-side implementation.
3. **Do NOT start with**: Candidate 4, BHV-SV-007. It depends on real
   provider discovery first, and starting there risks spending a round
   proving only that the Go fork's named provider route is still a stub.

## What R63 deliberately does NOT decide

- Does not pick R64 itself; planner and user will pick from this list
  in the next session.
- Does not commit to a sampler/dataplane change for the chosen BHV;
  that decision waits for stage-3 evidence.
- Does not assume the R62 framework is sufficient; if the chosen BHV
  exposes new evidence shape, R64 may need to extend
  dual_kernel_verification.

## File pointers needed by R64

- Spec: `labs/interop-lab/docs/dual_kernel_golden_spec.md` S3, S4, S5,
  and S6.
- Cases: `labs/interop-lab/cases/p1_service_failure_isolation.yaml`,
  `labs/interop-lab/cases/p1_optional_endpoints_contract.yaml`.
- Provider Go paths: `go_fork_source/sing-box-1.12.14/experimental/clashapi/provider.go`,
  `go_fork_source/sing-box-1.12.14/experimental/clashapi/ruleprovider.go`.
- Provider Rust paths: `crates/sb-api/src/clash/handlers.rs`,
  `crates/sb-api/src/managers.rs`, `crates/sb-api/tests/clash_http_e2e.rs`.
- Service Rust paths: `crates/sb-core/src/services/`,
  `app/src/bootstrap_runtime/api_services.rs`, `app/src/run_engine.rs`.
- Existing tests R64 must not break: `crates/sb-api/tests/clash_http_e2e.rs`
  provider tests, `p1_optional_endpoints_contract`, and
  `p1_service_failure_isolation` until the latter is deliberately
  remodeled.
