<!-- tier: B -->
# P1313-06 Adapter Surface Contracts

Priority: P1

Primary evidence:

- `agents-only/reference/GO_PARITY_MATRIX.md` PX-007, PX-008, PX-009
- `go_fork_source/sing-box-1.13.13/adapter/handler.go`
- `go_fork_source/sing-box-1.13.13/adapter/upstream.go`
- `go_fork_source/sing-box-1.13.13/adapter/router.go`
- `go_fork_source/sing-box-1.13.13/adapter/dns.go`
- `go_fork_source/sing-box-1.13.13/adapter/fakeip.go`
- `go_fork_source/sing-box-1.13.13/adapter/experimental.go`
- `go_fork_source/sing-box-1.13.13/adapter/{time,certificate,ssm,v2ray}.go`

## Goal

Expose stable Rust adapter-facing contracts for the Go 1.13.13 surfaces that are currently
hidden behind IR, global services, or one-off registries.

## Current Gap

PX-007/PX-008/PX-009 record missing or divergent handler/upstream/router/ruleset, DNS/FakeIP,
time/certificate/cache/clash/v2ray adapter surfaces.

## Task Split

1. Handler and upstream wrappers.
   - TCP and UDP connection handler traits.
   - Packet connection handler behavior.
   - Upstream metadata and transport wrapping.
   - Preserve existing `sb-types` boundary discipline.

2. Router and RuleSet API.
   - `PreMatch`, `RouteConnection`, `RoutePacketConnection`.
   - RuleSet lookup by tag.
   - Update callback plumbing for rule-set reload.
   - Connection tracker append/reset hooks.

3. DNS adapter API.
   - DNS client/router interfaces.
   - Transport manager lookup.
   - Query options surface: strategy, cache behavior, client subnet.

4. FakeIP adapter API.
   - Address allocation and reverse mapping.
   - Store metadata integration.
   - Persistence hooks for P1313-07.

5. Service-facing adapter API.
   - TimeService and NTP facade.
   - CertificateStore facade.
   - CacheFile facade.
   - ClashServer facade.
   - SSM and V2Ray service surfaces.

6. Cross-crate contract tests.
   - Add compile-level tests to prevent accidental downcast-only behavior.
   - Prefer trait methods over concrete downcasts.
   - Ensure feature gates do not silently remove required adapter surfaces.

## Acceptance

- `cargo check -p sb-types`
- `cargo check -p sb-core`
- `cargo check -p sb-adapters`
- At least one cross-crate integration test proving a consumer can use the new contract
  without depending on concrete implementation types.

## Non-Goals

- Do not force a byte-for-byte Go architecture clone.
- Do not expose public unstable `RuntimePlan` / `PlannedConfigIR`.
- Cache persistence implementation belongs to P1313-07.
