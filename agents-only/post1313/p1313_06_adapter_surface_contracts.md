<!-- tier: B -->
# P1313-06 Adapter Surface Contracts

Priority: P1

Status: DONE (2026-06-27)

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

## Result

- `sb-types::ports` now exposes object-safe adapter-facing contracts backed by a local
  `BoxFuture` alias, including handler/upstream, router/ruleset, DNS, FakeIP/RDRC,
  CacheFile, URLTest history, Clash, V2Ray, time, certificate, and the
  `AdapterServicePorts` bundle.
- Existing `InboundHandler`, `InboundAcceptor`, `OutboundConnector`, and `DnsPort`
  methods no longer use `impl Future` in trait signatures, so consumers can keep
  port values behind `dyn Trait`.
- `sb-core::adapter::surface` bridges `ContextRegistry` services into the new
  contracts through thin adapters; inbound/outbound adapter contexts expose the
  service bundle through `services()`.
- `context::CacheFile` now carries adapter-visible FakeIP, RDRC, and rule-set
  persistence hooks with conservative defaults. `CacheFileService` wires those
  hooks to its existing storage behavior.
- Router dispatch remains an explicit future wiring point: the bundle exposes a
  placeholder router port that supports pre-match/tracker shape without claiming
  direct stream/packet routing completion.

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

- `cargo check -p sb-types` PASS
- `cargo check -p sb-core --features router` PASS
- `cargo check -p sb-adapters` PASS
- `cargo check -p app --features parity` PASS
- `cargo check --workspace --all-features` PASS
- `cargo test -p sb-types` PASS
- `cargo test -p sb-core adapter_services_expose_trait_object_contracts_without_downcast --features router` PASS
- `./agents-only/06-scripts/verify-consistency.sh` PASS
- `make boundaries` PASS
- `cargo fmt --check` PASS
- Cross-crate contract test added at
  `crates/sb-core/tests/adapter_surface_contract.rs`; it consumes the adapter
  service bundle only through `dyn sb_types::ports::*` trait objects.

## Non-Goals

- Do not force a byte-for-byte Go architecture clone.
- Do not expose public unstable `RuntimePlan` / `PlannedConfigIR`.
- Cache persistence implementation belongs to P1313-07.
