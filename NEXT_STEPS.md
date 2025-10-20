Parity Roadmap (vs sing-box `dev-next`)

Last audited: 2025-10-14 23:30 UTC

## Current Snapshot
- CLI: Unified dispatcher exists in `app/src/main.rs` with `check/merge/format/generate/geoip/geosite/ruleset/run/tools/version` behind features.
- Config IR: V2 schema, migration, and IR are solid (`crates/sb-config/src/ir/*`), but top-level `ntp/certificate/endpoints/services/experimental` are not fully consumed by runtime.
- Runtime bridging: `run` now starts HTTP/SOCKS/TUN inbounds from IR, installs router index, and supports hot reload for router index and outbound registry (inbounds not hot-reloaded). Bridges minimal DNS pool from `dns.servers` via env.
- Protocol adapters: Broad implementations exist under `crates/sb-adapters` and `crates/sb-core/outbound`, but many are gated or only env-driven (e.g., VMess/VLESS transport chain), not yet wired from config.
- DNS: DoH/DoT/DoQ/FakeIP capabilities exist in sb-core; enabling is env-driven, not via `dns` config block.
- Rule-set/Geo: Tooling present; datasets are not packaged or auto-updated; compile/decompile/upgrade flows need finishing touches.
- Stubs/intentional gaps: WireGuard outbound is a stub; AnyTLS/Tor unimplemented; uTLS not targeted.

## Strategy (3 Phases)
- Phase 1 — Minimal viable run path (P0):
  - DONE (initial): Bridge IR → runtime: instantiate HTTP/SOCKS/TUN inbounds; direct/block/http/socks outbounds; build Router from IR; enable hot reload (file watcher) for rules.
  - DONE (initial): DNS minimal config path: consume `dns.servers` for upstream pool selection; keep env as override.
  - Next: expand protocol outbounds and config-driven options; inbounds hot reload (optional).
- Phase 2 — Protocol activation (P0):
  - Wire VLESS/VMess/Trojan/Shadowsocks/TUIC/Hysteria2 outbounds from IR, including transport chain (TLS/WS/H2/HTTPUpgrade/gRPC) and multiplex.
  - Expose selector/urltest via config; integrate health checks; reduce env knobs.
  - Add sniffing pipeline → router conditions (HTTP Host, TLS SNI, QUIC ALPN).
- Phase 3 — Parity completion (P1):
  - Top-level services (`ntp`, later `derp/resolved/ssm-api`) and `certificate/endpoints/experimental` wiring.
  - Rule-set compile/decompile/upgrade flow parity; package GeoIP/Geosite with update hooks.
  - ECH/REALITY end-to-end verification and config UX polish; document non-goals (uTLS, Tor if out-of-scope).

## Workstreams and Tasks
- WS1: Runtime Bridging (P0)
  - Build Router from `ConfigIR` and replace index live (`app/src/config_loader.rs`).
  - Map `ir::InboundIR`/`OutboundIR` → sb-adapters factories; start listeners and registries.
  - Re-enable hot reload; atomic swap of router and outbound registries.
- WS2: DNS Integration (P0)
  - Parse `dns` block into IR; create backend pool and strategy; wire into resolver; env overrides remain.
  - Metrics and error surfaces aligned with sb-core DNS modules.
- WS3: P0 Protocols (P0)
  - Implement config-driven builders for VLESS/VMess/Trojan/Shadowsocks/TUIC/Hysteria2.
  - Transport chain selection from IR (`tls/ws/h2/httpupgrade/grpc/multiplex`).
  - Selector wiring: DONE (manual selector via core `selector`), URLTest pending.
- WS4: Sniffing and Routing (P1)
  - Surface sniffed fields to router; add `alpn`/`protocol` matches; ensure performance safe defaults.
- WS5: Tooling & Data (P1)
  - Rule-set compile/decompile/upgrade; golden tests.
  - GeoIP/Geosite packaging and updater (scripts + release artifacts).
- WS6: Services & Certs (P1)
  - Enable `ntp` service from config; stage `derp/resolved/ssm-api` scaffolding.
  - `certificate` loading/reference; document secure defaults.
- WS7: Security/Hardening (cross-cutting)
  - Secrets redaction; zeroize sensitive material; consistent error mapping; rate limits.

## Milestones and Acceptance
- M1 (P0): `app run -c minimal.yaml` starts HTTP/SOCKS inbound, routes via direct/block/http/socks, router rules active; hot reload for rules; basic DNS block applied.
- M2 (P0): Config drives VLESS/VMess/Trojan/Shadowsocks/TUIC/Hysteria2 with transport chain; selector/urltest usable; health metrics; env knobs optional.
- M3 (P1): Sniff → route conditions wired; rule-set compile/upgrade parity; packaged GeoIP/Geosite; `ntp` service enabled from config.

## Risks & Mitigations
- Adapter duplication between sb-core and sb-adapters → converge via single builder path per protocol.
- Feature gating complexity → curated default feature set for release profiles; CI matrix to guard drift.
- DNS/doq platform nuances → keep graceful fallbacks; explicit errors with actionable hints.

## Verification
- Unit: expand `sb-config` and adapter builders coverage per protocol/transport.
- Integration: fixtures that run `app` vs upstream `sing-box` to compare exit codes/logs for config acceptance.
- E2E: smoke flows for each P0 protocol; router rule explain/preview parity; DNS pool strategies.
