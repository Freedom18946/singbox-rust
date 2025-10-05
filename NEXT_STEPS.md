Parity Roadmap (vs sing-box v1.12.4; CLI synced 1.13 alpha)

Priority legend
- P0: Critical for external parity (CLI/config/runtime) and high user impact
- P1: Important for feature completeness and common workflows
- P2: Nice-to-have or ecosystem-/platform-specific

P0 — Close critical gaps
- Sniffing pipeline
  - Implement TLS SNI / HTTP Host / QUIC ALPN sniff on inbound path and expose as routing conditions.
  - Add enable flags on inbounds (http/socks/mixed/tun) mirroring upstream.
  - Wire to router conditions and explain trace.
- TLS features to production
  - REALITY: Complete handshake path and configuration glue (crates/sb-tls + sb-transport), add E2E tests.
  - ECH: Integrate runtime handshake using generated key/config; add QUIC/ECH alignment.
- Inbound/outbound coverage
  - Implement inbound: direct, hysteria (v1), hysteria2, anytls.
  - Implement outbound: hysteria (v1), anytls; unify tuic/hysteria2 under sb-adapters and add tests.
  - Promote shadowtls outbound from sb-core to adapters and add test coverage.
  - SSH outbound: polish (host key handling), examples and E2E.
- CLI parity (externally visible)
  - rule-set: DONE — compile/convert/merge/upgrade implemented (plus validate/info/format/decompile/match).
  - format: DONE (app/src/bin/format.rs)
  - generate: add vapid/wireguard key generation; tls/reality/ech are DONE.
  - tools: DONE — http3 fetch via reqwest http3 feature; connect and synctime are present.
  - geosite/geoip: DONE for geoip; geosite near-complete
    - geosite: list/lookup/export support upstream binary geosite.db. Optional: add `matcher` subcommand for display-only UX.
    - geoip: list/lookup/export fully support MMDB sing-geoip; text DB fallback preserved.
  - merge: keep aligning edge cases/flags with upstream behavior.

P1 — DNS/route/services completeness
- DNS
  - DoH: expand to full behavior (GET/POST, content-types, error mapping, timeouts, HTTP/3 where applicable).
  - Add hosts override and per-domain bootstrap options; expose tailscale DNS server as N/A or implement equivalent if feasible.
  - Extend DNS rule actions to parity with upstream (where practical).
- Route engine
  - Consolidate keyword/regex conditions ergonomics; ensure rule-set remote caching and failure policies match upstream semantics.
  - Process-based routing: finalize Windows/macOS/Linux parity and document constraints.
- Services
  - NTP service: implement runtime service per config; integrate with time-sensitive components (TLS, VMess time checks).
  - Evaluate SSM API and DERP service feasibility; if committed, sketch minimal Rust equivalents.

P2 — Platform and ecosystem
- WireGuard outbound/endpoint
  - Replace stub with functional implementation or provide clear N/A rationale; add interop tests.
- Tailscale endpoint/DNS server integration: research Rust bindings and security posture; revisit based on demand.
- uTLS alternative
  - Investigate Rust-side ClientHello mimic options; document trade-offs if not feasible.

Tooling and quality gates
- Unify outbound implementations
  - Remove duplication between sb-core and sb-adapters; keep adapters as the single, tested integration surface.
- Schema/docs alignment
  - Update v2 schema to include all implemented inbounds/outbounds and shared fields; ensure examples and tests cover new types.
- E2E and interop tests
  - Add protocol-specific interop suites (tuic/hysteria2/vless/vmess/shadowtls) including UDP over stream where applicable.
- CLI UX
  - Snapshot tests for help/usage JSON outputs; align flags/exit codes with upstream.

Tracking
- See GO_PARITY_MATRIX.md for current status. Update both files as features land.
- Baseline: v1.12.4 stable; latest upstream pre-release v1.13.0-alpha.19 (2025-10-05) used for CLI inventory.
