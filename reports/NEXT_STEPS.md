Parity Roadmap (vs sing-box v1.12.4)

Priority legend
- P0: Critical for external parity (CLI/config/runtime) and high user impact
- P1: Important for feature completeness and common workflows
- P2: Nice-to-have or ecosystem-/platform-specific

P0 — Close critical gaps
- Sniffing pipeline
  - DONE: TLS SNI / HTTP Host / QUIC ALPN sniff implemented and exposed to router conditions; explain trace supports sniff fields.
  - DONE: Enable flags on inbounds (http/socks/mixed/tun) wired via `sniff` boolean in schema/IR.
- TLS features to production
  - REALITY: Complete handshake path and configuration glue (crates/sb-tls + sb-transport), add E2E tests. (remaining)
  - ECH: Integrate runtime handshake using generated key/config; add QUIC/ECH note alignment. (remaining)
- Inbound/outbound coverage
  - inbound `direct`: DONE.
  - inbound `hysteria`/`hysteria2`/`anytls`: remaining.
  - outbound `hysteria` (v1), `anytls`: remaining; unify tuic/hysteria2 under sb-adapters with tests.
  - shadowtls outbound: DONE (promoted to sb-adapters; basic tests landed).
  - SSH outbound: password/private-key wired; add example + E2E; host key management polish. (remaining E2E)
- CLI parity (externally visible)
  - rule-set: DONE — compile/convert/merge/upgrade implemented.
  - format: DONE (app/src/bin/format.rs)
  - generate: DONE — tls/reality/ech present; wireguard added; vapid available behind `jwt`.
  - tools: DONE — connect/fetch/fetch-http3 implemented (feature `tools_http3`); synctime implemented with unit tests.
  - geosite/geoip: DONE — list/export/lookup (plus geosite matcher helper) supported.
  - merge: path inlining for TLS/ECH/SSH DONE; continue to align edge-cases with upstream.

P1 — DNS/route/services completeness
- DNS
  - DoH: expand to full behavior (GET/POST, content-types, error mapping, timeouts, HTTP/3 where applicable).
  - Add hosts override and per-domain bootstrap options; expose tailscale DNS server as N/A or implement equivalent if feasible.
  - Extend DNS rule actions to parity with upstream (where practical).
- Route engine
  - Consolidate keyword/regex conditions ergonomics, ensure rule-set remote caching and failure policies match upstream semantics.
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
- Baseline version set in BASELINE_UPSTREAM.env: v1.12.4
