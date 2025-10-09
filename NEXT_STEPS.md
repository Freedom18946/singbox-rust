Parity Roadmap (vs sing-box v1.12.4; CLI synced 1.13 alpha)

Priority legend
- P0: Critical for external parity (CLI/config/runtime) and high user impact
- P1: Important for feature completeness and common workflows
- P2: Nice-to-have or ecosystem-/platform-specific

P0 — Close critical gaps ✅ COMPLETED
- Sniffing pipeline: ✅ DONE
  - HTTP Host sniff: DONE — integrated with CONNECT inbound routing; tests added.
  - Enable flags: DONE for http/socks/tun in scaffolds; config path accepts `sniff`.
  - TLS SNI and QUIC ALPN: DONE — extract_sni_from_tls_client_hello, extract_alpn_from_tls_client_hello, and QUIC ALPN detection implemented; RouterInput has sniff_host/sniff_alpn fields; routing engine uses them for domain/ALPN matching; E2E tests added (router_sniff_sni_alpn.rs).
  
- TLS features to production: ✅ DONE
  - REALITY: ✅ DONE — Complete client/server handshake with X25519 key exchange, auth data embedding, fallback proxy; integrated with VLESS/Trojan adapters; E2E tests in tests/reality_tls_e2e.rs
  - ECH: ✅ DONE — Runtime handshake with HPKE encryption, SNI encryption, ECHConfigList parsing; integrated with TLS transport; E2E tests in tests/e2e/ech_handshake.rs
  - ACME: N/A — Go-specific certmagic library; Rust alternatives exist but deprioritized (users typically deploy with pre-existing certs or reverse proxies)
  
- Inbound/outbound coverage: ✅ DONE
  - direct inbound: ✅ DONE (TCP+UDP forwarder with session-based NAT; automatic UDP timeout cleanup; E2E tests in inbound_direct_udp.rs)
  - hysteria (v1): ✅ DONE — Full inbound/outbound implementation with QUIC transport, custom congestion control, UDP relay; E2E tests in tests/e2e/hysteria_v1.rs
  - hysteria2: ✅ DONE — Full inbound/outbound with Salamander obfuscation, password auth, UDP over stream; comprehensive E2E tests
  - anytls: Deferred — Requires external Rust library (upstream uses github.com/anytls/sing-anytls); see .kiro/specs/p0-production-parity/anytls-research.md
  - tuic outbound: ✅ DONE — Full implementation with UDP over stream, authentication; E2E tests in tests/e2e/tuic_outbound.rs
  - shadowtls outbound: ✅ DONE — Adapter wrapper implemented in `crates/sb-adapters/src/outbound/shadowtls.rs`; basic unit tests added
  - SSH outbound: ✅ DONE — Password and private key auth, host key verification, connection pooling; E2E tests in tests/e2e/ssh_outbound.rs
  
- CLI parity (externally visible): ✅ DONE
  - rule-set: DONE — compile/convert/merge/upgrade implemented (plus validate/info/format/decompile/match)
  - format: DONE (app/src/bin/format.rs)
  - generate: DONE — reality-keypair, ech-keypair, wireguard-keypair, tls-keypair; vapid-keypair available behind feature `jwt`
  - tools: DONE — http3 fetch via reqwest http3 feature; connect and synctime are present
  - geosite/geoip: DONE — list/lookup/export support for both; geosite supports upstream binary geosite.db; geoip supports MMDB sing-geoip with text DB fallback
  - merge: keep aligning edge cases/flags with upstream behavior

P1 — DNS/route/services completeness
- DNS
  - DoH: expand to full behavior (GET/POST, content-types, error mapping, timeouts, HTTP/3 where applicable).
  - Add hosts override and per-domain bootstrap options; expose tailscale DNS server as N/A or implement equivalent if feasible.
  - Add DHCP DNS server backend (`dns.servers[].type = "dhcp"`).
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
