Parity Roadmap (vs sing-box v1.12.4; CLI synced 1.13 alpha)

**Last Updated**: 2025-10-11 00:00 UTC
**Baseline**: sing-box v1.13.0-alpha.19
**Source**: Synthesized from kiro audit conclusions (.kiro/specs/sing-box-parity-audit/) and repository analysis
**Related**: See GO_PARITY_MATRIX.md for detailed feature status

Priority legend
- P0: Critical for external parity (CLI/config/runtime) and high user impact
- P1: Important for feature completeness and common workflows
- P2: Nice-to-have or ecosystem-/platform-specific

## Sprint 5 Achievements (2025-10-09) 🎉

**Major Breakthrough**: TLS infrastructure completed, unblocking 15+ partial protocols

### Completed Features
- ✅ **TLS Infrastructure** (`crates/sb-tls`): REALITY, ECH, Standard TLS with comprehensive tests
- ✅ **Direct Inbound**: TCP+UDP forwarder with session-based NAT, automatic UDP timeout cleanup
- ✅ **Hysteria v1**: Full client/server with QUIC transport, custom congestion control
- ✅ **Hysteria2**: Complete with Salamander obfuscation, password auth, UDP over stream
- ✅ **TUIC Outbound**: Full UDP over stream support with authentication
- ✅ **Sniffing Pipeline**: HTTP Host, TLS SNI, QUIC ALPN detection integrated with routing

### Coverage Progress
- **Full implementations**: 6 → 15 (+150%)
- **Functional coverage**: 19.4% → 21.1%
- **Inbounds**: 13.3% → 33.3%
- **Outbounds**: 17.6% → 35.3%
- **TLS**: 0% → 50% (3/6 complete)

## Sprint 6 Achievements (2025-10-11) 🎉

**Major Success**: Protocol integration complete - VMess TLS/Multiplex, HTTP/Mixed TLS, full Multiplex support

### Completed Features
- ✅ **VMess Full Support**: TLS + Multiplex integration for both inbound and outbound
- ✅ **HTTP Inbound TLS**: Complete with Standard, REALITY, ECH support
- ✅ **Mixed Inbound TLS**: Complete with Standard, REALITY, ECH support
- ✅ **Multiplex Transport**: Full yamux-based stream multiplexing with connection pooling, Brutal Congestion Control
- ✅ **SOCKS Outbound**: Complete implementation with TCP/UDP support and authentication (verified existing)
- ✅ **UDP Support**: Direct and Block outbounds with UDP forwarding (verified existing)
- ✅ **Protocol Adapter Multiplex**: Shadowsocks, Trojan, VLESS, VMess all support Multiplex

### Coverage Progress
- **Full implementations**: 15 → 21 (+40%)
- **Functional coverage**: 21.1% (stable, Partial reduced)
- **Inbounds**: 33.3% → 40% (+6 protocols upgraded)
- **Outbounds**: 35.3% → 47.1% (+4 protocols upgraded)
- **Transport**: 21.4% → 28.6% (Multiplex + TLS complete)

### Upgraded to Full Status
1. HTTP Inbound (TLS support added)
2. Mixed Inbound (TLS support added)
3. VMess Inbound (TLS + Multiplex added)
4. VMess Outbound (TLS + Multiplex added)
5. Direct Outbound (UDP support verified)
6. Block Outbound (UDP support verified)

## Sprint 8 Achievements (2025-10-11) 🎉

**Major Success**: DNS Transport Layer Complete - 88.9% coverage in one sprint

### Completed Features
- ✅ **DoH (DNS over HTTPS)**: Full implementation with GET/POST methods, HTTP/2 support, connection pooling
  - Implementation: `crates/sb-core/src/dns/transport/doh.rs`
  - Features: Adaptive query selection, Cloudflare/Google/Quad9/AdGuard presets
  - Tests: Comprehensive unit tests (8 tests passing)
- ✅ **DoT (DNS over TLS)**: Full implementation with TLS 1.3, rustls, ALPN support
  - Implementation: `crates/sb-core/src/dns/transport/dot.rs`
  - Features: Server certificate verification, TCP length-prefix format
  - Tests: Unit tests with integration tests (requires network)
- ✅ **TCP DNS Transport**: RFC 1035 compliant implementation
  - Implementation: `crates/sb-core/src/dns/transport/tcp.rs`
  - Features: 2-byte length prefix, connection timeout, suitable for large queries
  - Tests: 5 unit tests (3 passed, 2 network tests ignored)
- ✅ **UDP DNS Transport**: Core transport with timeout support
  - Implementation: `crates/sb-core/src/dns/transport/udp.rs`
  - Features: Basic query/response, timeout handling
  - Status: Already existed, verified functional
- ✅ **FakeIP**: IPv4/IPv6 support with LRU caching
  - Implementation: `crates/sb-core/src/dns/fakeip.rs`
  - Features: CIDR range management, bidirectional mapping (domain↔IP), environment config
  - Tests: Comprehensive unit tests covering allocation and lookup
- ✅ **Hosts File Resolver**: Cross-platform parser and resolver
  - Implementation: `crates/sb-core/src/dns/hosts.rs`
  - Features: /etc/hosts and Windows hosts support, IPv4/IPv6, case-insensitive, file reload
  - Tests: 8 comprehensive unit tests (all passing)
- ✅ **System Resolver**: Tokio-based OS DNS resolution
  - Implementation: `crates/sb-core/src/dns/system.rs`
  - Features: Delegates to OS resolver, configurable TTL
  - Status: Already existed, verified functional
- ◐ **DoQ (DNS over QUIC)**: Partial implementation
  - Implementation: `crates/sb-core/src/dns/transport/doq.rs`
  - Status: Exists but needs verification and comprehensive testing

### Coverage Progress
- **Full implementations**: 24 → 31 (+29% in one sprint!)
- **Functional coverage**: 21.7% → 25.6%
- **DNS**: 0% → 88.9% (8/9 transports, only DHCP missing)
- **Total features**: 180 features, +7 Full implementations

### Impact
- Unblocks DNS-based routing rules
- Enables hosts file overrides and FakeIP for routing
- Production-ready secure DNS with DoH/DoT
- Foundation for DNS rule engine integration (Sprint 9)

---

P0 — Close critical gaps ✅ SPRINT 6 COMPLETED

- Sniffing pipeline: ✅ DONE (Sprint 5)
  - HTTP Host sniff: DONE — integrated with CONNECT inbound routing; tests added.
  - Enable flags: DONE for http/socks/tun in scaffolds; config path accepts `sniff`.
  - TLS SNI and QUIC ALPN: DONE — extract_sni_from_tls_client_hello, extract_alpn_from_tls_client_hello, and QUIC ALPN detection implemented; RouterInput has sniff_host/sniff_alpn fields; routing engine uses them for domain/ALPN matching; E2E tests added (router_sniff_sni_alpn.rs).

- TLS features to production: ✅ DONE (Sprint 5)
  - REALITY: ✅ DONE — Complete client/server handshake with X25519 key exchange, auth data embedding, fallback proxy; integrated with VLESS/Trojan adapters; E2E tests in tests/reality_tls_e2e.rs
  - ECH: ✅ DONE — Runtime handshake with HPKE encryption, SNI encryption, ECHConfigList parsing; integrated with TLS transport; E2E tests in tests/e2e/ech_handshake.rs
  - ACME: N/A — Go-specific certmagic library; Rust alternatives exist but deprioritized (users typically deploy with pre-existing certs or reverse proxies)

- Protocol TLS Integration: ✅ DONE (Sprint 6)
  - HTTP Inbound: ✅ DONE — TLS support (Standard, REALITY, ECH) via `sb_transport::TlsConfig`
  - Mixed Inbound: ✅ DONE — TLS support (Standard, REALITY, ECH) via `sb_transport::TlsConfig`
  - VMess Inbound: ✅ DONE — TLS + Multiplex support
  - VMess Outbound: ✅ DONE — TLS + Multiplex support

- Multiplex Transport: ✅ DONE (Sprint 5-6)
  - Core Implementation: ✅ DONE (Sprint 5) — yamux-based multiplexing with connection pooling, Brutal Congestion Control
  - Protocol Integration: ✅ DONE (Sprint 6) — Shadowsocks, Trojan, VLESS, VMess all support Multiplex
  - Unit Tests: ✅ DONE (Sprint 5) — 12 comprehensive tests covering pooling, lifecycle, max streams

- Inbound/outbound coverage: ✅ DONE (Sprint 5-6)
  - direct inbound: ✅ DONE (Sprint 5) — TCP+UDP forwarder with session-based NAT; automatic UDP timeout cleanup; E2E tests in inbound_direct_udp.rs
  - hysteria (v1): ✅ DONE (Sprint 5) — Full inbound/outbound implementation with QUIC transport, custom congestion control, UDP relay; E2E tests in tests/e2e/hysteria_v1.rs
  - hysteria2: ✅ DONE (Sprint 5) — Full inbound/outbound with Salamander obfuscation, password auth, UDP over stream; comprehensive E2E tests
  - anytls: Deferred — Requires external Rust library (upstream uses github.com/anytls/sing-anytls); see .kiro/specs/p0-production-parity/anytls-research.md
  - tuic outbound: ✅ DONE (Sprint 5) — Full implementation with UDP over stream, authentication; E2E tests in tests/e2e/tuic_outbound.rs
  - shadowtls outbound: ✅ DONE (Sprint 5) — Adapter wrapper implemented in `crates/sb-adapters/src/outbound/shadowtls.rs`; basic unit tests added
  - SSH outbound: ✅ DONE (Sprint 5) — Password and private key auth, host key verification, connection pooling; E2E tests in tests/e2e/ssh_outbound.rs
  - SOCKS outbound: ✅ DONE (Sprint 6 verified) — Complete SOCKS5 implementation with TCP/UDP support, authentication (no-auth, username/password), BIND command

- UDP Infrastructure: ✅ DONE (Sprint 6 verified)
  - Direct Outbound UDP: ✅ DONE — `udp_bind()` method functional in `crates/sb-core/src/outbound/direct.rs`
  - Block Outbound UDP: ✅ DONE — `udp_bind()` method returns error for blocked requests in `crates/sb-core/src/outbound/block.rs`
  - UDP NAT Manager: ✅ DONE — Session-based NAT with automatic timeout cleanup in `crates/sb-core/src/net/udp_nat.rs`

- CLI parity (externally visible): ✅ DONE (Sprint 5)
  - rule-set: DONE — compile/convert/merge/upgrade implemented (plus validate/info/format/decompile/match)
  - format: DONE (app/src/bin/format.rs)
  - generate: DONE — reality-keypair, ech-keypair, wireguard-keypair, tls-keypair; vapid-keypair available behind feature `jwt`
  - tools: DONE — http3 fetch via reqwest http3 feature; connect and synctime are present
  - geosite/geoip: DONE — list/lookup/export support for both; geosite supports upstream binary geosite.db; geoip supports MMDB sing-geoip with text DB fallback
  - merge: keep aligning edge cases/flags with upstream behavior

P1 — DNS/route/services completeness ✅ DNS TRANSPORT COMPLETE (Sprint 8)

**Status**: DNS transport layer complete (88.9%), routing engine next priority

- DNS: ✅ **TRANSPORT LAYER DONE (Sprint 8)**
  - ✅ **DoH (DNS over HTTPS)**: Full - GET/POST methods, HTTP/2, connection pooling
  - ✅ **DoT (DNS over TLS)**: Full - TLS 1.3, rustls, ALPN support
  - ✅ **UDP/TCP transports**: Full - RFC 1035 compliant, timeout support
  - ✅ **Hosts file override**: Full - Cross-platform parser with reload support
  - ✅ **FakeIP implementation**: Full - IPv4/IPv6, LRU caching, CIDR management
  - ✅ **System Resolver**: Full - Tokio-based OS DNS resolution
  - ◐ **DoQ (DNS over QUIC)**: Partial - exists, needs verification
  - ✗ **DHCP DNS backend**: Missing - platform-specific, deferred to future sprint
  - **Next**: Integrate DNS transports with routing engine, add DNS rule engine support
  - **Defer**: Tailscale DNS server (mark as N/A or implement equivalent if feasible)

- Route engine
  - **Critical need**: Essential matchers (CIDR, domain, port, protocol, network, inbound/outbound)
  - Implement rule-set support (local + remote with caching)
  - Consolidate keyword/regex conditions ergonomics
  - Ensure rule-set remote caching and failure policies match upstream semantics
  - Process-based routing: finalize Windows/macOS/Linux parity and document constraints
  - **Advanced matchers** (lower priority): process name/path, WiFi SSID/BSSID, user/auth, AdGuard

- Services
  - **NTP service**: Implement runtime service per config; integrate with time-sensitive components (TLS, VMess time checks)
  - Evaluate SSM API and DERP service feasibility; if committed, sketch minimal Rust equivalents

P2 — Platform and ecosystem (DEFERRED)

**Status**: Lower priority; evaluate based on user demand

- WireGuard outbound/endpoint
  - Replace stub with functional implementation or provide clear N/A rationale
  - Add interop tests with upstream Go sing-box
  - Consider using boringtun or wireguard-rs libraries

- Tailscale endpoint/DNS server integration
  - Research Rust bindings and security posture
  - Revisit based on demand and community interest

- uTLS alternative
  - Investigate Rust-side ClientHello mimic options (TLS fingerprint customization)
  - Document trade-offs if not feasible
  - Consider forking/porting relevant Go uTLS functionality

- Anytls protocol support
  - Requires external Rust library (upstream uses github.com/anytls/sing-anytls)
  - See `.kiro/specs/p0-production-parity/anytls-research.md` for investigation notes
  - Mark as deferred pending library availability

---

## Post-Sprint 8 Priority Recommendations

### Sprint 8 Summary ✅ COMPLETED

**Theme**: DNS Transport Layer - ACHIEVED 88.9% DNS coverage
- ✅ 7 Full DNS transport implementations (DoH, DoT, UDP, TCP, FakeIP, Hosts, System)
- ✅ 1 Partial implementation (DoQ - needs verification)
- ✅ Overall coverage increased from 21.7% → 25.6%
- ✅ +7 Full implementations in one sprint
- ✅ All tests passing (Hosts: 8/8, TCP: 3/3 unit tests)

---

### Next Sprint (Sprint 9) - Routing Engine Foundation

**Theme**: Build essential routing matchers and rule-set support

**Priority**: P1 - Critical for production deployments

1. **Core Routing Matchers** (2-3 weeks)
   - CIDR matcher (IPv4/IPv6 address ranges)
   - Domain matcher (exact, suffix, keyword, regex)
   - Port matcher (single, range, list)
   - Protocol matcher (TCP, UDP, ICMP)
   - Network matcher (tcp, udp)
   - Inbound/Outbound matcher
   - Expected outcome: Essential routing functionality for 80% use cases

2. **Rule-Set Support** (1-2 weeks)
   - Local rule-set loading (JSON/binary formats)
   - Remote rule-set with HTTP/HTTPS fetch
   - Rule-set caching (memory + disk)
   - Automatic update mechanism
   - Failure policies (use cached, fail-open, fail-closed)
   - Expected outcome: Compatible with upstream rule-set formats

3. **DNS Integration** (1 week)
   - DNS query routing (route queries to different upstreams)
   - DNS response routing (route based on resolved IPs)
   - FakeIP integration with routing rules
   - Expected outcome: DNS-aware routing for advanced use cases

**Sprint 9 Target**: 60%+ routing coverage, DNS integration, rule-set support

---

### Post-Sprint 6 Priority Recommendations (ARCHIVED)

### Next Sprint (Sprint 7) - Testing & UDP Protocol Support

**Theme**: Validate Multiplex integration, complete UDP relay for protocols

1. **E2E Testing for Multiplex Integration** (1 week)
   - Test Shadowsocks with Multiplex (multiple streams, data integrity)
   - Test Trojan with Multiplex (multiple streams, data integrity)
   - Test VLESS with Multiplex (multiple streams, data integrity)
   - Test VMess with TLS + Multiplex combined
   - Expected outcome: Comprehensive validation of Sprint 5-6 work

2. **UDP Protocol Support** (1-2 weeks)
   - Shadowsocks outbound UDP relay
   - Trojan outbound UDP relay
   - VLESS outbound UDP relay
   - Integration with existing UDP NAT manager
   - Expected outcome: 3 protocols upgraded to Full (UDP support)

3. **Documentation Sprint** (1 week - optional)
   - TLS integration guide (REALITY, ECH, Standard)
   - Multiplex usage and performance tuning
   - UDP support and NAT configuration
   - Example configurations for common scenarios

**Sprint 7 Target**: Validate all Sprint 5-6 work, add UDP relay, improve documentation

---

### Next Quarter (Sprints 8-11) - Foundation Systems

**Theme**: DNS, Routing, V2Ray Transport ecosystem

1. **DNS Transport Layer** (Sprint 8, 2-3 weeks)
   - DoH (DNS over HTTPS): GET/POST methods, HTTP/3 support
   - DoT (DNS over TLS): Using sb-tls infrastructure
   - UDP/TCP transports: Basic DNS queries
   - Hosts file override support
   - FakeIP implementation (memory-backed)
   - Expected outcome: Production-ready DNS subsystem

2. **Routing Engine** (Sprint 9, 3-4 weeks)
   - Core matchers: CIDR, domain, port, protocol, network
   - Rule-set support: Local + remote with caching
   - DNS routing integration
   - Outbound selection logic
   - Expected outcome: Essential routing functionality complete

3. **V2Ray Transport Suite** (Sprint 10-11, 4-6 weeks)
   - WebSocket transport (most critical, highest demand)
   - gRPC transport
   - HTTP/2 transport
   - HTTPUpgrade transport
   - Integration with existing protocols (VMess, VLESS, Trojan)
   - Expected outcome: V2Ray ecosystem compatibility

4. **Clash API Endpoints** (Sprint 11, 2 weeks)
   - Essential endpoints: GET /proxies, /connections, /logs, /configs, /version
   - WebSocket support for real-time logs/traffic
   - Basic provider API: /providers/proxies, /providers/rules
   - Expected outcome: Dashboard compatibility

**Quarter Target** (End of Sprint 11): DNS (100%), Routing (60%+ essential matchers), V2Ray Transports (50%+ core), Clash API (30%+ essential)

---

## Tooling and Quality Gates

### Code Organization

- **Unify outbound implementations**
  - Remove duplication between sb-core and sb-adapters
  - Keep adapters as the single, tested integration surface
  - Consolidate transport logic into sb-transport

- **Schema/docs alignment**
  - ✅ DONE: v2 schema includes TLS, REALITY, ECH configurations
  - Update schema to include all Sprint 5 implementations (Hysteria, Hysteria2, TUIC, Direct inbound)
  - Ensure examples and tests cover new types
  - Add inline documentation for complex config options

### Testing Strategy

- **E2E and interop tests**
  - ✅ DONE: TUN, SOCKS, SSH, Shadowtls, Hysteria, Hysteria2, TUIC, Direct, REALITY, ECH
  - **Next**: Add protocol-specific interop suites for VMess, VLESS, Trojan
  - Include UDP over stream tests where applicable
  - Add upstream Go sing-box interoperability tests

- **CLI UX**
  - ✅ DONE: CLI implementations exist for all major commands
  - **Next**: Snapshot tests for help/usage JSON outputs
  - Align flags/exit codes with upstream
  - Add integration tests for CLI commands

- **Performance benchmarks**
  - Baseline benchmarks exist (Criterion-based)
  - Add benchmarks for new TLS implementations (REALITY, ECH)
  - Protocol throughput benchmarks for Multiplex
  - DNS query performance benchmarks

### Continuous Integration

- **Parity regression detection**
  - Weekly automated audit runs via GitHub Actions
  - Compare parity percentage with baseline
  - Alert on new missing features or regressions
  - Automatic PR creation with updated GO_PARITY_MATRIX.md

---

## Tracking and Monitoring

- **Primary documents**
  - `GO_PARITY_MATRIX.md`: Detailed feature-by-feature status
  - `NEXT_STEPS.md` (this file): Roadmap and priorities
  - `.kiro/specs/sing-box-parity-audit/`: Kiro audit artifacts

- **Update cadence**
  - GO_PARITY_MATRIX.md: After each major feature completion
  - NEXT_STEPS.md: End of each sprint
  - Kiro audit re-run: Monthly or when upstream releases new version

- **Baseline versions**
  - **Stable**: v1.12.4 (production deployments)
  - **Alpha**: v1.13.0-alpha.19 (CLI feature parity, latest protocols)
  - **Next target**: v1.13.0 stable release (when available)

---

## Key Insights from Kiro Audit

### What We Learned

1. **TLS was the critical blocker**: Completing REALITY, ECH, and Standard TLS unblocked 15+ protocols
2. **CLI parity is high**: Most CLI commands implemented, just need matrix documentation updates
3. **Protocol coverage is strong**: 33.3% of inbounds, 35.3% of outbounds functionally complete
4. **Foundation gaps remain**: DNS (0%), Routing (0%), V2Ray transports (0%), Clash API (2.3%)

### Strategic Pivot

**Before Sprint 5**: Focus was scattered across protocols
**After Sprint 5**: Clear path forward with TLS foundation complete

**New strategy**:
1. Leverage TLS to complete protocol stack (Sprint 6)
2. Build foundation systems in parallel (Sprints 7-10)
3. Achieve 50%+ total coverage by Q2 2025

### Resource Allocation (Updated)

Based on kiro audit recommendations and Sprint 5 breakthroughs:
- **35%** effort → Multiplex + V2Ray transports (highest priority, TLS complete)
- **30%** effort → DNS + Routing engine (critical for production)
- **20%** effort → Protocol integration (leveraging new TLS/transport infrastructure)
- **15%** effort → APIs, Services, CLI polish

---

## Success Metrics

### Sprint 6 Goals
- [ ] Full implementations: 15 → 25 (+67%)
- [ ] Functional coverage: 21.1% → 30%+
- [ ] Multiplex support: 0% → 100%
- [ ] P0 protocols: All critical gaps closed

### Quarter Goals (End of Sprint 10)
- [ ] Full implementations: 25 → 60 (+140%)
- [ ] Functional coverage: 30% → 50%+
- [ ] DNS: 0% → 100%
- [ ] Routing: 0% → 60%+ (essential matchers)
- [ ] V2Ray Transports: 0% → 50%+ (core transports)
- [ ] Clash API: 2.3% → 30%+ (essential endpoints)

### Long-term Vision (6 months)
- [ ] Full implementations: 90+ (50%+)
- [ ] Functional coverage: 70%+
- [ ] Production-ready: All P0 and P1 features complete
- [ ] Upstream interoperability: 100% for core protocols

---

Tracking
- See GO_PARITY_MATRIX.md for current status
- Update both files as features land
- Baseline: v1.12.4 stable; latest upstream pre-release v1.13.0-alpha.19 (2025-10-05) used for CLI inventory
- Kiro audit system: `.kiro/specs/sing-box-parity-audit/` contains design, requirements, and task tracking
