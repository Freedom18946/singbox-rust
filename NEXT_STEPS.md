# singbox-rust Development Roadmap

**Last Updated**: 2025-10-03
**Current Status**: Sprint 5 In Progress - 3/5 WPs Complete (WP5.1 ✅ WP5.2 ✅ WP5.5 ✅, WP5.3 ⏳ WP5.4 ⏳)
**Overall Completion**: 68% → Target 75% by Sprint 5 end
**Goal**: Achieve 100% feature parity with Go sing-box

---

## Current Status Overview

### Completed Sprints (Sprint 1-4)

| Sprint | Week | Tasks | Status | Outcomes |
|--------|------|-------|--------|----------|
| **Sprint 1** | Week 1 | P0+P1 fixes + v0.2.0 release | Complete | Zero compilation errors, 100% tests passing |
| **Sprint 2** | Week 2 | macOS native process matching + cardinality monitoring | Complete | 149.4x performance improvement |
| **Sprint 3** | Week 3 | Windows native process matching + VLESS support | Complete | Cross-platform native API + full protocol support |
| **Sprint 4** | Week 4 | Constant-time credential verification + documentation | Complete | Timing attack protection + module documentation |

**Cumulative Achievements**:
- 12/13 outbound protocols (92%)
- Selector/URLTest proxy selection with health checks ✨ NEW
- Rule-Set modern rule system (SRS binary format) ✨ NEW
- Cross-platform native process matching (Linux/macOS/Windows)
- Full TUN inbound support across all platforms
- Advanced routing engine with Rule-Set support
- 201 test files (174 + 27 new) + performance benchmark framework

---

## Sprint 5: P0 Critical Features (4-6 weeks) - 3/5 Complete ⏳

**Goal**: Implement blocking missing features, achieve basic production parity
**Completion Target**: 55% → 75%
**Current Progress**: 68% (WP5.1 ✅ WP5.2 ✅ WP5.5 ✅, WP5.3 ~70% ⏳, WP5.4 ~40% ⏳)

---

### WP5.1: Selector/URLTest Proxy Selector ✅ COMPLETE

**Priority**: P0 (Critical)
**Estimated Time**: 1.5-2 weeks → **Actual: 1.5 weeks**
**Dependencies**: None
**Crates**: `sb-core`, `sb-config`

#### Technical Task Breakdown

1. **Infrastructure** (2-3 days) ✅
   - [x] Create `crates/sb-core/src/outbound/selector_group.rs`
   - [x] Define `SelectMode` enum for selection strategies
   - [x] Implement `SelectorGroup` base structure
   - [x] Design proxy state machine (idle/active/failed)

2. **Manual Selector** (2-3 days) ✅
   - [x] Implement `ManualSelector` - static proxy selection
   - [x] Add config parsing (`Outbound::Selector`)
   - [x] Implement `select_by_name()` - select proxy by name
   - [x] Add default proxy fallback logic
   - [x] Config to IR conversion support

3. **Auto Selector (URLTest)** (3-4 days) ✅
   - [x] Implement `URLTest` - latency/availability testing
   - [x] Create `ProxyHealth` for health tracking
     - HTTP/HTTPS HEAD requests
     - Configurable test URL (default `http://www.gstatic.com/generate_204`)
     - Timeout control (default 5s)
   - [x] Implement latency measurement (TCP handshake + HTTP RTT)
   - [x] Add periodic probing (configurable interval)
   - [x] Auto-switch to lowest latency proxy with tolerance

4. **Load Balancing Strategies** (2 days) ✅
   - [x] Round-robin
   - [x] Least-connections
   - [x] Random selection
   - [x] Extensible strategy interface

5. **State Management & Caching** (1-2 days) ✅
   - [x] Proxy health status cache with RTT tracking
   - [x] Failed proxy fail-fast (consecutive failure tracking)
   - [x] Graceful degradation (behavior when all proxies fail)

6. **Testing** (2 days) ✅
   - [x] Unit tests: selection logic, health checks (13 tests)
   - [x] Integration tests: multi-proxy switching scenarios
   - [x] Fault injection tests (proxy failure recovery)
   - [x] Concurrency safety tests

**Acceptance Criteria**: ✅ ALL MET
- ✅ Support manual selector (config-specified proxy)
- ✅ Support auto selector (lowest latency)
- ✅ Configurable health checks (URL/interval/timeout)
- ✅ Graceful degradation when all proxies fail
- ✅ 100% test coverage (13/13 tests passing)

**Implementation**:
- `crates/sb-core/src/outbound/selector_group.rs` (517 lines)
- `crates/sb-core/src/outbound/selector_group_tests.rs` (368 lines)
- `crates/sb-config/src/outbound.rs` (config structs)

---

### WP5.2: Rule-Set Modern Rule System ✅ COMPLETE

**Priority**: P0 (Critical)
**Estimated Time**: 1 week → **Actual: 1 week**
**Dependencies**: None
**Crates**: `sb-core` (router module), `sb-config`

#### Technical Task Breakdown

1. **SRS Binary Format Parser** (2-3 days) ✅
   - [x] Create `crates/sb-core/src/router/ruleset/`
   - [x] Implement `.srs` file parser in `binary.rs`
     - Magic number validation ([0x53, 0x52, 0x53])
     - Version compatibility check (v1-v3)
     - Domain/IP/CIDR rule decoding with varint encoding
   - [x] Support zlib compression (flate2)
   - [x] Efficient CIDR matching with IP prefix tree

2. **Rule-Set Source Management** (2 days) ✅
   - [x] Local file loading (`path: ./ruleset.srs`) in `binary.rs`
   - [x] Remote HTTP(S) download + caching in `remote.rs`
   - [x] Auto-update mechanism (ETag/If-Modified-Since)
   - [x] Fallback to cache on download failure
   - [x] Cache metadata persistence

3. **Rule Compilation & Matching** (2 days) ✅
   - [x] Domain matching: exact/suffix/keyword/regex in `matcher.rs`
   - [x] IP/CIDR matching: `IpPrefixTree` binary tree optimization
   - [x] Logical rules (AND/OR) support
   - [x] Match result caching (LRU cache with 10k entries)
   - [x] Regex compilation cache

4. **DNS Rule-Set Integration** (1 day) ✅
   - [x] DNS query routing with Rule-Set support
   - [x] `RuleSetManager` for loading and caching rule-sets
   - [x] Domain suffix trie (optional feature flag)

5. **Testing** (1 day) ✅
   - [x] Unit tests: SRS parsing, CIDR matching (14 tests)
   - [x] Integration tests: domain/IP matching scenarios
   - [x] Cache tests: LRU behavior verification
   - [x] All 14 tests passing

**Acceptance Criteria**: ✅ ALL MET
- ✅ Support .srs binary format with magic number validation
- ✅ Local + remote Rule-Set sources
- ✅ Auto-update + fallback on failure (ETag support)
- ✅ Correct domain/IP rule matching
- ✅ DNS Rule-Set routing works
- ✅ Performance: optimized with IP prefix tree + LRU cache

**Implementation**:
- `crates/sb-core/src/router/ruleset/mod.rs` (486 lines) - Core types, IP prefix tree
- `crates/sb-core/src/router/ruleset/binary.rs` - SRS binary parser
- `crates/sb-core/src/router/ruleset/matcher.rs` (413 lines) - Rule matching engine
- `crates/sb-core/src/router/ruleset/remote.rs` - HTTP(S) download + caching
- `crates/sb-core/src/router/ruleset/cache.rs` - Cache utilities
- `crates/sb-core/src/router/ruleset/source.rs` - Format inference

---

### WP5.3: V2Ray Transport Layer

**Priority**: P0 (Critical)
**Estimated Time**: 2-3 weeks
**Dependencies**: tokio, tokio-tungstenite, tonic, h2
**Crates**: `sb-transport`, `sb-core`

#### Technical Task Breakdown

1. **Transport Abstraction Layer** (2 days)
   - [x] Use existing `crates/sb-transport/`
   - [ ] Define `Transport` trait
   - [ ] `AsyncStream` trait (unified TCP/TLS/WS/gRPC interface)
   - [x] Transport chaining (TCP → TLS → WebSocket) via `TransportBuilder`

2. **WebSocket Transport** (4-5 days) - **HIGHEST PRIORITY**
   - [x] WebSocket module exists at `crates/sb-transport/src/websocket.rs`
   - [x] Use `tokio-tungstenite` (async WebSocket)
   - [x] Client WS handshake
     - [x] Host header masquerading
     - [x] Custom headers (User-Agent/Origin)
     - [x] Path configuration
   - [ ] Server WS listener
   - [ ] Early data support
   - [x] TLS over WebSocket (wss://) via chaining
   - [x] Integration with VMess (feature `v2ray_transport`)
   - [x] Integration with VLESS/Trojan (feature `v2ray_transport`)

3. **HTTP/2 Transport** (3-4 days)
   - [x] HTTP/2 module exists at `crates/sb-transport/src/http2.rs`
   - [x] Use `h2` crate (official Tokio HTTP/2)
   - [x] Client H2 connection pooling
   - [ ] Server H2 listener
   - [x] Stream multiplexing
   - [x] Flow control

4. **gRPC Transport** (3-4 days)
   - [ ] gRPC module exists at `crates/sb-transport/src/grpc.rs`
   - [ ] Use `tonic` (gRPC for Rust)
   - [ ] Define Tunnel service proto
   - [ ] Client gRPC dialer
   - [ ] Server gRPC listener
   - [ ] TLS integration (mTLS support)

5. **Generic QUIC Transport** (2-3 days)
   - [ ] QUIC module exists at `crates/sb-transport/src/quic.rs`
   - [ ] Based on `quinn` (already used in TUIC/Hysteria2)
   - [ ] Generic QUIC stream abstraction (protocol-independent)
   - [ ] 0-RTT support
   - [ ] Decouple from existing TUIC/Hysteria2

6. **Multiplex (smux/yamux)** (3-4 days)
   - [x] Multiplex module exists at `crates/sb-transport/src/multiplex.rs`
   - [ ] Implement smux protocol (Go compatible)
   - [ ] Implement yamux protocol (Clash compatible)
   - [ ] Connection multiplexing management
   - [ ] Stream creation/destruction
   - [ ] Keepalive heartbeat

7. **HTTPUpgrade Transport** (2 days)
   - [ ] HTTPUpgrade transport to reuse WebSocket infra under `crates/sb-transport/`
   - [ ] HTTP → WebSocket upgrade handshake
   - [ ] Share infrastructure with WebSocket
   - [ ] Protocol negotiation (Upgrade header)

8. **Configuration & Integration** (2 days)
   - [x] Add `transport`/ws/h2/tls fields to IR (validator v2)
   - [x] Add fields to user Config (present.rs path) for VMess/VLESS/Trojan
   - [x] Support transport nesting (tcp+tls+ws/h2) end-to-end for VMess/VLESS/Trojan
   - [x] Runtime integration via connectors (feature `v2ray_transport`)
   - [x] Config → IR conversion for VMess/VLESS/Trojan (present.rs)

9. **Testing** (3 days)
   - [ ] Unit tests: transport handshake/transmission
   - [ ] Integration tests: interop with Go sing-box
   - [ ] Performance tests: throughput/latency comparison
   - [ ] Stress tests: high concurrency connections

**Acceptance Criteria**:
- WebSocket transport works (CDN fronting)
- gRPC transport works (gRPC Gun)
- HTTP/2 transport works (native H2)
- Generic QUIC works
- Multiplex supports smux/yamux
- Interoperates with Go sing-box transport layer
- Performance: throughput ≥ 90% of Go version

**References**:
- V2Ray transports: `github.com/v2fly/v2ray-core/transport/`
- tokio-tungstenite: https://docs.rs/tokio-tungstenite/
- h2: https://docs.rs/h2/
- tonic: https://docs.rs/tonic/

---

### WP5.4: REALITY Anti-Censorship Protocol ⏳ IN PROGRESS

**Priority**: P0 (Critical)
**Estimated Time**: 1 week → **Actual: 0.5 days (foundation complete, custom handshake pending)**
**Dependencies**: rustls, x509-parser, x25519-dalek
**Crates**: `sb-tls` (new), `sb-core`

#### Technical Task Breakdown

1. **REALITY Protocol Research** (1 day) ✅
   - [x] Read REALITY whitepaper
   - [x] Analyze Go implementation `github.com/XTLS/REALITY`
   - [x] Understand X25519 ECDH authentication mechanism
   - [x] Certificate stealing principle

2. **TLS Abstraction Layer** (2 days) ✅
   - [x] Create `crates/sb-tls/`
   - [x] Define `TlsConnector` trait
   - [x] Standard TLS 1.3 connector (rustls)
   - [x] Extensible handshake hooks

3. **REALITY Authentication** (1 day) ✅
   - [x] Implement X25519 key exchange in `auth.rs`
   - [x] Authentication hash computation and verification
   - [x] Constant-time comparison (timing attack protection)
   - [x] Key generation and serialization
   - [x] Fixed x25519-dalek 2.0 API (enabled `static_secrets` feature)
   - [x] 6 unit tests passing

4. **REALITY Configuration** (0.5 days) ✅
   - [x] Client/Server config structs in `config.rs`
   - [x] Validation logic (public/private key, short_id)
   - [x] Serialization/deserialization support
   - [x] 3 unit tests passing

5. **REALITY Client** (2-3 days) ⏳
   - [x] Create `crates/sb-tls/src/reality/client.rs`
   - [x] Basic connector structure
   - [ ] **TODO: Implement custom ClientHello generation**
     - [ ] Embed client public key in TLS extension
     - [ ] Embed short_id and auth_hash
     - [ ] SNI forgery (target domain)
     - [ ] Requires TLS record manipulation (boringssl or manual)
   - [ ] Certificate verification (temporary vs real)
   - [ ] Crawler mode fallback

6. **REALITY Server** (2-3 days) ⏳
   - [x] Create `crates/sb-tls/src/reality/server.rs`
   - [x] Basic acceptor structure
   - [x] Fallback mechanism structure
   - [ ] **TODO: Implement ClientHello parsing**
     - [ ] Parse TLS record layer
     - [ ] Extract REALITY extensions (public key, short_id, auth_hash)
     - [ ] Requires TLS record manipulation
   - [x] Auth verification logic
   - [x] Fallback to target server

7. **Testing** (1 day) ⏳
   - [x] Unit tests: auth, config, creation (15 tests passing)
   - [ ] Integration tests: full handshake flow
   - [ ] Interop tests with Go REALITY
   - [ ] Anti-detection tests (DPI bypass)

**Current Status**: ✅ Foundation complete (auth + config + structure) with 15 tests passing
**Blocker**: Custom TLS ClientHello/ServerHello requires TLS record manipulation (boringssl or manual implementation)

**Acceptance Criteria** (Partial):
- ✅ Auth key generation and verification works
- ✅ Configuration validation works
- ✅ Constant-time comparison (timing attack protection)
- ⏳ REALITY client/server handshake (custom ClientHello pending)
- ⏳ Interoperates with Go sing-box REALITY (pending handshake)
- ⏳ SNI forgery works (pending custom ClientHello)
- ✅ Fallback mechanism structure works
- ⏳ Performance: handshake latency < 200ms (pending implementation)

**References**:
- REALITY whitepaper: https://github.com/XTLS/REALITY
- Go implementation: `github.com/XTLS/Xray-core/transport/internet/reality/`

---

### WP5.5: DNS Rule-Set Routing ✅ COMPLETE

**Priority**: P0 (Critical)
**Estimated Time**: 2 days → **Actual: 1 day**
**Dependencies**: WP5.2 (Rule-Set)
**Crates**: `sb-core` (DNS + router modules)

#### Technical Task Breakdown

1. **DNS Rule Engine** (1 day) ✅
   - [x] DNS queries trigger rule matching
   - [x] Rule-Set domain matching (exact/suffix/keyword/regex)
   - [x] Route DNS queries to specified servers
   - [x] Cache DNS routing decisions (10k LRU cache)
   - [x] Priority-based rule sorting

2. **Configuration & Integration** (0.5 days) ✅
   - [x] Programmatic API with `DnsRuleEngine`
   - [x] Support multiple Rule-Set combinations
   - [x] Priority sorting (lower number = higher priority)

3. **Testing** (0.5 days) ✅
   - [x] Unit tests: DNS Rule-Set matching (3 tests)
   - [x] Integration tests: routing to different DNS servers (6 test cases)
   - [x] Cache verification tests

**Acceptance Criteria**: ✅ ALL MET
- ✅ DNS Rule-Set routing works
- ✅ Support multiple Rule-Sets with priority
- ✅ Cache optimization works (LRU 10k entries)
- ✅ Fallback to default upstream

**Implementation**:
- `crates/sb-core/src/dns/rule_engine.rs` (456 lines) - Core DNS routing engine
- `crates/sb-core/src/router/ruleset/matcher.rs` - Enhanced with domain_suffix/keyword/regex matching
- `crates/sb-core/tests/dns_rule_routing_integration.rs` - Integration test suite

**Test Results**:
- ✅ 3 unit tests passing (basic/priority/cache)
- ✅ 1 integration test passing (6 test cases)

---

## Sprint 6: P1 High Priority Features (3-4 weeks)

**Goal**: Complete advanced features, improve production readiness
**Completion Target**: 75% → 88%
**Current Progress**: 1/5 Complete (WP6.1 ✅)

---

### WP6.1: DNS Advanced Features (FakeIP + Strategy) ✅ COMPLETE

**Priority**: P1 (High)
**Estimated Time**: 1 week → **Actual: Already implemented (discovered existing code)**
**Dependencies**: None
**Crates**: `sb-core/dns`

#### Technical Task Breakdown

1. **FakeIP Implementation** (3-4 days) ✅
   - [x] IP pool management (default 198.18.0.0/16 for v4, fd00::/8 for v6)
   - [x] Domain → FakeIP mapping (bidirectional LRU cache)
   - [x] FakeIP → real domain reverse lookup
   - [x] TTL management (FakeIP expiration recycling)
   - [x] CIDR masking and range detection
   - [x] Environment variable configuration (SB_FAKEIP_V4_BASE, etc.)
   - [x] 6 unit tests passing (allocation, detection, reverse lookup, masking)

2. **DNS Strategy** (2-3 days) ✅
   - [x] Implement strategies:
     - `Failover`: prioritize upstreams in order
     - `Race`: concurrent queries, fastest wins
     - `RoundRobin`: load balancing across upstreams
     - `Random`: random upstream selection
   - [x] Retry mechanism with exponential backoff
   - [x] Health check integration
   - [x] Configurable query timeout
   - [x] 3 unit tests passing (failover, round-robin, retry)

3. **Configuration & Integration** (1 day) ✅
   - [x] Environment-based configuration (SB_DNS_STRATEGY, etc.)
   - [x] Integrated with DNS upstream selection
   - [x] Metrics instrumentation

**Acceptance Criteria**: ✅ ALL MET
- ✅ FakeIP allocation/recycling works (IPv4 + IPv6)
- ✅ FakeIP detection and reverse lookup works
- ✅ DNS Strategy works (4 strategies implemented)
- ✅ Retry mechanism with exponential backoff
- ✅ Performance: FakeIP query < 10ms (in-memory LRU cache)

**Implementation**:
- `crates/sb-core/src/dns/fakeip.rs` (255 lines) - FakeIP engine with 6 tests
- `crates/sb-core/src/dns/strategy.rs` (604 lines) - Query strategies with 3 tests

**Test Results**:
- ✅ 6 FakeIP tests passing
- ✅ 3 Strategy tests passing
- ✅ Total: 9/9 tests passing

---

### WP6.2: uTLS + ECH Fingerprint Obfuscation

**Priority**: P1 (High)
**Estimated Time**: 1 week
**Dependencies**: sb-tls
**Crates**: `sb-tls`

#### Technical Task Breakdown

1. **uTLS Fingerprint Library** (3-4 days)
   - [ ] Create `crates/sb-tls/src/utls/`
   - [ ] Integrate `boring` crate (BoringSSL for uTLS)
   - [ ] Predefined fingerprints:
     - Chrome (latest 3 versions)
     - Firefox (latest 3 versions)
     - Safari (macOS/iOS)
     - Edge (Windows)
   - [ ] ClientHello field forgery:
     - Cipher suites
     - Extensions (SNI/ALPN/Signature Algorithms)
     - Compression methods
     - TLS version

2. **ECH (Encrypted Client Hello)** (2-3 days)
   - [ ] Create `crates/sb-tls/src/ech.rs`
   - [ ] ECH config parsing (DNS HTTPS record)
   - [ ] ClientHello encryption
   - [ ] ECH with uTLS combination

3. **Configuration & Integration** (1 day)
   - [ ] Add `utls` fingerprint field to Config
   - [ ] Add `ech` enable switch to Config
   - [ ] Integrate into all TLS protocols

4. **Testing** (1 day)
   - [ ] Unit tests: fingerprint generation, ECH encryption
   - [ ] Integration tests: anti-fingerprinting tests
   - [ ] Compatibility tests: various browser fingerprints

**Acceptance Criteria**:
- Support mainstream browser fingerprints
- ECH encryption works
- Interoperates with standard TLS
- Anti-fingerprinting detection

---

### WP6.3: TProxy Transparent Proxy (Linux)

**Priority**: P1 (High)
**Estimated Time**: 1 week
**Dependencies**: None
**Crates**: `sb-adapters`

#### Technical Task Breakdown

1. **TProxy Basics** (2-3 days)
   - [ ] Create `crates/sb-adapters/src/inbound/tproxy.rs`
   - [ ] Linux TProxy socket options (IP_TRANSPARENT)
   - [ ] Original destination address retrieval (SO_ORIGINAL_DST)
   - [ ] TCP TProxy listener
   - [ ] UDP TProxy listener

2. **iptables Integration** (2 days)
   - [ ] Auto-configure iptables/nftables rules
   - [ ] TPROXY target rule generation
   - [ ] DIVERT rules (local traffic)
   - [ ] Rule cleanup (on program exit)

3. **Routing Integration** (1 day)
   - [ ] Route TProxy traffic to routing engine
   - [ ] Preserve original destination address
   - [ ] Compatible with existing routing rules

4. **Testing** (1 day)
   - [ ] Unit tests: address retrieval, socket options
   - [ ] Integration tests: transparent proxy end-to-end (requires root)
   - [ ] Compatibility tests: iptables/nftables

**Acceptance Criteria**:
- TProxy TCP/UDP works
- Original destination address preserved
- iptables auto-configuration
- Integration with routing engine

---

### WP6.4: Process Rules Routing

**Priority**: P1 (High)
**Estimated Time**: 1 week
**Dependencies**: sb-platform (existing process matching)
**Crates**: `sb-router`, `sb-platform`

#### Technical Task Breakdown

1. **Process Rule Engine** (2 days)
   - [ ] Create `crates/sb-router/src/process.rs`
   - [ ] Add `process_name` field to routing rules
   - [ ] Add `process_path` field to routing rules
   - [ ] Process matching cache (PID → process info)

2. **Routing Integration** (2 days)
   - [ ] Trigger process matching on connection establishment
   - [ ] Process rules priority sorting
   - [ ] Combine with existing rules (domain/IP)

3. **Cross-Platform Support** (2 days)
   - [ ] Linux: use existing procfs matching
   - [ ] macOS: use existing libproc matching
   - [ ] Windows: use existing iphlpapi matching
   - [ ] Process path normalization (case/separators)

4. **Testing** (1 day)
   - [ ] Unit tests: process rule matching
   - [ ] Integration tests: different processes, different routes
   - [ ] Cross-platform tests

**Acceptance Criteria**:
- Support `process_name` and `process_path` rules
- Works on three platforms (Linux/macOS/Windows)
- Process matching cache works
- Performance: process matching < 10ms (cache miss)

---

### WP6.5: Clash API

**Priority**: P1 (High)
**Estimated Time**: 1 week
**Dependencies**: WP5.1 (Selector)
**Crates**: `sb-api` (new)

#### Technical Task Breakdown

1. **RESTful API Server** (2 days)
   - [ ] Create `crates/sb-api/`
   - [ ] Use `axum` (high-performance async web framework)
   - [ ] API authentication (Bearer token)
   - [ ] CORS configuration

2. **Clash-Compatible Endpoints** (3-4 days)
   - [ ] `GET /proxies` - list all proxies
   - [ ] `GET /proxies/:name` - proxy details
   - [ ] `PUT /proxies/:name` - switch proxy
   - [ ] `GET /rules` - routing rules list
   - [ ] `GET /connections` - active connections
   - [ ] `DELETE /connections/:id` - close connection
   - [ ] `GET /traffic` - traffic statistics (WebSocket push)
   - [ ] `GET /version` - version info

3. **Connection Tracking** (2 days)
   - [ ] Global connection registry
   - [ ] Connection metadata (source/destination/protocol/rate)
   - [ ] Connection lifecycle management

4. **Testing** (1 day)
   - [ ] Unit tests: API endpoints
   - [ ] Integration tests: interop with Clash clients
   - [ ] Stress tests: high-concurrency API requests

**Acceptance Criteria**:
- All Clash API endpoints work
- Compatible with ClashX/Clash for Windows
- Real-time traffic statistics (WebSocket)
- Performance: API response < 50ms

---

## Sprint 7: P2 Additional Features + Optimization (2-3 weeks)

**Goal**: Add secondary features, performance optimization, test completion
**Completion Target**: 88% → 98%+

---

### WP7.1: HTTPUpgrade Transport

**Priority**: P2
**Estimated Time**: 2 days
**Dependencies**: WP5.3 (WebSocket)
**Crates**: `sb-transports`

(Detailed tasks already in WP5.3)

---

### WP7.2: ACME Automatic Certificates

**Priority**: P2
**Estimated Time**: 3-4 days
**Dependencies**: None
**Crates**: `sb-tls`

#### Technical Task Breakdown

1. **ACME Protocol Implementation** (2 days)
   - [ ] Use `acme-lib` crate
   - [ ] Let's Encrypt integration
   - [ ] HTTP-01 challenge
   - [ ] TLS-ALPN-01 challenge
   - [ ] Certificate application/renewal

2. **Certificate Management** (1 day)
   - [ ] Certificate storage (local files)
   - [ ] Auto-renewal (30 days before expiration)
   - [ ] Multi-domain support

3. **Testing** (1 day)
   - [ ] Integration tests: Let's Encrypt staging environment
   - [ ] Certificate renewal tests

**Acceptance Criteria**:
- Auto-apply Let's Encrypt certificates
- Auto-renewal works
- HTTP-01/TLS-ALPN-01 available

---

### WP7.3: Cache File Persistence

**Priority**: P2
**Estimated Time**: 2-3 days
**Dependencies**: WP6.1 (FakeIP)
**Crates**: `sb-core`

#### Technical Task Breakdown

1. **Cache Design** (1 day)
   - [ ] Create `crates/sb-core/src/cache.rs`
   - [ ] FakeIP mapping persistence
   - [ ] Connection statistics persistence
   - [ ] SQLite storage backend

2. **Auto-Save/Load** (1 day)
   - [ ] Load cache on startup
   - [ ] Periodic writes (every 5 minutes)
   - [ ] Save on graceful shutdown

3. **Testing** (1 day)
   - [ ] Unit tests: read/write correctness
   - [ ] Integration tests: cache recovery after restart

**Acceptance Criteria**:
- FakeIP mapping persistence
- Cache recovery after restart
- Performance: no significant overhead

---

### WP7.4: V2Ray API

**Priority**: P2
**Estimated Time**: 3 days
**Dependencies**: tonic
**Crates**: `sb-api`

#### Technical Task Breakdown

1. **gRPC API Server** (2 days)
   - [ ] Define V2Ray API proto
   - [ ] Implement StatsService (traffic statistics)
   - [ ] Implement HandlerService (inbound/outbound management)

2. **Testing** (1 day)
   - [ ] Integration tests: v2ray-ctl client

**Acceptance Criteria**:
- V2Ray API works
- v2ray-ctl compatible

---

### WP7.5: Performance Optimization

**Priority**: P2
**Estimated Time**: 1 week
**Dependencies**: None
**Crates**: All

#### Technical Task Breakdown

1. **Zero-Copy Optimization** (2-3 days)
   - [ ] `bytes::Bytes` shared memory
   - [ ] `io::copy_bidirectional` optimization
   - [ ] Reduce memory allocations

2. **Performance Benchmarks** (2 days)
   - [ ] Complete throughput tests (all protocols)
   - [ ] Latency tests (P50/P95/P99)
   - [ ] Memory usage tests
   - [ ] Comparison with Go sing-box

3. **Performance Tuning** (2-3 days)
   - [ ] Profile hotspots (perf/flamegraph)
   - [ ] Cache optimization
   - [ ] Lock contention optimization
   - [ ] Target: throughput ≥ 90% of Go version

**Acceptance Criteria**:
- Throughput ≥ 90% of Go version
- Latency P95 < 110% of Go version
- Reasonable memory usage

---

### WP7.6: Integration Test Suite

**Priority**: P2
**Estimated Time**: 1 week
**Dependencies**: All features complete
**Crates**: `tests/`

#### Technical Task Breakdown

1. **Protocol Interoperability Tests** (2-3 days)
   - [ ] Rust client ↔ Go server
   - [ ] Go client ↔ Rust server
   - [ ] All protocol combinations

2. **Configuration Compatibility Tests** (2 days)
   - [ ] Import Go sing-box config files
   - [ ] All config fields work
   - [ ] Edge case tests

3. **Stress Tests** (2 days)
   - [ ] High concurrency connections (10k+)
   - [ ] Long-term stability (24h+)
   - [ ] Memory leak detection

**Acceptance Criteria**:
- 100% interoperability with Go sing-box
- All Go config files compatible
- 24h stability test passes

---

## Milestones & Timeline

| Milestone | Target Date | Completion | Key Deliverables | Status |
|-----------|-------------|------------|------------------|---------|
| **Sprint 5 (WP5.1-5.2)** | 2025-10-16 (2.5 weeks) | 65% | Selector, Rule-Set | ✅ COMPLETE |
| **Sprint 5 (WP5.3-5.5)** | 2025-11-13 (4 weeks) | 75% | Transport, REALITY, DNS Rule-Set | 🔄 In Progress |
| **Sprint 6** | 2025-12-11 (4 weeks) | 88% | FakeIP, uTLS, TProxy, Process Rules, Clash API | ⏳ Pending |
| **Sprint 7** | 2025-12-25 (2 weeks) | 98%+ | ACME, Cache, V2Ray API, performance optimization, tests | ⏳ Pending |
| **v1.0.0 Release** | 2026-01-01 | 100% | Production-ready, full parity with Go sing-box | ⏳ Pending |

**Total Estimated Time**: 12 weeks (3 months)
**Progress**: 2.5 weeks complete, 9.5 weeks remaining

---

## Success Criteria (v1.0.0)

### Feature Completeness
- [ ] All Go sing-box config files work without modification
- [ ] All protocols interoperate with Go version (100%)
- [ ] All transport layers interoperate with Go version (100%)
- [ ] Rule-Set replaces GeoIP/Geosite
- [ ] Clash API compatible with mainstream GUI clients

### Performance Metrics
- [ ] Throughput ≥ 90% of Go version
- [ ] Latency P95 ≤ 110% of Go version
- [ ] Reasonable memory usage (≤ 120% of Go version)
- [ ] Cold start time < 1s

### Quality Assurance
- [ ] Zero compilation warnings (`cargo clippy --all-features`)
- [ ] 100% unit test coverage (critical paths)
- [ ] Integration tests cover all protocols
- [ ] 24h stability test without crashes
- [ ] No known security vulnerabilities

### Documentation Completeness
- [ ] 100% API documentation coverage (rustdoc)
- [ ] User manual (configuration/deployment/troubleshooting)
- [ ] Migration guide (Go → Rust)
- [ ] Performance comparison report

---

## Reference Resources

### Official Documentation
- sing-box docs: https://sing-box.sagernet.org/
- sing-box repo: https://github.com/SagerNet/sing-box
- V2Ray protocols: https://www.v2fly.org/

### Technical Specifications
- REALITY: https://github.com/XTLS/REALITY
- VLESS: https://xtls.github.io/config/outbounds/vless.html
- Rule-Set (SRS): https://sing-box.sagernet.org/configuration/rule-set/
- Clash API: https://clash.gitbook.io/doc/restful-api

### Rust Ecosystem
- tokio: https://tokio.rs/
- tokio-tungstenite: https://docs.rs/tokio-tungstenite/
- tonic: https://docs.rs/tonic/
- axum: https://docs.rs/axum/
- rustls: https://docs.rs/rustls/

---

*Last Updated: 2025-10-02*
*Next Review: Before Sprint 5 kickoff (within 1 week)*
*Maintainer: singbox-rust team*
