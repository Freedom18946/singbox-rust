# Integration Test Plan

**Status**: 🚧 In Progress
**Last Updated**: 2025-10-04
**Goal**: Achieve comprehensive integration test coverage for 99%+ completed features

## Test Coverage Matrix

### 1. End-to-End Protocol Tests (Priority: P0)

#### 1.1 Inbound → Router → Outbound Flow
- [ ] **SOCKS5 Inbound → Direct Outbound**
  - Test basic proxy flow
  - Verify connection tracking
  - Check metrics reporting

- [ ] **HTTP Inbound → SOCKS5 Outbound**
  - Test protocol translation
  - Verify header handling
  - Check authentication flow

- [ ] **Mixed Inbound → Selector → URLTest**
  - Test automatic proxy selection
  - Verify health checks
  - Check failover behavior

#### 1.2 Server Inbound Tests (10/10 implemented)
- [ ] **Naive Server** (HTTP/2 CONNECT + TLS + Basic Auth)
  - Test client connection and authentication
  - Verify constant-time credential comparison
  - Check TLS negotiation

- [ ] **TUIC Server** (QUIC + UUID + Token)
  - Test QUIC connection establishment
  - Verify authentication flow
  - Check congestion control algorithms (cubic/bbr/new_reno)

- [ ] **VMess Server** (AEAD + HMAC)
  - Test client handshake
  - Verify encryption/decryption
  - Check AEAD integrity

- [ ] **VLESS Server** (UUID + Flow)
  - Test UUID authentication
  - Verify flow control
  - Check transport integration

- [ ] **Trojan Server** (TLS + Password)
  - Test TLS handshake
  - Verify password authentication
  - Check fallback mechanism

- [ ] **ShadowTLS Server**
  - Test TLS masquerading
  - Verify handshake hijacking
  - Check target fallback

- [ ] **Shadowsocks Server** (AEAD)
  - Test AEAD encryption
  - Verify TCP/UDP relay
  - Check cipher compatibility

### 2. Transport Layer Integration (Priority: P0)

#### 2.1 WebSocket Transport (4/4 tests ✅)
- [x] Basic echo test
- [x] Multi-client test
- [x] Large message test (100KB)
- [x] Configuration validation

#### 2.2 HTTP/2 Transport (3/3 tests ✅)
- [x] Basic echo test
- [x] Large message test (100KB) - Fixed
- [x] Server configuration test

#### 2.3 HTTPUpgrade Transport (4/4 tests ✅)
- [x] Basic echo test
- [x] Multi-client test
- [x] Large message test (100KB) - Fixed
- [x] Configuration validation

#### 2.4 Multiplex/yamux Transport (2/2 tests ✅)
- [x] Basic echo test
- [x] Configuration validation

#### 2.5 Protocol + Transport Combinations
- [ ] **VMess + WebSocket + TLS**
  - Test full chain: TCP → TLS → WebSocket → VMess
  - Verify encryption layering
  - Check performance overhead

- [ ] **VLESS + HTTP/2 + TLS**
  - Test H2 multiplexing with VLESS
  - Verify flow control
  - Check stream management

- [ ] **Trojan + HTTPUpgrade**
  - Test upgrade handshake
  - Verify password auth
  - Check target connection

### 3. Routing Engine Tests (Priority: P1)

#### 3.1 Rule-Set System
- [x] **Binary SRS Format** (WP5.2 complete)
  - [x] Parse .srs files
  - [x] Domain/IP/CIDR matching
  - [x] Remote caching with ETag
  - [ ] Auto-update mechanism testing

- [ ] **DNS Rule-Set Routing**
  - Test domain-based routing
  - Verify priority ordering
  - Check cache effectiveness

#### 3.2 GeoIP/GeoSite
- [ ] **GeoIP Routing**
  - Test mmdb database lookup
  - Verify country-based rules
  - Check IP range matching

- [ ] **GeoSite Routing**
  - Test domain database lookup
  - Verify category-based rules
  - Check pattern matching

#### 3.3 Process Rules (8/8 tests ✅)
- [x] Process name matching
- [x] Process path matching
- [x] Rule priority verification
- [x] Engine hot-reload

### 4. DNS Advanced Features (Priority: P1)

#### 4.1 FakeIP (6/6 tests ✅)
- [x] IPv4/IPv6 allocation
- [x] Domain → FakeIP mapping
- [x] Reverse lookup
- [x] TTL expiration
- [x] CIDR masking
- [ ] FakeIP → routing integration

#### 4.2 DNS Strategy (3/3 tests ✅)
- [x] Failover strategy
- [x] Round-robin strategy
- [x] Retry mechanism
- [ ] Race strategy testing
- [ ] Random strategy testing

#### 4.3 DNS Transport
- [ ] **DoH (DNS over HTTPS)**
  - Test HTTPS transport
  - Verify HTTP/2 support
  - Check fallback behavior

- [ ] **DoT (DNS over TLS)**
  - Test TLS transport
  - Verify certificate validation
  - Check connection reuse

- [ ] **DoQ (DNS over QUIC)**
  - Test QUIC transport
  - Verify 0-RTT support
  - Check error handling

### 5. Selector/URLTest (Priority: P1)

#### 5.1 Manual Selector
- [ ] **Static Selection**
  - Test proxy selection by name
  - Verify default fallback
  - Check configuration reload

#### 5.2 Auto Selector (URLTest) (13/13 tests ✅)
- [x] Health check HTTP/HTTPS
- [x] Latency measurement
- [x] Auto-switch with tolerance
- [x] Periodic probing
- [ ] Integration with real proxies

#### 5.3 Load Balancing
- [ ] **Round-robin**
  - Test even distribution
  - Verify state persistence
  - Check connection tracking

- [ ] **Least-connections**
  - Test connection counting
  - Verify load balancing
  - Check failover

### 6. Performance & Stress Tests (Priority: P2)

#### 6.1 Throughput Tests
- [ ] **TCP Throughput**
  - Baseline: 1GB data transfer
  - Target: ≥90% of Go sing-box
  - Measure: MB/s

- [ ] **UDP Throughput**
  - Baseline: 1GB data transfer
  - Target: ≥90% of Go sing-box
  - Measure: packets/s

#### 6.2 Latency Tests
- [ ] **Proxy Latency**
  - Measure: P50/P90/P95/P99
  - Target: P95 < 110% of Go sing-box
  - Test various protocols

#### 6.3 Concurrency Tests
- [ ] **High Concurrency**
  - Test: 10,000 concurrent connections
  - Verify: No connection drops
  - Check: Memory usage < 120% of Go

- [ ] **Long-term Stability**
  - Test: 24h continuous operation
  - Verify: No memory leaks
  - Check: Connection pool behavior

### 7. Interoperability Tests (Priority: P2)

#### 7.1 Go sing-box Compatibility
- [ ] **Rust Client → Go Server**
  - Test all protocols
  - Verify encryption compatibility
  - Check transport compatibility

- [ ] **Go Client → Rust Server**
  - Test all server inbounds
  - Verify authentication
  - Check protocol compliance

#### 7.2 Configuration Compatibility
- [ ] **Import Go Configs**
  - Test all config fields
  - Verify migration logic
  - Check edge cases

## Test Execution Strategy

### Phase 1: Core Integration (Week 1)
1. Run all existing integration tests
2. Fix failing tests
3. Document test results

### Phase 2: New Protocol Tests (Week 2)
1. Implement server inbound tests
2. Implement transport combination tests
3. Add metrics verification

### Phase 3: Performance Testing (Week 3)
1. Establish performance baselines
2. Run throughput/latency tests
3. Compare with Go sing-box

### Phase 4: Interop Testing (Week 4)
1. Set up Go sing-box test environment
2. Run cross-implementation tests
3. Document compatibility matrix

## Test Infrastructure

### Required Setup
- [ ] Go sing-box installation for interop tests
- [ ] Test server infrastructure (local/Docker)
- [ ] Performance benchmarking tools
- [ ] Test data generators

### Metrics Collection
- [ ] Test execution time tracking
- [ ] Memory usage monitoring
- [ ] Network bandwidth measurement
- [ ] CPU utilization tracking

## Success Criteria

- ✅ **100% Core Tests Passing**: All existing integration tests pass
- ⏳ **Server Inbound Coverage**: All 10 server inbounds tested
- ⏳ **Transport Coverage**: All 4 core transports tested with protocols
- ⏳ **Performance Target**: ≥90% of Go sing-box throughput
- ⏳ **Interop Target**: 100% protocol compatibility with Go sing-box

## Current Status

**Completed**:
- Transport layer: 13/13 tests passing ✅
- Process rules: 8/8 tests passing ✅
- DNS FakeIP: 6/6 tests passing ✅
- DNS Strategy: 3/3 tests passing ✅
- Selector: 13/13 tests passing ✅

**In Progress**:
- Server inbound testing (0/10)
- Protocol + transport combinations (0/5)
- Performance benchmarking (0/3)

**Blocked**:
- Interop testing (requires Go sing-box setup)

## Next Actions

1. **Immediate** (Today):
   - Run all existing integration tests with proper features
   - Document current test pass/fail status
   - Create test execution summary

2. **Short-term** (This Week):
   - Implement server inbound integration tests
   - Add protocol + transport combination tests
   - Fix any failing tests

3. **Medium-term** (Next Week):
   - Establish performance baselines
   - Run throughput/latency benchmarks
   - Document performance comparison

---

**Notes**:
- This plan focuses on testing already-implemented features (99%+ complete)
- REALITY TLS handshake tests deferred until implementation complete
- uTLS/ECH tests deferred until implementation complete
