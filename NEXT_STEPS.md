# Phase 1 Production Roadmap

**Project**: singbox-rust  
**Last Updated**: 2025-11-26  
**Target Release**: v1.0.0 (Phase 1)

---

## 🎯 Phase 1 Strategic Focus

**Objective**: Deliver production-ready **Trojan** and **Shadowsocks** protocols for enterprise deployment.

**Core Protocols**:
- 🎯 **Trojan** (inbound + outbound) - TLS-based protocol with fallback support
- 🎯 **Shadowsocks** (inbound + outbound) - All AEAD variants (AES-GCM, ChaCha20-Poly1305, AEAD-2022)

**Supporting Infrastructure**:
- ✅ Routing engine (domain/IP/GeoIP matching)
- ✅ DNS resolution (UDP, DoH, DoT, DoQ, DoH3)
- ✅ CLI tools (check, route, format, merge, geoip, geosite, ruleset)
- ✅ Metrics & observability (Prometheus, structured logging)

**Non-Phase 1** (optional, feature-gated):
- 📦 VMess, VLESS, Hysteria, TUIC, AnyTLS, ShadowTLS
- 📦 HTTP, SOCKS, Naive, SSH, Tor
- 🧪 DERP service, WireGuard/Tailscale endpoints

---

## 🚦 Production Readiness Dashboard

| Component | Status | Blockers | Target Week |
|-----------|--------|----------|-------------|
| **Trojan Inbound** | 🟡 Testing | Verification needed | Week 48 |
| **Trojan Outbound** | 🟡 Testing | Performance validation | Week 48 |
| **Shadowsocks Inbound** | 🟢 Ready | None | ✅ Complete |
| **Shadowsocks Outbound** | 🟢 Ready | None | ✅ Complete |
| **Routing Engine** | 🟢 Ready | None | ✅ Complete |
| **DNS Resolution** | 🟡 Testing | DoH/DoT validation | Week 48 |
| **TLS Infrastructure** | 🟡 Testing | Certificate validation | Week 49 |
| **Metrics/Observability** | 🟢 Ready | None | ✅ Complete |
| **Security Hardening** | 🔴 Critical | Rate limiting implementation | Week 49 |
| **Performance Benchmarks** | 🟡 In Progress | Go baseline comparison | Week 49-50 |
| **Deployment Artifacts** | 🟡 In Progress | Docker/K8s manifests | Week 50 |
| **Documentation** | 🟡 In Progress | Deployment guides | Week 50 |

**Legend**: 
- 🟢 **Ready** - Production-ready, no blockers
- 🟡 **In Progress** - Work ongoing, on track
- 🔴 **Critical** - Blocking production release
- ✅ **Complete** - Verification passed

---

## 🚀 Critical Path to Production

### Milestone 1: Protocol Validation (Week 48)
**Goal**: Verify Trojan and Shadowsocks meet production quality standards

#### Trojan Protocol Validation
- [ ] **TLS Handshake Testing**
  - [ ] 1000+ successful TLS 1.3 handshakes
  - [ ] Certificate validation (valid + expired + self-signed scenarios)
  - [ ] Cipher suite compatibility testing
  - [ ] ALPN negotiation verification
  - [ ] SNI verification and fallback behavior

- [ ] **Connection Management**
  - [ ] Connection pooling (100+ concurrent connections)
  - [ ] Graceful connection close
  - [ ] Timeout handling (connect, read, write)
  - [ ] Fallback proxy activation on TLS failure

- [ ] **Security Validation**
  - [ ] Replay attack protection
  - [ ] Authentication failure scenarios
  - [ ] TLS version enforcement (≥1.2)
  - [ ] Strong cipher suite filtering

#### Shadowsocks Protocol Validation  
- [ ] **AEAD Cipher Testing**
  - [ ] AES-128-GCM encryption/decryption
  - [ ] AES-256-GCM encryption/decryption
  - [ ] ChaCha20-Poly1305 encryption/decryption
  - [ ] AEAD-2022 cipher support
  - [ ] Nonce handling and replay protection

- [ ] **UDP Relay Validation**
  - [ ] UDP associate command
  - [ ] UDP packet forwarding
  - [ ] NAT session management
  - [ ] UDP timeout handling

- [ ] **Multi-User Support**
  - [ ] Password-based authentication
  - [ ] Per-user traffic accounting
  - [ ] Concurrent user sessions

#### Integration Testing
- [ ] **Protocol Chaining**
  - [ ] Trojan → Shadowsocks multi-hop
  - [ ] Shadowsocks → Trojan reverse chain
  - [ ] Routing integration (domain rules, IP rules, GeoIP)

- [ ] **Failover Scenarios**
  - [ ] Primary outbound failure → fallback
  - [ ] DNS resolution failure handling
  - [ ] Network interruption recovery

- [ ] **DNS Integration**
  - [ ] DNS leak prevention
  - [ ] FakeIP with Trojan/Shadowsocks
  - [ ] DNS over various transports (UDP, DoH, DoT)

**Exit Criteria**: 
- ✅ All protocol tests pass (100%)
- ✅ No P0/P1 bugs in issue tracker
- ✅ 7-day stability test (no crashes, no memory leaks)

**Estimated Effort**: 2-3 days

---

### Milestone 2: Security Hardening (Week 49)
**Goal**: Achieve enterprise-grade security posture

#### TLS Security
- [ ] **Certificate Validation**
  - [ ] Strict certificate verification (no `skip_verify` in production configs)
  - [ ] CA bundle management
  - [ ] Certificate expiration warnings
  - [ ] OCSP stapling support evaluation

- [ ] **Cipher Suite Control**
  - [ ] TLS 1.2+ enforcement
  - [ ] Strong cipher suite allowlist (ECDHE, GCM, ChaCha20)
  - [ ] Deprecated cipher rejection (CBC, RC4, 3DES)
  - [ ] Configurable cipher preferences

- [ ] **Protocol Security**
  - [ ] ALPN enforcement for Trojan
  - [ ] SNI verification
  - [ ] TLS session resumption security

#### Authentication & Authorization
- [ ] **Rate Limiting** (🔴 **CRITICAL**)
  - [ ] Per-IP connection rate limiting
  - [ ] Failed authentication attempt tracking
  - [ ] Sliding window rate limiter implementation
  - [ ] Configurable QPS limits

- [ ] **Credential Management**
  - [ ] Secure password storage (hashed, salted)
  - [ ] Password rotation support
  - [ ] Multi-user isolation
  - [ ] Time-based credential expiration (optional)

- [ ] **Access Control**
  - [ ] IP allowlist/blocklist
  - [ ] User-based routing rules
  - [ ] Connection limits per user

#### Attack Mitigation
- [ ] **DoS Protection**
  - [ ] Connection flood protection (max connections per IP)
  - [ ] Slowloris attack mitigation
  - [ ] Resource exhaustion limits (memory, CPU, file descriptors)

- [ ] **Protocol-Level Protection**
  - [ ] Replay attack prevention (nonce tracking)
  - [ ] Packet injection detection
  - [ ] DNS amplification prevention

#### Security Audit
- [ ] **Dependency Security**
  - [ ] `cargo audit` - no known vulnerabilities
  - [ ] `cargo deny` - license and security policy compliance
  - [ ] Dependency freshness check (latest stable versions)

- [ ] **Code Security**
  - [ ] `cargo clippy --all-targets -- -D warnings` passes
  - [ ] Pedantic + nursery lints enabled for core crates
  - [ ] No `unwrap()`, `expect()`, or `panic!()` in production code paths
  - [ ] Unsafe code audit (all `unsafe` blocks documented)

- [ ] **Secret Management**
  - [ ] No hardcoded credentials in source
  - [ ] Environment variable validation
  - [ ] Secret redaction in logs
  - [ ] Secure memory clearing (ZeroizeOnDrop)

**Exit Criteria**:
- ✅ All security checklist items complete
- ✅ Zero high/critical vulnerabilities in dependencies
- ✅ Security audit passed
- ✅ Rate limiting tested under load (1000+ requests/sec)

**Estimated Effort**: 3-4 days

---

### Milestone 3: Performance Validation (Week 49-50)
**Goal**: Match or exceed Go sing-box 1.12.12 baseline

#### Throughput Benchmarks
- [ ] **Shadowsocks Performance**
  - [ ] AES-256-GCM: ≥80 MiB/s (current: ~80 MiB/s) ✅
  - [ ] ChaCha20-Poly1305: ≥120 MiB/s (current: ~123 MiB/s) ✅
  - [ ] Target: ≥100% of Go baseline
  - [ ] Validate: 1KB, 64KB, 1MB payload sizes

- [ ] **Trojan Performance**
  - [ ] TLS throughput: ≥95% of Go baseline
  - [ ] Handshake overhead: ≤10% slowdown vs direct
  - [ ] Multi-connection scaling: Linear to 1000 connections

- [ ] **Multi-Hop Performance**
  - [ ] 2-hop chain: ≥90% of single-hop
  - [ ] 3-hop chain: ≥80% of single-hop
  - [ ] Overhead measurement and profiling

#### Latency Benchmarks
- [ ] **Connection Establishment**
  - [ ] Shadowsocks handshake: ≤1ms
  - [ ] Trojan TLS handshake: ≤10ms (localhost)
  - [ ] DNS resolution: ≤50ms (cached), ≤200ms (uncached)

- [ ] **Request-Response**
  - [ ] First byte latency: ≤110% of Go baseline
  - [ ] P50 latency: ≤105% of Go baseline
  - [ ] P99 latency: ≤150% of Go baseline

#### Resource Usage
- [ ] **Memory Efficiency**
  - [ ] Idle memory: ≤50MB
  - [ ] 1000 connections: ≤500MB
  - [ ] No memory leaks (24-hour soak test)
  - [ ] Target: ≤100% of Go baseline

- [ ] **CPU Efficiency**
  - [ ] Idle CPU: ≤1%
  - [ ] 1000 req/s: ≤110% of Go baseline CPU usage
  - [ ] Encryption overhead: Acceptable (ChaCha20 < AES-GCM)

- [ ] **File Descriptor Usage**
  - [ ] Linear scaling with connections
  - [ ] Graceful degradation at ulimit
  - [ ] Connection cleanup verification

#### Load Testing
- [ ] **Sustained Load**
  - [ ] 1000 concurrent connections × 1 hour
  - [ ] 10,000 requests/second × 10 minutes
  - [ ] Memory stability (no growth)
  - [ ] No connection errors

- [ ] **Spike Testing**
  - [ ] 0 → 5000 connections in 10 seconds
  - [ ] Graceful handling of connection bursts
  - [ ] Recovery after spike

- [ ] **Endurance Testing**
  - [ ] 24-hour continuous operation
  - [ ] 1 week uptime test (staging)
  - [ ] Memory leak detection (valgrind, heaptrack)

**Exit Criteria**:
- ✅ All throughput targets met
- ✅ Latency within acceptable range
- ✅ Memory usage ≤ Go baseline
- ✅ Zero crashes in 24-hour test

**Estimated Effort**: 3-5 days

---

### Milestone 4: Deployment Preparation (Week 50)
**Goal**: Production-ready deployment artifacts and procedures

#### Build Artifacts
- [ ] **Binary Builds**
  - [ ] Release binary (musl + static linking)
  - [ ] Cross-platform builds (x86_64, aarch64)
  - [ ] Linux (glibc + musl)
  - [ ] macOS (Intel + Apple Silicon)
  - [ ] Optimized release profile (opt-level=3, LTO)

- [ ] **Packages**
  - [ ] Debian package (.deb)
  - [ ] RPM package (.rpm)
  - [ ] Arch Linux PKGBUILD
  - [ ] Homebrew formula

- [ ] **Container Images**
  - [ ] Docker image (Alpine-based, <50MB)
  - [ ] Multi-arch support (amd64, arm64)
  - [ ] Security: non-root user, minimal layers
  - [ ] Published to Docker Hub / GHCR

#### Configuration Templates
- [ ] **Production Configs**
  - [ ] Trojan inbound + Shadowsocks outbound
  - [ ] Shadowsocks inbound + Trojan outbound
  - [ ] Multi-hop routing examples
  - [ ] DNS configuration (DoH + FakeIP)

- [ ] **Environment Variables**
  - [ ] Complete reference documentation
  - [ ] Default values documented
  - [ ] Validation and error messages

- [ ] **Migration Tools**
  - [ ] Go → Rust config converter script
  - [ ] Config validation tool (`app check`)
  - [ ] Schema version migration

#### Deployment Tools
- [ ] **systemd Integration**
  - [ ] Service file with hardening options
  - [ ] Restart policies (on-failure, max 3 retries)
  - [ ] Logging to journal
  - [ ] Socket activation support (optional)

- [ ] **Docker Compose**
  - [ ] Single-node deployment
  - [ ] Multi-container examples
  - [ ] Volume mounting for configs
  - [ ] Health checks

- [ ] **Kubernetes**
  - [ ] Helm chart (v3)
  - [ ] Deployment manifests
  - [ ] ConfigMap/Secret management
  - [ ] Service/Ingress configuration
  - [ ] Health probes (liveness, readiness)

- [ ] **Infrastructure as Code**
  - [ ] Ansible playbooks (basic deploy + upgrade)
  - [ ] Terraform modules (optional)

#### Documentation
- [ ] **Quick Start Guide**
  - [ ] 5-minute deployment walkthrough
  - [ ] Docker quick start
  - [ ] Binary installation and first run
  - [ ] Common configuration examples

- [ ] **Production Deployment Guide**
  - [ ] Architecture recommendations
  - [ ] Security best practices
  - [ ] High availability setup
  - [ ] Scaling considerations

- [ ] **Configuration Reference**
  - [ ] Complete schema documentation
  - [ ] All Trojan/Shadowsocks parameters
  - [ ] Routing rules syntax
  - [ ] DNS configuration options

- [ ] **Troubleshooting Guide**
  - [ ] Common errors and solutions
  - [ ] Debug mode activation
  - [ ] Log interpretation
  - [ ] Performance profiling

**Exit Criteria**:
- ✅ Complete deployment package available
- ✅ All build artifacts tested
- ✅ Documentation reviewed and complete
- ✅ Migration from Go sing-box validated

**Estimated Effort**: 4-5 days

---

### Milestone 5: Observability & Operations (Week 50-51)
**Goal**: Production-grade monitoring and operational excellence

#### Monitoring & Metrics
- [ ] **Prometheus Integration**
  - [ ] Metrics endpoint (`/metrics`) exposed
  - [ ] Core metrics: connections, throughput, errors
  - [ ] Protocol-specific metrics (Trojan, Shadowsocks)
  - [ ] DNS metrics (queries, cache hits, errors)
  - [ ] Resource metrics (memory, CPU, goroutines)

- [ ] **Grafana Dashboards**
  - [ ] Overview dashboard (health, traffic, errors)
  - [ ] Protocol-specific dashboards
  - [ ] DNS monitoring dashboard
  - [ ] Resource usage dashboard
  - [ ] Published to grafana.com

- [ ] **Alerting Rules**
  - [ ] High error rate alert (>5%)
  - [ ] High latency alert (P99 >500ms)
  - [ ] Memory leak detection (growth >10%/hour)
  - [ ] Connection limit approaching
  - [ ] DNS resolution failures

#### Logging
- [ ] **Structured Logging**
  - [ ] JSON format for production
  - [ ] Human-readable for development
  - [ ] Configurable log levels (error/warn/info/debug)
  - [ ] Context propagation (request IDs)

- [ ] **Log Management**
  - [ ] Log rotation (size + time-based)
  - [ ] Retention policies
  - [ ] Compression
  - [ ] Integration with log aggregators (ELK, Loki)

- [ ] **Security Logging**
  - [ ] PII redaction (passwords, tokens)
  - [ ] Sensitive data scrubbing
  - [ ] Authentication events
  - [ ] Security audit trail

#### Health Checks
- [ ] **Endpoints**
  - [ ] `/health` - basic liveness check
  - [ ] `/ready` - readiness check (dependencies healthy)
  - [ ] `/metrics` - Prometheus endpoint

- [ ] **Validation**
  - [ ] Config validation on startup
  - [ ] Dependency checks (DNS, upstream reachability)
  - [ ] Resource availability (memory, file descriptors)

#### Operational Procedures
- [ ] **Backup & Restore**
  - [ ] Configuration backup procedure
  - [ ] State backup (if applicable)
  - [ ] Restore validation

- [ ] **Graceful Operations**
  - [ ] Graceful shutdown (SIGTERM handling)
  - [ ] Zero-downtime restart (socket handoff, optional)
  - [ ] Config reload without restart (SIGHUP)

- [ ] **Upgrade Procedure**
  - [ ] Binary upgrade steps
  - [ ] Config compatibility check
  - [ ] Rollback procedure
  - [ ] Smoke test after upgrade

- [ ] **Troubleshooting Runbook**
  - [ ] High CPU usage → profiling steps
  - [ ] High memory usage → memory analysis
  - [ ] Connection errors → diagnostic commands
  - [ ] DNS resolution failures → upstream validation

**Exit Criteria**:
- ✅ Full observability stack operational
- ✅ Dashboards and alerts deployed
- ✅ Operational procedures documented and tested
- ✅ Troubleshooting runbook validated

**Estimated Effort**: 3-4 days

---

### Milestone 6: Pilot Deployment (Week 51-52)
**Goal**: Validate production readiness in controlled environment

#### Staging Environment
- [ ] **Infrastructure Setup**
  - [ ] Production-identical hardware/cloud instances
  - [ ] Matching network topology
  - [ ] Monitoring and logging configured
  - [ ] Backup and recovery tested

- [ ] **Traffic Simulation**
  - [ ] Replay real traffic patterns from Go sing-box
  - [ ] Load testing (baseline + 2x load)
  - [ ] Spike testing (sudden traffic bursts)
  - [ ] Failover testing (planned outages)

- [ ] **Soak Testing**
  - [ ] 7-day continuous operation
  - [ ] Memory stability verification
  - [ ] Performance degradation check
  - [ ] Log analysis for warnings/errors

- [ ] **Comparison Validation**
  - [ ] Metrics comparison: Rust vs Go
  - [ ] Performance parity check
  - [ ] Error rate comparison
  - [ ] Resource usage comparison

#### Canary Deployment
- [ ] **Infrastructure**
  - [ ] A/B deployment setup (Go vs Rust)
  - [ ] Traffic splitting (1% → 10% → 50%)
  - [ ] Metrics collection for both versions
  - [ ] Automated rollback triggers

- [ ] **Monitoring**
  - [ ] Real-time metrics comparison
  - [ ] Error rate monitoring (<0.1% threshold)
  - [ ] Latency monitoring (within 10% of Go)
  - [ ] User experience metrics

- [ ] **Gradual Rollout**
  - [ ] Week 1: 1% traffic (monitor closely)
  - [ ] Week 2: 10% traffic (validate stability)
  - [ ] Week 3: 50% traffic (final validation)
  - [ ] Week 4: 100% traffic (full cutover)

#### Production Readiness Review
- [ ] **Technical Validation**
  - [ ] Zero critical bugs in canary period
  - [ ] Performance within 10% of Go baseline
  - [ ] No security incidents
  - [ ] Memory/CPU usage acceptable

- [ ] **Operational Validation**
  - [ ] Monitoring effective (no blind spots)
  - [ ] Alerts firing correctly (no false positives)
  - [ ] Runbooks tested and accurate
  - [ ] Team trained on new tooling

- [ ] **Business Validation**
  - [ ] User feedback net positive
  - [ ] No customer-facing incidents
  - [ ] Cost efficiency acceptable
  - [ ] Migration path validated

**Exit Criteria**:
- ✅ 7-day staging soak test passed
- ✅ Canary deployment successful (no rollbacks)
- ✅ Production readiness review approved
- ✅ Go-off from stakeholders

**Estimated Effort**: 2 weeks (includes waiting time for soak tests)

---

### Milestone 7: Production Release (Week 52+)
**Goal**: Phase 1 general availability

#### Release Preparation
- [ ] **Version Control**
  - [ ] Version tag: `v1.0.0`
  - [ ] Changelog complete (all changes since last release)
  - [ ] Breaking changes highlighted
  - [ ] Migration notes included

- [ ] **Artifact Publishing**
  - [ ] GitHub Release created
  - [ ] Binary artifacts uploaded
  - [ ] Docker image pushed to registry
  - [ ] Package repositories updated (Debian, RPM, Homebrew)

- [ ] **Documentation**
  - [ ] Release notes published
  - [ ] Migration guide finalized
  - [ ] Breaking changes documented
  - [ ] Upgrade procedure validated

#### Communication
- [ ] **Announcements**
  - [ ] GitHub repository announcement
  - [ ] Community channels (Discord, Telegram, Reddit)
  - [ ] Social media (Twitter, etc.)
  - [ ] Email notification to beta testers

- [ ] **Support Channels**
  - [ ] GitHub Issues enabled
  - [ ] Discussion forum active
  - [ ] FAQ updated
  - [ ] Support email/contact info published

#### Post-Release Monitoring
- [ ] **Week 1: Close Monitoring**
  - [ ] Daily metrics review
  - [ ] Error rate tracking
  - [ ] User feedback collection
  - [ ] Hotfix readiness (on-call rotation)

- [ ] **Week 2-4: Stabilization**
  - [ ] Performance trending analysis
  - [ ] Bug triage and prioritization
  - [ ] Documentation improvements
  - [ ] User onboarding support

- [ ] **Month 2+: Optimization**
  - [ ] Performance optimization backlog
  - [ ] Feature requests prioritization
  - [ ] Phase 2 planning (optional protocols)

**Exit Criteria**:
- ✅ v1.0.0 released and published
- ✅ No critical production issues in first week
- ✅ User feedback positive (net promoter score)
- ✅ Migration from Go sing-box validated at scale

**Estimated Effort**: 2-3 days (release prep) + ongoing monitoring

---

## 📋 Complete Production Checklist

### P0: Critical for Production
- [ ] Trojan protocol fully validated
- [ ] Shadowsocks protocol fully validated
- [ ] TLS certificate validation enforced
- [ ] Rate limiting implemented and tested
- [ ] Security audit passed (zero high/critical vulns)
- [ ] Performance benchmarks ≥95% of Go baseline
- [ ] 7-day soak test passed
- [ ] Deployment documentation complete

### P1: Highly Recommended
- [ ] Grafana dashboards deployed
- [ ] Alerting rules configured
- [ ] Troubleshooting runbook complete
- [ ] Backup/restore procedures tested
- [ ] Graceful shutdown implemented
- [ ] Config reload without restart
- [ ] Multi-platform builds available

### P2: Nice to Have
- [ ] Kubernetes Helm chart
- [ ] Ansible playbooks
- [ ] Advanced monitoring (distributed tracing)
- [ ] Automated canary deployments
- [ ] Performance profiling tools

---

## 🗓️ Timeline Summary

| Week | Milestone | Deliverables |
|------|-----------|--------------|
| **Week 48** | Protocol Validation | Trojan/SS tests, integration tests |
| **Week 49** | Security + Performance | Security audit, benchmarks, rate limiting |
| **Week 50** | Deployment Prep | Artifacts, configs, documentation |
| **Week 50-51** | Observability | Metrics, dashboards, runbooks |
| **Week 51-52** | Pilot Deployment | Staging, canary, validation |
| **Week 52+** | Production Release | v1.0.0 GA, monitoring, optimization |

**Total Duration**: ~5-6 weeks  
**Target Release**: End of December 2025

---

## 🚧 Known Issues & Mitigations

### Critical Issues (Blocking Production)
1. **Rate Limiting Not Implemented** 🔴
   - **Impact**: DoS vulnerability
   - **Mitigation**: Week 49 priority implementation
   - **Tracking**: Issue #TBD

### Important Issues (Degraded Experience)
2. **DNS DoH/DoT Validation Incomplete** 🟡
   - **Impact**: Limited DNS transport options
   - ✅ **Verification Framework**: 3-layer validation system - [VERIFICATION_RECORD.md](reports/VERIFICATION_RECORD.md) - Feature verification and quality assurance records
   - **Mitigation**: Complete validation in Week 48
   - **Workaround**: Use UDP/DoH3 (already validated)

3. **Benchmark Comparison with Go Missing** 🟡
   - **Impact**: Unknown performance delta
   - **Mitigation**: Establish baseline in Week 49
   - **Current**: Shadowsocks shows ≥100% performance

### Minor Issues (Can Ship With)
4. **Documentation Gaps** 🟡
   - **Impact**: Harder user onboarding
   - **Mitigation**: Week 50 documentation sprint
   - **Workaround**: Community support, examples

---

## 📦 Optional Features (Post-Phase 1)

The following protocols are **fully implemented** but not prioritized for Phase 1 production release. They are available via feature flags for advanced users.

### Optional Protocols
- **VMess** (inbound + outbound) - `--features adapter-vmess`
- **VLESS** (inbound + outbound) - `--features adapter-vless`
- **Hysteria v1/v2** - `--features adapter-hysteria,adapter-hysteria2`
- **TUIC** - `--features adapter-tuic`
- **HTTP/SOCKS** - `--features adapter-http,adapter-socks`
- **Naive** - `--features adapter-naive`
- **SSH, Tor** - `--features adapter-ssh,adapter-tor`
- **AnyTLS, ShadowTLS** - `--features adapter-anytls,adapter-shadowtls`

### Experimental Services
- **DERP** - `--features service_derp` (mesh relay networking)
- **WireGuard Endpoint** - `--features adapter-wireguard-endpoint`
- **NTP, Resolved, SSMAPI** - `--features service_ntp,service_resolved,service_ssmapi`

### Phase 2 Roadmap (Post-v1.0.0)
1. **Stabilize optional protocols** (weeks 1-4)
2. **Feature parity improvements** (weeks 5-8)
3. **Advanced services** (DERP production-ready, WireGuard improvements)
4. **Performance optimizations** (zero-copy, SIMD, async improvements)
5. **Platform support** (Windows native, BSD)

---

## 📞 Communication & Support

### Release Communication
- **Status Updates**: Weekly progress reports
- **Blockers**: Escalate immediately to team leads
- **Changes**: Document all breaking changes

### Support Channels
- **GitHub Issues**: Bug reports, feature requests
- **Discussions**: Q&A, troubleshooting
- **Documentation**: README, guides, runbooks

---

**Last Updated**: 2025-11-24 20:23  
**Next Review**: 2025-11-25 (daily during Week 48-52)  
**Owner**: singbox-rust core team
