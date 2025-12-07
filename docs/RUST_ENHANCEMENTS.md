# Rust-Only Enhancements

> Features exclusive to the Rust implementation, going beyond Go parity.

---

## 🚀 Performance Enhancements

### Native Process Matching (macOS)
- **149x faster** than Go implementation on macOS
- Direct syscall integration without CGO overhead
- Zero-copy path extraction

### Memory Efficiency
- Zero-copy packet parsing with `bytes` crate
- Arena allocation for hot paths
- Predictable memory footprint with no GC pauses

### Connection Management
- Lock-free connection tracking (`DashMap`)
- Efficient UDP session pooling
- Automatic connection pruning

---

## 🔐 Security Enhancements

### TLS Stack
| Feature | Status | Notes |
| --- | --- | --- |
| **REALITY** | ✅ Complete | Native implementation in `sb-tls` |
| **ECH** | ✅ Complete | Encrypted Client Hello support |
| **uTLS Fingerprinting** | ✅ 27+ fingerprints | Chrome, Firefox, Safari, Edge, Random |
| **BadTLS Detection** | ✅ Passive analyzer | `TlsAnalyzer` for issue detection |
| **JA3 Fingerprinting** | ✅ Complete | Inline MD5 implementation |

### ACME Certificate Management
- Automatic certificate provisioning (Let's Encrypt, ZeroSSL)
- Background auto-renewal with configurable threshold
- HTTP-01, DNS-01, TLS-ALPN-01 challenge support
- Certificate parsing with `rustls-pemfile`

---

## 🌐 Protocol Extras

### DoH3 (DNS over HTTP/3)
- **Location**: `sb-core/src/dns/transport/doh3.rs`
- QUIC-based DNS resolution
- Lower latency than DoH (HTTP/2)
- Multiplexed queries

### SOCKS4 Outbound
- Legacy protocol support
- **Location**: `sb-adapters/src/outbound/socks4.rs`
- Useful for legacy systems

### ShadowsocksR (Restored)
- Removed in Go sing-box, preserved in Rust
- Protocol compatibility maintained
- **Note**: Consider deprecated, but supported for migration

---

## 📊 Observability

### Circuit Breaker
- **Location**: `sb-transport/src/circuit_breaker.rs`
- Automatic failure detection and recovery
- Configurable thresholds and cooldown
- Prevents cascade failures

### Enhanced Metrics
- Prometheus-compatible endpoint
- Per-connection latency histograms
- Memory usage tracking
- Connection state distribution

### Resource Pressure Management
- Adaptive connection limiting
- Memory pressure detection
- Graceful degradation under load

---

## 🔗 Mesh Networking

### DERP Transport
- Tailscale relay protocol support
- Cross-region connectivity
- NAT traversal without port forwarding
- **Location**: `sb-transport/src/derp/`

### Tailscale Integration
- WireGuard mode
- MagicDNS resolution
- SOCKS5 fallback
- **Location**: `sb-core/src/services/tailscale.rs`

---

## 🖥️ Platform Integration

### macOS Enhancements
- Native TUN support (utun)
- System proxy integration (networksetup)
- Keychain credential storage
- macOS-specific optimizations

### Android Enhancements
- Package-based rule matching (JNI bindings)
- VPN service integration
- Battery optimization handling

---

## 📋 Configuration Extensions

### Hot Reload
- Admin API endpoint for live config updates
- Graceful connection migration
- Rule change detection and reporting

### Flexible IR (Intermediate Representation)
- Type-safe configuration parsing
- Validation before application
- Clear error messages with context

---

## 🧪 Test Infrastructure

### Comprehensive Test Suite
| Category | Tests | Coverage |
| --- | --- | --- |
| Unit Tests | 279+ | Core functionality |
| Integration Tests | 50+ | Protocol E2E |
| Feature-gated Tests | 100+ | Optional features |

### Fuzzing Support
- `router_rules_fuzz.rs` for rule parsing
- Input mutation testing
- Crash resistance validation

---

## Migration from Go

When migrating from Go sing-box, these Rust-only features are available:

1. **Performance**: Expect 2-10x improvement in CPU-bound operations
2. **Memory**: More predictable usage, no GC spikes
3. **DoH3**: Consider enabling for reduced DNS latency
4. **DERP**: Available for mesh networking scenarios

### Configuration Compatibility

Rust accepts the same JSON configuration format as Go. Any Go config should work with:

```bash
./singbox-rust run -c config.json
```

### Known Differences

| Aspect | Go | Rust | Impact |
| --- | --- | --- | --- |
| DHCP DNS | Active client | Passive `/etc/resolv.conf` | Renamed to `system` |
| BadTLS | Active wrapping | Passive analysis | Same detection, different mechanism |
| V2Ray API | gRPC-first | HTTP/JSON-first | gRPC optional |

---

## Version History

- **2025-12-07**: Initial documentation of Rust-only enhancements
- **Reference**: Go sing-box 1.12.12 parity baseline
