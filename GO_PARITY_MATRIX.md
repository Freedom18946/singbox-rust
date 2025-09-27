# Go sing-box vs Rust sing-box Protocol Parity Matrix

This matrix tracks protocol implementation status between the original Go sing-box and this Rust implementation.

## Overall Status: 🔶 Partial Parity (6/13 protocols implemented)

| Protocol | Go Status | Rust Status | Implementation | Notes |
|----------|-----------|-------------|----------------|--------|
| **Direct** | ✅ Full | ✅ Full | `crates/sb-adapters/src/outbound/direct.rs` | Basic direct connection |
| **HTTP Proxy** | ✅ Full | ⚠️ Config Only | `crates/sb-config/src/outbound.rs:HttpProxyConfig` | Stub needed |
| **SOCKS5** | ✅ Full | ⚠️ Config Only | `crates/sb-config/src/outbound.rs:Socks5Config` | Stub needed |
| **VMess** | ✅ Full | ✅ Full | `crates/sb-adapters/src/outbound/vmess.rs` | Complete implementation |
| **VLESS** | ✅ Full | ✅ Full | `crates/sb-adapters/src/outbound/vless.rs` | Complete implementation |
| **TUIC** | ✅ Full | ✅ Full | `crates/sb-adapters/src/outbound/tuic.rs` | Complete implementation |
| **Shadowsocks** | ✅ Full | ❌ Missing | Feature: `out_ss` | Stub needed |
| **Trojan** | ✅ Full | ❌ Missing | Feature: `out_trojan` | Stub needed |
| **Hysteria2** | ✅ Full | ❌ Missing | Feature: `out_hysteria2` | Stub needed |
| **Naive** | ✅ Full | ❌ Missing | Feature: `out_naive` | Stub needed |
| **WireGuard** | ✅ Full | ❌ Missing | Feature: `out_wireguard` | Stub needed |
| **SSH** | ✅ Full | ❌ Missing | Feature: `out_ssh` | Stub needed |
| **ShadowTLS** | ✅ Full | ❌ Missing | Feature: `out_shadowtls` | Stub needed |

## Inbound Protocols

| Protocol | Go Status | Rust Status | Implementation | Notes |
|----------|-----------|-------------|----------------|--------|
| **HTTP** | ✅ Full | ✅ Full | `crates/sb-adapters/src/inbound/http.rs` | Complete |
| **TUN** | ✅ Full | ✅ Full | `crates/sb-adapters/src/inbound/tun*.rs` | Multiple variants |
| **SOCKS5** | ✅ Full | ❌ Missing | - | Stub needed |
| **Mixed** | ✅ Full | ❌ Missing | - | Stub needed |
| **Redirect** | ✅ Full | ❌ Missing | - | Stub needed |

## Router Features

| Feature | Go Status | Rust Status | Implementation | Notes |
|---------|-----------|-------------|----------------|--------|
| **Basic Routing** | ✅ Full | ✅ Full | `crates/sb-core/src/router/` | Complete |
| **Rule Engine** | ✅ Full | ✅ Full | `crates/sb-core/src/router/engine.rs` | Complete |
| **Explain** | ✅ Full | ✅ Full | `crates/sb-core/src/router/explain.rs` | Complete |
| **GeoIP** | ✅ Full | ⚠️ Partial | - | Basic support |
| **Process Rules** | ✅ Full | ❌ Missing | - | Feature needed |

## Priority Implementation Order

Based on usage and ecosystem importance:

### High Priority (Production Critical)
1. **HTTP Proxy** - Common enterprise proxy protocol
2. **SOCKS5 Outbound** - Universal proxy protocol
3. **Shadowsocks** - Widespread circumvention protocol

### Medium Priority (Common Use Cases)
4. **Trojan** - Popular protocol for circumvention
5. **SOCKS5 Inbound** - Server-side SOCKS support
6. **Mixed Inbound** - HTTP/SOCKS hybrid listener

### Lower Priority (Specialized)
7. **Hysteria2** - Modern QUIC-based protocol
8. **WireGuard** - VPN tunnel integration
9. **Naive** - Chrome-based proxy
10. **SSH** - SSH tunnel support
11. **ShadowTLS** - Shadowsocks over TLS
12. **Redirect** - Transparent proxy

## Implementation Strategy

### Phase 1: Core Proxy Protocols
- Implement HTTP proxy outbound
- Implement SOCKS5 outbound
- Implement Shadowsocks outbound

### Phase 2: Inbound Support
- Implement SOCKS5 inbound
- Implement Mixed inbound

### Phase 3: Advanced Protocols
- Implement remaining outbound protocols
- Add protocol-specific optimizations

## Testing Requirements

Each protocol implementation should include:
- [ ] Unit tests for protocol parsing
- [ ] Integration tests with reference implementations
- [ ] Performance benchmarks vs Go version
- [ ] Interoperability tests

## Documentation Requirements

Each protocol should include:
- [ ] Protocol specification documentation
- [ ] Configuration examples
- [ ] Performance characteristics
- [ ] Security considerations

---

*Generated: $(date)*
*Last Updated by: Claude Code Assistant*
*Status: Active Development*