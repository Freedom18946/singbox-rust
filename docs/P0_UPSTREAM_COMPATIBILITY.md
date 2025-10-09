# P0 Protocols Upstream Compatibility Report

This document describes the compatibility status between the Rust implementation and upstream Go sing-box for P0 protocols.

## Test Date
Generated: 2025-10-08

## Tested Versions
- **Rust Implementation**: Current development version
- **Upstream sing-box**: v1.12.4 stable / v1.13.0-alpha.19 CLI

## Protocol Compatibility Matrix

| Protocol | Config Compatibility | Rust Client → Go Server | Go Client → Rust Server | Notes |
|----------|---------------------|------------------------|------------------------|-------|
| REALITY TLS | ✅ Full | ⚠️ Requires Testing | ⚠️ Requires Testing | Config validation passes |
| ECH | ✅ Full | ⚠️ Requires Testing | ⚠️ Requires Testing | Config validation passes |
| Hysteria v1 | ✅ Full | ⚠️ Requires Testing | ⚠️ Requires Testing | Config validation passes |
| Hysteria v2 | ✅ Full | ⚠️ Requires Testing | ⚠️ Requires Testing | Config validation passes |
| SSH | ✅ Full | ⚠️ Requires Testing | N/A | SSH is outbound-only |
| TUIC | ✅ Full | ⚠️ Requires Testing | ⚠️ Requires Testing | Config validation passes |

**Legend:**
- ✅ Full: Fully compatible and tested
- ⚠️ Requires Testing: Config compatible, runtime testing needed
- ❌ Incompatible: Known incompatibilities
- N/A: Not applicable

## Configuration Compatibility

### REALITY TLS

**Status**: ✅ Config Compatible

Both Rust and Go implementations accept REALITY configurations with the following fields:
- `enabled`: Boolean flag
- `public_key`: X25519 public key (hex string)
- `short_id`: Short ID for authentication (hex string, 0-16 chars)
- `server_name`: Target server name for fallback

**Example Config**:
```json
{
  "type": "vless",
  "server": "proxy.example.com",
  "server_port": 443,
  "uuid": "12345678-1234-1234-1234-123456789abc",
  "tls": {
    "enabled": true,
    "server_name": "www.apple.com",
    "reality": {
      "enabled": true,
      "public_key": "fedcba9876543210...",
      "short_id": "01ab"
    }
  }
}
```

**Known Limitations**: None

### ECH (Encrypted Client Hello)

**Status**: ✅ Config Compatible

Both implementations accept ECH configurations with:
- `enabled`: Boolean flag
- `config`: Base64-encoded ECHConfigList
- `pq_signature_schemes_enabled`: Post-quantum signature schemes (optional)
- `dynamic_record_sizing_disabled`: TLS record sizing (optional)

**Example Config**:
```json
{
  "type": "trojan",
  "server": "trojan.example.com",
  "server_port": 443,
  "password": "password123",
  "tls": {
    "enabled": true,
    "server_name": "www.example.com",
    "ech": {
      "enabled": true,
      "config": "AEX+DQBBzQAgACCm6NzGiTKdRzVzPJBGUVXZPLqKJfLJmJLjJmJLjJmJLg=="
    }
  }
}
```

**Known Limitations**: None

### Hysteria v1

**Status**: ✅ Config Compatible

Both implementations support:
- `protocol`: Transport protocol (udp, wechat-video, faketcp)
- `up_mbps` / `down_mbps`: Bandwidth limits
- `auth_str`: Authentication string
- `obfs`: Obfuscation password (optional)
- `alpn`: ALPN protocols (optional)

**Example Config**:
```json
{
  "type": "hysteria",
  "server": "hy1.example.com",
  "server_port": 443,
  "protocol": "udp",
  "up_mbps": 100,
  "down_mbps": 100,
  "auth_str": "password123"
}
```

**Known Limitations**: None

### Hysteria v2

**Status**: ✅ Config Compatible

Both implementations support:
- `password`: Authentication password
- `up_mbps` / `down_mbps`: Bandwidth limits
- `obfs`: Salamander obfuscation (optional)
- `salamander`: Obfuscation configuration (optional)

**Example Config**:
```json
{
  "type": "hysteria2",
  "server": "hy2.example.com",
  "server_port": 443,
  "password": "password123",
  "up_mbps": 100,
  "down_mbps": 100
}
```

**Known Limitations**: None

### SSH

**Status**: ✅ Config Compatible

Both implementations support:
- `user`: SSH username
- `password`: Password authentication
- `private_key`: Private key authentication (optional)
- `private_key_passphrase`: Key passphrase (optional)
- `host_key_algorithms`: Supported algorithms (optional)

**Example Config**:
```json
{
  "type": "ssh",
  "server": "ssh.example.com",
  "server_port": 22,
  "user": "proxyuser",
  "password": "secret123"
}
```

**Known Limitations**: 
- SSH is outbound-only in both implementations
- Host key verification may differ in implementation details

### TUIC

**Status**: ✅ Config Compatible

Both implementations support:
- `uuid`: User UUID
- `password`: Authentication password
- `congestion_control`: Congestion control algorithm (bbr, cubic, new_reno)
- `udp_relay_mode`: UDP relay mode (native, quic)
- `zero_rtt_handshake`: 0-RTT handshake (optional)

**Example Config**:
```json
{
  "type": "tuic",
  "server": "tuic.example.com",
  "server_port": 443,
  "uuid": "12345678-1234-1234-1234-123456789abc",
  "password": "password123",
  "congestion_control": "bbr"
}
```

**Known Limitations**: None

## Integration Features Compatibility

### Selectors

**Status**: ✅ Compatible

All P0 protocols work with:
- URLTest selector (automatic health checking)
- Manual selector (user selection)
- Fallback selector (failover)

**Tested Scenarios**:
- ✅ REALITY in URLTest selector
- ✅ Hysteria v2 in fallback selector
- ✅ SSH in manual selector
- ✅ TUIC in URLTest selector
- ✅ Mixed P0 protocols in single selector
- ✅ Nested selectors with P0 protocols

### Routing Rules

**Status**: ✅ Compatible

All P0 protocols work with:
- Domain-based routing (domain, domain_suffix, domain_keyword)
- IP-based routing (ip_cidr, geoip)
- Port-based routing (port, port_range)
- Process-based routing (process_name)
- Network-based routing (tcp, udp)
- GeoSite routing

**Tested Scenarios**:
- ✅ Domain routing with REALITY
- ✅ IP routing with Hysteria v2
- ✅ Port routing with SSH
- ✅ Process routing with TUIC
- ✅ Combined routing rules with mixed protocols

### DNS Subsystem

**Status**: ✅ Compatible

All P0 protocols work with:
- DNS resolution through P0 outbounds
- DNS over HTTPS (DoH)
- DNS over TLS (DoT)
- Fake-IP mode
- DNS routing rules
- DNS caching

**Tested Scenarios**:
- ✅ DNS resolution with REALITY
- ✅ DNS resolution with Hysteria v2
- ✅ DNS resolution with SSH
- ✅ DNS resolution with TUIC
- ✅ Fake-IP with P0 protocols
- ✅ DNS routing rules with P0 protocols
- ✅ Mixed DNS servers with different P0 protocols

### TUN Inbound

**Status**: ✅ Compatible

All P0 protocols work with:
- TUN → P0 protocol proxy chains
- UDP relay through TUN
- Routing from TUN to P0 outbounds
- Different TUN stacks (system, gvisor, mixed)
- IPv4 and IPv6 support

**Tested Scenarios**:
- ✅ TUN with REALITY outbound
- ✅ TUN with Hysteria v2 outbound (TCP and UDP)
- ✅ TUN with SSH outbound
- ✅ TUN with TUIC outbound (TCP and UDP)
- ✅ TUN UDP relay with Hysteria v1
- ✅ TUN with ECH-enabled outbound
- ✅ TUN routing to different P0 protocols
- ✅ TUN with DNS and Fake-IP

## Runtime Interoperability

### Rust Client → Go Server

**Status**: ⚠️ Requires Live Testing

Config compatibility is verified, but runtime interoperability requires:
1. Running Go sing-box server instances for each protocol
2. Connecting Rust client to Go server
3. Verifying data transfer and protocol handshakes

**Testing Checklist**:
- [ ] REALITY: Rust VLESS client → Go VLESS+REALITY server
- [ ] Hysteria v1: Rust client → Go server
- [ ] Hysteria v2: Rust client → Go server
- [ ] TUIC: Rust client → Go server
- [ ] ECH: Rust Trojan+ECH client → Go Trojan+ECH server

### Go Client → Rust Server

**Status**: ⚠️ Requires Live Testing

Config compatibility is verified, but runtime interoperability requires:
1. Running Rust sing-box server instances for each protocol
2. Connecting Go client to Rust server
3. Verifying data transfer and protocol handshakes

**Testing Checklist**:
- [ ] REALITY: Go VLESS client → Rust VLESS+REALITY server
- [ ] Hysteria v1: Go client → Rust server
- [ ] Hysteria v2: Go client → Rust server
- [ ] TUIC: Go client → Rust server
- [ ] ECH: Go Trojan+ECH client → Rust Trojan+ECH server

## Known Issues and Limitations

### General

1. **Runtime Interoperability**: While config compatibility is verified, full runtime interoperability testing requires live server/client setups which are not part of automated tests.

2. **Protocol Version Compatibility**: Tests are based on upstream sing-box v1.12.4 stable and v1.13.0-alpha.19 CLI. Newer versions may introduce changes.

### Protocol-Specific

#### REALITY TLS
- No known issues

#### ECH
- ECH support depends on underlying TLS library capabilities
- Some ECH features may require specific TLS library versions

#### Hysteria v1/v2
- Custom congestion control algorithms (BBR, Brutal) may have implementation differences
- Performance characteristics may vary between implementations

#### SSH
- Host key verification implementation details may differ
- Connection pooling behavior may vary

#### TUIC
- UDP relay mode implementation details may differ
- Zero-RTT handshake behavior may vary

## Testing Methodology

### Config Validation Tests

All tests use the `check` command to validate configuration files:

```bash
# Rust implementation
cargo run --bin check -- --config config.json

# Go implementation (if GO_SINGBOX_BIN is set)
$GO_SINGBOX_BIN check --config config.json
```

Tests verify that both implementations accept or reject configs consistently.

### Integration Tests

Integration tests verify that P0 protocols work correctly with:
- Selectors (URLTest, manual, fallback)
- Routing rules (domain, IP, port, process, network)
- DNS subsystem (resolution, Fake-IP, routing)
- TUN inbound (TCP, UDP, routing)

### Running Tests

```bash
# Run all P0 integration tests
cd app
cargo test --test p0_selector_integration
cargo test --test p0_routing_integration
cargo test --test p0_dns_integration
cargo test --test p0_tun_integration
cargo test --test p0_upstream_compatibility

# Run with upstream comparison (requires GO_SINGBOX_BIN)
GO_SINGBOX_BIN=/path/to/sing-box cargo test --test p0_upstream_compatibility
```

## Recommendations

### For Users

1. **Config Migration**: Configs from upstream sing-box should work directly with the Rust implementation for all P0 protocols.

2. **Testing**: When migrating from Go to Rust implementation, test your specific use case thoroughly, especially if using advanced features.

3. **Reporting Issues**: If you encounter compatibility issues, please report them with:
   - Config file (sanitized)
   - Upstream sing-box version
   - Rust implementation version
   - Specific error messages or behavior differences

### For Developers

1. **Runtime Testing**: Implement automated runtime interoperability tests with actual server/client connections.

2. **Protocol Compliance**: Ensure protocol implementations strictly follow upstream specifications.

3. **Continuous Validation**: Run compatibility tests against new upstream releases.

4. **Documentation**: Keep this document updated as compatibility status changes.

## Conclusion

All P0 protocols show **full configuration compatibility** with upstream sing-box. Integration with selectors, routing rules, DNS subsystem, and TUN inbound is verified through comprehensive automated tests.

Runtime interoperability (Rust ↔ Go) requires live testing with actual server/client setups, which should be performed before production deployment.

## References

- [Upstream sing-box Documentation](https://sing-box.sagernet.org/)
- [REALITY Protocol Specification](https://github.com/XTLS/REALITY)
- [Hysteria Protocol](https://hysteria.network/)
- [TUIC Protocol](https://github.com/EAimTY/tuic)
- [ECH Specification](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/)
