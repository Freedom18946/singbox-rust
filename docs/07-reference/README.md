# Reference

Technical reference materials and specifications.

---

## Documentation Sections

### Configuration Schemas

- **[Config V2 Schema](schemas/config-v2.md)** - Schema reference (in progress)
- **[Subscription Schema](schemas/subscription.md)** - Subscription file format
- **[Rule-Set Format](schemas/rule-set.md)** - SRS binary format specification

### Error Reference

- **[Error Codes](error-codes.md)** - All error codes and meanings
- **[Exit Codes](../02-cli-reference/exit-codes.md)** - CLI exit codes

### Compatibility

- **[Compatibility Matrix](compatibility-matrix.md)** - Platform and protocol support
- **[Feature Parity](feature-parity.md)** - sing-box (Go) parity status
- **[Breaking Changes](breaking-changes.md)** - Version migration guide

### Glossary

- **[Terminology](glossary.md)** - Technical terms and definitions

---

## Quick Reference

### Configuration Schema V2

**Minimal valid config**:

```yaml
schema_version: 2
inbounds:
  - type: socks
    tag: in
    listen: 127.0.0.1
    port: 1080
outbounds:
  - type: direct
    tag: out
route:
  default: out
```

**Full schema**: See [Config V2 Schema](schemas/config-v2.md)

### Common Error Codes

| Code   | Type    | Meaning                         | Solution                  |
| ------ | ------- | ------------------------------- | ------------------------- |
| `E001` | Config  | Invalid JSON/YAML syntax        | Check file format         |
| `E002` | Config  | Missing required field          | Add required field        |
| `E003` | Config  | Invalid value                   | Check value type/range    |
| `E101` | Network | Connection refused              | Check server address      |
| `E102` | Network | Connection timeout              | Increase timeout          |
| `E201` | TLS     | Certificate verification failed | Check SNI and certificate |
| `E301` | Auth    | Authentication failed           | Verify credentials        |

**Complete list**: See [Error Codes](error-codes.md)

### Platform Support

| Platform           | Status     | Notes                    |
| ------------------ | ---------- | ------------------------ |
| **Linux** x86_64   | ✅ Full    | Core + platform IO best  |
| **Linux** aarch64  | ✅ Full    | ARM64                    |
| **macOS** x86_64   | ✅ Core    | See Platform IO notes    |
| **macOS** arm64    | ✅ Core    | See Platform IO notes    |
| **Windows** x86_64 | ✅ Core    | See Platform IO notes    |
| **FreeBSD**        | ⚠️ Partial | Limited TUN support      |
| **Android**        | 🚧 Planned | Via JNI bindings         |
| **iOS**            | 🚧 Planned | Via Swift bindings       |

See Platform IO specifics: `docs/07-reference/platform-io.md`.

### Protocol Support Matrix

**Inbound Protocols (12/12 Complete)**:

- ✅ SOCKS5, HTTP, Mixed, TUN, Direct
- ✅ Shadowsocks, VMess, VLESS, Trojan
- ✅ TUIC, Hysteria v1/v2, Naive, ShadowTLS

**Outbound Protocols (15/15 Complete)**:

- ✅ Direct, Block, DNS
- ✅ HTTP, SOCKS5, SSH
- ✅ Shadowsocks, VMess, VLESS, Trojan
- ✅ TUIC, Hysteria v1/v2, ShadowTLS
- ✅ Selector, URLTest

**Transport Layers (All Complete)**:

- ✅ TCP, UDP, QUIC
- ✅ WebSocket, HTTP/2, HTTPUpgrade, gRPC
- ✅ Multiplex (yamux)

**TLS Support**:

- ✅ Standard TLS 1.2/1.3
- ✅ REALITY (X25519)
- ✅ ECH (Encrypted Client Hello)
- 🚧 uTLS (future)

See [Compatibility Matrix](compatibility-matrix.md).

---

## Feature Parity with sing-box (Go)

**Overall**: 99%+ feature parity

### ✅ Complete Parity

- Core routing engine
- All inbound/outbound protocols
- DNS resolution (System, DoH, DoT, DoQ, FakeIP)
- TLS infrastructure (Standard, REALITY, ECH)
- Transport layers (WS, H2, gRPC, QUIC, Multiplex)
- CLI tools (generate, geoip, geosite, rule-set)
- Metrics and observability
- Admin API

### ⚠️ Differences

- **Better Performance**: 149x faster process matching on macOS
- **Memory Safety**: No null pointer crashes or use-after-free
- **Better Error Messages**: More detailed validation errors
- **Stricter Validation**: Catches config errors earlier

### 🚧 Future Additions

- uTLS (TLS fingerprint mimicry)
- Additional platform bindings (Android, iOS)

See [Feature Parity Guide](feature-parity.md).

---

## Terminology

### Core Concepts

**Inbound**: Local listener that accepts incoming connections

- Examples: SOCKS5 proxy, HTTP proxy, TUN device

**Outbound**: Upstream connection handler

- Examples: Direct connection, Shadowsocks proxy, Selector

**Router**: Traffic routing engine that matches rules

- Decides which outbound to use for each connection

**Transport**: Layer that wraps protocols

- Examples: WebSocket, HTTP/2, gRPC, TLS

**Adapter**: Protocol implementation (inbound or outbound)

- Implements specific proxy protocol logic

### TLS Terms

**SNI (Server Name Indication)**: Domain name in TLS handshake

- Can be encrypted with ECH

**ALPN (Application-Layer Protocol Negotiation)**: Protocol selection in TLS

- Examples: `h2` (HTTP/2), `http/1.1`

**REALITY**: Anti-censorship TLS protocol

- Masquerades as legitimate TLS to bypass DPI

**ECH (Encrypted Client Hello)**: Encrypts SNI in TLS handshake

- Prevents SNI-based censorship

### Routing Terms

**GeoIP**: IP address to country/region mapping

- Used for geographic routing

**GeoSite**: Domain to category mapping

- Examples: `netflix`, `google`, `cn` (China domains)

**Rule-Set**: Binary format for routing rules (SRS)

- Compiled from JSON/DSL for efficiency

**FakeIP**: Virtual IP addresses for domains

- Enables routing before DNS resolution

### Observability Terms

**Metrics**: Prometheus-format performance counters

- Examples: connection count, bandwidth, latency

**Cardinality**: Number of unique metric label combinations

- Important to prevent metric explosion

**Tracing**: Structured logging with context

- Uses Rust `tracing` crate

See [Complete Glossary](glossary.md).

---

## Configuration Schema Reference

### Inbound Schema

```yaml
inbounds:
  - type: string # Required: Protocol type
    tag: string # Required: Unique identifier
    listen: string # Optional: Listen address (default: 127.0.0.1)
    port: integer # Required: Listen port
    # Protocol-specific fields...
```

### Outbound Schema

```yaml
outbounds:
  - type: string # Required: Protocol type
    tag: string # Required: Unique identifier
    server: string # Optional: Server address (for proxies)
    port: integer # Optional: Server port
    # Protocol-specific fields...
```

### Route Schema

```yaml
route:
  rules: # Optional: Array of rules
    - domain: [string] # Optional: Exact domain match
      domain_suffix: [string] # Optional: Domain suffix match
      domain_keyword: [string] # Optional: Domain keyword match
      ip_cidr: [string] # Optional: IP CIDR match
      port: [integer] # Optional: Port match
      protocol: string # Optional: tcp/udp
      process_name: [string] # Optional: Process name
      inbound: [string] # Optional: Source inbound
      outbound: string # Required: Target outbound
  default: string # Required: Default outbound
```

See [Config V2 Schema](schemas/config-v2.md) for complete reference.

---

## Error Code Reference

### Configuration Errors (E001-E099)

- `E001`: Invalid JSON/YAML syntax
- `E002`: Missing required field
- `E003`: Invalid field value
- `E004`: Duplicate tag/identifier
- `E005`: Invalid reference (outbound not found)

### Network Errors (E101-E199)

- `E101`: Connection refused
- `E102`: Connection timeout
- `E103`: DNS resolution failed
- `E104`: Network unreachable

### TLS Errors (E201-E299)

- `E201`: Certificate verification failed
- `E202`: TLS handshake failed
- `E203`: ALPN negotiation failed
- `E204`: REALITY authentication failed
- `E205`: ECH decryption failed

### Authentication Errors (E301-E399)

- `E301`: Authentication failed
- `E302`: Authorization denied
- `E303`: JWT token invalid
- `E304`: JWT token expired

See [Error Codes Reference](error-codes.md) for complete list.

---

## Related Documentation

- **[User Guide](../01-user-guide/)** - Configuration guides
- **[CLI Reference](../02-cli-reference/)** - Command-line tools
- **[API Reference](../05-api-reference/)** - HTTP and gRPC APIs
- **[Development](../04-development/)** - Architecture and implementation
