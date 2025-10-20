# TLS Infrastructure (`sb-tls` crate)

## Overview

The `sb-tls` crate provides comprehensive TLS abstractions and anti-censorship protocols for singbox-rust:

- **Standard TLS 1.2/1.3**: Production-ready TLS using rustls
- **REALITY**: Anti-censorship protocol with TLS fingerprint masquerading
- **ECH (Encrypted Client Hello)**: HPKE-based SNI encryption for privacy
- **uTLS**: TLS fingerprint mimicry (future)

## Architecture

```
┌─────────────────────────────────────────┐
│         TlsConnector Trait              │
│  (Unified abstraction for all TLS)      │
└──────────┬──────────────────────────────┘
           │
     ┌─────┴──────┬─────────────┬──────────┐
     │            │             │          │
┌────▼────┐ ┌────▼────┐  ┌────▼────┐ ┌──▼──┐
│Standard │ │ REALITY │  │   ECH   │ │uTLS │
│   TLS   │ │  Client │  │ Client  │ │(TBD)│
└─────────┘ └─────────┘  └─────────┘ └─────┘
```

### Key Design Principles

1. **Pluggable**: All TLS implementations use the same `TlsConnector` trait
2. **Async-first**: Built on `tokio` with `#[async_trait]`
3. **Zero-cost abstractions**: Feature flags enable/disable implementations
4. **Security-focused**: Proper key management, authentication, validation

## Components

### 1. Standard TLS (`standard.rs`)

Production-ready TLS 1.2/1.3 implementation using rustls.

**Features**:
- WebPKI root certificate verification
- ALPN negotiation support
- SNI configuration
- Custom CA certificate support
- Client certificate authentication

**Usage**:
```rust
use sb_tls::{StandardTlsConnector, TlsConnector};

let tls = StandardTlsConnector::new()?;
let stream = tls.connect(tcp_stream, "example.com").await?;
```

**Configuration**:
- `ALPN`: Set via config (e.g., `["h2", "http/1.1"]`)
- `SNI`: Automatically derived from server name
- `Certificate Verification`: Enabled by default, disable only for testing

### 2. REALITY Protocol (`reality/`)

Anti-censorship protocol that masquerades as legitimate TLS traffic to bypass DPI.

**How it works**:
1. Client performs X25519 key exchange with server's public key
2. Auth data is embedded in TLS ClientHello extension
3. Server verifies auth data using shared secret
4. On success: Connection proceeds normally
5. On failure: Fallback to configured target server (e.g., `www.microsoft.com`)

**Client Implementation** (`reality/client.rs`):
```rust
use sb_tls::{RealityConnector, RealityClientConfig};

let config = RealityClientConfig {
    public_key: "YOUR_PUBLIC_KEY_HEX",
    short_id: "SHORT_ID_HEX",
    server_name: "www.microsoft.com",
    fallback_addr: Some("www.microsoft.com:443"),
};

let reality = RealityConnector::new(config)?;
let stream = reality.connect(tcp_stream, "www.microsoft.com").await?;
```

**Server Implementation** (`reality/server.rs`):
```rust
use sb_tls::{RealityAcceptor, RealityServerConfig};

let config = RealityServerConfig {
    private_key: "YOUR_PRIVATE_KEY_HEX",
    short_ids: vec!["SHORT_ID_HEX".to_string()],
    fallback_addr: "www.microsoft.com:443",
};

let acceptor = RealityAcceptor::new(config)?;
let stream = acceptor.accept(tcp_stream).await?;
```

**Key Generation**:
```bash
# Generate REALITY keypair
sing-box generate reality-keypair

# Output:
# Private key: <64 hex characters>
# Public key: <64 hex characters>
```

**Configuration Fields**:
- `public_key`: Server's X25519 public key (64 hex chars)
- `private_key`: Server's X25519 private key (64 hex chars)
- `short_id`: Authentication identifier (0-16 hex chars)
- `server_name`: Target domain for SNI
- `fallback_addr`: Where to forward unauthenticated connections

**Security**:
- ✅ Constant-time comparison for auth verification
- ✅ Secure X25519 key exchange
- ✅ Fallback prevents active probing

### 3. ECH (Encrypted Client Hello) (`ech/`)

HPKE-based encryption of TLS ClientHello to hide SNI from network observers.

**How it works**:
1. Client obtains server's ECHConfigList (public ECH configuration)
2. Client generates ephemeral X25519 keypair
3. SNI and sensitive extensions are encrypted using HPKE
4. Server decrypts inner ClientHello using private key
5. Handshake proceeds with encrypted SNI

**Client Implementation** (`ech/mod.rs`):
```rust
use sb_tls::{EchConnector, EchClientConfig};

let config = EchClientConfig {
    config_list: "BASE64_ENCODED_ECHCONFIGLIST",
    outer_sni: "public.example.com",
    inner_sni: "secret.example.com",
};

let ech = EchConnector::new(config)?;
let stream = ech.connect(tcp_stream, "public.example.com").await?;
```

**Server Implementation** (future):
```rust
// Server-side ECH acceptance (not yet implemented)
// See: crates/sb-tls/src/ech/server.rs (TODO)
```

**Key Generation**:
```bash
# Generate ECH keypair
sing-box generate ech-keypair

# Output:
# Private key: <64 hex characters>
# ECH config: <base64 encoded ECHConfigList>
```

**Configuration Fields**:
- `config_list`: Base64-encoded ECHConfigList (from server)
- `outer_sni`: Public SNI visible to observers
- `inner_sni`: Real SNI encrypted in inner ClientHello

**Cryptographic Details**:
- **KEM**: DHKEM-X25519-HKDF-SHA256
- **KDF**: HKDF-SHA256
- **AEAD**: CHACHA20POLY1305
- **HPKE Mode**: Base mode (mode 0)

**Security**:
- ✅ SNI encrypted end-to-end
- ✅ HPKE provides forward secrecy
- ✅ Prevents SNI-based censorship

### 4. uTLS (Future)

TLS fingerprint mimicry for bypassing fingerprint-based detection.

**Status**: Placeholder module exists (`src/utls.rs`)
**Implementation**: Requires Rust equivalent of Go uTLS library
**Research**: See `.kiro/specs/p0-production-parity/` for investigation notes

## Feature Flags

Enable TLS implementations via Cargo features:

```toml
[dependencies]
sb-tls = { path = "crates/sb-tls", features = ["reality", "ech"] }
```

**Available features**:
- `reality`: REALITY anti-censorship protocol (default)
- `ech`: Encrypted Client Hello support (default)
- `utls`: uTLS fingerprint mimicry (future)

## Integration with Protocols

TLS infrastructure integrates with protocol adapters:

### VLESS + REALITY
```rust
// VLESS outbound with REALITY TLS
use sb_adapters::outbound::VlessOutbound;
use sb_tls::{RealityConnector, RealityClientConfig};

let reality_config = RealityClientConfig {
    public_key: "...",
    short_id: "...",
    server_name: "www.microsoft.com",
    fallback_addr: Some("www.microsoft.com:443"),
};

let vless = VlessOutbound::new(config)
    .with_tls(RealityConnector::new(reality_config)?);
```

### VMess + ECH
```rust
// VMess outbound with ECH
use sb_adapters::outbound::VmessOutbound;
use sb_tls::{EchConnector, EchClientConfig};

let ech_config = EchClientConfig {
    config_list: "...",
    outer_sni: "cdn.example.com",
    inner_sni: "real.example.com",
};

let vmess = VmessOutbound::new(config)
    .with_tls(EchConnector::new(ech_config)?);
```

### Trojan + Standard TLS
```rust
// Trojan outbound with standard TLS
use sb_adapters::outbound::TrojanOutbound;
use sb_tls::StandardTlsConnector;

let trojan = TrojanOutbound::new(config)
    .with_tls(StandardTlsConnector::new()?);
```

## Testing

### Unit Tests

```bash
# Run sb-tls unit tests
cargo test -p sb-tls

# Run with specific features
cargo test -p sb-tls --features reality,ech
```

### E2E Tests

```bash
# REALITY end-to-end tests
cargo test --test reality_tls_e2e

# ECH end-to-end tests
cargo test --test e2e/ech_handshake

# All TLS-related E2E tests
cargo test reality ech tls
```

## Troubleshooting

### REALITY Issues

**Authentication failures**:
- ✅ Verify `public_key` matches server's public key
- ✅ Verify `short_id` is in server's allowed list
- ✅ Check `server_name` is a valid, reachable domain
- ✅ Ensure fallback address is accessible

**Handshake errors**:
- ✅ Target server must be real and respond to TLS
- ✅ Check network connectivity to fallback address
- ✅ Verify X25519 keys are 64 hex characters

**Config validation**:
```bash
# Test REALITY config
sing-box check --config your-config.yaml

# Generate test keys
sing-box generate reality-keypair
```

### ECH Issues

**Config format errors**:
- ✅ ECHConfigList must be valid base64
- ✅ Use `sing-box generate ech-keypair` for correct format
- ✅ Verify outer_sni is a valid domain

**Handshake failures**:
- ✅ Server must support ECH
- ✅ Check ECH config version compatibility
- ✅ Verify HPKE cipher suite is supported

**SNI encryption verification**:
```bash
# Capture traffic to verify SNI is encrypted
tcpdump -i any -w ech-test.pcap port 443

# Analyze with Wireshark
# Look for "encrypted_client_hello" extension in ClientHello
```

### Standard TLS Issues

**Certificate verification failures**:
- ✅ Check system time is correct
- ✅ Verify target certificate is valid and not expired
- ✅ Ensure CA certificates are installed

**ALPN negotiation failures**:
- ✅ Server must support requested ALPN protocols
- ✅ Check protocol list order (client preference)

**SNI mismatch**:
- ✅ Verify `sni` field matches server certificate
- ✅ Use wildcard certificates if needed

## Performance

### Benchmarks

```bash
# Run TLS benchmarks
cargo bench -p sb-tls

# Specific benchmark groups
cargo bench -p sb-tls -- reality
cargo bench -p sb-tls -- ech
```

**Expected Performance**:
- **REALITY handshake**: ~1-2ms overhead (X25519 key exchange)
- **ECH handshake**: ~2-3ms overhead (HPKE encryption)
- **Standard TLS**: ~0.5-1ms (rustls handshake)

### Optimization Tips

1. **Connection Pooling**: Reuse TLS connections when possible
2. **Session Resumption**: Enable TLS session tickets (rustls default)
3. **ALPN**: Negotiate H2 for multiplexing
4. **Key Caching**: Cache X25519 keys for REALITY/ECH

## Debugging

### Enable Debug Logging

```bash
# Verbose TLS logging
RUST_LOG=sb_tls=debug cargo run

# REALITY-specific logging
RUST_LOG=sb_tls::reality=trace cargo run

# ECH-specific logging
RUST_LOG=sb_tls::ech=trace cargo run
```

### Common Debug Patterns

**REALITY auth debugging**:
```rust
// Add logging to see auth data
tracing::debug!(
    short_id = %config.short_id,
    server_name = %config.server_name,
    "REALITY auth attempt"
);
```

**ECH config parsing**:
```rust
// Verify ECHConfigList parsing
let config_list = base64::decode(&ech_config)?;
tracing::debug!(config_len = config_list.len(), "Parsed ECH config");
```

## Security Considerations

### Production Checklist

- [ ] **REALITY**: Use strong, randomly generated X25519 keys
- [ ] **ECH**: Rotate ECH config periodically
- [ ] **Standard TLS**: Enable certificate verification
- [ ] **ALPN**: Use H2 for better multiplexing
- [ ] **SNI**: Set correct SNI for certificate validation
- [ ] **Fallback**: Configure real, accessible fallback targets
- [ ] **Logging**: Redact sensitive keys in logs
- [ ] **Config**: Store private keys securely (not in configs)

### Threat Model

**REALITY protects against**:
- ✅ Active probing (fallback to real server)
- ✅ DPI fingerprinting (TLS looks legitimate)
- ✅ SNI-based censorship (uses real domains)

**ECH protects against**:
- ✅ SNI snooping (encrypted in ClientHello)
- ✅ Passive observation of target domains
- ✅ Censorship based on SNI patterns

**Standard TLS protects against**:
- ✅ Passive eavesdropping
- ✅ Man-in-the-middle attacks (with cert verification)
- ✅ Downgrade attacks (TLS 1.2+ only)

## References

- **REALITY**: [XTLS/REALITY GitHub](https://github.com/XTLS/REALITY)
- **ECH**: [RFC 9460 - Encrypted Client Hello](https://datatracker.ietf.org/doc/rfc9460/)
- **HPKE**: [RFC 9180 - Hybrid Public Key Encryption](https://datatracker.ietf.org/doc/rfc9180/)
- **rustls**: [rustls Documentation](https://docs.rs/rustls/)

## Related Documentation

- **REALITY Details**: `crates/sb-tls/docs/reality.md`
- **ECH Configuration**: `docs/ECH_CONFIG.md`
- **Protocol Integration**: `crates/sb-adapters/README.md`
- **Transport Layer**: `crates/sb-transport/README.md`
- **Feature Parity**: `GO_PARITY_MATRIX.md`

## Version Information

- **sb-tls**: 0.1.0
- **rustls**: 0.23.x
- **tokio-rustls**: 0.26.x
- **hpke**: Latest stable
- **x25519-dalek**: 2.x

Last Updated: 2025-10-09
