# TLS Integration Guide

This guide explains how TLS is integrated into the singbox-rust project across different protocols and transport layers.

## Overview

TLS (Transport Layer Security) support in singbox-rust provides secure, encrypted connections for all major proxy protocols. The implementation supports:

- **Standard TLS 1.2 and 1.3**
- **REALITY** - Anti-censorship TLS camouflage (feature: `tls_reality`)
- **ECH (Encrypted Client Hello)** - Enhanced privacy (feature: `transport_ech`)
- **ALPN negotiation** - Protocol selection (HTTP/2, HTTP/1.1)
- **Certificate verification** - With option to skip for testing

## Architecture

### TLS Layer Components

```
┌─────────────────────────────────────────┐
│         Application Layer               │
│  (Shadowsocks, Trojan, VLESS, VMess)   │
└─────────────────────────────────────────┘
                  ↓
┌─────────────────────────────────────────┐
│          TLS Transport Layer            │
│  - Standard TLS                         │
│  - REALITY TLS                          │
│  - ECH TLS                              │
└─────────────────────────────────────────┘
                  ↓
┌─────────────────────────────────────────┐
│            TCP Transport                │
└─────────────────────────────────────────┘
```

### Key Modules

- **`sb-tls`** - Core TLS implementation crate
  - `TlsConnector` - Standard TLS client
  - `RealityConnector` - REALITY protocol support
  - `EchConfig` - ECH configuration and handling

- **`sb-transport`** - Transport abstraction layer
  - `TlsConfig` - Unified TLS configuration
  - `TlsTransport` - Transport wrapper for TLS streams

- **`sb-adapters`** - Protocol adapters with TLS integration
  - Each protocol (Shadowsocks, Trojan, VLESS, VMess) supports TLS wrapping

## Protocol-Specific Integration

### 1. Trojan

Trojan inherently requires TLS - the protocol specification mandates TLS for authentication concealment.

**Configuration:**
```rust
let config = TrojanConfig {
    server: "example.com:443".to_string(),
    password: "your-password".to_string(),
    sni: Some("example.com".to_string()),
    skip_cert_verify: false,

    // Optional REALITY support
    #[cfg(feature = "tls_reality")]
    reality: Some(RealityClientConfig {
        public_key: "...".to_string(),
        short_id: "0123456789abcdef".to_string(),
        server_name: "www.microsoft.com".to_string(),
        fingerprint: "chrome".to_string(),
        spiderx: None,
    }),

    multiplex: None,
};
```

**Implementation (crates/sb-adapters/src/outbound/trojan.rs:124)**:
```rust
async fn perform_standard_tls_handshake(
    &self,
    tcp_stream: tokio::net::TcpStream,
    config: &TrojanConfig,
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    // Create TLS config
    let tls_config = if config.skip_cert_verify {
        // Test mode: skip verification
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    } else {
        // Production: use webpki-roots
        let root_store = tokio_rustls::rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
        };
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    // Perform handshake
    let connector = TlsConnector::from(Arc::new(tls_config));
    let tls_stream = connector.connect(domain, tcp_stream).await?;
    Ok(tls_stream)
}
```

**With REALITY (crates/sb-adapters/src/outbound/trojan.rs:295)**:
```rust
#[cfg(feature = "tls_reality")]
let mut stream: BoxedStream = if let Some(ref reality_cfg) = config.reality {
    // Use REALITY TLS
    let reality_connector = sb_tls::reality::RealityConnector::new(reality_cfg.clone())?;
    let tls_stream = reality_connector.connect(tcp_stream, &server_name).await?;
    Box::new(tls_stream)
} else {
    // Standard TLS
    let tls_stream = self.perform_standard_tls_handshake(tcp_stream, config).await?;
    Box::new(tls_stream)
};
```

### 2. VLESS

VLESS supports optional TLS through REALITY integration for enhanced anti-censorship.

**Configuration:**
```rust
let config = VlessConfig {
    server_addr: "127.0.0.1:443".parse().unwrap(),
    uuid: Uuid::new_v4(),
    flow: FlowControl::None,
    encryption: Encryption::None,

    // Optional REALITY TLS
    #[cfg(feature = "tls_reality")]
    reality: Some(RealityClientConfig {
        public_key: "...".to_string(),
        short_id: "0123456789abcdef".to_string(),
        server_name: "www.microsoft.com".to_string(),
        fingerprint: "chrome".to_string(),
        spiderx: None,
    }),

    // Optional ECH
    #[cfg(feature = "transport_ech")]
    ech: Some(EchClientConfig {
        enabled: true,
        config: vec![...],  // ECH config bytes
        retry_configs: vec![],
    }),

    multiplex: None,
    ..Default::default()
};
```

**Implementation (crates/sb-adapters/src/outbound/vless.rs:286)**:
```rust
// If REALITY is configured, wrap the stream with REALITY TLS
#[cfg(feature = "tls_reality")]
let stream: BoxedStream = if let Some(ref reality_cfg) = self.config.reality {
    tracing::debug!("VLESS using REALITY TLS");

    let reality_connector = RealityConnector::new(reality_cfg.clone())?;
    let server_name = &reality_cfg.server_name;
    let tls_stream = reality_connector.connect(stream, server_name).await?;

    // Wrap in adapter
    Box::new(TlsStreamAdapter { inner: tls_stream })
} else {
    stream
};
```

### 3. VMess

VMess supports full TLS configuration including standard TLS, REALITY, and ECH.

**Configuration:**
```rust
let config = VmessConfig {
    server_addr: "127.0.0.1:443".parse().unwrap(),
    auth: VmessAuth {
        uuid: Uuid::new_v4(),
        alter_id: 0,
        security: Security::Auto,
        additional_data: None,
    },

    // Full TLS configuration
    tls: Some(TlsConfig {
        enabled: true,
        server_name: Some("example.com".to_string()),
        insecure: false,
        min_version: Some(TlsVersion::Tls12),
        max_version: Some(TlsVersion::Tls13),
        alpn: vec!["h2".to_string(), "http/1.1".to_string()],
        certificate: None,
        certificate_file: Some("/path/to/cert.pem".to_string()),
        key: None,
        key_file: None,
        ca_certificate: None,
        ca_certificate_file: Some("/path/to/ca.pem".to_string()),
    }),

    multiplex: None,
    ..Default::default()
};
```

**Implementation (crates/sb-adapters/src/outbound/vmess.rs:356)**:
```rust
// Wrap with TLS if configured
if let Some(ref tls_config) = self.config.tls {
    tracing::debug!("Wrapping VMess connection with TLS");
    let tls_transport = sb_transport::TlsTransport::new(tls_config.clone());
    let server_name = self.config.server_addr.ip().to_string();

    boxed_stream = tokio::time::timeout(
        timeout,
        tls_transport.wrap_client(boxed_stream, &server_name)
    )
    .await
    .map_err(|_| AdapterError::Timeout(timeout))?
    .map_err(|e| AdapterError::Other(format!("TLS handshake failed: {}", e)))?;

    tracing::debug!("VMess TLS handshake successful");
}
```

### 4. Shadowsocks

Shadowsocks typically doesn't use TLS at the protocol level, but can be combined with transport-layer TLS through plugins or wrappers.

## TLS Configuration Options

### TlsConfig Structure

```rust
pub struct TlsConfig {
    /// Enable TLS
    pub enabled: bool,

    /// Server name for SNI
    pub server_name: Option<String>,

    /// Skip certificate verification (testing only)
    pub insecure: bool,

    /// Minimum TLS version
    pub min_version: Option<TlsVersion>,

    /// Maximum TLS version
    pub max_version: Option<TlsVersion>,

    /// ALPN protocols
    pub alpn: Vec<String>,

    /// Client certificate (PEM bytes)
    pub certificate: Option<Vec<u8>>,

    /// Client certificate file path
    pub certificate_file: Option<String>,

    /// Client private key (PEM bytes)
    pub key: Option<Vec<u8>>,

    /// Client private key file path
    pub key_file: Option<String>,

    /// CA certificate (PEM bytes)
    pub ca_certificate: Option<Vec<u8>>,

    /// CA certificate file path
    pub ca_certificate_file: Option<String>,
}
```

### TlsVersion Enum

```rust
pub enum TlsVersion {
    Tls12,  // TLS 1.2
    Tls13,  // TLS 1.3
}
```

## REALITY Protocol

REALITY is an anti-censorship protocol that makes TLS traffic indistinguishable from legitimate HTTPS connections to real websites.

### How REALITY Works

1. **Handshake Splitting**: REALITY splits the TLS handshake:
   - ClientHello goes to the real target server (e.g., www.microsoft.com)
   - After ServerHello, connection switches to proxy server

2. **Traffic Camouflage**:
   - Actual server certificate from real website
   - No custom certificates to detect
   - Indistinguishable from normal HTTPS

3. **Authentication**:
   - Public/private key pair
   - Short ID for quick identification
   - Fingerprint emulation (Chrome, Firefox, Safari)

### REALITY Configuration

```rust
pub struct RealityClientConfig {
    /// Server public key
    pub public_key: String,

    /// Short ID for fast identification
    pub short_id: String,

    /// Real server name to camouflage as
    pub server_name: String,

    /// Browser fingerprint to emulate
    pub fingerprint: String,

    /// SpiderX routing (optional)
    pub spiderx: Option<String>,
}
```

### Example: VLESS + REALITY

```rust
let reality_config = RealityClientConfig {
    public_key: "xIl2b8rERud8fmFzJzoWdKQDZSVxIpGROGn9ICVd61w",
    short_id: "0123456789abcdef",
    server_name: "www.microsoft.com",  // Camouflage as Microsoft
    fingerprint: "chrome",             // Emulate Chrome browser
    spiderx: None,
};

let connector = VlessConnector::new(VlessConfig {
    reality: Some(reality_config),
    ..Default::default()
});
```

### REALITY Implementation (crates/sb-tls/src/reality.rs)

The core REALITY implementation in `sb-tls` provides:
- ClientHello splitting and routing
- Certificate chain validation bypass
- Fingerprint emulation
- Short ID authentication

## ECH (Encrypted Client Hello)

ECH encrypts the ClientHello message, hiding the SNI (Server Name Indication) from network observers.

### ECH Configuration

```rust
pub struct EchClientConfig {
    /// Enable ECH
    pub enabled: bool,

    /// ECH configuration (binary format)
    pub config: Vec<u8>,

    /// Retry configurations for fallback
    pub retry_configs: Vec<Vec<u8>>,
}
```

### Example: VLESS + ECH

```rust
let ech_config = EchClientConfig {
    enabled: true,
    config: fetch_ech_config("cloudflare.com").await?,
    retry_configs: vec![],
};

let connector = VlessConnector::new(VlessConfig {
    ech: Some(ech_config),
    ..Default::default()
});
```

## Certificate Verification

### Production Mode (Secure)

```rust
let tls_config = TlsConfig {
    enabled: true,
    server_name: Some("example.com".to_string()),
    insecure: false,  // Verify certificates
    ca_certificate_file: Some("/etc/ssl/certs/ca-certificates.crt".to_string()),
    ..Default::default()
};
```

### Testing Mode (Insecure)

```rust
let tls_config = TlsConfig {
    enabled: true,
    server_name: Some("localhost".to_string()),
    insecure: true,  // Skip verification - TESTING ONLY
    ..Default::default()
};
```

### Custom CA Certificates

```rust
let tls_config = TlsConfig {
    enabled: true,
    server_name: Some("internal-server.local".to_string()),
    insecure: false,
    ca_certificate_file: Some("/path/to/internal-ca.pem".to_string()),
    ..Default::default()
};
```

## ALPN (Application-Layer Protocol Negotiation)

ALPN allows the client and server to negotiate which protocol to use over TLS.

### Common ALPN Values

- **"h2"** - HTTP/2
- **"http/1.1"** - HTTP/1.1
- **"h3"** - HTTP/3 (QUIC)

### Configuration

```rust
let tls_config = TlsConfig {
    enabled: true,
    alpn: vec!["h2".to_string(), "http/1.1".to_string()],
    ..Default::default()
};
```

## TLS + Multiplex

TLS can be combined with multiplex (yamux) for efficient connection pooling over a single TLS connection.

### Layer Stack

```
Application Protocol (VMess, Trojan, etc.)
              ↓
     Multiplex (yamux)
              ↓
         TLS 1.3
              ↓
            TCP
```

### Configuration Example

```rust
let config = VmessConfig {
    tls: Some(TlsConfig {
        enabled: true,
        server_name: Some("example.com".to_string()),
        ..Default::default()
    }),

    multiplex: Some(MultiplexConfig {
        enabled: true,
        protocol: "yamux".to_string(),
        max_streams: 16,
        ..Default::default()
    }),

    ..Default::default()
};
```

## Performance Considerations

### TLS Handshake Optimization

1. **Session Resumption**: Not yet implemented - planned feature
2. **ALPN Negotiation**: Adds minimal overhead
3. **Certificate Caching**: Automatic in rustls

### Throughput

- **TLS 1.3**: ~5-10% overhead vs plain TCP
- **REALITY**: Additional ~2-3% overhead
- **ECH**: Minimal additional overhead (<1%)

## Security Best Practices

1. **Always use TLS in production** unless you have specific reasons not to
2. **Never skip certificate verification** (`insecure: false`) in production
3. **Use REALITY for anti-censorship** in restrictive network environments
4. **Keep certificates up to date** - monitor expiration
5. **Use strong TLS versions** - prefer TLS 1.3, minimum TLS 1.2

## Troubleshooting

### Common Issues

**1. Certificate Verification Failed**
```
Error: TLS handshake failed: invalid peer certificate
```
**Solution**: Check that `server_name` matches certificate CN/SAN, or provide correct CA certificate.

**2. REALITY Handshake Failed**
```
Error: REALITY handshake failed
```
**Solution**: Verify `public_key`, `short_id`, and ensure `server_name` points to a real, accessible website.

**3. ALPN Negotiation Failed**
```
Error: no application protocol
```
**Solution**: Ensure server supports the ALPN protocols you're offering.

### Debug Logging

Enable TLS debug logging:
```rust
RUST_LOG=sb_tls=debug,sb_transport=debug cargo run
```

## Testing

### Unit Tests

See test files:
- `app/tests/tls_inbound_e2e.rs` - TLS inbound tests
- `app/tests/vmess_tls_variants_e2e.rs` - VMess TLS variants

### Manual Testing

```bash
# Test Trojan with TLS
cargo run --bin singbox-rust -- \
    --protocol trojan \
    --server example.com:443 \
    --password your-password \
    --sni example.com
```

## References

- **TLS 1.3 RFC**: [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446)
- **REALITY Protocol**: [XTLS/REALITY](https://github.com/XTLS/REALITY)
- **ECH Specification**: [draft-ietf-tls-esni](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/)
- **ALPN RFC**: [RFC 7301](https://datatracker.ietf.org/doc/html/rfc7301)

## Feature Flags

- `tls_reality` - Enable REALITY protocol support
- `transport_ech` - Enable ECH (Encrypted Client Hello)
- `adapter-trojan` - Trojan protocol (requires TLS)
- `adapter-vmess` - VMess protocol (optional TLS)
- `adapter-vless` - VLESS protocol (optional REALITY/ECH)
