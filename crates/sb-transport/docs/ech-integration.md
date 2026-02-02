# ECH (Encrypted Client Hello) Integration

## Overview

ECH (Encrypted Client Hello) support has been integrated into the TLS transport layer. This allows clients to encrypt the SNI (Server Name Indication) in the TLS ClientHello, preventing traffic analysis and SNI-based blocking.

## Architecture

The ECH integration follows the same pattern as REALITY:

```
Application
    ↓
EchDialer (sb-transport)
    ↓
EchConnector (sb-tls)
    ↓
TLS Handshake (rustls)
    ↓
TCP Connection
```

## Components

### 1. EchDialer (crates/sb-transport/src/tls.rs)

The `EchDialer` wraps any underlying dialer and adds ECH encryption support:

```rust
pub struct EchDialer<D: Dialer> {
    pub inner: D,
    pub config: Arc<rustls::ClientConfig>,
    pub ech_connector: sb_tls::EchConnector,
}
```

### 2. EchConnector (crates/sb-tls/src/ech/mod.rs)

The `EchConnector` handles ECH configuration validation:
- Parses ECHConfigList
- Validates public name / cipher suites
- Feeds config into rustls ECH mode

## Usage

### Basic Usage

```rust
use sb_transport::{EchDialer, TcpDialer, webpki_roots_config};
use sb_tls::EchClientConfig;

// Create ECH configuration
let ech_config = EchClientConfig {
    enabled: true,
    config: Some("base64_encoded_ech_config_list".to_string()),
    config_list: None,
    pq_signature_schemes_enabled: false,
    dynamic_record_sizing_disabled: None,
};

// Create TLS configuration
let tls_config = webpki_roots_config();

// Create ECH dialer
let dialer = EchDialer::new(TcpDialer, tls_config, ech_config)?;

// Connect to server
let stream = dialer.connect("secret.example.com", 443).await?;
```

### Environment Variable Configuration

```bash
# Set ECH configuration
export SB_ECH_CONFIG="base64_encoded_ech_config_list"
export SB_ECH_ENABLED="true"
export SB_ECH_PQ_ENABLED="false"
```

```rust
use sb_transport::{EchDialer, TcpDialer, webpki_roots_config};

let tls_config = webpki_roots_config();
let dialer = EchDialer::from_env(TcpDialer, tls_config)?;
```

## Feature Flags

To enable ECH support, add the `transport_ech` feature:

```toml
[dependencies]
sb-transport = { path = "../sb-transport", features = ["transport_ech"] }
```

This automatically enables:
- `transport_tls`: TLS support
- `sb-tls/ech`: ECH implementation in sb-tls

## Configuration

### ECH Client Configuration

```rust
pub struct EchClientConfig {
    /// Enable ECH
    pub enabled: bool,
    
    /// ECH configuration list (base64 encoded)
    pub config: Option<String>,
    
    /// ECH configuration list (raw bytes)
    pub config_list: Option<Vec<u8>>,
    
    /// Enable post-quantum signature schemes
    pub pq_signature_schemes_enabled: bool,
    
    /// Dynamic record sizing hint
    pub dynamic_record_sizing_disabled: Option<bool>,
}
```

### Obtaining ECH Configuration

ECH configuration is typically obtained from:
1. DNS TXT records (HTTPS/SVCB records)
2. Server configuration files
3. Out-of-band distribution

## Error Handling

The `EchDialer` handles errors gracefully:

```rust
match dialer.connect("example.com", 443).await {
    Ok(stream) => {
        // ECH handshake successful
    }
    Err(DialError::Tls(msg)) => {
        // ECH encryption or TLS handshake failed
        eprintln!("ECH error: {}", msg);
    }
    Err(e) => {
        // Other connection errors
        eprintln!("Connection error: {}", e);
    }
}
```

## Implementation Notes

### Current Status

- ✅ ECH configuration structures
- ✅ ECH connector integration
- ✅ Transport layer wiring
- ✅ Environment variable support
- ✅ rustls ECH client handshake integration (TLS 1.3 only)

### rustls Compatibility

rustls 0.23+ provides client-side ECH support (TLS 1.3 only). The current implementation:
1. Enables rustls ECH mode with the provided ECHConfigList
2. Performs standard TLS handshake; rustls builds the outer ClientHello
3. Logs ECH acceptance status (accepted/rejected)

### Future Enhancements

- Server-side ECH integration
- QUIC ECH alignment
- ECH retry configuration handling

## Testing

Run ECH tests:

```bash
cargo test -p sb-transport --features transport_ech ech_tests
```

## Security Considerations

1. **ECH Configuration Trust**: Ensure ECH configuration is obtained from trusted sources
2. **Public Name Selection**: Choose innocuous public names that don't raise suspicion
3. **Key Management**: Protect ECH private keys on the server side
4. **Fallback Behavior**: Understand that ECH failures may fall back to standard TLS

## References

- RFC 9180: HPKE (Hybrid Public Key Encryption)
- draft-ietf-tls-esni: TLS Encrypted Client Hello
- sing-box ECH implementation
- rustls documentation
