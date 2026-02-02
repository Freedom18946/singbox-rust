# ECH (Encrypted Client Hello) Usage Guide

## Overview

ECH (Encrypted Client Hello) is a TLS extension that encrypts the ClientHello message to prevent traffic analysis and SNI-based blocking. This implementation provides runtime integration with rustls for ECH support.

Note: For production TLS handshakes, prefer rustls ECH via `sb-transport` (it uses `ClientConfig::with_ech`). `EchConnector::wrap_tls` remains a legacy/fixture helper and is not used by the rustls handshake path.

## Features

- ✅ ECH configuration parsing (ECHConfigList)
- ✅ HPKE (Hybrid Public Key Encryption) for ClientHello encryption
- ✅ X25519 key encapsulation (DHKEM)
- ✅ AES-128-GCM authenticated encryption
- ✅ ECH acceptance verification
- ✅ Compatible with sing-box ECH configuration format

## Quick Start

### 1. Create ECH Configuration

```rust
use sb_tls::ech::{EchClientConfig, EchConnector};

// ECH config typically comes from DNS TXT records or server configuration
let ech_config_base64 = "..."; // Base64-encoded ECHConfigList

let config = EchClientConfig::new(ech_config_base64.to_string())?;
```

### 2. Initialize ECH Connector

```rust
let connector = EchConnector::new(config)?;
```

### 3. Encrypt ClientHello

```rust
// Encrypt the real server name in the inner ClientHello
let real_server_name = "secret.example.com";
let ech_hello = connector.wrap_tls(real_server_name)?;

println!("Outer SNI: {}", ech_hello.outer_sni);  // Public name
println!("Inner SNI: {}", ech_hello.inner_sni);  // Encrypted
```

### 4. Verify ECH Acceptance

```rust
// After receiving ServerHello from the server
let server_hello = /* ... received from server ... */;
let accepted = connector.verify_ech_acceptance(&server_hello)?;

if accepted {
    println!("Server accepted ECH");
} else {
    println!("Server rejected ECH");
}
```

## Configuration Format

### ECH Client Configuration

```rust
use sb_tls::ech::EchClientConfig;

let config = EchClientConfig {
    enabled: true,
    config: Some("base64_encoded_ech_config_list".to_string()),
    config_list: None, // Auto-decoded from config
    pq_signature_schemes_enabled: false,
    dynamic_record_sizing_disabled: None,
};
```

### ECHConfigList Structure

The ECHConfigList is a binary structure containing:

- **Version**: ECH protocol version (0xfe0d for Draft-13)
- **Public Key**: Server's X25519 public key (32 bytes)
- **Cipher Suites**: Supported HPKE cipher suites
  - KEM: Key Encapsulation Mechanism (e.g., X25519)
  - KDF: Key Derivation Function (e.g., HKDF-SHA256)
  - AEAD: Authenticated Encryption (e.g., AES-128-GCM)
- **Public Name**: SNI to use in outer ClientHello
- **Maximum Name Length**: Maximum length for encrypted names

## How ECH Works

### Client Side

1. **Obtain ECHConfigList**: From DNS, configuration, or other sources
2. **Encrypt ClientHello**: Using server's public key (HPKE)
3. **Send Encrypted ClientHello**: In TLS extension
4. **Server Decrypts**: And processes the real ClientHello

### Encryption Process

```
Real Server Name (secret.example.com)
         ↓
   Inner ClientHello
         ↓
   HPKE Encryption (X25519 + AES-128-GCM)
         ↓
   Encrypted Payload
         ↓
   ECH Extension in Outer ClientHello
         ↓
   Outer SNI: public.example.com
```

## Security Considerations

### Key Management

- ECH public keys should be obtained securely (e.g., DNSSEC)
- Keys should be rotated regularly
- Private keys must be kept secure on the server

### Traffic Analysis Resistance

- ECH encrypts the SNI field to prevent SNI-based blocking
- The outer ClientHello uses a public name (e.g., cloudflare.com)
- The real server name is encrypted in the inner ClientHello

### Fallback Behavior

- If ECH is not supported by the server, the connection may fail
- Clients should handle ECH rejection gracefully
- Consider implementing fallback to non-ECH connections

## Integration with Transport Layer

### Using with TLS Dialer

```rust
use sb_transport::{TlsDialer, TcpDialer};
use sb_tls::ech::{EchClientConfig, EchConnector};

// Create ECH connector
let ech_config = EchClientConfig::new(ech_config_base64)?;
let ech_connector = EchConnector::new(ech_config)?;

// Encrypt ClientHello before TLS handshake
let ech_hello = ech_connector.wrap_tls("secret.example.com")?;

// Use outer SNI for TLS connection
let tls_dialer = TlsDialer {
    inner: TcpDialer,
    config: tls_config,
    sni_override: Some(ech_hello.outer_sni),
    alpn: None,
};

// The ECH payload would be embedded in the TLS handshake
// rustls ECH mode handles the extension during the handshake
```

## Testing

### Unit Tests

```bash
cargo test --package sb-tls --features ech -- ech
```

### Example

```bash
cargo run --package sb-tls --example ech_example --features ech
```

## Limitations

### Current Implementation

- ✅ ECH configuration parsing
- ✅ ClientHello encryption (HPKE)
- ✅ ECH payload construction
- ✅ ECH acceptance verification
- ✅ rustls client-side ECH integration (TLS 1.3 only)
- ⚠️ Server-side ECH and QUIC ECH pending

### rustls 0.23 Compatibility

rustls 0.23+ provides client-side ECH support. This implementation provides:

1. ECH configuration structures
2. HPKE encryption primitives (legacy tests/fixtures)
3. rustls ECH wiring in sb-transport
4. Foundation for QUIC/server-side ECH integration

### Future Work

- [ ] Server-side ECH integration
- [ ] ECH-QUIC alignment for QUIC transport
- [ ] Additional cipher suite support
- [ ] ECH retry configuration handling

## References

- [RFC 9180: HPKE (Hybrid Public Key Encryption)](https://datatracker.ietf.org/doc/html/rfc9180)
- [draft-ietf-tls-esni: TLS Encrypted Client Hello](https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni)
- [sing-box ECH Implementation](https://github.com/SagerNet/sing-box)

## Troubleshooting

### ECH Configuration Invalid

```
Error: Invalid ECH configuration: Invalid config
```

**Solution**: Ensure the ECH config is properly base64-encoded and contains a valid ECHConfigList.

### ECH Not Enabled

```
Error: ECH not enabled
```

**Solution**: Set `enabled: true` in the ECH client configuration.

### No ECH Config List Available

```
Error: No ECH config list available
```

**Solution**: Provide a valid ECH configuration in base64 format.

### Server Rejected ECH

If the server rejects ECH, check:

1. Server supports ECH protocol
2. ECH configuration is current and valid
3. Cipher suites are compatible
4. Public key matches server's key

## Support

For issues or questions:

- Check the [examples](../examples/ech_example.rs)
- Review the [test cases](../src/ech/mod.rs)
- Consult the [design document](../../../.kiro/specs/p0-production-parity/design.md)
