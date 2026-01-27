# ECH (Encrypted Client Hello) Configuration Guide

## Overview

ECH (Encrypted Client Hello) is a TLS extension that encrypts the ClientHello message to prevent traffic analysis and SNI-based blocking. This guide explains how to configure ECH in singbox-rust outbound connections.

## What is ECH?

ECH encrypts the Server Name Indication (SNI) field in the TLS ClientHello, preventing network observers from seeing which domain you're connecting to. This is particularly useful for:

- Bypassing SNI-based censorship
- Protecting privacy from network observers
- Preventing traffic analysis based on SNI

## How ECH Works

1. **Client Side:**
   - Obtains ECHConfigList (from DNS, config, or other sources)
   - Encrypts ClientHello using server's public key (HPKE)
   - Sends encrypted ClientHello in TLS extension
   - Server decrypts and processes the real ClientHello

2. **Key Components:**
   - DHKEM(X25519, HKDF-SHA256): Key encapsulation mechanism
   - HPKE: Hybrid Public Key Encryption for ClientHello encryption
   - ECHConfigList: Server's ECH configuration (public key, cipher suites, etc.)

## Configuration

### Basic ECH Configuration

```json
{
  "outbounds": [
    {
      "name": "my-outbound",
      "type": "http",
      "server": "proxy.example.com:443",
      "tls": {
        "enabled": true,
        "sni": "proxy.example.com",
        "ech": {
          "enabled": true,
          "config": "base64_encoded_ech_config_list"
        }
      }
    }
  ]
}
```

### ECH Configuration Fields

#### `enabled` (boolean, required)
Enable or disable ECH for this outbound connection.

```json
"ech": {
  "enabled": true
}
```

#### `config` (string, optional)
Base64-encoded ECHConfigList obtained from the server. This is typically retrieved from:
- DNS TXT records (HTTPS/SVCB records)
- Server configuration
- Out-of-band communication

```json
"ech": {
  "enabled": true,
  "config": "AEX+DQBBpAAgACCpEZ..."
}
```

#### `pq_signature_schemes_enabled` (boolean, optional, default: false)
Enable post-quantum signature schemes for enhanced security against quantum computing threats.

```json
"ech": {
  "enabled": true,
  "config": "...",
  "pq_signature_schemes_enabled": true
}
```

#### `dynamic_record_sizing_disabled` (boolean, optional)
Disable dynamic TLS record sizing. This can improve performance in some scenarios but may affect traffic analysis resistance.

```json
"ech": {
  "enabled": true,
  "config": "...",
  "dynamic_record_sizing_disabled": false
}
```

## Supported Outbound Types

ECH can be configured on the following outbound types:

### HTTP Proxy
```json
{
  "type": "http",
  "server": "proxy.example.com:443",
  "tls": {
    "enabled": true,
    "ech": {
      "enabled": true,
      "config": "..."
    }
  }
}
```

### SOCKS5 Proxy
```json
{
  "type": "socks",
  "server": "socks.example.com:1080",
  "tls": {
    "enabled": true,
    "ech": {
      "enabled": true,
      "config": "..."
    }
  }
}
```

### VLESS Protocol
```json
{
  "type": "vless",
  "server": "vless.example.com",
  "port": 443,
  "uuid": "...",
  "tls": {
    "enabled": true,
    "ech": {
      "enabled": true,
      "config": "..."
    }
  }
}
```

### VMess Protocol
```json
{
  "type": "vmess",
  "server": "vmess.example.com:443",
  "uuid": "...",
  "tls": {
    "enabled": true,
    "ech": {
      "enabled": true,
      "config": "..."
    }
  }
}
```

### TUIC Protocol
```json
{
  "type": "tuic",
  "server": "tuic.example.com:443",
  "uuid": "...",
  "password": "...",
  "tls": {
    "enabled": true,
    "ech": {
      "enabled": true,
      "config": "..."
    }
  }
}
```

## Obtaining ECH Configuration

### Method 1: DNS Query
Query the HTTPS/SVCB DNS record for the domain:

```bash
dig +short HTTPS example.com
```

Look for the `ech` parameter in the response.

### Method 2: CLI Tool
Use the singbox-rust CLI to generate ECH keypair:

```bash
singbox-rust generate ech-keypair
```

This generates:
- Private key (for server)
- Public key (for client)
- ECHConfigList (base64 encoded)

### Method 3: Server Configuration
Obtain the ECHConfigList from your server administrator or configuration.

## Complete Example

```json
{
  "schema_version": 2,
  "outbounds": [
    {
      "name": "ech-proxy",
      "type": "http",
      "server": "proxy.example.com:443",
      "username": "user",
      "password": "pass",
      "tls": {
        "enabled": true,
        "sni": "proxy.example.com",
        "alpn": "h2,http/1.1",
        "ech": {
          "enabled": true,
          "config": "AEX+DQBBpAAgACCpEZ...",
          "pq_signature_schemes_enabled": false,
          "dynamic_record_sizing_disabled": false
        }
      }
    }
  ],
  "route": {
    "final": "ech-proxy"
  }
}
```

## Combining ECH with Other TLS Features

### ECH + ALPN
```json
"tls": {
  "enabled": true,
  "sni": "example.com",
  "alpn": "h2,http/1.1",
  "ech": {
    "enabled": true,
    "config": "..."
  }
}
```

### ECH + Custom SNI
```json
"tls": {
  "enabled": true,
  "sni": "custom.example.com",
  "ech": {
    "enabled": true,
    "config": "..."
  }
}
```

## Troubleshooting

### ECH Not Working
1. **Verify ECH is enabled:**
   ```json
   "ech": { "enabled": true }
   ```

2. **Check ECH config is valid:**
   - Ensure the base64 string is correctly formatted
   - Verify it's the correct ECHConfigList for the server

3. **Server support:**
   - Confirm the server supports ECH
   - Check server logs for ECH-related errors

### Invalid ECH Configuration
If you see errors like "Invalid ECH configuration", check:
- The `config` field contains a valid base64-encoded ECHConfigList
- The ECHConfigList matches the server's configuration
- The server's public key hasn't changed

### ECH Handshake Failed
Common causes:
- Mismatched ECH configuration between client and server
- Server doesn't support ECH
- Network interference with ECH extension

## Implementation Status

### Current Status (Sprint 5 - 2025-10-09)
- ✅ ECH configuration structures
- ✅ ECH config parsing and validation
- ✅ ECHConfigList parsing and decoding
- ✅ HPKE encryption primitives (DHKEM-X25519-HKDF-SHA256 + CHACHA20POLY1305)
- ✅ CLI keypair generation (`sing-box generate ech-keypair`)
- ✅ **Runtime handshake integration** - Fully implemented in `crates/sb-tls/src/ech/`
- ✅ **SNI encryption** - Inner ClientHello encryption complete
- ✅ **E2E tests** - Comprehensive testing in `tests/e2e/ech_handshake.rs`

### Implementation Details

The ECH implementation is **production-ready** and includes:

1. **HPKE Encryption Stack**:
   - KEM: DHKEM-X25519-HKDF-SHA256
   - KDF: HKDF-SHA256
   - AEAD: CHACHA20POLY1305
   - Mode: Base mode (mode 0)

2. **ECHConfigList Support**:
   - Base64 decoding and validation
   - Version compatibility checking
   - Cipher suite negotiation
   - Public key extraction

3. **ClientHello Encryption**:
   - Outer ClientHello with public SNI
   - Inner ClientHello with encrypted SNI
   - HPKE encapsulation of inner hello
   - Extension embedding in TLS handshake

4. **Integration**:
   - Works with all TLS-capable outbound protocols (HTTP, SOCKS5, VLESS, VMess, TUIC)
   - Compatible with V2Ray transports (WebSocket, HTTP/2, etc.)
   - Feature-gated via `ech` Cargo feature

### Testing

End-to-end tests validate:
- ECHConfigList parsing
- HPKE encryption/decryption
- SNI privacy preservation
- Handshake success with ECH-enabled servers
- Fallback behavior on ECH rejection

Run tests:
```bash
cargo test --test ech_handshake
cargo test -p sb-tls --features ech
```

### Future Work
- Add ECH-QUIC alignment for QUIC-based protocols
- Implement ECH retry configuration (retry_configs)
- Add ECH acceptance verification for server-side
- Support ECH outer ALPN differentiation
- Add ECH Grease (fake ECH for non-ECH connections)

## Security Considerations

1. **ECH Config Security:**
   - Obtain ECHConfigList from trusted sources
   - Verify ECHConfigList authenticity (e.g., via DNSSEC)
   - Rotate ECH keys regularly

2. **Post-Quantum Security:**
   - Enable `pq_signature_schemes_enabled` for quantum-resistant security
   - Note: This may increase handshake size and latency

3. **Traffic Analysis:**
   - ECH protects SNI but not other traffic patterns
   - Combine with other privacy measures (VPN, Tor, etc.)
   - Consider using obfuscation protocols (REALITY, etc.)

## References

- [RFC 9180: HPKE (Hybrid Public Key Encryption)](https://datatracker.ietf.org/doc/html/rfc9180)
- [draft-ietf-tls-esni: TLS Encrypted Client Hello](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/)
- [Cloudflare ECH Documentation](https://blog.cloudflare.com/encrypted-client-hello/)
- [sing-box ECH Implementation](https://sing-box.sagernet.org/)

## See Also

- [TLS Configuration Guide](TLS.md)
- [REALITY TLS Guide](../../01-user-guide/protocols/reality.md)
- [User Guide](../../01-user-guide/README.md)
