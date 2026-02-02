# ECH (Encrypted Client Hello) Implementation

## Overview

This module provides ECH (Encrypted Client Hello) support for singbox-rust, implementing the TLS extension that encrypts the ClientHello message to prevent traffic analysis and SNI-based blocking.

## Current Status

### ✅ Completed (Task 2.1)

1. **Research**: rustls ECH support status
   - rustls 0.23+ provides client-side ECH support (TLS 1.3 only)
   - Runtime handshakes integrate rustls ECH mode
   - Compatible with sing-box ECH configuration format

2. **Module Structure**: Created `crates/sb-tls/src/ech/`
   - `mod.rs`: Main module with error types and enums
   - `config.rs`: ECH configuration structures
   - `parser.rs`: ECHConfigList parsing
   - `hpke.rs`: HPKE encryption primitives

3. **ECH Configuration Structures**:
   - `EchKeypair`: X25519 keypair for HPKE
   - `EchClientConfig`: Client-side ECH configuration
   - `EchServerConfig`: Server-side ECH configuration
   - Base64 encoding/decoding support
   - Validation logic

4. **ECHConfigList Parsing**:
   - Wire format parser for ECHConfigList
   - Support for ECH version 0xfe0d (Draft 13)
   - HPKE cipher suite parsing (KEM, KDF, AEAD)
   - Public key and public name extraction

5. **HPKE Implementation**:
   - `HpkeSender`: Client-side encryption
   - `HpkeContext`: Encryption/decryption context
   - DHKEM(X25519, HKDF-SHA256) key encapsulation
   - HKDF-SHA256 key derivation
   - AES-128-GCM authenticated encryption
   - RFC 9180 compatible (used for legacy tests/fixtures)

6. **Runtime Integration**:
   - rustls ECH client handshake wiring in sb-transport (TLS 1.3 only)
   - ECH acceptance status surfaced via rustls `EchStatus`

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    ECH Module                            │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │   config.rs  │  │  parser.rs   │  │   hpke.rs    │ │
│  │              │  │              │  │              │ │
│  │ - EchKeypair │  │ - ECHConfig  │  │ - HpkeSender │ │
│  │ - ClientCfg  │  │   List       │  │ - HpkeContext│ │
│  │ - ServerCfg  │  │ - Parser     │  │ - DHKEM      │ │
│  │ - Validation │  │ - Wire fmt   │  │ - HKDF       │ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

## Key Components

### 1. Configuration (`config.rs`)

- **EchKeypair**: X25519 keypair management
  - Base64 encoding/decoding
  - Key validation (32 bytes)
  - Compatible with CLI-generated keys

- **EchClientConfig**: Client configuration
  - ECHConfigList (base64 or raw bytes)
  - Post-quantum signature schemes flag
  - Dynamic record sizing options

- **EchServerConfig**: Server configuration
  - Server keypair
  - ECH configuration to advertise

### 2. Parser (`parser.rs`)

- **ECHConfigList**: Parsed configuration list
  - Multiple ECH configurations support
  - Version detection (Draft 13)
  - Public key extraction
  - Cipher suite parsing

- **Wire Format**: RFC-compliant parsing
  - Variable-length structures
  - Big-endian encoding
  - Length-prefixed fields

### 3. HPKE (`hpke.rs`)

- **HpkeSender**: Client-side encryption
  - Ephemeral key generation
  - Shared secret derivation (X25519 DH)
  - Key derivation (HKDF-SHA256)
  - Returns encapsulated key + context

- **HpkeContext**: Encryption context
  - AES-128-GCM AEAD
  - Nonce management (sequence-based)
  - Seal (encrypt) and Open (decrypt) operations

## Supported Algorithms

### Key Encapsulation Mechanism (KEM)
- ✅ DHKEM(X25519, HKDF-SHA256) - 0x0020

### Key Derivation Function (KDF)
- ✅ HKDF-SHA256 - 0x0001

### Authenticated Encryption (AEAD)
- ✅ AES-128-GCM - 0x0001
- ⚠️ AES-256-GCM - 0x0002 (defined, not implemented)
- ⚠️ ChaCha20-Poly1305 - 0x0003 (defined, not implemented)

## Integration with sing-box

### CLI Keypair Generation
Already implemented in `app/src/cli/generate.rs`:
```bash
singbox generate ech-keypair
```

Output format:
```
PrivateKey: <base64>
PublicKey: <base64>
```

### Configuration Format
Compatible with sing-box ECH configuration:
```json
{
  "tls": {
    "enabled": true,
    "ech": {
      "enabled": true,
      "config": "<base64_encoded_ech_config_list>",
      "pq_signature_schemes_enabled": false
    }
  }
}
```

## Next Steps (Future Tasks)

### Task 2.3: QUIC-ECH Alignment
- QUIC transport ECH support
- Different handshake flow handling
- QUIC-specific ECH configuration

### Task 2.4: Server-Side ECH
- ECH key schedule + decryption
- HelloRetryRequest handling
- Retry configs / rejection logic

### Task 2.5: Testing
- E2E tests with packet capture
- Compatibility tests with upstream sing-box

## Testing

Run ECH module tests:
```bash
cargo test -p sb-tls --features ech --lib
```

All tests passing ✅

## References

- [RFC 9180](https://datatracker.ietf.org/doc/html/rfc9180): HPKE (Hybrid Public Key Encryption)
- [draft-ietf-tls-esni](https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni): TLS Encrypted Client Hello
- [sing-box ECH](https://sing-box.sagernet.org/configuration/shared/tls/#ech): Upstream implementation reference

## Dependencies

- `x25519-dalek`: X25519 key exchange
- `ring`: HKDF and AES-GCM
- `sha2`: SHA-256 hashing
- `base64`: Base64 encoding/decoding
- `serde`: Configuration serialization

## Notes

- rustls 0.23+ provides client-side ECH support (TLS 1.3 only)
- Server-side ECH is not yet integrated
- HPKE implementation follows RFC 9180
- Compatible with sing-box configuration format
- Post-quantum algorithms not yet implemented
- `EchConnector::wrap_tls` is a legacy/fixture helper; rustls handles real ECH handshakes
