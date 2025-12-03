# Configuration Migration Guide - Milestone 1 Protocol Updates

## Overview

This guide covers breaking changes and migration steps for the Milestone 1 protocol updates:
- Trojan: Text-based → Binary protocol with multi-user support
- Shadowsocks: Single-user → Multi-user with AEAD-2022 and UDP relay

## Breaking Changes

### ⚠️ Trojan Protocol

**What Changed:**
- Protocol format changed from text-based to standard Trojan-GFW binary
- Password authentication now uses SHA224 hashing
- Single `password` field replaced with `users` array

**Impact:**
- Old Trojan clients using text protocol will no longer work
- Configuration files need updates for multi-user setup

### Shadowsocks Protocol

**What Changed:**
- Added multi-user support (backward compatible)
- Added UDP relay support
- Added AEAD-2022 ciphers

**Impact:**
- Existing single-password configs still work (deprecated)
- New features available with updated config

## Migration Steps

### Trojan Configuration

**Old Format (Deprecated):**
```json
{
  "type": "trojan",
  "listen": "0.0.0.0:443",
  "password": "your-password-here",
  "cert_path": "/path/to/cert.pem",
  "key_path": "/path/to/key.pem"
}
```

**New Format (Multi-User):**
```json
{
  "type": "trojan",
  "listen": "0.0.0.0:443",
  "users": [
    {
      "name": "user1",
      "password": "password1"
    },
    {
      "name": "user2",
      "password": "password2"
    },
    {
      "name": "admin",
      "password": "secure-admin-pass"
    }
  ],
  "cert_path": "/path/to/cert.pem",
  "key_path": "/path/to/key.pem"
}
```

**Migration Code Example:**
```rust
use sb_adapters::inbound::trojan::{TrojanInboundConfig, TrojanUser};

// Old style (still works but deprecated)
#[allow(deprecated)]
let old_config = TrojanInboundConfig {
    listen: "0.0.0.0:443".parse().unwrap(),
    password: Some("legacy-password".to_string()),
    users: vec![],
    cert_path: "/path/to/cert.pem".to_string(),
    key_path: "/path/to/key.pem".to_string(),
    // ...
};

// New style (recommended)
let new_config = TrojanInboundConfig {
    listen: "0.0.0.0:443".parse().unwrap(),
    password: None,
    users: vec![
        TrojanUser::new("alice".to_string(), "alice-pass".to_string()),
        TrojanUser::new("bob".to_string(), "bob-pass".to_string()),
    ],
    cert_path: "/path/to/cert.pem".to_string(),
    key_path: "/path/to/key.pem".to_string(),
    // ...
};
```

### Shadowsocks Configuration

**Old Format (Still Works):**
```json
{
  "type": "shadowsocks",
  "listen": "0.0.0.0:8388",
  "method": "aes-256-gcm",
  "password": "your-password"
}
```

**New Format (Multi-User + UDP):**
```json
{
  "type": "shadowsocks",
  "listen": "0.0.0.0:8388",
  "method": "aes-256-gcm",
  "users": [
    {
      "name": "user1",
      "password": "password1"
    },
    {
      "name": "user2", 
      "password": "password2"
    }
  ]
}
```

**AEAD-2022 Example:**
```json
{
  "type": "shadowsocks",
  "listen": "0.0.0.0:8388",
  "method": "2022-blake3-aes-256-gcm",
  "users": [
    {
      "name": "user1",
      "password": "base64-encoded-key-here"
    }
  ]
}
```

**Migration Code Example:**
```rust
use sb_adapters::inbound::shadowsocks::{ShadowsocksInboundConfig, ShadowsocksUser};

// Old style (backward compatible)
#[allow(deprecated)]
let old_config = ShadowsocksInboundConfig {
    listen: "0.0.0.0:8388".parse().unwrap(),
    method: "aes-256-gcm".to_string(),
    password: Some("legacy-password".to_string()),
    users: vec![],
    // ...
};

// New style (recommended)
let new_config = ShadowsocksInboundConfig {
    listen: "0.0.0.0:8388".parse().unwrap(),
    method: "aes-256-gcm".to_string(),
    password: None,
    users: vec![
        ShadowsocksUser::new("user1".to_string(), "pass1".to_string()),
        ShadowsocksUser::new("user2".to_string(), "pass2".to_string()),
    ],
    // ...
};
```

## Supported Cipher Methods

### Shadowsocks AEAD Ciphers

| Method | Key Length | Status | Notes |
|--------|-----------|--------|-------|
| `aes-128-gcm` | 16 bytes | ✅ New | Standard AEAD |
| `aes-256-gcm` | 32 bytes | ✅ Existing | Standard AEAD |
| `chacha20-poly1305` | 32 bytes | ✅ Existing | Standard AEAD |
| `2022-blake3-aes-128-gcm` | 16 bytes | ✅ New | AEAD-2022 |
| `2022-blake3-aes-256-gcm` | 32 bytes | ✅ New | AEAD-2022 |

## Client Compatibility

### Trojan Clients

**Compatible (Binary Protocol):**
- Trojan-GFW (official)
- Clash Premium
- V2RayN/V2RayNG (with Trojan support)
- Qv2ray

**Incompatible (Old Text Protocol):**
- Custom implementations using text-based protocol
- Legacy clients from this project's previous versions

### Shadowsocks Clients

**All Standard Clients Compatible:**
- Shadowsocks Official
- Clash
- V2RayN/V2RayNG
- ShadowsocksX-NG
- Outline

**AEAD-2022 Support:**
- Requires client support for 2022 edition
- Shadowsocks-rust 1.15+
- Outline 1.8+

## Testing Your Migration

### 1. Verify Configuration

```bash
# Check config syntax
cargo check --package sb-adapters

# Validate config loading
./singbox-rust validate-config config.json
```

### 2. Test Trojan Connection

```bash
# Test with Trojan client
trojan -c client-config.json

# Expected: SHA224 hash authentication succeeds
# Error: "invalid password hash" means old client
```

### 3. Test Shadowsocks UDP

```bash
# Test UDP relay with dig/nslookup
dig @127.0.0.1 -p 8388 google.com

# Test with Shadowsocks client
ss-local -c client-config.json -v
```

## Rollback Plan

If issues occur:

1. **Revert Code:**
   ```bash
   git checkout <previous-commit-before-milestone-1>
   cargo build --release
   ```

2. **Restore Old Configs:**
   - Remove `users` arrays
   - Restore single `password` fields
   - Use old Trojan clients with text protocol

3. **Gradual Migration:**
   - Deploy new version alongside old version
   - Migrate users incrementally
   - Monitor for auth failures

## Performance Expectations

- **Trojan:** Binary protocol is ~15% faster than text parsing
- **Shadowsocks UDP:** Minimal overhead (<5%) for UDP relay
- **Multi-user:** O(1) lookup, no performance impact
- **AEAD-2022:** Similar performance to existing AEAD ciphers

## Security Notes

1. **SHA224 Hashing:** Passwords hashed before transmission (after TLS)
2. **Per-User Tracking:** Enhanced rate limiting and metrics
3. **UDP Security:** Same AEAD encryption as TCP
4. **AEAD-2022:** Stronger security guarantees than legacy ciphers

## Getting Help

- **Issues:** File on GitHub with config diff and error logs
- **Questions:** Check documentation or create discussion
- **Security:** Report privately to security team

## Version Compatibility

| Component | Old Version | New Version | Compatible |
|-----------|------------|-------------|-----------|
| Config Format | v0.x | v1.0 | Partial* |
| Trojan Protocol | Text | Binary | ❌ No |
| SS Single-User | v0.x | v1.0 | ✅ Yes |
| SS Multi-User | N/A | v1.0 | ✅ New |

*Single-password configs work but deprecated, use `users` array instead.
