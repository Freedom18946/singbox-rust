# Adapter Architecture Issues (2025-11-11)

## Overview
During WS-E Task 5 implementation (adapter path testing), multiple architectural mismatches were discovered between the IR (config), core, and adapter layers. While commit b856ff2 claimed to "fix(adapters): resolve trait architecture mismatch for 4 encrypted protocol outbounds", significant issues remain.

## Critical Issues

### 1. OutboundIR Field Mismatches

**Problem**: `sb_config::ir::OutboundIR` is missing protocol-specific fields that adapters expect.

**Missing Fields**:
```rust
// Expected by VMess builder (register.rs:363-367)
pub security: Option<String>,      // ✗ Missing in OutboundIR
pub alter_id: Option<u8>,          // ✗ Missing in OutboundIR

// Expected by Shadowsocks builder
pub method: Option<String>,        // ✗ Missing in OutboundIR
pub plugin: Option<String>,        // ✗ Missing in OutboundIR
pub plugin_opts: Option<String>,   // ✗ Missing in OutboundIR

// Expected by VLESS builder
pub encryption: Option<String>,    // ✗ Missing in OutboundIR
```

**Impact**: Cannot instantiate VMess/Shadowsocks outbounds via adapter path.

**Files affected**:
- `crates/sb-config/src/ir/mod.rs` (OutboundIR definition)
- `crates/sb-adapters/src/register.rs` (builders)

**Fix required**: Extend OutboundIR with protocol-specific fields, following the pattern used for InboundIR v2 (completed in Task 3).

---

### 2. Core Config Struct Field Mismatches

**Problem**: Adapter builders try to set fields that don't exist in core config structs.

**Shadowsocks** (`sb_core::outbound::shadowsocks::ShadowsocksConfig`):
```rust
// Tried to set (register.rs)
method: ir.method.clone(),         // ✗ Field doesn't exist
plugin: ir.plugin.clone(),         // ✗ Field doesn't exist
plugin_opts: ir.plugin_opts.clone(), // ✗ Field doesn't exist
```

**Trojan** (`sb_core::outbound::trojan::TrojanConfig`):
```rust
// Tried to set (register.rs)
tls_ca_paths: ir.tls_ca_paths.clone(), // ✗ Field doesn't exist
tls_ca_pem: ir.tls_ca_pem.clone(),     // ✗ Field doesn't exist
```

**Impact**: Cannot create Shadowsocks/Trojan outbound instances.

**Files affected**:
- `crates/sb-core/src/outbound/shadowsocks.rs`
- `crates/sb-core/src/outbound/trojan.rs`
- `crates/sb-adapters/src/register.rs`

**Fix required**: Align core config structs with IR fields, or update builders to use correct field names.

---

### 3. HeaderEntry Field Access Issues

**Problem**: `HeaderEntry` struct fields are private or don't exist.

**Error**:
```rust
// In register.rs:378, 380, 468, 470
ir.grpc_metadata.iter().map(|e| (e.key.clone(), e.value.clone())) // ✗ no field `key`
```

**Impact**: Cannot map grpc_metadata and http_upgrade_headers.

**Files affected**:
- `crates/sb-config/src/ir/mod.rs` (HeaderEntry definition)
- `crates/sb-adapters/src/register.rs`

**Fix required**: Either:
1. Make HeaderEntry fields public
2. Add accessor methods
3. Change HeaderEntry to a tuple struct: `pub struct HeaderEntry(pub String, pub String);`

---

### 4. UDP Factory Trait Implementation

**Problem**: Builders incorrectly claim UDP factory support for protocols that don't implement `UdpOutboundFactory`.

**Correct implementation status**:
```rust
// ✓ Implements UdpOutboundFactory
- Hysteria2Outbound
- TuicOutbound

// ✗ Does NOT implement UdpOutboundFactory (FIXED in d19cbc9)
- VmessOutbound      // Fixed: return None for UDP factory
- VlessOutbound      // Fixed: return None for UDP factory
- ShadowsocksOutbound  // Still broken in register.rs
- TrojanOutbound       // Still broken in register.rs
```

**Files affected**:
- `crates/sb-adapters/src/register.rs:195, 275` (Shadowsocks/Trojan builders)

**Fix required**: Change return values to `None` for UDP factory (similar to d19cbc9 fix for VMess/VLESS).

---

### 5. Type Mismatches

**Problem**: IR and core configs use incompatible types for the same semantic field.

**tls_alpn**:
```rust
// In InboundIR (line 338)
pub tls_alpn: Option<Vec<String>>,

// In OutboundIR (line 427)
pub tls_alpn: Option<String>,  // Expects comma-separated string

// In core configs (VMess/VLESS)
pub tls_alpn: Option<Vec<String>>,
```

**Fix applied** (d19cbc9): Convert string to vec in builder:
```rust
tls_alpn: ir.tls_alpn.clone().map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
```

**Better fix**: Make OutboundIR.tls_alpn consistent with InboundIR (`Option<Vec<String>>`).

---

## Impact on WS-E Task 5

**Blocked subtasks**:
- ✗ Cannot write comprehensive adapter instantiation tests for VMess/Shadowsocks/Trojan/VLESS outbounds
- ✗ Cannot verify adapter path (vs scaffold path) for encrypted protocols
- ✗ Cannot test feature gate combinations for these adapters

**Workaround**:
- Test only working adapters: HTTP, SOCKS, Mixed, TUN, TUIC, Hysteria2
- Document broken adapters as known issues
- Proceed with other WS-E subtasks (CLI integration, hot reload, comparison scripts)

---

## Recommended Fix Priority

1. **P0 - OutboundIR extension** (blocks all outbound adapters)
   - Add missing protocol-specific fields following InboundIR v2 pattern
   - Reference: Task 3 completion (commit 9504f12)
   - Fields to add: security, alter_id, method, plugin, plugin_opts, encryption, tls_ca_paths, tls_ca_pem

2. **P0 - HeaderEntry accessibility** (blocks transport config)
   - Make fields public or add accessors
   - Affects grpc_metadata, http_upgrade_headers mapping

3. **P1 - Core config alignment** (blocks Shadowsocks/Trojan)
   - Update ShadowsocksConfig to accept method/plugin/plugin_opts
   - Update TrojanConfig to accept tls_ca_paths/tls_ca_pem
   - Or update builders to use correct field names

4. **P1 - Type consistency** (tech debt)
   - Standardize tls_alpn as `Option<Vec<String>>` across IR/core
   - Remove string splitting workaround

5. **P2 - UDP factory claims** (minor)
   - Fix Shadowsocks/Trojan builders to return None for UDP factory

---

## Testing Strategy

### Phase 1: Test Working Adapters (Current)
```rust
// Inbounds that work
- HTTP, SOCKS, Mixed, TUN (verified in existing tests)

// Outbounds that work
- TUIC, Hysteria2 (via adapter path)
- HTTP, SOCKS, Direct, Block, Selector, URLTest (via scaffold)
```

### Phase 2: After OutboundIR Extension
```rust
// Enable testing for
- VMess, VLESS, Shadowsocks, Trojan outbounds
- Full adapter instantiation test suite
- Feature gate combination matrix
```

### Phase 3: After All Fixes
```rust
// Complete WS-E Task 5
- Comprehensive adapter path tests (10 inbounds, 10 outbounds)
- Hot reload with adapter reconstruction
- Go ↔ Rust CLI comparison with all protocols
```

---

## Files Requiring Changes

### Config Layer (sb-config)
- `crates/sb-config/src/ir/mod.rs`
  - Extend OutboundIR with protocol-specific fields (lines 351-430)
  - Fix HeaderEntry accessibility
  - Standardize tls_alpn type

### Core Layer (sb-core)
- `crates/sb-core/src/outbound/shadowsocks.rs`
  - Add method/plugin/plugin_opts to ShadowsocksConfig
- `crates/sb-core/src/outbound/trojan.rs`
  - Add tls_ca_paths/tls_ca_pem to TrojanConfig

### Adapter Layer (sb-adapters)
- `crates/sb-adapters/src/register.rs`
  - Fix Shadowsocks builder (lines ~180-200)
  - Fix Trojan builder (lines ~260-280)
  - Update all builders after IR extension

---

## Related Commits

- `b856ff2` - "fix(adapters): resolve trait architecture mismatch" (INCOMPLETE)
- `9504f12` - "feat(config): complete Task 3 - extend Inbound IR v2 fields" (SUCCESS - use as pattern)
- `d19cbc9` - "fix(adapters): resolve adapter registration field mismatches" (PARTIAL FIX)

---

## Next Steps

1. Complete OutboundIR v2 extension (mirror Task 3 approach)
2. Run full adapter instantiation test suite
3. Fix remaining field mismatches incrementally
4. Update GO_PARITY_MATRIX.md with actual working adapter counts
5. Complete WS-E Task 5 with full protocol coverage
