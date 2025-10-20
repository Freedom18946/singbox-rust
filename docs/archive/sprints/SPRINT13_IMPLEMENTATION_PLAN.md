# Sprint 13 Implementation Plan - Protocol Adapter V2Ray Transport Integration

**Status**: In Progress
**Date**: 2025-10-11
**Sprint Goal**: Integrate V2Ray transports (WebSocket, gRPC, HTTPUpgrade) into VMess, VLESS, and Trojan protocol adapters

## Completed Work ✅

### 1. Transport Layer Abstraction
- ✅ Created `crates/sb-adapters/src/transport_config.rs`
- ✅ Defined `TransportConfig` enum with support for:
  - TCP (default)
  - WebSocket (`WebSocketTransportConfig`)
  - gRPC (`GrpcTransportConfig`)
  - HTTPUpgrade (`HttpUpgradeTransportConfig`)
- ✅ Implemented `create_dialer()` method with proper feature gates
- ✅ Implemented `create_dialer_with_layers()` for TLS and Multiplex chaining
- ✅ Added to `sb-adapters/src/lib.rs` and exported

### 2. Architecture Analysis
- ✅ Analyzed current VMess adapter implementation (`vmess.rs`)
- Current flow: `VMess → TcpDialer (hardcoded) → [Optional TLS] → [Optional Multiplex]`
- Target flow: `VMess → Transport (TCP/WS/gRPC/HTTP) → [Optional TLS] → [Optional Multiplex]`

## Remaining Work 🔄

### 3. Refactor Protocol Adapters

#### VMess Adapter (`crates/sb-adapters/src/outbound/vmess.rs`)
**Changes needed:**
1. Add `transport: TransportConfig` field to `VmessConfig` (line 90-107)
2. Replace hardcoded `TcpDialer` usage in `create_connection()` (line 312-373)
   - Remove line 158: `let tcp_dialer = Box::new(sb_transport::TcpDialer)`
   - Remove line 337-352: Direct TCP connection code
   - Use `self.config.transport.create_dialer_with_layers()` instead
3. Update Multiplex integration to work with transport layer
4. Keep TLS wrapping logic (already correct)

**Estimated effort**: 1-2 hours

#### VLESS Adapter (`crates/sb-adapters/src/outbound/vless.rs`)
**Changes needed** (similar to VMess):
1. Add `transport: TransportConfig` field to `VlessConfig`
2. Refactor connection creation to use transport layer
3. Update Multiplex integration

**Estimated effort**: 1 hour

#### Trojan Adapter (`crates/sb-adapters/src/outbound/trojan.rs`)
**Changes needed** (similar to VMess):
1. Add `transport: TransportConfig` field to `TrojanConfig`
2. Refactor connection creation to use transport layer
3. Update Multiplex integration

**Estimated effort**: 1 hour

### 4. Configuration Parsing

**File**: `crates/sb-config/src/` (config parsing modules)

**Changes needed:**
1. Add transport field parsing for VMess/VLESS/Trojan configs
2. Support JSON structure:
   ```json
   {
     "type": "vmess",
     "transport": {
       "type": "websocket",
       "path": "/ws",
       "headers": {...}
     }
   }
   ```
3. Update schema validation

**Estimated effort**: 2-3 hours

### 5. E2E Tests

#### VMess + WebSocket Test
**File**: Create `crates/sb-adapters/tests/vmess_websocket_e2e.rs`

**Test scenarios:**
1. VMess over WebSocket basic connection
2. VMess over WebSocket with TLS
3. VMess over WebSocket with Multiplex
4. Large data transfer test

**Estimated effort**: 2 hours

#### VLESS + gRPC Test
**File**: Create `crates/sb-adapters/tests/vless_grpc_e2e.rs`

**Test scenarios:**
1. VLESS over gRPC basic connection
2. VLESS over gRPC with TLS
3. Bidirectional streaming test
4. Connection pooling test

**Estimated effort**: 2 hours

#### Trojan + HTTPUpgrade Test
**File**: Create `crates/sb-adapters/tests/trojan_httpupgrade_e2e.rs`

**Test scenarios:**
1. Trojan over HTTPUpgrade basic connection
2. Trojan over HTTPUpgrade with TLS (mandatory for Trojan)
3. Performance comparison with direct TCP

**Estimated effort**: 2 hours

### 6. Feature Flags

**File**: `crates/sb-adapters/Cargo.toml`

**Changes needed:**
1. Add transport feature dependencies:
   ```toml
   adapter-vmess = ["dep:sb-transport", "sb-transport/transport_ws"]
   adapter-vless = ["dep:sb-transport", "sb-transport/transport_grpc"]
   adapter-trojan = ["dep:sb-transport", "sb-transport/transport_httpupgrade"]
   ```
2. Ensure all three adapters can enable all transports when needed

**Estimated effort**: 30 minutes

### 7. Documentation

**Files to update:**
- `GO_PARITY_MATRIX.md` - Note protocol adapter transport support
- `NEXT_STEPS.md` - Mark Sprint 13 completion
- Add configuration examples in `docs/examples/`

**Estimated effort**: 1 hour

## Total Estimated Effort: 12-15 hours

## Implementation Priority

1. **High Priority** (Sprint 13 Core):
   - Refactor VMess adapter ⭐
   - Add VMess+WebSocket E2E test
   - Update configuration parsing for VMess

2. **Medium Priority** (Sprint 13 Extension):
   - Refactor VLESS adapter
   - Add VLESS+gRPC E2E test
   - Refactor Trojan adapter

3. **Low Priority** (Sprint 14+):
   - Trojan+HTTPUpgrade E2E test
   - Advanced transport combination tests
   - Performance benchmarks

## Success Criteria

✅ Sprint 13 is complete when:
- [ ] All three adapters (VMess, VLESS, Trojan) support `TransportConfig`
- [ ] At least 2 E2E tests pass (VMess+WebSocket, VLESS+gRPC)
- [ ] Configuration parsing works for transport selection
- [ ] Documentation updated with examples
- [ ] Feature flags properly configured
- [ ] GO_PARITY_MATRIX.md reflects protocol adapter transport support

## Known Challenges

1. **Backward Compatibility**: Need to ensure existing configs with direct TCP still work
2. **Feature Gate Complexity**: Multiple transport features need careful coordination
3. **Testing Infrastructure**: E2E tests require both client and server components
4. **TLS + Transport Layering**: Order matters (Transport → TLS or TLS → Transport)

## Next Immediate Steps

Run these commands to start implementation:

```bash
# 1. Start with VMess adapter refactoring
code crates/sb-adapters/src/outbound/vmess.rs

# 2. Update VmessConfig structure (add transport field)
# 3. Refactor create_connection() method
# 4. Test compilation:
cargo build --package sb-adapters --features adapter-vmess

# 5. Create E2E test
cargo new --lib crates/sb-adapters/tests/vmess_websocket_e2e.rs
```

## References

- Transport implementations: `crates/sb-transport/src/{websocket,grpc,httpupgrade}.rs`
- Transport config: `crates/sb-adapters/src/transport_config.rs`
- Current VMess impl: `crates/sb-adapters/src/outbound/vmess.rs:312-373`
- Sprint 12 report: `NEXT_STEPS.md:432-476`
