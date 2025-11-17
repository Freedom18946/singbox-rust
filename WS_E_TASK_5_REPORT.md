# WS-E Task 5 Progress Report (2025-11-11)

## Task Overview
**WS-E Task 5: Add adapter path testing** (Priority P1)
- Add e2e tests for TUIC/Hysteria2/DNS outbound (10 种入站 + 8 种出站)
- Verify feature gate combinations
- Add hot reload tests for adapter path
- Create Go ↔ Rust CLI comparison scripts

## Completion Status: 60% (Partial - Blocked by Architecture Issues)

### ✅ Completed (60%)

#### 1. Test Coverage Audit
- **Analyzed 97 integration tests** in `app/tests/`
- **Identified gaps**: No DNS outbound tests, incomplete TUIC/Hysteria2 tests, no adapter instantiation validation
- **Finding**: Existing tests focus on protocol e2e, not adapter registry path

#### 2. Architecture Issue Discovery & Documentation
- **Created ADAPTER_ARCHITECTURE_ISSUES.md** - comprehensive analysis of blocking issues
- **Identified 5 critical problems**:
  1. OutboundIR missing protocol-specific fields (security, alter_id, method, etc.)
  2. Core config struct field mismatches (Shadowsocks/Trojan)
  3. HeaderEntry field accessibility issues
  4. Incorrect UDP factory trait claims
  5. Type inconsistencies (tls_alpn: String vs Vec<String>)
- **Impact**: Cannot instantiate VMess/Shadowsocks/Trojan/VLESS outbounds via adapter path

#### 3. Compilation Error Fixes (Commits: d19cbc9)
- Fixed `io::Error` → `anyhow::Error` conversion in Shadowsocks AEAD UDP
- Made `RunArgs.config_path` public to fix CLI access
- Updated VMess/VLESS builders to match actual Config struct fields
- Fixed `tls_alpn` type mismatch with string split/map conversion
- Fixed `grpc_metadata` and `http_upgrade_headers` mapping
- Removed incorrect UDP factory claims for VMess/VLESS

#### 4. Parity Validation Infrastructure (Commit: 7315a00)
- **Created `scripts/route_explain_parity.sh`**:
  - Automated pass/fail validation for route explain outputs
  - Compares outbound, matched_rule, chain length
  - Supports strict mode and CI mode with GitHub Actions annotations
  - Color-coded output for manual inspection

- **Created `scripts/geodata_parity.sh`**:
  - Validates geoip/geosite query consistency
  - Custom data directory support
  - Same strict/CI modes as route_explain

- **Created `.github/workflows/parity-tests.yml`**:
  - Automated route explain parity tests
  - Geodata parity validation
  - Adapter smoke tests for working adapters
  - Currently disabled (pending Go binary availability in CI)

#### 5. Test Infrastructure Preparation
- Created `app/tests/adapter_instantiation_e2e.rs` (blocked by compilation errors)
- Designed comprehensive test cases for 10 inbounds + 10 outbounds
- Feature gate control validation framework

### ✅ Follow-up Status Update (2025-11-16)

Since this report was written, several of the “Blocked / NOT STARTED” items have been unblocked or completed. Summary of changes:

#### 1. Adapter Instantiation Tests
- OutboundIR v2 fields（VMess security/alter_id、VLESS encryption、Shadowsocks method、Trojan TLS 相关）已补齐，Shadowsocks/Trojan 等 builder 也已与核心配置结构对齐（参见 `crates/sb-config/src/ir/mod.rs`、`crates/sb-adapters/src/register.rs`）。
- 适配器实例化相关测试（包括 CLI/tools 侧）现已可以完整编译并在 CI/本地执行。

#### 2. DNS Outbound E2E Tests
- DNS outbound e2e 覆盖已完成，验证 UDP/TCP/DoT/DoH/DoQ 路径及配置组合（`app/tests/dns_outbound_e2e.rs`），并通过 `app check` 测试完整配置样例。

#### 3. TUIC/Hysteria2 Tests
- Hysteria2：新增基于 `UdpOutboundFactory` 的真实 UDP 会话往返测试（`app/tests/hysteria2_udp_e2e.rs`，在 `net_e2e` 特性 + `SB_E2E_UDP=1` 下可运行），验证 core inbound/outbound 的协同。
- TUIC：保留需要真实 TUIC 服务器的端到端场景为 `#[ignore]` 占位，但针对数据包编码/解码的无网络测试已落地（`app/tests/tuic_outbound_e2e.rs` 的 `packet_tests` 模块），覆盖 IPv4/IPv6/域名等情况。

#### 4. Hot Reload Tests for Adapter Path
- 已新增专门针对 adapter 路径的热重载测试（`app/tests/reload_adapter_path.rs`），验证配置更新后适配器重建及路由行为稳定性。

#### 5. Feature Gate Combination Matrix / CI
- Parity 校验脚本与基础 CI 工作流已存在并可用（route explain、geodata parity 等），但完整的 feature 矩阵和启用后的 Go+Rust 并行测试仍属于后续工作，保持原“部分完成”状态。

整体上，WS‑E Task 5 当前状态接近“完成”，主要剩余工作集中在：  
- 针对启用真实后端（TUIC/Hysteria2/WireGuard 等）的全网络端到端场景（受外部依赖和 CI 环境限制）；  
- 扩展 CI feature 矩阵与 Go/Rust 并行合同测试。  
本报告保留原始 2025‑11‑11 的问题分析与架构建议以供参考，上述段落反映的是 2025‑11‑16 的最新进展。 

## Root Cause Analysis

### Why Task 5 is Blocked

The adapter registration system (commit b856ff2) claimed to "resolve trait architecture mismatch" but actually:
1. Only fixed trait signatures, not config layer
2. Left IR ↔ Core config field mismatches unresolved
3. Didn't extend OutboundIR with protocol-specific fields (unlike InboundIR v2 in Task 3)

**Missing prerequisite**: **OutboundIR v2 Extension** (mirror of Task 3's InboundIR v2)

Task 3 (commit 9504f12) successfully extended InboundIR with protocol-specific fields. Task 5 assumed OutboundIR had the same treatment, but it didn't.

## Recommended Next Steps

### P0 - Unblock Task 5 (1-2 days)
1. **Extend OutboundIR v2** following Task 3 pattern:
   ```rust
   pub struct OutboundIR {
       // ... existing fields ...

       // VMess-specific
       pub security: Option<String>,
       pub alter_id: Option<u8>,

       // Shadowsocks-specific
       pub method: Option<String>,
       pub plugin: Option<String>,
       pub plugin_opts: Option<String>,

       // VLESS-specific
       pub encryption: Option<String>,

       // Trojan-specific
       pub tls_ca_paths: Option<Vec<String>>,
       pub tls_ca_pem: Option<String>,
   }
   ```

2. **Fix HeaderEntry accessibility**:
   ```rust
   pub struct HeaderEntry {
       pub key: String,
       pub value: String,
   }
   ```

3. **Compile and run adapter_instantiation_e2e.rs tests**

### P1 - Complete Task 5 (2-3 days)
4. Add DNS outbound e2e tests
5. Complete TUIC/Hysteria2 tests (remove placeholders)
6. Add hot reload tests for adapter path
7. Extend feature-matrix.yml for adapter combinations
8. Enable parity-tests.yml (after Go binary availability)

### P2 - Core Config Alignment (1 week)
9. Update ShadowsocksConfig/TrojanConfig to accept new fields
10. Standardize tls_alpn type across IR/core
11. Remove remaining type conversion workarounds

## Impact Assessment

### What Works Now
- ✅ Parity validation infrastructure ready
- ✅ Architecture issues documented
- ✅ Compilation errors partially fixed
- ✅ Basic adapters (HTTP/SOCKS/Mixed/TUN) work via adapter path

### What's Broken
- ❌ VMess/VLESS/Shadowsocks/Trojan outbounds cannot be instantiated
- ❌ Adapter instantiation tests don't compile
- ❌ Cannot verify adapter path vs scaffold path for encrypted protocols
- ❌ Feature gate combinations untested for new adapters

### Risk to Go Parity Goal
**MEDIUM**: Current adapter coverage is 53-59% vs Go's 100%. Without Task 5 completion:
- Cannot prove adapters work correctly
- Cannot catch regressions in adapter path
- Cannot validate TUIC/Hysteria2 migrations (Task 2 completion)

## Lessons Learned

1. **Incremental IR extension is critical**: OutboundIR should have been extended immediately after InboundIR v2
2. **Trait fixes ≠ config fixes**: Commit b856ff2's scope was too narrow
3. **Test-first approach reveals issues early**: Attempting tests uncovered 20+ compilation errors
4. **Documentation prevents duplicate work**: ADAPTER_ARCHITECTURE_ISSUES.md will guide future fixes

## Files Modified

### New Files
- `ADAPTER_ARCHITECTURE_ISSUES.md` - comprehensive issue analysis
- `app/tests/adapter_instantiation_e2e.rs` - blocked test suite
- `scripts/route_explain_parity.sh` - automated route parity validation
- `scripts/geodata_parity.sh` - automated geodata parity validation
- `.github/workflows/parity-tests.yml` - CI parity testing workflow

### Modified Files
- `crates/sb-core/src/outbound/ss/aead_udp.rs` - error conversion fix
- `crates/sb-adapters/src/register.rs` - VMess/VLESS/UDP factory fixes
- `app/src/cli/run.rs` - make config_path public

## Conclusion

Task 5 achieved 60% completion with valuable outputs:
1. **Identified and documented** blocking architecture issues
2. **Created infrastructure** for parity validation and CI testing
3. **Partially fixed** compilation errors in adapter registration
4. **Established clear path** to completion via OutboundIR v2 extension

**Blocker**: Missing OutboundIR v2 extension (P0 prerequisite)
**ETA to unblock**: 1-2 days
**ETA to complete Task 5**: 3-5 days after unblock

**Recommendation**: Prioritize OutboundIR v2 extension before continuing with other NEXT_STEPS.md tasks.

---

**Report Date**: 2025-11-11
**Author**: Claude (WS-E Task 5 Implementation)
**Related Commits**: d19cbc9, 97ec89c, 7315a00
