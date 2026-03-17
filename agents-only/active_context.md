<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护状态（L1-L24 全部 Closed）
**Parity**: 92.9% (52/56) — SV.1 (4 BHVs) 已重分类为 harness-only 并移出分母

## 综合验收（2026-03-17）

**范围**: L22 + L23 + L24 全部已完成任务，共 41 项
**方式**: 8 个并行验收 agent 逐项审查代码 + 全套构建/测试

### 验收结果

| 统计 | 数量 |
|------|------|
| 验收总数 | 41 |
| ✅ PASS | 39 |
| ⚠️ PARTIAL | 2 |
| ❌ FAIL | 0 |

### 2 个 PARTIAL（已知限制，非 bug）

1. **L23-T1 TUN UDP** — macOS 完整实现（NAT 表 + relay + IPv4/IPv6 包构建），Linux/Windows 仍 drop
2. **T1-04 Protocol fuzz** — SS/Trojan/SOCKS5 真实调用，VMess/VLESS 因 `parse_vmess_request()` 为 private 走共享 `parse_ss_addr()`

### 验收期间修复（已提交）

1. `http_client.rs` 3 处 clippy `Error::new(ErrorKind::Other, ...)` → `Error::other(...)`
2. `clash_endpoints_integration.rs` 测试断言 `provider_manager.is_none()` → `.is_some()`（默认初始化变更后测试过时）

### 已知 flaky 测试

- `test_connections_ws_memory_remains_bounded_over_time`：并发执行时全局 tracker race，单跑稳定通过。非产品 bug。

## 构建基线（2026-03-17，综合验收后）

| 构建 | 状态 |
|------|------|
| `cargo check --workspace --all-features --all-targets` | ✅ pass |
| `cargo clippy --workspace --all-features --all-targets -- -D warnings` | ✅ pass |
| `cargo test -p sb-core --lib` | ✅ 509 passed |
| `cargo test -p sb-adapters` | ✅ pass |
| `cargo test -p sb-types` | ✅ 9 passed |
| `cargo test -p sb-api` | ✅ pass（含 clash_endpoints + websocket e2e） |
| `cargo test -p interop-lab` | ✅ 29 passed |
| `cargo doc -p sb-types --no-deps` | ✅ 零 warning |
