<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: **L23 — TUN / Sniff 运行时补全**
**历史阶段**: L1-L22 + 后 L22 补丁 全部 Closed
**工作区状态**: Tier 1 全部完成（T3→T2→T1），进入 Tier 2

## L23 Tier 1 完成摘要（2026-03-16）

### T3: TUN sniff override_destination ✅
- `tun/mod.rs` 的 `matches!()` → `if let` 解构 `override_destination`
- sniff 成功后用 `Endpoint::Domain(sniffed_host, port)` 替换原始 IP

### T2: `sniff:true` 自动注入 ✅
- `RouteCtx` 新增 `inbound_sniff` + `inbound_sniff_override`
- `engine.rs::decide()` 开头注入 `Decision::Sniff`（Go parity: `actionSniff()` 前置）
- 全链路 IR → Param → Config → RouteCtx 传递：`sniff_override_destination`
- 涉及: `engine.rs`, `mod.rs(router)`, `ir/mod.rs`, `adapter/mod.rs`, `bridge.rs`, `v2.rs`, `register.rs`, `inbound_starter.rs`, `http.rs`, `socks/mod.rs`, `mixed.rs`, `tun/mod.rs`

### T1: TUN UDP 转发 ✅
- 新文件 `tun/udp.rs`: `UdpNatTable` + `UdpFourTuple` + `spawn_reverse_relay` + `spawn_eviction_task`
- IP/UDP 包构造（IPv4, macOS AF prefix + Linux PI header）、RFC 1071 checksum
- macOS TUN 主循环 UDP 分支：提取完整 payload → `udp_nat.forward()` → outbound relay
- 反向路径: outbound 回包 → 构造 raw IP/UDP → `TunWriter::write_packet()` 写回 TUN
- Linux/Windows UDP 分支仍为 stub（无 TunWriter 基础设施）

## 构建基线（2026-03-16）

| 构建 | 状态 |
|------|------|
| `cargo check --workspace --all-features --all-targets` | ✅ pass |
| `cargo clippy -p sb-adapters --all-features -- -D warnings` | ✅ pass |
| `cargo test -p sb-core --lib` | ✅ 504 passed |
| `cargo test -p sb-adapters --all-features --lib -- tun::udp` | ✅ 2 passed |
| pre-existing: `shutdown_lifecycle.rs:98` clippy `io_other_error` | ⚠️ 不属于 L23 |

## 下一步：L23 Tier 2

| 任务 | 描述 | 状态 |
|------|------|------|
| L23-T4 | Provider 后台更新循环 (DIV-H-003) | pending |
| L23-T5 | Provider 健康检查探针 (DIV-H-004) | pending |

## 关键文件速查

| 内容 | 路径 |
|------|------|
| TUN UDP NAT | `crates/sb-adapters/src/inbound/tun/udp.rs` |
| TUN inbound | `crates/sb-adapters/src/inbound/tun/mod.rs` |
| Router engine | `crates/sb-core/src/router/engine.rs` |
| InboundParam | `crates/sb-core/src/adapter/mod.rs` |
| V2 inbound 解析 | `crates/sb-config/src/validator/v2.rs` |
