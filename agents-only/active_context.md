<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: **L23 — TUN / Sniff 运行时补全** (Closure)
**历史阶段**: L1-L22 + 后 L22 补丁 全部 Closed
**工作区状态**: Tier 1-3 全部完成

## L23 Closure（2026-03-16）

### L23-T7: Redirect IPv6 ✅
- `get_original_dst()` in `redirect.rs` now branches on peer address family
- IPv6: `SOL_IPV6` + `IP6T_SO_ORIGINAL_DST` (=80) + `sockaddr_in6`
- Also fixes tproxy IPv6 (shares `get_original_dst()`)
- **DIV-H-002 → CLOSED**

### DIV-C-002: SOCKS5 UDP default ON ✅
- Changed all defaults from `false` to `true` (Go parity)
- `socks_udp_enabled()`, `run()`, `socks_udp_should_start()` — all `.unwrap_or(true)`
- `bind_udp_from_env_or_any()` binds `0.0.0.0:0` when no explicit config
- Removed `SB_SOCKS_UDP_ENABLE: "1"` from 10 case YAMLs
- **DIV-C-002 → CLOSED**

### Case Promotions ✅
- `p1_clash_api_auth_enforcement` → `kernel_mode: both` (BHV-CP-012..017)
- `p1_gui_group_delay_replay` → `kernel_mode: both` (BHV-CP-005 group variant)

## 构建基线（2026-03-16）

| 构建 | 状态 |
|------|------|
| `cargo check --workspace --all-features --all-targets` | ✅ pass |
| `cargo clippy --workspace --all-features --all-targets -- -D warnings` | ✅ pass |

## 关键文件速查

| 内容 | 路径 |
|------|------|
| Redirect IPv6 | `crates/sb-adapters/src/inbound/redirect.rs` |
| SOCKS5 UDP | `crates/sb-adapters/src/inbound/socks/udp.rs`, `mod.rs` |
| UDP start gate | `app/src/inbound_starter.rs` |
| Go auth config | `labs/interop-lab/configs/go_core_clash_api_auth.json` |
| Golden spec | `labs/interop-lab/docs/dual_kernel_golden_spec.md` |
