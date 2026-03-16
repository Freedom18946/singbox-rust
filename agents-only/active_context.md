<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: **L23 Closure** → T4 Protocol Suite 推进中
**历史阶段**: L1-L22 + L23 全部 Closed
**Parity**: 92.9% (52/56) — SV.1 (4 BHVs) 已重分类为 harness-only 并移出分母

## SV.1 重分类（2026-03-16）

BHV-SV-001..004（subscription parsing）被确认为 harness 侧功能，非内核行为：
- `subscription_parse` gui_sequence 由 `interop-lab/src/subscription.rs` 执行
- 不启动任何内核进程，不涉及 Go/Rust 行为对比
- 升级到 both-mode 只是同一段代码解析同一份输入两次，diff 必然 clean
- Go 内核完全没有 subscription 解析能力（由 GUI 外部处理）
- 所有 8 个 subscription case 移入 Non-Promotable 列表
- Golden spec S1/S2/S3/S5/S6 + compat_matrix 已更新

## T4 Protocol Suite 侦察（2026-03-16）

关键发现：
- `p2_trojan_dual_dataplane_local` + `p2_shadowsocks_dual_dataplane_local` **已存在且为 both-mode**
- Go 完整支持 trojan/ss/vless/vmess inbound + outbound
- Rust 完整支持所有四种协议 inbound + outbound
- Harness 已有 `TrojanInbound` + `ShadowsocksInbound` upstream kinds
- **缺 `VlessInbound` + `VmessInbound`** upstream kinds（需加到 case_spec.rs + upstream.rs）
- 缺 VLESS/VMess 双核 config 和 case YAML

## 构建基线（2026-03-16）

| 构建 | 状态 |
|------|------|
| `cargo check --workspace --all-features --all-targets` | ✅ pass |
| `cargo clippy --workspace --all-features --all-targets -- -D warnings` | ✅ pass |
