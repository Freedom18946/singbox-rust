<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: L22 dual-kernel parity — **天花板已达 86.7%**
**当前工作包 ID**: `WP-L22`
**Source of Truth**: `labs/interop-lab/docs/dual_kernel_golden_spec.md`
**工作区状态**: Sniff Phase A 已落地，准备提交

## 已提交覆盖（2026-03-15 最新快照）

- `Both-Covered = 52 / 60`，覆盖率 `86.7%`（从 51/60 提升）
- strict both 覆盖：`43 / 60`
- both-case ratio：`36 / 100`

## 本轮新增 (2026-03-15 当前会话)

### Sniff Phase A: Rule-Action Integration（DIV-C-003 关闭）

- **实现**: `Decision::Sniff` 作为非终端规则动作（Go parity: `action: "sniff"`）
- 所有 inbound（socks/http/tun/endpoint）处理 Sniff：
  - 读初始字节 → `sniff_stream()` → 填充 protocol/host → 重新 decide
  - Engine 新增 "already sniffed" 守卫：`protocol.is_some()` 时跳过 Sniff 规则
- 新增文件：`sb-adapters/src/inbound/sniff_util.rs`（SniffedStream 包装器）
- 新增：`skip_sniff()` for SMTP/IMAP/POP3 server-first 端口
- 新增 interop case：`p1_sniff_rule_action_tls`（both-mode）
- **DIV-C-003**: KNOWN-GAP → CLOSED
- **BHV-DP-014**: 注册 both-case

## 天花板分析（更新）

剩余 8 个未覆盖 BHV：

| 类别 | 数量 | BHV IDs | 原因 |
|------|------|---------|------|
| SV 结构性阻塞 | 7 | SV-001~007 | Go 无等价订阅解析 API，双方 provider 端点均为 stub |
| 已确认不可行 | 1 | LC-003 | Go 结构性 fail-fast |

新天花板：**52/60 (86.7%)**（已达，无更多 KNOWN-GAP 可关闭）

## 下一步候选

1. **Sniff Phase B** — QUIC SNI 提取（~600 行，生产价值但不新增 BHV）
2. **宣布 L22 完成** → 归档，开始下一阶段

## 关键文件速查

| 内容 | 路径 |
|------|------|
| 当前工作包 | `agents-only/planning/L22-DUAL-KERNEL-PARITY.md` |
| 当前阶段地图 | `agents-only/workpackage_latest.md` |
| SoT spec | `labs/interop-lab/docs/dual_kernel_golden_spec.md` |
| 兼容矩阵 | `labs/interop-lab/docs/compat_matrix.md` |
| case 积压 | `labs/interop-lab/docs/case_backlog.md` |
