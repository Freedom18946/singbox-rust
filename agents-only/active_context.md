<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 无活跃工作包（L22 已关闭）
**所有历史阶段**: L1-L22 全部 Closed
**工作区状态**: clean，等待新指令

## L22 关闭摘要（2026-03-15）

- **dual-kernel parity**: 52/60 (86.7%)，天花板已达
- **Sniff Phase A**: `Decision::Sniff` 规则动作 + SniffedStream（DIV-C-003 关闭）
- **Sniff Phase B**: QUIC SNI 提取（v1/v2/Draft-29，Go parity 测试全过）
- **16 个 both-case** 新增覆盖（详见 `archive/L22/`）
- **3 个 bug fix**: direct_connect IPv6-first, mixed peek dup, URLTest now()

## 关键文件速查

| 内容 | 路径 |
|------|------|
| 阶段地图 | `agents-only/workpackage_latest.md` |
| L22 归档 | `agents-only/archive/L22/` |
| SoT spec | `labs/interop-lab/docs/dual_kernel_golden_spec.md` |
| 兼容矩阵 | `labs/interop-lab/docs/compat_matrix.md` |
| 经验模式 | `agents-only/memory/LEARNED-PATTERNS.md` |
| 踩坑记录 | `agents-only/memory/TROUBLESHOOTING.md` |
