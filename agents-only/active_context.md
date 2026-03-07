<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：更新时先删除 >7 天的快照段落，再写新内容。本文件严格 ≤100 行。
> **历史**：完整历史见 `archive/logs/` 和 git log。

---

## 战略状态

**当前阶段**: L18 认证替换
**执行焦点**: L18 Phase 2 Batch H 完成 → Batch I（GUI 替换首跑）待执行
**Parity**: 100%（209/209 closed）
**MIG-02**: ACCEPTED（2026-03-07，Step 0-5 全绿，541 V7 assertions）

## 关键里程碑

- **Batch H 完成（2026-03-07）**：3 WP 全部 PASS
  - H1: daily 双核差分 5/5 PASS, run_fail=0, diff_fail=0
  - H2: 差分归因 — 零 MIG-02 回归；Phase 1 Go 快照为空致基线无效，Phase 2 为首次有效双核基线
  - H3: nightly 5/6 PASS, 1 P2 soak case ENV_LIMITED（binary path mismatch）
  - 关键发现: 需设 INTEROP_*_API_BASE/SECRET 环境变量供 case 定位内核
- Batch G 完成（2026-03-07）：Rust 单核认证 3/3 PASS
- Batch E+F 完成（2026-03-07）：环境开封 + MIG-02 适配审计

## 当前构建状态

| 构建 | 状态 |
|------|------|
| `cargo check --workspace` | ✅ |
| `cargo clippy --workspace --all-features --all-targets -- -D warnings` | ✅ |
| `cargo test --workspace` | ✅ (1 pre-existing flake: upstream_auth) |
| `cargo test -p interop-lab` | ✅ 27 passed |
| `check-boundaries.sh` | ✅ exit 0 (541 assertions) |
| Go kernel (`with_clash_api`) | ✅ 18MB arm64 |
| GUI.for.SingBox (wails v2.11.0) | ✅ 13MB arm64 |

## 下一步

1. 执行 L18 Phase 2 Batch I（GUI 替换首跑）：I1 GUI Rust 单核 → I2 GUI 双核 → I3 sandbox 验证
2. Batch I 依赖 H1（已完成）
3. 所有双核相关工作 **必须** 引用 `dual_kernel_golden_spec.md`（S2-S6）
4. 工作包详见 `planning/L18-PHASE2.md` §7

## 关键文件速查

| 内容 | 路径 |
|------|------|
| **双核黄金基准（必读）** | **`labs/interop-lab/docs/dual_kernel_golden_spec.md`** |
| L18 Phase 2 工作包 | `agents-only/planning/L18-PHASE2.md` |
| Go/GUI/API 参考 | `scripts/l18/REFERENCE.md` |
| 边界检查脚本 | `agents-only/06-scripts/check-boundaries.sh` |
| Parity 矩阵 | `agents-only/reference/GO_PARITY_MATRIX.md` |
| 经验模式 | `agents-only/memory/LEARNED-PATTERNS.md` |
| 踩坑记录 | `agents-only/memory/TROUBLESHOOTING.md` |
| 流水帐日志 | `agents-only/log.md`（C-tier，持续写入） |
