<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：更新时先删除 >7 天的快照段落，再写新内容。本文件严格 ≤100 行。
> **历史**：完整历史见 `archive/logs/` 和 git log。

---

## 战略状态

**当前阶段**: L18 认证替换
**执行焦点**: L18 Phase 2 Batch F 完成 → Batch G（Rust 单核认证首跑）待执行
**Parity**: 100%（209/209 closed）
**MIG-02**: ACCEPTED（2026-03-07，Step 0-5 全绿，541 V7 assertions）

## 关键里程碑

- **Batch F 完成（2026-03-07）**：3 WP 全部 PASS
  - F1: route.final 审计 → 全部 L18/capstone 配置已有显式 route.final
  - F2: Env-var 审计 → 所有 L18_*/INTEROP_* 变量与 MIG-02 后代码兼容
  - F3: 隐式回退影响评估 → 修复 SelectorGroup first-member fallback（Go parity）
- Batch E 完成（2026-03-07）：环境开封，3 WP 全绿
- 双核黄金基准文档创建（2026-03-07）
- MIG-02 大验收 ACCEPTED（2026-03-07）

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

1. 执行 L18 Phase 2 Batch G（Rust 单核认证首跑）：G1 启动+API → G2 interop-lab → G3 workspace+stability
2. Batch G 依赖 E2+F1+F3（已完成）
3. 所有双核相关工作 **必须** 引用 `dual_kernel_golden_spec.md`（S2-S6）
4. 工作包详见 `planning/L18-PHASE2.md` §5

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
