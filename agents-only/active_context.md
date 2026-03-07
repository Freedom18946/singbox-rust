<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：更新时先删除 >7 天的快照段落，再写新内容。本文件严格 ≤100 行。
> **历史**：完整历史见 `archive/logs/` 和 git log。

---

## 战略状态

**当前阶段**: L18 认证替换
**执行焦点**: L18 Phase 2 Batch I 完成 → Batch J（Capstone 首跑与基线锁定）待执行
**Parity**: 100%（209/209 closed）
**MIG-02**: ACCEPTED（2026-03-07，Step 0-5 全绿，541 V7 assertions）

## 关键里程碑

- **Batch I 完成（2026-03-07）**：3 WP 全部 PASS
  - I1: GUI Rust 单核五步全 PASS（capability v2.0.0 ok）
  - I2: GUI 双核对比五步全 PASS（Go/Rust 行为一致，logs_panel 呈现差异已归因）
  - I3: sandbox 不扰民全 PASS（系统代理 byte-level 一致, HOME 隔离, 端口释放, 无 0.0.0.0）
- Batch H 完成（2026-03-07）：双核差分 daily PASS / nightly PASS_ENV_LIMITED
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

1. 执行 L18 Phase 2 Batch J（Capstone 首跑与基线锁定）：J1 daily capstone → J2 perf gate → J3 基线锁定
2. Batch J 依赖 G3+H1+I1（全部已完成）
3. 工作包详见 `planning/L18-PHASE2.md` §8

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
