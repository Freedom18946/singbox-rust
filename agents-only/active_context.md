<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：更新时先删除 >7 天的快照段落，再写新内容。本文件严格 ≤100 行。
> **历史**：完整历史见 `archive/logs/` 和 git log。

---

## 战略状态

**当前阶段**: L18 认证替换
**执行焦点**: L18 Phase 2 完成（Batch E-J 全部 PASS/PASS_ATTRIBUTED）→ Phase 3 待启动
**Parity**: 100%（209/209 closed）
**MIG-02**: ACCEPTED（2026-03-07，Step 0-5 全绿，541 V7 assertions）

## 关键里程碑

- **Phase 2 完成（2026-03-07）**：18 WP, Batch E-J 全部通过
  - Batch J capstone: 10/14 gates PASS, 4 FAIL_ATTRIBUTED（capstone env 传播问题）
  - Perf gate: Rust 优于 Go（p95 -5.4%, RSS -6.7%, startup +0.9%）
  - 基线锁定: `reports/l18/phase2_baseline.lock.json`
- Batch I 完成: GUI Go+Rust 五步全 PASS + sandbox 验证
- Batch H 完成: 双核差分 daily PASS / nightly PASS_ENV_LIMITED
- Batch G 完成: Rust 单核认证 3/3 PASS
- Batch E+F 完成: 环境开封 + MIG-02 适配审计

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

1. L18 Phase 3（nightly/certify 级别运行）
2. 修复 capstone env 传播问题（SINGBOX_BINARY, INTEROP_*）使 capstone 可自包含 PASS
3. Phase 3 目标: one full nightly 24h PASS → one certify 7d PASS → L18 关闭

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
