<!-- tier: B -->
# MIG-03 WP05 — 按覆盖矩阵把缺口语义补进 sb-adapters

Status: PLANNED
Priority: P0
Depends on: WP02（正典契约已落地）、WP04（矩阵已定稿且 SCAFFOLD-ONLY 项已按 D9 判定完毕）
Blocks: WP06

Primary evidence:

- `agents-only/mig03/mig03_wp04_coverage_matrix.md`（本包唯一施工单）。
- adapters 侧目标文件：`crates/sb-adapters/src/outbound/*`、`inbound/*`。

## Goal

把 WP04 矩阵中全部 `GAP` 项和按 D9 判为"移植"的 `SCAFFOLD-ONLY` 项实现进
sb-adapters，使每个 scaffold 协议达到 `ADAPTERS-COVERS` 判定，为 WP06 的
删除扫清语义障碍。

## Current Gap

以矩阵为准。（立项时可预期的典型缺口：scaffold inbound 与
`routing::engine` 的直连集成、UDP 会话语义、认证边界情况、metrics 标签对齐、
env 变量驱动的行为开关。）

## Non-goals

- 不删任何 scaffold 代码（WP06）。
- 不改 bridge 的回退逻辑（WP06）。
- 矩阵之外的"顺手增强"一律不做。

## Task Split

1. **施工排序**：按矩阵 GAP 数量从少到多排列协议，先易后难，逐协议独立提交。
2. **逐 GAP 实现**：每个 GAP 项对应：
   - adapters 侧实现（实现正典契约，不得引入对 scaffold 模块的新依赖）；
   - 一条以上锁定该语义的测试（单测或集成测；语义源自 scaffold 的，测试断言
     要与 scaffold 现行为逐字节/逐字段对齐）；
   - 矩阵中该行判定翻转为 `ADAPTERS-COVERS` 并附 commit 引用。
3. **metrics 对齐**：矩阵标记的打点差异按"以现有 Prometheus 面板消费的名称为准"
   原则对齐；如两套名称都被消费，登记进包尾"发现移交"交 WP14 统一。
4. **测试移植**：WP04 盘点的"需移植测试"逐个移到 adapters 侧并确认通过。
5. **半共享结构解耦**：矩阵标注的共享代码（如 `UpSocksSession`）在本包完成
   归属迁移（建议迁入 sb-adapters 或独立模块），并修好 sb-core 侧引用——
   这是 WP06 删除的前置。

## Acceptance

- [ ] 矩阵中 GAP 项清零；每行翻转都有 commit 引用与测试锚点。
- [ ] 按 D9 判为 DROP 的 SCAFFOLD-ONLY 项在矩阵中标记 `DROPPED-BY-DECISION`，
      并确认没有测试仍在锁定该行为；判为 Rust-only 扩展的项已挂 feature 且
      默认构建不启用。
- [ ] `crates/sb-adapters/src/inbound/socks/udp.rs` 等交叉依赖点不再引用
      `sb_core::outbound::*` scaffold 符号。
- [ ] `cargo test -p sb-adapters` 全绿；新增测试均可单独复跑。
- [ ] 全局验收门禁五连全绿。
- [ ] 双核差分：矩阵涉及协议的 interop case 无新增差分（S4 归因）。

## 验证命令

```bash
cargo fmt --all -- --check
cargo check --workspace --all-features
cargo clippy -p sb-adapters --all-targets --all-features
cargo test -p sb-adapters
make boundaries
git diff --check
grep -rn "sb_core::outbound::" crates/sb-adapters/src --include='*.rs'   # 目标：仅剩 WP07 范围的 hysteria/quic 引用
```

## Risks / known traps

- "补齐语义"最容易发生的事故是把 scaffold 的 bug 也当语义移植——按 D10：
  Go 内核行为是最高仲裁，与 Go 一致则保留、相悖则修正并在矩阵记录；
  仅当 Go 侧行为无法确证时才按 D18 升级。
- scaffold inbound 直连 `routing::engine::Engine`，adapters inbound 走
  `AdapterInboundContext`——集成面不同导致 sniff/DNS 行为可能有隐性差异，
  这类 GAP 必须用端到端测试锁（起 inbound → 发请求 → 断言路由决策），
  不能只靠单测。
- 本包与 WP03 都会碰 adapters 的 trait impl 行——若并行，按文件粒度协调，
  冲突时 WP05 让行。

## 发现移交

（执行时填写。）
