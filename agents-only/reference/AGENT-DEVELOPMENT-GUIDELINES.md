# 后续 Agents 开发准则（Durable Guidelines）

> **用途**：将 Rust 规范、维护复盘结论和当前仓库事实固化为后续 agents 的长期开发准则。  
> **适用阶段**：2026-04 maintenance close-out 之后，进入“实际部署收尾验收”准备阶段。  
> **口径**：maintenance / structural-quality / deployment-acceptance prep。**不是 dual-kernel parity completion。**

---

## 1. 权威来源

后续 agents 的判断优先级如下：

1. `AGENTS.md`
2. `agents-only/active_context.md`
3. `agents-only/workpackage_latest.md`
4. 本文档
5. `agents-only/Rust_spec_v2.md`
6. `agents-only/reference/ACCEPTANCE-CRITERIA.md`
7. `agents-only/reference/ARCHITECTURE-SPEC.md`
8. `agents-only/maintenance_recap_2026-04-03.md`
9. `agents-only/mt_audit_01_reconciliation.md`
10. `agents-only/mt_audit_01_full_report.md`

解释：

- `Rust_spec_v2.md` 是长期规则原文。
- `MT-AUDIT-01` 文档给出“当前仓库事实下哪些命中已修、哪些是 future boundary、哪些仍是 non-blocking structural debt”。
- 当规则原文与当前仓库现状需要结合判断时，以“规则原文 + 复扫结论 + 当前源码事实”共同决定，不得只凭旧 prompt。

---

## 2. 当前阶段默认目标

当前阶段的默认目标已经不是继续拆 maintenance 细卡，而是：

- 准备“实际部署的收尾验收”
- 保持当前 maintenance close-out 的稳定状态
- 只在出现真实 blocker、部署验收阻塞或明确的高层 regroup 主题时再开新线

因此：

- 不恢复 `WP-30k` ~ `WP-30as` 式细碎排程
- 不把任何 maintenance / quality work 表述成 parity completion
- 不因为 still-active structural debt 存在，就自动继续开局部修补卡

---

## 3. Rust 规范如何在当前仓库落地

### 3.1 一律长期遵守的规则

以下规则应视为长期有效的开发准则：

- 生产代码禁止新增 `unwrap()` / `expect()` / `panic!()` / `todo!()` / `unimplemented!()` / `unreachable!()`
- 优先使用 `crate::` 绝对路径，不扩大 `super::` 依赖面
- 不随意新增 `pub use` 再导出；只有 facade/compat shell 可明确说明意图后保留
- 禁止新增硬全局可变状态；新的共享状态必须走 owner/context/DI
- 不允许丢弃 `JoinHandle`、跨 `await` 持锁、无主后台任务
- 外部输入边界继续坚持 Raw / Validated / internal typed seam
- 公开 API 文档、`#[must_use]`、`deny_unknown_fields`、Clippy 与边界门禁继续执行

### 3.2 允许保留但必须诚实标注的 future boundary

以下类型的问题，当前仓库已允许以“future boundary”形式存在，但不得伪装成已彻底消失：

- lifecycle-aware compat shell：
  - `logging`
  - `security_metrics`
  - `geoip`
  - `prefetch`
- metrics statics：
  - `sb-metrics` 中 prometheus 风格的 `LazyLock` metric families
- local bootstrap debt：
  - `registry_ext.rs` 中局部 `'static` promotion
- staged private seam：
  - `planned.rs` 继续是 crate-private staged seam
  - 不推进 public `RuntimePlan`
  - 不推进 public `PlannedConfigIR`
  - 不推进 generic query API

### 3.3 仍然算问题，但不是当前 blocker 的结构债

以下类别仍可能被未来命中，但当前默认不单开细卡：

- mega-file bulk
- protocol-specific corner cases
- tun/router/dns/outbound 深层性能与结构债
- boundary assertion script 的 stale targets
- 局部 dev/debug/bin 的独立 bootstrap 差异

处理原则：

- 若没有部署验收阻塞或明确收益，不继续散修
- 若要处理，必须 regroup 成少数高层主题，不再按旧线名拆小卡

---

## 4. 后续 agents 的默认工作流

### 4.1 开工前

必须先完成：

1. 读 `active_context.md`
2. 读 `workpackage_latest.md`
3. 读本文档
4. 读与当前任务直接相关的 inventory / reconciliation 文档
5. 复核 `git status --short --branch`
6. 先看当前源码事实，再判断是否值得开改

### 4.2 开工时

默认采用：

- owner-first
- query/snapshot-first
- smallest sufficient write-set
- tests first or tests with change
- self-verify
- self-review
- 更新 `agents-only`
- commit 并 push `main`

### 4.3 发现问题时的分类

所有新发现都先分成三类：

1. `Resolved`
2. `Still Active`
3. `Reduced to Future Boundary`

禁止：

- 把 future boundary 直接写成“已彻底修复”
- 把 still-active structural debt 自动写成“当前 blocker”
- 因为有 grep 命中就自动开卡，不看 blast radius 和当前阶段目标

---

## 5. 当前阶段哪些事不该再做

- 不重开旧 maintenance 线
- 不继续发散 `metrics/logging/admin_debug` 小尾巴修补
- 不把 `planned.rs` 当作默认继续推进的主线
- 不因为 audit 仍有 partial clearance 就宣称“问题还很多，需要继续大量拆卡”
- 不恢复 `.github/workflows/*`

---

## 6. 若未来继续开新线，允许的高层主题

当前只建议在以下主题里择一推进，并且必须证明有真实收益：

1. `runtime / control-plane / observability convergence`
2. `router / dns / tun / outbound convergence`
3. `deployment acceptance close-out`

条件性主题：

- `planned/private seam consumer gate`
  只有在真实稳定 consumer 出现时才允许重新评估

---

## 7. 当前阶段的最终判断

对后续 agents 而言，当前最重要的认识是：

- 仓库已经完成一轮大规模 maintenance close-out
- 当前没有新的最前置 blocker
- 默认动作应从“继续拆 maintenance 卡”切换为“准备部署收尾验收”
- 所有后续改动都应先问一句：
  - 这件事是否真的阻塞部署验收？
  - 如果不阻塞，是否值得作为高层 regroup 主题推进？

若答案都是否定的，就不应继续开卡。

