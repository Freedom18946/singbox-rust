<!-- tier: S -->
# 当前上下文（Active Context）
> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。
---
## 战略状态
**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)，以 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 为准
**当前维护线**: `WP-30` 已完成总体验收，进入 archive baseline

## 最近完成（2026-04-02）

### WP-30at：`WP-30k` ~ `WP-30as` maintenance line 总体验收 / 归档收口 — 已完成
- 已先按仓库当前事实重建上下文，再复核 `WP-30k` ~ `WP-30as` 的 owner/facade 收口，确认主要成果都已落在当前代码，而不是只停在文档
- `crates/sb-config/src/ir/mod.rs` 当前为 135 行 compat facade；`crates/sb-config/src/validator/v2/mod.rs` 当前为 49 行 thin facade；shared owner 已分别稳定留在 `ir/*` 与 `validator/v2/*`
- `crates/sb-config/src/ir/planned.rs` 当前稳定停在 crate-private staged seam：`collect_planned_facts` / `validate_with_planned_facts` / `validate_planned_facts`；`Config::validate()` 继续只是 thin entry；当前仍无 public `RuntimePlan` / `PlannedConfigIR` / builder API / generic query API
- `crates/sb-config/src/ir/dns_raw.rs` 与 `crates/sb-config/src/ir/dns.rs` 的 DNS Raw / Validated boundary 已稳定成立；`planned.rs` 继续只做 namespace/reference facts，不接手 DNS runtime semantics
- `app/src/run_engine.rs` 当前为 public facade，active runtime owner 位于 `app/src/run_engine_runtime/*`；`app/src/bootstrap.rs` 当前为 legacy high-level facade，helper/starter owner 位于 `app/src/bootstrap_runtime/*`，first/second pass 与 router text 分别留在 `outbound_builder/*` / `outbound_groups.rs` / `router_text.rs`
- 强制基线已复核并通过：`cargo test -p sb-config --lib`、`cargo clippy -p sb-config --all-features --all-targets -- -D warnings`、`cargo test -p app --lib`、`cargo test -p app`、`cargo clippy -p app --all-features --all-targets -- -D warnings`
- 文档已压缩为 archive 口径：旧的“`cargo test -p app` 失败 / 下一卡继续拆 facade”表述已下线，`WP-30` 不再保留细碎 maintenance 排程
- 新增最小 source pin：`app/tests/wp30ap_baseline_gates.rs` 继续 pin 住 active `run_engine` facade 与 legacy/test-only bootstrap seams 的当前 wiring

## 当前稳定事实
- `WP-30` 这条线是 maintenance archive / stabilization 收口，不是 dual-kernel parity completion
- `WP-30k` ~ `WP-30as` 的主要 owner 已进入代码：planned/staged seam、validator-v2 facade/helpers、ir compat seam、app runtime seams、DNS phase boundary 都有对应 source pins 或回归测试
- 当前仓库没有 public `RuntimePlan` / public `PlannedConfigIR` / generic query API；这不是缺漏回归，而是刻意保留的 future boundary
- `bootstrap.rs` / `run_engine.rs` / `ir/mod.rs` / `validator/v2/mod.rs` 当前都应视为稳定 facade / compat shell，而不是下一轮大拆入口

## Future Work（高层方向）
- 仅在出现真实稳定消费者时，再评估 `PlannedFacts` exact accessor、private query seam、public `RuntimePlan`
- 更大的 runtime seam 仍可继续向 RuntimeContext / actor / manager lifecycle 方向治理
- `sb-core` 的 DNS / router mega-file、TUN 热路径、metrics compat 壳等仍是 maintenance 债务，但不再挂成 `WP-30` 细粒度排程

## 归档判断
- 建议将 `WP-30` 视为“已归档维护线”
- 后续如再开启新卡，应以高层 maintenance 主题立项，而不是恢复 `WP-30k` ~ `WP-30as` 式连续拆卡
