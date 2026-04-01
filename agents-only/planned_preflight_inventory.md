# WP-30 planned seam archive inventory

## Status

- 本文件已从“preflight 迁移地图”更新为 **archive-safe inventory**。
- `WP-30k` ~ `WP-30as` 已在 2026-04-02 通过 `WP-30at` 做过总体验收 / 归档收口。
- 这份 inventory 只记录 **仓库当前事实**，不再把 `planned.rs` 写成进行中实现卡，也不把维护工作误写成 parity completion。

## 已落地事实

- `crates/sb-config/src/ir/planned.rs` 当前稳定停在 crate-private staged seam：
  - `collect_planned_facts(&ConfigIR) -> Result<PlannedFacts>`
  - `validate_with_planned_facts(&PlannedFacts, &ConfigIR) -> Result<()>`
  - `validate_planned_facts(&ConfigIR) -> Result<()>`
- `PlannedFacts` 继续只做 **collect/validate 两段式 fact graph**，覆盖 4 个 namespace 与 11 类 reference checks。
- `crates/sb-config/src/lib.rs` 的 `Config::validate()` 当前是 thin entry，只委托 `crate::ir::planned::validate_planned_facts(&self.ir)`。
- `crates/sb-config/src/ir/dns_raw.rs` 当前拥有 `RawDns*` 与 Raw -> Validated bridge；`crates/sb-config/src/ir/dns.rs` 当前拥有 validated DNS types 与 `Deserialize` delegation。
- `crates/sb-config/src/validator/v2/mod.rs` 当前是 thin facade；parse-time defaults / alias fill / credential ENV resolution 继续留在 `validator/v2/*`。
- `normalize` / `minimize` / `present` 仍是独立边界；它们没有接管 planned consumer owner。
- `app/src/outbound_builder/*`、`app/src/outbound_groups.rs`、`app/src/router_text.rs`、`app/src/bootstrap_runtime/*`、`app/src/dns_env.rs`、`app/src/run_engine_runtime/*` 继续是 runtime owner，不属于 planned seam。

## 当前 owner map

| Responsibility | Current owner | Archive-safe conclusion |
| --- | --- | --- |
| namespace/reference fact graph | `crates/sb-config/src/ir/planned.rs` | 已稳定为 crate-private staged seam，不向 public API 扩张 |
| `Config::validate()` orchestration | `crates/sb-config/src/lib.rs` | 继续保持 thin entry，不重新持有 inline planned logic |
| DNS Raw boundary | `crates/sb-config/src/ir/dns_raw.rs` | 已稳定；Raw unknown-field rejection 与 Raw->Validated bridge 均有 pin |
| DNS validated owner | `crates/sb-config/src/ir/dns.rs` | 已稳定；`Deserialize` 经 `dns_raw` 委托 |
| parse-time defaults / alias / ENV | `crates/sb-config/src/validator/v2/*` | 继续留在 validator，不搬进 planned |
| canonicalization / minimization / projection | `ir::normalize` / `ir::minimize` / `present.rs` | 继续明确不是 planned consumer owner |
| selector/urltest binding、router text、DNS env、bootstrap/run_engine runtime | `app/src/*` runtime seams | 继续明确是 runtime owner，不搬进 planned |

## 明确未落地的边界

- 没有 public `RuntimePlan`
- 没有 public `PlannedConfigIR`
- 没有 public builder API
- 没有 crate-internal generic query API
- 没有 exact private accessor（当前没有稳定 private consumer）
- 没有 runtime connector binding
- 没有 runtime-facing DNS env bridge 并入 planned

## 归档结论

- `WP-30k` ~ `WP-30as` 这条线已经把 `planned.rs` 从前置 inventory 收成 **维护期可接受的 staged private seam**。
- 当前最重要的稳定事实不是“继续拆 planned”，而是：
  - planned / validated / runtime 三条边界已经分清
  - DNS Raw / Validated / planned boundary 已稳定
  - `normalize` / `minimize` / `present` / app runtime seams 没有越权变成 planned consumer
- 因此这条线现在应按 **archive baseline** 维护，而不是继续按“下一卡继续拆 facade / 推 RuntimePlan”排程。

## Future Work（高层方向）

- 仅当出现真实稳定 consumer 时，再评估：
  - `PlannedFacts` exact accessor
  - private query seam
  - public `RuntimePlan`
- 更大的 runtime actor/context 化仍属于 app / runtime maintenance 主题，不属于这条 planned seam archive 卡

## 验收基线（WP-30at）

- `cargo test -p sb-config --lib`
- `cargo clippy -p sb-config --all-features --all-targets -- -D warnings`
- `cargo test -p app --lib`
- `cargo test -p app`
- `cargo clippy -p app --all-features --all-targets -- -D warnings`

以上命令已在 `WP-30at` 归档验收中按当前仓库事实复跑通过。
