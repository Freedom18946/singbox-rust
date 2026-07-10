<!-- tier: B -->
# MIG-03 WP03 — sb-core 内部 trait 收敛 + sb-proto 处置

Status: DONE (2026-07-10; combined WP02+WP03 cutover)
Priority: P1
Depends on: WP01（ADR 已批准）；建议在 WP02 落地后进行以减少返工
Blocks: WP12

Primary evidence:

- `crates/sb-core/src/adapter/mod.rs:120` — bridge/registry 消费的主 trait
  （connect→`TcpStream` + `connect_io` 旁路 + `as_group`/`as_any`）。
- `crates/sb-core/src/outbound/traits.rs:16/:42` — `OutboundConnector` +
  `OutboundConnectorIo` 第二套。
- `crates/sb-core/src/runtime/switchboard.rs:149` — switchboard 第三套。
- `crates/sb-core/src/pipeline.rs:14`、`crates/sb-core/src/outbound/types.rs:158` —
  两个 `Outbound`（疑似部分死代码，以 WP01 盘点为准）。
- `crates/sb-proto/` — 604 LOC 独立 crate，`connector.rs:116` 又一定义。

## Goal

sb-core 内与"建立出站连接"相关的 trait 收敛为**正典契约一个**（+ ADR 允许的
集中式过渡适配），switchboard/bridge/manager 全部消费正典对象；sb-proto 的
去留拿到用户决策并执行。

## Current Gap

sb-core 三套自有 trait 各自有实现者与调用方（WP01 census 给出精确清单），
互相之间还有 74 处 `impl ... for` 胶水中的一部分。它们的存在使"scaffold 删除"
（WP06）和"selector 家族合并"（WP12）无法安全进行——删一处会被另一套 trait
的孤儿实现绊住。

## Non-goals

- 不删 scaffold 协议实现本体（WP06 按 WP04 矩阵执行）。
- 不合并 selector 家族实现（WP12），本包只统一它们实现的 trait。
- 不动 inbound 数据面逻辑。

## Task Split

1. **switchboard 收敛**：`runtime/switchboard.rs:149` 的自有 trait 退役，
   注册表改存正典 trait 对象。核对 switchboard 默认连接器（direct 等）的构造点。
2. **outbound/traits.rs 收敛**：`OutboundConnector`/`OutboundConnectorIo` 的
   实现者（以 WP01 census 清单为施工单）逐个改实现正典契约；两 trait 删除。
3. **adapter/mod.rs 收敛**：`:120` 的 trait 与正典合并（若 ADR 判定其消费面
   保留，则改为正典的 re-export；否则删除并修 bridge/registry 全部引用）。
   `OutboundGroup` 按 ADR d 项结论落位。
4. **pipeline.rs / outbound/types.rs 的 `Outbound`**：按 WP01 的死代码标记核实
   调用方；确为死代码 → 直接删除（D15 预授权），删除清单与证据记录在包内；
   仍有活调用方 → 改实现正典契约并入收敛。
5. **sb-proto 删除（D15 已定）**：
   - 盘点 sb-proto 的全部下游引用（workspace 内 grep + Cargo.toml 依赖）；
   - 仍被消费的类型并入 sb-types，然后删除整个 crate；
   - 更新 workspace members、boundary 脚本、`PROJECT_STRUCTURE_NAVIGATION.md`；
   - 若盘点发现无法并入 sb-types 的活跃消费面，按 D18 升级。
6. **度量记录**：全仓 `pub trait OutboundConnector` 定义计数（目标：1，位于
   sb-types）；`impl OutboundConnector for` 计数变化。

## Acceptance

- [x] canonical connector definition only exists as `sb_types::Outbound`; legacy
      `OutboundConnector` definitions and handler aliases are 0.
- [x] `outbound/traits.rs`、`pipeline.rs` 删除；switchboard/types 自有 connector trait 为 0。
- [x] WP02 遗留仅 inbound transition；文件头与本包锁定 WP06 移除。
- [x] sb-proto 已按 D15 删除（共享契约并入 sb-types），workspace/boundary/导航文档
      同步完毕；无未升级的 D18 冲突项。
- [x] 全局验收门禁五连全绿；`cargo test -p sb-core` 全绿。
- [x] 双核冒烟：interop route/socks TCP+UDP case 无新增差分（S4 口径）。

## 验证命令

```bash
cargo fmt --all -- --check
cargo check --workspace --all-features
cargo clippy -p sb-core --all-targets --all-features
cargo test -p sb-core
make boundaries
git diff --check
grep -rn "pub trait OutboundConnector" crates/ app/ | grep -v tests
```

## Risks / known traps

- switchboard 是 UDP 平衡/选择路径的枢纽（`switchboard.rs:537` 还在拼装
  hysteria2 配置）——hysteria2 相关引用**不要**在本包顺手迁移，留给 WP07，
  本包只换 trait 形状。
- `as_any()` 下转型钩子被谁用（GUI 组操作？admin 面板？）——census 里核对，
  钩子的取舍在 ADR 已定，不许现场发挥。
- 删 sb-proto 若发现 fuzz/ 或 xtests/ 有引用（它们不在主 workspace 全量编译里），
  用 `Makefile.fuzz` / xtests 构建单独验证。

## 发现移交

- `sb-proto` crate、workspace member、lockfile、structure/SPECS references removed.
- Legacy connector/UDP traits, handler aliases, manager compatibility spellings,
  and `connect_io` escape hatch removed.
- Runtime named dialing always uses canonical boxed stream. UDP registry accepts a
  finalized `Session`, preserving route-resolved packet controls.
- Sole lifecycle transition: `adapter/inbound_transition.rs`; WP06 owns removal.
- Core `direct_connector` remains scaffold-era implementation until WP06 removes
  core fallback ownership per D11. It now obeys idle/deadline/udp_connect/close.
- Zero-reference core direct/block variants deleted.
