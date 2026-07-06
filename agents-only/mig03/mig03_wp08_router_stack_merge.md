<!-- tier: B -->
# MIG-03 WP08 — 路由双栈合并（router/ + routing/），matcher 原语共享给 DNS

Status: PLANNED
Priority: P1
Depends on: WP06（共同触碰 bridge/registry，强制串行）
Blocks: WP11

Primary evidence:

- `crates/sb-core/src/router/` — 23,340 LOC 主实现（mod.rs 2,952 / rules.rs 2,579 /
  engine.rs 2,290 / conn.rs 1,730 / ruleset/ 等）。
- `crates/sb-core/src/routing/` — 1,487 LOC 第二套门面（engine/explain/ir/trace/
  matcher/router.rs），`routing/engine.rs:107` 内部又构造
  `crate::router::RouterHandle::from_env()`。
- 消费面分裂：`routing::engine::Engine` 被 `runtime/supervisor.rs:18`、
  `adapter/registry.rs:24`、`adapter/bridge.rs:823`、core 内 inbound 使用；
  `sb_core::router` 被 sb-adapters inbound（tuic 13 处 / hysteria2 13 处 /
  socks/udp 12 处 / http 6 处 / tun 4 处）与 app（route.rs 23 处、ruleset 17 处、
  preview/sb-explaind 等）直接使用。
- 匹配原语重复：`router/matcher.rs` 与 `routing/matcher.rs` 并存；
  `dns/rule_engine.rs`（2,646 行）再实现一遍 exact/suffix/keyword/regex 域名匹配。
- 测试锚点：`crates/sb-core/tests/router_options_parity_test.rs`（同时 import
  两套栈！`routing::engine::Engine` + `sb_core::router`）、`tests/tun_sni_routing.rs`、
  bin `rule-hot-reload.rs`。

## Goal

单一路由栈：一个 `Engine` 类型、一套 matcher 原语、一个对外模块路径。
`routing/` 收敛为纯 re-export 垫片（≤50 行，标注退役期）或直接消失；
DNS 规则引擎复用同一套 matcher 原语，不再自带实现。

## Current Gap

两套栈都是活代码且互相缠绕（routing 包裹 router 又自带 matcher/ir）。
所有新功能不知道该加在哪边；`from_env()` 藏在 Engine 手柄获取路径里，
是 WP11 env 上收的直接障碍。

## Non-goals

- 不改任何路由决策语义（规则优先级、默认路由、sniff 集成行为全部保持）。
- 不做 env 上收（WP11；本包只把 `from_env()` 从 Engine 内部提升到构造点）。
- 不动 `router/ruleset` 的二进制格式与 geoip/geosite 数据面。

## Task Split

1. **职责测绘**（先文档后动手，产出 `mig03_wp08_router_map.md`）：
   - 两套栈逐文件职责表：router/ 每个子模块 vs routing/ 每个子模块，标注
     重复对（engine↔engine、matcher↔matcher、router.rs↔RouterHandle）；
   - 消费面清单：谁用哪套的哪个类型（以 evidence 的 grep 为起点补全）；
   - 定稿目标形态：**推荐 `router/` 为唯一实现家**（体量与 ruleset/hot_reload
     都在这边），`routing::{Engine, Input}` 等公共类型平移进 `router::engine`，
     `routing/` 变 re-export 垫片。若测绘推翻此推荐，在包内写 mini-ADR。
2. **Engine 合并**：`routing/engine.rs`（947 行）与 `router/engine.rs`（2,290 行）
   合并为一个 Engine；`routing/engine.rs:107` 的 `RouterHandle::from_env()`
   改为构造注入（调用方 supervisor/bridge 在组装时传入），本包内 env 读取点
   数量不得增加。
3. **matcher 归一**：`routing/matcher.rs` 并入 `router/matcher.rs`；
   两者 API 差异处以现有测试为语义准绳。
4. **explain/trace/ir 归位**：`routing/{explain,trace,ir}.rs` 平移进 router/
   对应位置；`sb-explaind`、`route-explain`、admin `analyze` 端点的输出格式
   逐字段回归（有 JSON 快照测试的跑快照，没有的补最小快照测试再迁）。
5. **消费面切换**：supervisor/bridge/registry/core inbound → 新路径；
   sb-adapters 与 app 的 `sb_core::router` 引用保持兼容（目标形态就在 router/，
   预期改动小）；`routing/` 留垫片一个包周期，垫片文件头标注"WP14 删除"。
6. **DNS matcher 共享**：`dns/rule_engine.rs` 的域名匹配部分改调 router matcher
   原语；DNS 侧删除重复实现（预期净删数百行）。DNS 规则**行为**以现有
   dns 测试 + interop dns case 为锁。
7. **度量记录**：路由栈文件数/LOC 前后对比；matcher 实现数 2→1；
   `router_options_parity_test.rs` 不再需要同时 import 两套。

## Acceptance

- [ ] `crates/sb-core/src/routing/` 只剩 ≤50 行 re-export 垫片（或已删除且
      全部调用方切换完成）。
- [ ] 全仓只有一个 `pub struct Engine`（路由域内）与一套 matcher 原语；
      `dns/rule_engine.rs` 不再含独立的 suffix/keyword/regex 匹配实现。
- [ ] `router_options_parity_test.rs`、`tun_sni_routing.rs`、
      `rule-hot-reload` bin、`sb-explaind`/`route`/`preview` bins 全部编译且测试绿。
- [ ] explain JSON 输出逐字段一致（快照测试证明）。
- [ ] 全局验收门禁五连全绿；`cargo test -p sb-core router` +
      `cargo test -p sb-core dns` 全绿。
- [ ] 双核回归：route/dns 维度 interop case 无新增差分（S2/S3 定位、S4 归因）。

## 验证命令

```bash
cargo fmt --all -- --check
cargo check --workspace --all-features
cargo clippy -p sb-core --all-targets --all-features
cargo test -p sb-core
cargo test -p app --features "router,tools"
make boundaries
git diff --check
```

## Risks / known traps

- 这是**语义风险最高的包**（路由 = 双核对齐的主战场之一）。任何 matcher 合并
  中发现两套实现行为不一致（如后缀匹配对空标签的处理），必须停下：先写测试
  钉住两边现状，查 golden spec S3 找对应 BHV-ID，按 Go 语义为准裁决并记录。
- `router/mod.rs` 有 12 处 env 读取、`router/engine.rs` 11 处——本包**不迁移**
  它们（WP11），但合并时别把读取点复制成两份。
- hot_reload 路径（`rule-hot-reload` bin + `hot_reload.rs`）依赖
  `Arc<RouterIndex>` 原子替换语义，合并时保持无锁读路径设计不变。
- app 的 `analyze/`、`admin_debug/endpoints/analyze.rs` 也消费 router 类型，
  改公共类型路径时全仓 grep，别只看 crates/。

## 发现移交

（执行时填写。）
