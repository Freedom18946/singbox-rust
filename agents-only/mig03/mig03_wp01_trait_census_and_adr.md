<!-- tier: B -->
# MIG-03 WP01 — Trait 契约全量盘点与正典契约 ADR

Status: DONE
Priority: P0（整条 MIG-03 的前置闸门）
Depends on: 无
Blocks: WP02, WP03（ADR 未定稿前两包不得开工；技术方向已由 D1–D8 预决策，
本包无用户批复轮次）
性质: **纯文档包**——本包不改任何 `crates/`、`app/` 代码。

Primary evidence（2026-07-06 实测行号）:

- `crates/sb-types/src/ports/outbound.rs:11` — `connect_stream(&Session, &TargetAddr) -> BoxFuture<Result<BoxedStream, CoreError>>` + `send_datagram`；非 async_trait，手写 BoxFuture。
- `crates/sb-adapters/src/traits.rs:535` — `#[async_trait] dial(Target, DialOpts) -> Result<BoxedStream>` + `start()`/`name()`；25 个协议实现按此形状写成。
- `crates/sb-core/src/adapter/mod.rs:120` — `async fn connect(host, port) -> io::Result<tokio::net::TcpStream>`；返回**具体类型**，加密协议被迫走 `cfg(feature = "v2ray_transport")` 下的 `connect_io` 旁路；附带 `as_group()` 钩子连接 `OutboundGroup` trait。
- `crates/sb-core/src/outbound/traits.rs:16` 与 `:42` — 又一对 `OutboundConnector` / `OutboundConnectorIo`。
- `crates/sb-core/src/runtime/switchboard.rs:149` — switchboard 自持一套 `OutboundConnector`。
- `crates/sb-core/src/pipeline.rs:14`、`crates/sb-core/src/outbound/types.rs:158` — 两个独立 `Outbound` trait。
- `crates/sb-proto/src/connector.rs:116` — 近空壳 crate（全 crate 604 LOC）内又一定义。
- Inbound 侧：`sb-types/src/ports/inbound.rs:29/:49`（InboundHandler/InboundAcceptor）vs `sb-core/src/adapter/`（InboundService）vs sb-adapters 侧 inbound trait。
- 胶水后果：`crates/sb-adapters/src/register.rs`（4,264 行）中 `AdapterIoBridge:34`、`BoxedStreamAdapter:264`、`HttpConnectorWrapper:606`、`Socks5ConnectorWrapper:723`、`Socks4ConnectorWrapper:825`、`ShadowsocksRConnectorWrapper:974`、`DnsConnectorWrapper:2506`、`BlockConnectorWrapper:2661`、`TorConnectorWrapper:2732`、`HttpInboundAdapter:3937`、`MixedInboundAdapter:4039`、`RedirectInboundAdapter:4133`；全仓 74 处 `impl OutboundConnector for`。

## Goal

产出一份经用户批准的 ADR，钦定**全仓唯一**的 outbound/inbound/UDP 契约（落位
sb-types），并给出"每个现存 trait → 正典契约"的迁移映射表，作为 WP02/WP03 的
施工图。目标状态：任何协议实现只写一次、只实现一个 trait，注册进唯一 registry。

## Current Gap

- 同一概念 ≥6 处定义；sb-types ports 全仓仅 12 个文件引用，名义契约层被架空。
- `adapter/mod.rs:120` 的 `connect` 返回具体 `TcpStream`，是 register.rs 每个
  Wrapper 存在的直接原因（加密流必须绕道 `connect_io`）。
- UDP 抽象三套并存：sb-types `send_datagram`、sb-core `UdpOutboundSession`/
  `UdpOutboundFactory`（adapter/mod.rs）、adapters 侧各协议自有 UDP 路径。

## Non-goals

- 不改实现代码、不删任何 trait（那是 WP02/WP03 的事）。
- 不设计 public RuntimePlan / generic query API（项目明确暂停项；正典契约是
  **内部**接口统一）。
- 不统一 Session/路由元数据的全部字段语义——只统一连接建立契约所需的最小面。

## Task Split

1. **全量盘点**（产出 `mig03_wp01_trait_census.md`，落本目录）。
   对 Primary evidence 列出的**每一个** trait 逐一记录：
   - 完整方法签名（含默认实现）、async 形态（async_trait vs 手写 BoxFuture）、
     错误类型（`CoreError` / `anyhow::Result` / `io::Result`）；
   - 实现者清单与数量（附可复现的 grep 命令及输出摘录）；
   - 调用方清单（谁以 `dyn` 持有、谁静态分发）；
   - 对象安全性、`'static`/`Send`/`Sync` 约束差异；
   - UDP 侧单独一节：三套 UDP 抽象的能力差异表（connect-style vs sendto-style、
     是否支持 recv、生命周期归属）。
   - Inbound 侧单独一节：InboundHandler/InboundAcceptor/InboundService 的职责
     重叠与 register.rs 中 `*InboundAdapter` 的适配点。
2. **正典形态决策**（ADR，套用 `agents-only/templates/DECISION.template.md`，
   落本目录，命名 `mig03_adr01_canonical_connector.md`）。
   - **形状已定（D1，binding）**：镜像 Go `adapter.Outbound` 语义、落位 sb-types
     ——`tag()/type()/network()/dependencies()` + 流式 dial（BoxedStream）+
     `listen_packet` 式 UDP。ADR 的工作是把 D1–D8 落到**精确 Rust 签名**
     （trait 定义草案、类型归属、错误映射表），不是重新选型。
     census 证据若与 D 条目冲突，按 D18 升级，不得现场改道。
   - ADR 必须把以下八问落到精确签名（答案已由决策登记册预决策，映射：
     a→D2、b→D3、c→D4、d→D5、e→D6、f→D1、g→D7、h→D8）：
     a. 错误类型统一方案（推荐 `CoreError` 或专用 `ConnectError`，禁止裸 anyhow 穿契约）；
     b. `Target`/`DialOpts` 与 sb-types `Session`/`TargetAddr` 的归一（谁进 sb-types、谁退役）；
     c. UDP 抽象归一（一个 trait 还是 stream+datagram 两个能力接口）；
     d. `OutboundGroup`（selector/urltest）落位与 `as_group()` 钩子的去留；
     e. Inbound 正典（InboundService 形状 vs ports 双 trait 形状，二选一）；
     f. 具体类型 `tokio::net::TcpStream` 是否彻底退出契约签名（推荐：是）；
     g. sb-types 依赖红线的遵守方式（ARCHITECTURE-SPEC §1.2 禁止 tokio/hyper 等
        重依赖；如需 IO trait，写明用什么抽象、增加哪些受控依赖）；
     h. 过渡期兼容策略：旧 trait 是否保留 deprecated 薄适配一个包周期，还是
        WP02/WP03 内直接切换。
   - 至少给出 2 个被否决备选（如"以 sb-types 现形状为正典"）及否决理由。
3. **迁移映射表**（并入 ADR 或独立小节）。
   每个现存 trait 一行：去向（实现正典 / 薄适配过渡 / 直接删除）、受影响文件数
   （grep 计数）、预计风险（低/中/高 + 一句话）。**不允许留 TBD。**
4. **决策一致性核对**。ADR 与 D1–D8 逐条对照（对照表写入 ADR）；
   无冲突即可把 ADR 状态改"已批准（依 D1–D8）"，本包标 DONE；
   有冲突按 D18 升级，冲突项未决前不标 DONE。

## Acceptance

- [x] `mig03_wp01_trait_census.md` 覆盖 Primary evidence 全部条目，每条含
      实现者/调用方计数与可复现 grep 命令。
- [x] `mig03_adr01_canonical_connector.md` 完成，a–h 八问全部落到精确签名，
      与 D1–D8 的逐条对照表在 ADR 内，含 ≥2 个被否决备选的记录。
- [x] 迁移映射表无 TBD 项。
- [x] 无未升级的 D 条目冲突项（有升级则记录用户答复后才勾）。
- [x] `git status` 确认本包只新增了 `agents-only/mig03/` 下的文档。

## 验证命令

```bash
git status --porcelain   # 只允许 agents-only/mig03/ 下新增
```

## Risks / known traps

- 最大风险是把正典契约做成**第 7 套悬空定义**——ADR 必须与 WP02/WP03 的删除
  清单绑定，凡新增必有对应退役项。
- 盘点时注意 `#[cfg(feature)]` 门控下的方法（如 `connect_io`），带 feature 维度记录，
  否则 WP02 施工时会漏。
- `sb-core/src/pipeline.rs` 的 `Outbound` 可能已无活跃调用方——盘点须给出
  "疑似死代码"标记，但处置留给 WP03。

## 发现移交

- `sb-types::AsyncStream` 当前只是 marker，必须由 WP02 变为基于 `futures::io`
  的真实 I/O 契约；Tokio compat 留在拥有实现的 crate。
- `sb-proto::connector::TrojanConnector` 仍有一个生产泛型实现；D15 的 crate
  删除动作留给 WP03，先迁移所需 helper/type。
- 现有 select 是 GUI 可见面，ADR 将其迁为显式 `SelectorControl`，避免把所有
  group 误判为可选组；`members_health` 无调用方，随旧 core group trait 删除。
- `adapter-trojan` 单独启用时，`register.rs` 引用 `inbound::trojan` 但 feature
  未启用 `trojan`；已记录在 census，留给 feature/implementation sweep，未在
  本纯文档包顺手修改。
