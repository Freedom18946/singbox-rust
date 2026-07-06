<!-- tier: B -->
# MIG-03 决策登记册（D1–D18）

Status: **已批准**（2026-07-06 用户委托 Claude 按既定立场统一敲定）
决策立场（用户明示，按此三轴裁决，**不计短期迁移成本**）：
1. 最佳现实可行性；2. 长远维护利益；3. 最终目标 = 完美等价 Go sing-box 内核。

> 各工作包遇到对应事项**直接执行 D 条目，不再回头请示**。
> 包内证据与 D 条目冲突、或出现 D 未覆盖的删除/行为变更 → 按 D18 升级。

---

## A. 正典契约（WP01–WP03 施工依据）

**D1 — 正典 outbound 契约形状：镜像 Go `adapter.Outbound` 语义，落位 sb-types。**
方法面 = `tag()` / `type()` / `network()`（声明 tcp/udp 支持）/
`dependencies()`（默认空，供 supervisor 启动排序，对应 Go `Dependencies()`）/
流式连接（对应 Go `DialContext`，返回 `BoxedStream`）/
`listen_packet` 风格 UDP（返回 packet-conn 对象，对应 Go `ListenPacket`）。
对象安全；签名中**不出现任何具体 socket 类型**（`tokio::net::TcpStream` 出局）。
精确 Rust 签名由 WP01 ADR 定稿，语义边界以本条为准。
*理由：三轴同向——Go 形状是终局目标的形状；adapters 的 `dial()` 平移进流式方法即可（可行）；
单一 Go 同构契约让未来每次 Go 版本抬升都有明确映射面（维护）。*

**D2 — 契约错误类型：sb-types 结构化错误（以现有 `CoreError` 为基座扩展变体）。**
禁止 `anyhow` / 裸 `io::Error` 穿越契约边界；`AdapterError` 在实现层映射进来。
*理由：对齐 Go 的显式错误分类（超时/拒绝/协议错），差分测试需要可断言的错误面。*

**D3 — 地址与元数据：sb-types `TargetAddr` + `Session` 为唯一载体。**
adapters 的 `Target` / `DialOpts` 退役，字段并入 `Session`（或其携带的连接选项结构）；
语义对齐 Go `M.Socksaddr` / `M.Metadata`。
*理由：消灭 register.rs 里 Target↔host,port↔TargetAddr 的三向转换；元数据面与 Go 同构。*

**D4 — UDP 模型：Go `ListenPacket` 式 packet-conn 对象，唯一 UDP 抽象。**
sb-types 现 `send_datagram`（无 recv 路径）与 sb-core `UdpOutboundFactory`/
`UdpOutboundSession` 双轨全部退役，能力并入 D1 的 `listen_packet`。
*理由：per-datagram sendto 无法表达 Go 的 NAT/会话语义，是现有 UDP 行为对不齐的结构性根源。*

**D5 — 组抽象：canonical `OutboundGroup` trait 进 sb-types，保留 `as_group()` 下转钩子。**
镜像 Go `adapter.OutboundGroup`（Now/All + 组类型）；Rust 侧用显式钩子替代 Go 的
interface type-assertion。`as_any()` 钩子仅在 census 证明有消费方时保留。
*理由：GUI 组操作（Clash API select/now/all）是既有验收面，钩子模式改动半径最小且与 Go 同构。*

**D6 — 正典 inbound 契约：单一 `Inbound` trait，镜像 Go `adapter.Inbound` 生命周期。**
`tag()` / `type()` + 分阶段 `start(stage)` / `close()`（对齐 supervisor 现有 `StartStage`）；
连接分发保持 registry builder context 内部实现细节。sb-types 现 `InboundHandler` /
`InboundAcceptor` 双 trait 退役。
*理由：supervisor 已按 Go 的分阶段启动建模，契约跟上；双 trait 无实际双消费面。*

**D7 — sb-types 依赖红线：允许 `async_trait` 与 `futures`（trait 对象需要），禁 tokio/hyper/axum。**
IO 抽象沿用现有 `BoxedStream` 机制。
*理由：维持契约层可被任何运行时实现的长期属性。*

**D8 — 过渡策略：直接切换，不留 deprecated 兼容层。**
每包内完成"转换 + 删旧"；WP02 允许的集中式过渡适配 ≤1 文件，且必须在
WP03/WP06 内消亡。旧 trait 一律删除而非 deprecate。
*理由：用户明示不计短期成本；兼容层是本仓库当前病灶（cp 而不删）的复发路径。*

## B. scaffold 退役裁决（WP04–WP06 施工依据）

**D9 — SCAFFOLD-ONLY 能力三档裁决：**
- Go 内核有同等能力 → **移植进 adapters**；
- Go 无此能力、且无消费证据（验收文档/GUI/scripts/xtests 均无引用）→ **DROP**；
- Go 无此能力、但有真实消费证据 → 保留，并在矩阵登记为 **Rust-only 扩展**（挂 feature，
  默认构建不启用）。
Go 有、但 scaffold 与 adapters 都没有的能力 = parity 缺口，**不属于 MIG-03**，登记移交。
*理由：终局是 Go 等价内核；Rust-only 行为必须显式隔离而非混在默认路径。*

**D10 — 语义分歧最高仲裁 = Go 内核行为。**
scaffold 与 adapters 行为不一致时，以 Go 1.13.13 同场景行为为准绳修正；
scaffold 的 bug **不做 bug-for-bug 移植**。Go 侧行为无法确证时才按 D18 升级。
*理由：完美等价 Go 是最终目标，scaffold 不是参照系。*

**D11 — direct/block 正典 = sb-adapters 实现。**
switchboard 等处的默认连接器一律改为消费 registry 注册的 direct；
sb-core 不保留任何本地 direct/block 实现。初始化次序确实无法经 registry 时按 D18 升级。

## C. 控制面与配置面（WP09–WP11 施工依据）

**D12 — 服务落位：`v2ray_api` + `ssmapi` → sb-api；`derp` → 新 crate `crates/sb-service-derp`。**
注册外置到 app 组合根（对齐 `register_all()` 模式）；sb-core 只留 `Service` trait 与 registry。
*理由：sb-api 本就是控制面钦定位置；derp 依赖重、演进独立，单独成 crate 隔离编译半径。*

**D13 — 控制面 HTTP/auth 栈全仓唯一，归 sb-api。**
sb-api 暴露路由扩展点（组合根可注册额外路由域）；admin_debug 活 endpoint 中仅依赖
core/api 状态的迁入 sb-api（`debug` feature 门控），依赖 app 内部状态的由 app 经扩展点
注册；admin_debug 自建 http_server/auth/middleware 栈拆除；SUSPECT-DEAD 复核后删除。
*理由：两套 HTTP/auth 栈是双倍安全面与双倍维护面；Go 亦只有一个 experimental API 栈。*

**D14 — env 收敛终态：sb-core 内 SB_* 读取点目标 **0**，容忍例外 ≤5 且逐项登记理由。**
全部变量语义保留（MIG-03 **不废弃任何 SB_***，废弃留给后续轨迹）；解析一律上收
app 组合根；一律 freeze-at-construction——census 若发现确有消费方依赖"运行中重读"，
按 D18 升级，不得默认保留热读。
*理由：Go 内核纯配置驱动；0 是与终局一致的锚点，≤5 例外只为 panic/debug 类开关兜底。*

## D. 收网裁决（WP12–WP14 施工依据）

**D15 — 去重与废弃物处置（预授权，凭 census 证据直接执行）：**
- **sb-proto**：删除 crate，仍被消费的类型并入 sb-types（WP03 执行）；
- **疑似死 trait**（`pipeline.rs` / `outbound/types.rs` 的 `Outbound` 等）：census 证明
  无活跃调用方即删，清单记录在包内；
- **selector 家族**：合并为一套 group 实现（selector/urltest/fallback 语义对齐 Go
  `protocol/group`）；p3/实验变体无活跃构造方即删（连带审计 observe/feedback/health
  三个疑似伴生文件）；
- **WireGuard/Tailscale**：netstack/设备层唯一归 sb-transport；endpoint 型实现归
  core/endpoint 并消费 transport 层；outbound 壳消费同一底层——重复的隧道/密钥逻辑合并；
- **影子模块**：`core/transport/`→sb-transport、`core/tls/`→sb-tls、
  `core/subscribe/`→sb-subscribe、`core/config/`→sb-config、`core/socks5/`→并入
  adapters；`core/metrics/` 若 census 确认"registry 在 core / exporter 在 sb-metrics"
  分工清晰则保留并写明契约，分工不清则并入 sb-metrics。
超出本清单的删除按 D18 升级。

**D16 — `router` feature 常驻化：删除该 feature 及全部 `#[cfg(feature = "router")]` 双版本分支。**
普查若发现真实 no-router 消费方，按 D18 升级，不得自行保留双版本。
*理由：全部下游强制开启，双版本分支是纯维护税；Go 内核路由不可拆卸。*

**D17 — 收口纪律：WP14 终验全绿即归档，无需请示；overview §6 指标不达标默认补做**
（新开跟进包），仅当存在阻塞性证据时才升级用户裁决"接受"。

## E. 元规则

**D18 — 升级通道（唯一的回头请示路径）：**
包内证据与任何 D 条目冲突、或出现 D 未覆盖的删除/用户可见行为变更时：停下、
在包内"发现移交"登记冲突证据、升级用户。**任何 agent 不得自行修改本登记册的决策内容。**
