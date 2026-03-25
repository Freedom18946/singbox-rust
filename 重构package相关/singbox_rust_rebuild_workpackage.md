# singbox-rust 全局重构战略规划与 Workpackage

## 0. 这份 Workpackage 如何配合前一份审计报告使用

本文件是针对以下三份输入材料的“执行版总包”：

1. `singbox_rust_audit_report.md`
2. `34524458-593a-401f-bec1-0ab2fe0787df.md`（Rust Agent Ruleset / Layer 1-4）
3. `singbox_rust_audit_processed_findings.json`
4. `2026-03-25_5.4pro第三次审计核验记录.md`（维护期事实校正层）

建议 coding agent 先读以下章节，再按本文的阶段推进：

- 审计总览与问题成因：`singbox_rust_audit_report.md` §1, §3, §4
- 目标架构与阶段规划：`singbox_rust_audit_report.md` §5, §6, §7, §8
- 具体命中清单：`singbox_rust_audit_report.md` 附录 A / B
- 规则原文：`34524458-593a-401f-bec1-0ab2fe0787df.md` Layer 1-4
- 维护期校正：`2026-03-25_5.4pro第三次审计核验记录.md` §2, §3

为了便于 agent 理解，本文统一使用以下引用缩写：

- **[AUDIT-4.1]** = `singbox_rust_audit_report.md` §4.1
- **[AUDIT-5.2]** = `singbox_rust_audit_report.md` §5.2
- **[AUDIT-A/spawn_unhandled]** = `singbox_rust_audit_report.md` 附录 A 中 `spawn_unhandled`
- **[RULE-L3]** = 规则文件中 Layer 3

---

## 1. 上帝视野下的总判断

这次重构不能按“哪个文件报错多就先改哪个”的方式推进。全局视角下，这个仓库当前的根因链是：

1. **运行时骨架不够显式**
   - `http_client`、`geoip`、`metrics`、`logging`、`prefetch`、`security_metrics` 等基础设施通过全局静态或弱引用共享，违反 [RULE-L1]，并在 [AUDIT-4.1] 被确认是系统性问题。
2. **生命周期纪律没有统一收口**
   - `tokio::spawn` 大量丢 `JoinHandle`，锁跨 `await` 广泛存在，在 [AUDIT-4.2]、[AUDIT-4.3] 被确认是联调期最不稳定的链路。
3. **配置边界没有完成“原始输入 -> 领域模型 -> 运行计划”转换**
   - `Deserialize` 类型缺 `deny_unknown_fields`，原始 `String/Option<String>` 下沉到 runtime，在 [AUDIT-4.5] 被点名。
4. **组合根和控制面过厚，导致无关职责在联调时互相牵扯**
   - `bootstrap.rs`、`run_engine.rs`、`admin_debug`、`sb-api` 与 runtime owner 混在一起，[AUDIT-4.6]、[AUDIT-5.4] 已明确。
5. **工具链治理没有变成“硬闸门”**
   - 当前更像“靠人自觉”，而不是“CI 自动卡死”，见 [AUDIT-4.7] 与 [RULE-L4]。

所以正确顺序不是“先全仓修 lint”，而是：

> **先立 runtime contract，再拆 globals，再建 config plan，再 actor 化 manager，再清热点 panic/锁/任务，再封工具链。**

### 1.1 2026-03-25 核验后的顺序校正

保持上述总顺序不变，但要把维护期已经收口过一轮的条目和仍会直接影响稳定性的条目分开：

- **仍是 Phase 2 / Phase 4 第一波 blocker**：
  - `sb-config` Raw 边界（~~`outbound.rs`~~ ✅ 已完成 Raw/Validated 边界试点 2026-03-26 / `ir/mod.rs` / `validator/v2.rs`）
- **已完成 hard global + lifecycle 收口**：
  - `outbound/ssh.rs` — session lock 消除（`Arc<PostAuthSession>` 最小能力封装，handle 私有，仅暴露 `open_direct_tcpip()`），pool 三阶段锁无 lock-across-await，bridge `JoinSet` tracked，零 `tokio::spawn`
  - `outbound/anytls.rs` — `SessionRuntime`（`JoinSet` owner + `shutdown()` abort+join），三阶段锁无 lock-across-await，bridge `JoinSet` tracked（`264cb5a2` + follow-up）
  - `http_server.rs` — accept/connection lifecycle tracked（`AdminDebugHandle` + `JoinSet` + `CancellationToken`），runtime shutdown 已接入（`15093767`）
  - `prefetch.rs` — hard global 已删，worker lifecycle 改为 tracked/owned（dispatcher + CancellationToken + JoinSet），仅剩 `DEFAULT_PREFETCHER` weak-owner compat
  - `http_client.rs` — hard global 已删（`d3a0b1e7`），仅剩 `DEFAULT_HTTP_CLIENT` weak-owner
  - `geoip/mod.rs` — hard global 已删（`f5297845`），仅剩 `DEFAULT_GEOIP_SERVICE` weak-owner
- **保留为债务，但下调优先级**：
  - `logging.rs`
  - `security_metrics.rs`
  - `sb-metrics/src/lib.rs`
  - `metrics/registry_ext.rs`

原因见 `2026-03-25_5.4pro第三次审计核验记录.md`：`http_client.rs` 和 `geoip/mod.rs` 已完成 hard global fallback 收口（2026-03-25），不再是第一波 blocker。其余模块在 2026-03-24 维护期已做过 compat shell 瘦身、owner-first 收口或 registry plumbing 收口，问题仍在，但不应继续压过当前更硬的稳定性链路。

---

## 2. 北极星目标架构

以 [AUDIT-5.1] 到 [AUDIT-5.4] 为基础，目标态应统一为以下六条架构不变量：

### 2.1 RuntimeContext 是唯一合法的运行时依赖入口

所有基础设施依赖必须通过 `RuntimeContext` / `KernelRuntime` 显式持有，而不是通过静态全局获取：

- `HttpClientProvider`
- `GeoIpProvider`
- `MetricsRegistryOwner`
- `LoggingSupervisorHandle`
- `PrefetchServiceHandle`
- `TaskRegistry`
- `ShutdownCoordinator`
- `DnsManagerHandle`
- `RouteManagerHandle`
- `InboundManagerHandle`
- `OutboundManagerHandle`
- `ServiceManagerHandle`

### 2.2 所有外部输入只允许在边界处以 Raw 形态出现

只允许下面的单向转换链存在：

`RawConfig / RawApiInput / RawScenario -> Validated* -> RuntimePlan -> Runtime owners`

禁止让 serde 派生类型直接流入 runtime manager、router、dns、service。

### 2.3 Manager 必须是 owner task，而不是“共享状态 + 锁”的壳

每个 manager 统一采用：

- `Handle` 对外 API
- `Command` / `Query` 消息
- owner task 内持有真实状态
- 所有后台子任务注册进 `TaskRegistry`

### 2.4 控制面只能读快照，不能偷读活体状态

`sb-api` / `admin_debug` 只能通过只读 query port 获取 runtime snapshot，不能：

- 直接访问 global
- 直接读 `Arc<Mutex<_>>`
- 持锁跨 `await`
- 自己随手 `spawn` 一个隐式后台循环

### 2.5 compat shell 只作为迁移垫片，不得成为新常态

迁移阶段允许：

- 新代码只依赖 `RuntimeContext`
- 老代码经 `compat::*` 适配层转发
- `compat::*` 采用“context 优先，legacy fallback 兜底”

但每个 compat 点必须被登记为债务，最终删掉兜底。

### 2.6 工具链是裁判，不是建议板

最终状态必须把 [RULE-L4] 变成自动化 gate：

- `missing_docs = deny`
- `unused_must_use = deny`
- `clippy -D warnings`
- `pedantic` / `nursery` 统一配置
- 新增 `unwrap/expect/global spawn-drop/lock-across-await` 直接 CI fail

---

## 3. 推进原则与依赖图

### 3.1 必须先做的三件事

1. **冻结债务继续扩张**
2. **建立 runtime spine**
3. **建立 Raw -> Validated -> RuntimePlan 三相模型**

如果这三件事不先完成，后面的改动会不断打架：

- 去 globals 会没有承接容器
- 去 dropped spawn 会没有 TaskRegistry 承接
- 去 serde 脏模型会没有 RuntimePlan 承接

### 3.2 允许并行的工作流

在 `RuntimeContext` 与 `ConfigPlan` 主干建好后，可以并行推进四条流：

1. 配置流
2. DNS / Route 流
3. Manager / Lifecycle 流
4. Service Surface / Control Plane 流

这与 [AUDIT-8] 对 repo 当前 parity / spec 状态的建议一致。

### 3.3 不允许并行的工作

以下组合不要同时大规模动，否则冲突会很多：

- `bootstrap.rs` / `run_engine.rs` 大拆分 与 manager actor 化 同一 PR
- `sb-config` 三相重构 与 `sb-api/v2ray` 改模型 同一 PR
- `TaskRegistry` 落地前大面积修 `spawn_unhandled`
- `RuntimeContext` 落地前全面去 global

---

## 4. 阶段总览

| 阶段 | 聚焦 Layer | 核心目标 | 主产物 |
| --- | --- | --- | --- |
| Phase 0 | Layer 4 为主，冻结 Layer 1/3 新债 | 建立 debt ratchet、统一 lint / 审计入口 | 可重复审计脚本、CI 闸门、runtime contract 文档 |
| Phase 1 | Layer 1 + Layer 3 | 抽出 RuntimeContext / KernelRuntime / TaskRegistry 骨架 | 明确 runtime spine、compat shell、显式依赖注入 |
| Phase 2 | Layer 1 + Layer 3 | 去掉核心基础设施 globals | metrics / logging / http_client / geoip / prefetch / security_metrics 去单例化 |
| Phase 3 | Layer 3 + Layer 4 | 建立 Raw -> Validated -> RuntimePlan 三相配置边界 | `sb-config` 重构、validator 拆分、外部输入卫生化 |
| Phase 4 | Layer 3 | manager actor 化与任务生命周期收口 | owner-task manager、tracked spawn、graceful shutdown |
| Phase 5 | Layer 1 + Layer 3 | 热点链路稳定化 | tun / optimizations / ssh / anytls / wireguard / derp 等高风险链路整改 |
| Phase 6 | Layer 2 + Layer 4 | 控制面解耦与 mega-file 结构治理 | admin_debug / sb-api 解耦、模块拆分、must_use/docs/super_path/pub_use 治理 |
| Phase 7 | Layer 4，收口全层 | 工具链强制化与最终一致性验收 | deny 策略、doc test、全仓 gate、最终 conformance 报告 |

---

## 5. 详细 Workpackage

## WP-00: Debt Ratchet 与运行时契约落盘

- **归属阶段**：Phase 0
- **聚焦 Layer**：Layer 4，冻结 Layer 1 / 3 新债
- **建议先读**：`singbox_rust_audit_report.md` §3, §4.7, §6.1, §6.2, 附录 A / B
- **目标**：把“不能继续恶化”变成机器可执行事实

### 范围

- 仓库根 `Cargo.toml` / `.clippy.toml` / CI workflow
- 审计脚本目录，例如 `tools/audit/`
- 架构说明文档，例如 `docs/architecture/runtime_contract.md`

### 处理的问题

- `allow_clippy_escapes` 28 处，当前豁免策略分散，见 [AUDIT-A/allow_clippy_escapes]
- 规则没有 ratchet，导致 `unwrap/global/spawn` 可以继续悄悄增长
- runtime contract 仅存在于脑内和报告里，没有成为工程约束

### 必做任务

1. 提交**可重复执行**的静态审计脚本，输出与 `singbox_rust_audit_processed_findings.json` 同结构或兼容结构。
2. 在 CI 中加入 ratchet：以下类别禁止新增，数量必须 `<= baseline`：
   - `unwrap`
   - `expect`
   - `panic` / `todo_unimpl_unreachable`
   - `static_once_lock` / `static_lazy_lock` / `static_once_cell`
   - `spawn_unhandled`
   - `lock_cross_await`
   - `anyhow_pub_fn`
   - `serde_without_deny_unknown_fields`
   - `allow_clippy_escapes`
3. 建立统一 allowlist 文件，禁止业务代码散落 `#[allow(clippy::...)]`。
4. 落一份 `runtime_contract.md`，明确：
   - RuntimeContext 是唯一依赖入口
   - manager owner-task 模式
   - `TaskRegistry` / `ShutdownCoordinator` 约束
   - control plane 只能查快照

### 完美实践下的联调修复要求

- 任何后续 PR，如果新增了一个 dropped spawn，即使功能正确，也必须被 CI 挡住。
- 任何新增全局静态，即使只是“方便临时调试”，也必须被 CI 挡住。
- runtime contract 必须能被 review checklist 明确对照，而不是靠口头约定。

### 验收标准

- CI 可以在 PR 上显示审计 diff
- 业务代码不再新增局部 clippy allow
- 新增债务会红灯
- 架构约束文档落库并被引用到贡献指南

---

## WP-10: RuntimeContext / KernelRuntime / ServicePorts 主干落地

- **归属阶段**：Phase 1
- **聚焦 Layer**：Layer 1 + Layer 3
- **建议先读**：`singbox_rust_audit_report.md` §4.1, §4.6, §5.1, §5.3, §6.2
- **目标**：建立全仓统一的运行时承载容器

### 首批触达文件

- `app/src/bootstrap.rs`
- `app/src/run_engine.rs`
- `app/src/main.rs`（若存在，仅保持极薄）
- `crates/sb-core/src/runtime/supervisor.rs`
- 新增：`crates/sb-core/src/runtime/{context,kernel,task_registry,shutdown}.rs`

### 处理的问题

- 组合根过厚，[AUDIT-4.6]
- 后续去 globals、去 dropped spawn 都缺承接容器
- 当前 runtime owner 和 service ports 没有统一抽象

### 必做任务

1. 定义 `RuntimeContext`，显式持有：
   - providers / registries / managers / shutdown components
2. 定义 `KernelRuntime` 或 `AppRuntime` 组合对象，作为 bootstrap 的构建结果。
3. 定义 `ServicePorts`，区分：
   - write path handles
   - read-only query ports
4. bootstrap 只负责：
   - 加载配置
   - 生成 `RuntimePlan`
   - 构建 runtime
   - 启动 runtime
   - 等待关闭
5. 所有新代码禁止再通过 global 获取基础设施依赖。

### 完美实践下的联调修复要求

- 启动顺序与关闭顺序必须显式编码，而不是隐含在多个模块 init side-effect 中。
- runtime 的“可替换性”要成立，未来单元测试 / 集成测试 / 场景测试应能注入 fake provider。
- `main.rs` 只保留参数解析、tokio 初始化、顶层错误处理，符合 [RULE-L2]。

### 验收标准

- `bootstrap.rs` / `run_engine.rs` 中不再直接拼装随机 global
- 新的 runtime 构造路径清晰可追踪
- 测试可直接实例化最小 runtime skeleton

---

## WP-11: TaskRegistry / CancellationToken / ShutdownCoordinator 落地

- **归属阶段**：Phase 1
- **聚焦 Layer**：Layer 3
- **建议先读**：`singbox_rust_audit_report.md` §4.2, §5.2, §6.1, §8
- **目标**：为后续清理 dropped spawn 提供统一承接层

### 首批触达文件

- `crates/sb-core/src/runtime/supervisor.rs`
- `app/src/logging.rs`
- `app/src/admin_debug/http_server.rs`
- `crates/sb-core/src/services/derp/server.rs`
- `crates/sb-adapters/src/inbound/{socks/udp.rs,shadowsocks.rs,anytls.rs,ssh.rs}`
- `crates/sb-adapters/src/outbound/{anytls.rs,ssh.rs}`
- `crates/sb-transport/src/{grpc.rs,multiplex.rs,wireguard.rs}`

### 处理的问题

- `spawn_unhandled` 152 处，[AUDIT-A/spawn_unhandled]
- graceful shutdown 没有统一 choreography，[RULE-L3]

### 必做任务

1. 设计 `TaskRegistry`：
   - `spawn_tracked(name, scope, future)`
   - 收集 `JoinHandle`
   - 记录 task 名称、来源模块、取消策略
2. 设计分层取消：
   - app 级 token
   - service 级 token
   - connection / session 级 token
3. 定义 shutdown 流程：
   - stop acceptors
   - 广播 cancel
   - drain command channels
   - join handles
   - 超时后强退
4. 禁止新的裸 `tokio::spawn(...)`；统一包进 registry helper。

### 完美实践下的联调修复要求

- 联调时必须能回答“当前还有哪些活跃后台任务、属于哪个 subsystem、关闭时卡在哪一步”。
- panic 于后台 task 时必须被观测和汇总，而不是沉入黑盒。

### 验收标准

- 新增的后台任务都有名字、归属、取消路径
- 关键服务支持优雅关闭测试
- `spawn_unhandled` 在首批核心链路开始下降

---

## WP-20: 核心基础设施去全局化

- **归属阶段**：Phase 2
- **聚焦 Layer**：Layer 1 + Layer 3
- **建议先读**：`singbox_rust_audit_report.md` §4.1, §5.3, §7
- **目标**：先拔掉“基础设施单例网”的总开关

### 首批目标文件

- `crates/sb-metrics/src/lib.rs`
- `crates/sb-core/src/metrics/registry_ext.rs`
- `crates/sb-core/src/http_client.rs`
- `crates/sb-core/src/geoip/mod.rs`
- `app/src/logging.rs`
- `app/src/admin_debug/prefetch.rs`
- `app/src/admin_debug/security_metrics.rs`
- `crates/sb-tls/src/global.rs`（作为第二批）

### 处理的问题

- `static_once_lock` / `static_lazy_lock` / `static_once_cell` 高密度命中，[AUDIT-3.2], [AUDIT-4.1]
- 典型 backlog 已在 [AUDIT-7] 点名

### 2026-03-25 优先级校正（updated）

- **已完成**：`crates/sb-core/src/http_client.rs` — hard global singleton 已删（`d3a0b1e7`），仅剩 weak-owner compat
- **已完成**：`crates/sb-core/src/geoip/mod.rs` — `GEOIP_SERVICE` / `init()` / `service()` 已删除，仅剩 weak-owner compat
- **已完成**：`app/src/admin_debug/prefetch.rs` — `GLOBAL` / `global()` / `global_take()` 已删除，worker lifecycle 改为 tracked dispatcher + CancellationToken + JoinSet，仅剩 weak-owner compat
- **第二波**：`app/src/logging.rs`、`app/src/admin_debug/security_metrics.rs`
- **第三波**：`crates/sb-metrics/src/lib.rs`、`crates/sb-core/src/metrics/registry_ext.rs`

说明：

- `http_client.rs` 的 `GLOBAL_HTTP_CLIENT` / `install_http_client()` / `global_http_client()` 已在 2026-03-25 维护任务中删除。`http_execute()` 不再有 hard global fallback，只走 weak-owner lookup。剩余 compat 是 `DEFAULT_HTTP_CLIENT` weak 注册表，等后续 `RuntimeContext` 落地后统一收口。
- `logging.rs` 与 `security_metrics.rs` 当前仍有 compat 壳，但已不是原始审计时期那种”主链继续扩散的散点全局”。
- `sb-metrics` / `registry_ext` 仍需治理，但在维护模式下更接近 Prometheus 设计债与局部 leak/fallback 债，不宜继续排在 `prefetch` 之前。

### 必做任务

1. Metrics
   - 移除默认 global registry
   - 建 `MetricsRegistryOwner` / `MetricsHandle`
   - `registry_ext` 改为 owned cache，不允许 `Box::leak`
2. Http client
   - 引入 `HttpClientProvider`
   - 所有调用点从 `RuntimeContext` 获取 client
3. GeoIP
   - 引入 `GeoIpProvider`
   - 删除 `DEFAULT_GEOIP_SERVICE` / `GEOIP_SERVICE` 式全局路径
4. Logging
   - `ACTIVE_RUNTIME` 改成 `LoggingSupervisor`
   - signal / watcher task 纳入 `TaskRegistry`
5. Prefetch / security metrics
   - 变成 actor service
   - control plane 经 handle/query 访问
6. compat 过渡
   - 新代码严禁调用 legacy global
   - 老代码经 `compat::*` 桥接

### 完美实践下的联调修复要求

- 任何 subsystem 的依赖来源都应在 runtime 构造图中一眼可见。
- 测试可构造隔离的 metrics/http/geoip 实例，不受进程级污染。
- 热重载或多 runtime 场景下，不能出现“第二次初始化污染第一次实例”的现象。

### 验收标准

- 首批模块不再直接暴露 mutable global 入口
- compat 层数量有限且已登记删除计划
- 相关静态状态命中显著下降，最好在这些文件清零

---

## WP-30: 配置三相模型重构（Raw / Validated / RuntimePlan）

- **归属阶段**：Phase 3
- **聚焦 Layer**：Layer 3 + Layer 4
- **建议先读**：`singbox_rust_audit_report.md` §4.5, §5.1, §5.4, §7, §8
- **目标**：彻底切断“serde struct 直接下沉 runtime”的链路

### 首批目标文件

- `crates/sb-config/src/ir/mod.rs`
- `crates/sb-config/src/validator/v2.rs`
- `crates/sb-config/src/outbound.rs`
- `crates/sb-config/src/model.rs`
- `crates/sb-core/src/routing/ir.rs`
- `crates/sb-api/src/v2ray/mod.rs`
- `crates/sb-api/src/types.rs`
- `crates/sb-runtime/src/scenario.rs`
- `crates/sb-core/src/geoip/mmdb.rs`

### 处理的问题

- `serde_without_deny_unknown_fields` 261，[AUDIT-A/serde_without_deny_unknown_fields]
- `sb-config/src/ir/mod.rs` 单文件 51 处缺失，[AUDIT-3.2]
- 原始 `String/Option<String>` 裸奔，[AUDIT-4.5]
- validator / IR 巨石，[AUDIT-3.1], [AUDIT-5.4]

### 2026-03-25 核验说明

- 这一组结论在当前仓库上 **没有被维护期修正推翻**。
- ~~`crates/sb-config/src/outbound.rs` 仍是直接 `Deserialize` 的 Raw 边界模型。~~ → ✅ 2026-03-26 已完成 Raw/Validated 边界试点（`deny_unknown_fields` + 自定义 `Deserialize` via Raw bridge）
- `crates/sb-config/src/ir/mod.rs` 仍是 3755 LOC 巨石，未完成 Raw / Validated / Planned 三相拆分。
- `crates/sb-config/src/validator/v2.rs` 仍是 5384 LOC 巨石校验器。

因此 `WP-30` / `WP-31` 仍是中期主线，不建议因为 `logging` / `security_metrics` 的 compat 壳残留而后移。

### 必做任务

1. 按 [AUDIT-5.4] 建目录：
   - `ir/raw.rs`
   - `ir/validated.rs`
   - `ir/planned.rs`
   - `ir/normalize.rs`
2. 所有外部输入结构改名为 `Raw*`，并统一：
   - `#[serde(deny_unknown_fields)]`
   - 显式 `#[serde(default)]` 或 `Option<T>`
3. 建 `Validated*` 领域类型：
   - tag / endpoint / route rule / protocol kind / auth scheme / tls mode 等应尽量 newtype / enum 化
4. 建 `RuntimePlan`：
   - 解析默认值
   - tag 唯一性
   - 引用解析
   - DNS/FakeIP/route/outbound/service 规划
5. 将 runtime 入口改成接收 `RuntimePlan`，不再接受 serde 派生类型。
6. 统一错误：
   - raw parse error
   - validation error
   - planning error

### 完美实践下的联调修复要求

- 联调时出现配置问题，必须能明确告诉使用者：是**解析失败**、**字段非法**、还是**依赖解析冲突**。
- `sb-api/v2ray` / 场景测试 / 配置文件输入必须共享同一套验证语义，而不是每条路径自己补丁式修一遍。
- router / dns / service manager 不再理解“原始配置语义”，只消费 `RuntimePlan`。

### 验收标准

- 新增的 runtime builder 只接受 `ValidatedConfig` / `RuntimePlan`
- 首批 Raw 结构全部 `deny_unknown_fields`
- `validator/v2.rs` 和 `ir/mod.rs` 被拆分成稳定子模块

---

## WP-31: validator / planner 拆分与规则归位

- **归属阶段**：Phase 3
- **聚焦 Layer**：Layer 3
- **建议先读**：`singbox_rust_audit_report.md` §3.1, §5.4, §7
- **目标**：把 5375 LOC 校验器从“巨型神函数”拆回规则域

### 目标模块结构

- `validator/v2/root.rs`
- `validator/v2/dns.rs`
- `validator/v2/route.rs`
- `validator/v2/inbound.rs`
- `validator/v2/outbound.rs`
- `validator/v2/service.rs`
- `validator/v2/endpoint.rs`

### 必做任务

1. 先按领域切，再按阶段切：
   - normalize
   - validate
   - plan hooks
2. 每个子模块输出具名错误枚举或错误子域。
3. 把 cross-cutting 规则抽成共享 helper，例如：
   - tag uniqueness
   - endpoint reference resolution
   - TLS/profile compatibility
   - DNS / route dependency checks
4. 为每个规则子域建立 fixture tests。

### 验收标准

- `validator/v2.rs` 不再承担巨型集散地角色
- 新规则新增位置可预测
- 错误信息能映射到具体子域

---

## WP-40: Manager Actor 化基座

- **归属阶段**：Phase 4
- **聚焦 Layer**：Layer 3
- **建议先读**：`singbox_rust_audit_report.md` §4.2, §4.3, §5.2, §8
- **目标**：建立统一 manager runtime discipline

### 首批目标文件

- `crates/sb-core/src/inbound/manager.rs`
- `crates/sb-core/src/outbound/manager.rs`
- `crates/sb-core/src/service.rs`
- `crates/sb-core/src/runtime/supervisor.rs`
- `crates/sb-api/src/managers.rs`
- `crates/sb-api/src/monitoring/bridge.rs`

### 处理的问题

- 锁跨 await 高密度集中于 manager 链路，[AUDIT-3.2], [AUDIT-A/lock_cross_await]
- manager 更像共享状态注册表，而不是 owner task，[AUDIT-5.2]

### 必做任务

1. 统一 manager 形态：
   - `Handle`
   - `Command`
   - `Query`
   - `Owner`
   - `Snapshot`
2. 明确状态机：
   - `Constructed`
   - `Prepared`
   - `Started`
   - `Stopping`
   - `Stopped`
3. 外部交互只走 channel / oneshot，不共享内部状态锁。
4. Query 返回 snapshot，而不是借用内部可变状态。
5. 所有 owner task 统一注册到 `TaskRegistry`。

### 完美实践下的联调修复要求

- 调试“某个 outbound 当前是否 healthy”时，不需要直接摸内部锁；应通过 query API 获取快照。
- reload / shutdown 时，manager 不应因为外部还持有锁或引用而卡死。

### 验收标准

- 目标 manager 的内部状态从共享锁迁移到 owner task
- `lock_cross_await` 在这些文件中显著下降或清零
- start/stop/reload 有单测或集成测覆盖

---

## WP-41: 关键网络子系统的任务与锁整改

- **归属阶段**：Phase 4 与 Phase 5 之间
- **聚焦 Layer**：Layer 3 + Layer 1
- **建议先读**：`singbox_rust_audit_report.md` §3.2, §4.2, §4.3, §7, 附录 A
- **目标**：优先修联调时最容易炸的链路

### 首批目标文件

- `crates/sb-adapters/src/outbound/ssh.rs`
- `crates/sb-adapters/src/outbound/anytls.rs`
- `crates/sb-transport/src/wireguard.rs`
- `crates/sb-core/src/net/udp_processor.rs`
- `crates/sb-core/src/services/derp/server.rs`
- `crates/sb-adapters/src/inbound/{socks/udp.rs,shadowsocks.rs,anytls.rs,ssh.rs}`
- `app/src/admin_debug/http_server.rs`

### 必做任务

1. SSH / AnyTLS
   - 拆 session / pool owner task
   - 不允许持锁跨 `await`
   - 连接桥接 task 必须 tracked
2. WireGuard / UDP processor
   - 先拍快照，再 `await`
   - 如有明确 owner，改为消息驱动
3. DERP server / http_server
   - accept loop task tracked
   - per-connection spawn tracked / scoped
4. inbound UDP / shadowsocks
   - 把“读包 -> 分发 -> 回写”拆成明确生命周期节点

### 2026-03-25 核验说明

- ~~`app/src/admin_debug/http_server.rs`~~ — **已收口**（2026-03-25）：accept loop 改为 `JoinSet` + `CancellationToken`，per-connection tracked，`AdminDebugHandle` + runtime shutdown 已接入。
- ~~`crates/sb-adapters/src/outbound/anytls.rs`~~ — **已收口**（2026-03-26）：`SessionRuntime` owner + `AbortHandle` Drop，`get_or_create_session()` 三阶段锁无 lock-across-await，bridge tasks 改为 `JoinSet` tracked，loopback accept 无 spawn。
- ~~`crates/sb-adapters/src/outbound/ssh.rs`~~ — **已收口**（2026-03-26）：session lock 消除（`Arc<PostAuthSession>` 最小能力封装，handle 私有，仅暴露 `open_direct_tcpip()`；`unsafe impl Sync` 仅服务于该方法），pool 三阶段锁无 lock-across-await，bridge tasks 改为 `JoinSet` tracked，零 `tokio::spawn`。

`WP-41` 中 http_server + anytls + ssh 部分均已关闭。

### 完美实践下的联调修复要求

- 网络高并发下，不能因为锁竞争与 await 交错导致隐性死锁或尾延迟飙升。
- 连接生命周期、会话池生命周期、后台桥接生命周期必须都可观测。

### 验收标准

- 关键目标文件的 `spawn_unhandled` 和 `lock_cross_await` 下降到可接受水平，最好清零
- 关闭时不会残留后台连接桥接 task
- 压测下可验证无明显 shutdown hang

---

## WP-50: 热路径 panic 清零与不变量类型化

- **归属阶段**：Phase 5
- **聚焦 Layer**：Layer 1
- **建议先读**：`singbox_rust_audit_report.md` §4.4, §7, 附录 A/unwrap, A/expect, A/todo_unimpl_unreachable
- **目标**：把“会炸”的热点从运行时移走，塞回类型系统或错误系统

### 首批目标文件

- `crates/sb-core/src/inbound/tun.rs`
- `crates/sb-core/src/outbound/optimizations.rs`
- `crates/sb-core/src/adapter/registry.rs`
- `crates/sb-core/src/context.rs`
- `crates/sb-core/src/inbound/loopback.rs`
- `crates/sb-adapters/src/inbound/tun/platform/linux.rs`
- `crates/sb-adapters/src/inbound/tun/platform/macos.rs`
- `crates/sb-metrics/src/lib.rs`
- `crates/sb-core/src/services/cache_file.rs`
- `app/src/http_util.rs`
- `crates/sb-core/src/metrics/{udp.rs,udp_v2.rs}`
- `crates/sb-adapters/src/outbound/shadowtls.rs`

### 必做任务

1. 把 `unwrap/expect` 分三类处理：
   - 真正错误传播：改 `?` / `map_err` / 具名错误枚举
   - 逻辑不变量：引入 newtype / enum / builder 保证构造期成立
   - 资源状态竞争：引入显式状态检查或快照
2. `tun.rs`
   - 抽 `SessionTable`
   - 明确容量、锁中毒、状态切换错误
3. `outbound/optimizations.rs`
   - 全局 buffer pool 改为 per-runtime owned arena / pool
4. `cache_file.rs` / `http_util.rs`
   - 去 `expect` 风格兜底
5. `shadowtls.rs`
   - `todo/unreachable` 改具名错误

### 完美实践下的联调修复要求

- 热路径不能因为一个“理论上不会失败”的假设而直接炸进程。
- 如果某个状态理论上不可能，必须在构造期编码，而不是在执行期用 `unwrap` 赌。

### 验收标准

- 首批热点文件中 `unwrap/expect/todo/unreachable` 清零
- 错误能够被上层区分并记录
- 关键链路具备回归测试

---

## WP-51: unsafe 收口与边界测试

- **归属阶段**：Phase 5
- **聚焦 Layer**：Layer 3 + Layer 4
- **建议先读**：`singbox_rust_audit_report.md` 附录 A/unsafe_missing_safety_comment
- **目标**：给所有 unsafe 建立精确安全边界叙述

### 首批目标文件

- `crates/sb-platform/src/tun/macos.rs`
- `crates/sb-adapters/src/inbound/tun/mod.rs`
- `crates/sb-core/src/router/{context_pop.rs,conn.rs}`
- `crates/sb-platform/src/{monitor.rs,network.rs,tun/linux.rs,process/native_windows.rs}`
- `crates/sb-transport/src/dialer.rs`

### 必做任务

1. 每个 unsafe 块正上方补 `// SAFETY:`，说明：
   - 依赖什么不变量
   - 为什么当前上下文满足
   - 谁维护这个不变量
2. 给 unsafe 边界补测试：
   - 参数边界
   - 生命周期边界
   - 平台行为边界
3. 如 unsafe 过大，先缩作用域再写注释。

### 验收标准

- `unsafe_missing_safety_comment` 清零
- 相关边界测试能解释 unsafe 的依赖假设

---

## WP-60: Control Plane 解耦与快照读取化

- **归属阶段**：Phase 6
- **聚焦 Layer**：Layer 1 + Layer 3 + Layer 4
- **建议先读**：`singbox_rust_audit_report.md` §4.1, §4.3, §8
- **目标**：让 `admin_debug` / `sb-api` 只做控制面，不再偷偷变成 runtime owner 的旁路

### 首批目标文件

- `app/src/admin_debug/*`
- `app/src/router/mod.rs`
- `app/src/admin_debug/http_util.rs`
- `crates/sb-api/src/managers.rs`
- `crates/sb-api/src/monitoring/{bridge.rs,reporter.rs}`
- `crates/sb-api/src/v2ray/{mod.rs,simple.rs,server.rs}`
- `crates/sb-api/src/types.rs`

### 处理的问题

- admin/API 大量 public surface 缺 docs / must_use
- 部分路径直接触 runtime 状态或 global
- wildcard import / debug output / let _ 也在这些控制面模块有明显分布

### 必做任务

1. 定义只读 query traits：
   - `RuntimeSnapshotQuery`
   - `MetricsReadPort`
   - `RouteReadPort`
   - `DnsReadPort`
   - `ServiceStateReadPort`
2. `admin_debug` / `sb-api` 只依赖 read ports，不依赖具体 owner 内部状态。
3. 控制面输出统一：
   - HTTP/JSON 响应层处理错误
   - CLI 才做最终人类可读格式化
4. 清理：
   - wildcard imports
   - debug output
   - 散落 `let _ =`
   - public API 的 docs / `#[must_use]`

### 完美实践下的联调修复要求

- 控制面查询不能改变运行时状态，除非通过显式命令接口。
- 控制面不应为了“方便”引入新的全局状态或隐式后台任务。
- 在联调现场，debug 页面与 API 页面读到的是**同一快照语义**，而不是不同模块各读各的状态。

### 验收标准

- `admin_debug` / `sb-api` 不再偷读 global
- 核心接口文档和 must_use 在触达面补齐
- 控制面操作与数据面 owner 的边界清楚

---

## WP-61: Mega-file 拆分、路径与 API 表面治理

- **归属阶段**：Phase 6
- **聚焦 Layer**：Layer 2 + Layer 4
- **建议先读**：`singbox_rust_audit_report.md` §3.1, §5.4, §7
- **目标**：用模块边界重建可维护性，而不是只做格式化手术

### 首批目标文件

- `app/src/bootstrap.rs`
- `app/src/run_engine.rs`
- `crates/sb-config/src/validator/v2.rs`
- `crates/sb-config/src/ir/mod.rs`
- `crates/sb-core/src/dns/upstream.rs`
- `crates/sb-core/src/router/mod.rs`
- `crates/sb-core/src/router/engine.rs`
- `crates/sb-api/src/v2ray/mod.rs`
- `app/src/router/mod.rs`

### 必做任务

1. 按 [AUDIT-5.4] 的建议目录拆分：
   - `bootstrap/{config,compose,services,startup}.rs`
   - `run_engine/{load,build,run,report}.rs`
   - `validator/v2/{root,dns,route,inbound,outbound,service,endpoint}.rs`
   - `ir/{raw,validated,planned,normalize}.rs`
   - `dns/upstream/{exchange,cache,transport,rules}.rs`
   - `router/{engine,planner,context,conn,rules}.rs`
2. 拆分过程中同步治理：
   - `super::` -> `crate::`
   - 非 facade 的 `pub use` 回收
   - `pub fn(Result/Option)` 标 `#[must_use]`
   - 为公开项补 docs
3. 明确 facade 模块的公开意图，避免随意再导出。

### 完美实践下的联调修复要求

- 任何一个子模块应能清楚回答：自己是 raw/validate/plan/runtime/control plane 的哪一层。
- 同一文件不要同时做“类型定义 + 验证 + 运行时装配 + HTTP 输出格式化”。

### 2026-03-25 核验说明

- `app/src/bootstrap.rs`、`app/src/run_engine.rs`、`crates/sb-core/src/dns/upstream.rs`、`crates/sb-core/src/router/mod.rs` 的 mega-file 判断仍成立。
- 但 `bootstrap.rs` / `run_engine.rs` 至少已有一部分 `JoinHandle` / shutdown 承接，不应把它们和裸全局 / 裸 spawn 主链放在同一优先级。
- 因此 `WP-61` 仍然重要，但排序应稳定在 `WP-20` / `WP-41` 之后，而不是抢前。

### 验收标准

- 目标 mega-file 明显瘦身
- 路径引用与 API 表面更稳定
- must_use/docs/super_path/pub_use 命中显著下降

---

## WP-70: Toolchain 强制化与最终收口

- **归属阶段**：Phase 7
- **聚焦 Layer**：Layer 4，收口全层
- **建议先读**：`34524458-593a-401f-bec1-0ab2fe0787df.md` Layer 4, `singbox_rust_audit_report.md` §6.1, §9
- **目标**：把前面阶段的“约定”变成仓库级刚性边界

### 必做任务

1. 打开：
   - `#![deny(missing_docs)]`
   - `#![deny(unused_must_use)]`
2. CI 固定执行：
   - `cargo fmt --check`
   - `cargo clippy -- -D warnings`
   - 文档测试
   - 静态审计 ratchet
3. 明确 central allowlist：
   - 哪些 clippy lint 因项目现实被豁免
   - 统一写在根配置里并附理由
4. 最终 conformance 清单：
   - Layer 1 全清零
   - Layer 2 主要项清零
   - Layer 3 关键生命周期项清零
   - Layer 4 gate 生效

### 完美实践下的联调修复要求

- 新人 agent 不需要理解全部历史，也能靠工具链避免把旧病带回来。
- 所有例外都可追踪、可审计、可讨论。

### 验收标准

- 仓库默认 CI 就是规则执行者
- 关键 lint/审计项不再依赖人工 review 兜底
- 最终审计报告可对照 Layer 1-4 逐条说明满足情况

---

## 6. 推荐的 PR / 迭代切片

为了降低冲突，建议按如下切片推进，而不是搞一个超级长分支：

1. **PR-01**: `WP-00` 审计脚本 + ratchet + runtime contract 文档
2. **PR-02**: `WP-10` RuntimeContext / KernelRuntime skeleton
3. **PR-03**: `WP-11` TaskRegistry / ShutdownCoordinator / tracked spawn helper
4. **PR-04**: `WP-20a` metrics / registry_ext 去全局化
5. **PR-05**: `WP-20b` http_client / geoip / logging 去全局化
6. **PR-06**: `WP-20c` prefetch / security_metrics actor 化
7. **PR-07**: `WP-30a` `ir/raw + validated + planned` 骨架
8. **PR-08**: `WP-31` validator 拆分
9. **PR-09**: `WP-30b` API / scenario / v2ray 边界接入新模型
10. **PR-10**: `WP-40` manager actor 基座
11. **PR-11**: `WP-41a` outbound/ssh + outbound/anytls + wireguard
12. **PR-12**: `WP-41b` derp/http_server/inbound UDP 系列
13. **PR-13**: `WP-50` tun / optimizations / hotspot panic 清零
14. **PR-14**: `WP-51` unsafe 注释与边界测试
15. **PR-15**: `WP-60` admin_debug / sb-api control plane 解耦
16. **PR-16**: `WP-61` mega-file 拆分与 API 表面治理
17. **PR-17**: `WP-70` toolchain hard close + 最终 conformance 审计

---

## 7. coding agent 的执行规则

### 7.1 每个 Workpackage 都必须交付四类产物

1. **代码变更**
2. **测试变更**
3. **架构注释 / 模块文档**
4. **审计 diff 说明**

### 7.2 每个 Workpackage 提交前都要回答五个问题

1. 这个改动消灭了哪个 Layer 的什么问题？
2. 它依赖哪个上游骨架已经存在？
3. 它会不会引入新的 compat 债务？若会，删除计划是什么？
4. 它的 shutdown / reload / error propagation 是否更清楚？
5. 它有没有让控制面与数据面的边界更清楚？

### 7.3 明确禁止的“伪修复”

- 为了消灭 `spawn_unhandled`，把 `JoinHandle` 存进某个没人 join 的 `Vec`
- 为了消灭 global，换成 `Arc<Mutex<_>>` 再到处传
- 为了消灭 `unwrap`，改成 `.ok()` / `.err()` 然后静默丢错误
- 为了通过 docs gate，写空洞注释
- 为了通过 `deny_unknown_fields`，把所有字段都改成 `Option<String>`
- 为了消灭 `super::`，引入更多无意义 `pub use`

---

## 8. 最终出口标准

### Layer 1 出口

- 生产代码 `unwrap/expect/panic/todo/unreachable = 0`
- 可变 global 清零，或仅残留在过渡 compat 层且有明确删除计划

### Layer 2 出口

- wildcard imports 清零
- debug output 清零
- `let _ =` 全部显式处理
- `&PathBuf` 改为 `&Path`

### Layer 3 出口

- `spawn_unhandled = 0`
- `lock_cross_await = 0`
- manager lifecycle 有测试验证
- graceful shutdown 可证明

### Layer 4 出口

- `missing_docs = deny`
- `unused_must_use = deny`
- `clippy -D warnings`
- `deny_unknown_fields` / `#[must_use]` 在边界与公开 API 上成体系执行

---

## 9. 给 coding agent 的最短行动路径

如果你希望 agent 先从“最值回票价”的路径开始，直接按下面顺序：

1. `WP-00`
2. `WP-10`
3. `WP-11`
4. `WP-20`
5. `WP-30` + `WP-31`
6. `WP-40`
7. `WP-41`
8. `WP-50` + `WP-51`
9. `WP-60`
10. `WP-61`
11. `WP-70`

这条路径与 `singbox_rust_audit_report.md` §6.2 的逻辑一致，优先切断联调风险传导链，而不是优先清表面 lint。
