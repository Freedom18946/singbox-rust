# L3 前置信息收集与差距分析（Polish / Edge Services + Quality）

> **日期**：2026-02-08  
> **用途**：为 L3 阶段开工前提供“现状-差距-落点文件-最小验收”清单，避免边做边考古。  
> **范围来源**：`agents-only/active_context.md` 的 L3 scope（L3.1~L3.5） + `agents-only/03-planning/06-STRATEGIC-ROADMAP.md` 的质量里程碑（M3.1~M3.3）。

---

## 0. 当前状态快照

- 当前阶段：L3 Polish / Edge Services（L1 ✅ Closed, L2 ✅ Closed）见 `agents-only/active_context.md`
- L3 工作包：
  - L3.1 SSMAPI 对齐（PX-011）
  - L3.2 DERP 配置对齐（PX-014）
  - L3.3 Resolved 完整化（PX-015）
  - L3.4 Cache File 深度对齐（PX-009/013）
  - L3.5 ConnMetadata chain/rule 填充（L2.8 延后）

---

## 1. L3.1 SSMAPI 对齐（PX-011）

### 1.1 Rust 现状（已读代码定位）

- 实现位置：
  - `crates/sb-core/src/services/ssmapi/mod.rs`
  - `crates/sb-core/src/services/ssmapi/server.rs`
  - `crates/sb-core/src/services/ssmapi/api.rs`
  - `crates/sb-core/src/services/ssmapi/user.rs`
  - `crates/sb-core/src/services/ssmapi/traffic.rs`
  - 入站侧：`crates/sb-adapters/src/inbound/shadowsocks.rs`（`ManagedSSMServer` + `TrafficTracker`）
- 配置字段（IR）：
  - `crates/sb-config/src/ir/mod.rs`：`ServiceIR.servers`（endpoint -> inbound_tag）, `ServiceIR.cache_path`, `ServiceIR.tls`, `ServiceIR.listen*`

### 1.2 关键差距（对照 Go 行为）

Go 参考：
- `go_fork_source/sing-box-1.12.14/service/ssmapi/server.go`
- `go_fork_source/sing-box-1.12.14/service/ssmapi/cache.go`

差距结论（以“可导致功能不可用/偏差”优先排序）：
- **未做 per-endpoint inbound 绑定**：Go 在 `NewService()` 中按 `servers` 映射逐条：
  - 通过 `InboundManager.Get(tag)` 找 inbound
  - 校验 `adapter.ManagedSSMServer`
  - `managedServer.SetTracker(traffic)`
  - `NewUserManager(managedServer, traffic)`
  - 按 endpoint mount API routes
  Rust `SsmapiService` 当前仅创建单一 `UserManager`/`TrafficManager`，并未按 `servers` 查找/绑定 inbound，也未调用 `ManagedSSMServer::set_tracker()`（导致 SS inbound 的 tracker 永远是 `None`）。
- **Cache JSON 格式不一致**：Go cache 字段是 snake_case（如 `global_uplink`），Rust 当前使用了 camelCase（如 `globalUplink`，见 `EndpointCache` 上 `rename = "globalUplink"`），会导致与 Go/GUI 的缓存文件不兼容。
- **缺少周期性保存**：Go `Start()` 启动后 `time.NewTicker(1m)` 周期 `saveCache()`；Rust 当前只在 `Close()` 时保存（中途崩溃/kill 会丢统计与用户映射）。
- **每 endpoint 独立 Traffic/User 管理**：Go 的 `traffics/users` 是 endpoint 级别 map；Rust API state 当前是全局单例（无法做到“endpoint 维度”隔离）。

### 1.3 落点建议（最小变更路径）

- 服务侧：
  - 让 `SsmapiService` 按 `servers` 构造 `endpoint -> (traffic_manager, user_manager, inbound_tag)` 的表，并在启动前完成绑定：
    - 从 Rust 的 `InboundManager` 拉取 inbound 实例（候选：`crate::context::context_registry().inbound_manager`，或在 `ServiceContext` 显式注入 inbound_manager 句柄）。
    - 对 inbound 做 `ManagedSSMServer` trait object 适配/暴露，调用 `set_tracker() / update_users()`
- API 侧：
  - 路由仍可按 endpoint mount，但 state 需按 endpoint 选择对应的 manager（而非全局单例）
- Cache 侧：
  - 改为 Go 的 snake_case 字段名，补齐“增量变化才写盘”的逻辑（Go 用 `lastSavedCache` 比对）
  - 增加后台定时保存（tokio interval 或独立任务）

### 1.4 最小验收（建议）

- 单元/集成测试（不需要真实网络）：
  - 为 `ManagedSSMServer` 提供 test stub：验证 `set_tracker()` 被调用、`update_users()` 被调用
  - 验证每 endpoint 的 stats 隔离（A endpoint 的 traffic 不影响 B）
  - cache 编解码 round-trip 与 Go 字段名一致（至少断言 JSON key）

---

## 2. L3.2 DERP 配置对齐（PX-014）

### 2.1 Rust 现状（已读代码定位）

- 实现位置：
  - `crates/sb-core/src/services/derp/server.rs`（HTTP handler 包含 `/derp`、`/bootstrap-dns`、mesh、probe 等）
- 配置字段（IR）：
  - `crates/sb-config/src/ir/mod.rs`：`ServiceIR`（`config_path/verify_client_* / mesh_* / stun / tls / listen*`）
- 当前行为要点（从代码直接可见）：
  - `/bootstrap-dns` 使用 `crate::dns::global::get()`（全局 resolver），没有按 DERP 的 dialer/TLS/路由选项定制
  - `verify_client_url` 是 `Vec<String>`（只有 URL，没有 dialer options）
  - `mesh_with` 是 `Vec<String>`（只有 peer 列表，没有 dialer/TLS 选项）
  - STUN 默认：未配置 `stun` 时走 `(true, listen_addr)`（即“默认启用且端口=DERP listen_port”）
  - ListenOptions（bind_interface / routing_mark / netns / reuse_addr 等）目前未用于 socket bind 路径

### 2.2 关键差距（对照 Go 行为）

Go 参考：
- `go_fork_source/sing-box-1.12.14/service/derp/service.go`

差距要点（直接对应 GO_PARITY_MATRIX 的 PX-014 结论）：
- `verify_client_url` 在 Go 是结构体数组，包含 dialer options，且为每条 URL 构造独立 `http.Client` + `DialContext`
- `mesh_with` 在 Go 是结构体数组，包含 dialer options（以及与 TLS/RootCA/TimeFunc 相关的连接语义）
- STUN 默认值/ListenOptions honored 的语义需要与 Go 对齐（尤其是默认 listen addr/port 及是否开启）
- `/bootstrap-dns` 需要与 Go 的 handler 行为一致（Go 走 `handleBootstrapDNS(ctx)`，依赖更完整的上下文能力）
- HTTP/2/h2c 处理方式需确认与 Go（`derphttp` + `h2c`）一致（Rust 目前是自实现 hyper 路由）

### 2.3 落点建议（先“schema”后“runtime”）

1. **先对齐配置 schema（IR）**：
   - 将 `ServiceIR.verify_client_url` 从 `Vec<String>` 升级为 `Vec<DerpVerifyClientUrlIR>`（包含 URL + DialerOptions + “server_is_domain”等必要字段）
   - 将 `ServiceIR.mesh_with` 从 `Vec<String>` 升级为 `Vec<DerpMeshPeerIR>`（peer + DialerOptions + TLS 相关）
2. **再对齐 runtime 行为**：
   - `/bootstrap-dns` 走 DNSRouter/可注入 resolver（而不是全局 resolver）
   - ListenOptions 用于 TCP/UDP bind（至少 bind_interface/routing_mark/netns/reuse_addr）
   - STUN 默认策略与 Go 一致（并补齐测试）

---

## 3. L3.3 Resolved 完整化（PX-015）

### 3.1 Rust 现状（已读代码定位）

- D-Bus server（Manager 接口）：`crates/sb-adapters/src/service/resolve1.rs`
  - 已实现：`SetLinkDNS/SetLinkDNSEx/SetLinkDomains/SetLinkDefaultRoute/SetLinkDNSOverTLS`
  - 大量方法仍是 stub
- Resolved service：`crates/sb-adapters/src/service/resolved_impl.rs`
  - 当前实现包含 D-Bus client 调用 `ResolveHostname`（连接到系统 `org.freedesktop.resolve1`），并以 UDP stub 监听提供 DNS 服务
- DNS transport（消费 per-link 配置的共享状态）：`crates/sb-core/src/dns/transport/resolved.rs`（`RESOLVED_STATE`）

### 3.2 关键差距（对照 Go 行为）

Go 参考：
- `go_fork_source/sing-box-1.12.14/service/resolved/resolve1.go`

Go 的 `org.freedesktop.resolve1.Manager` 还实现了：
- `ResolveHostname`
- `ResolveAddress`
- `ResolveRecord`
- `ResolveService`

且这些 Resolve* 调用走 **dnsRouter**（并携带 inbound metadata 做日志与策略一致性）。Rust 的 `resolve1.rs` 目前未实现上述 Resolve* 方法，导致“完整 resolve1 API”缺失（与 `agents-only/active_context.md` 的 L3.3 描述一致）。

### 3.3 落点建议（最小闭环）

- 在 `crates/sb-adapters/src/service/resolve1.rs` 补齐 Resolve* 方法：
  - 走 `sb_core::dns::DnsRouter`（或 `DnsRouter.exchange/lookup` 等统一入口）
  - 填充 inbound metadata（如 inbound_type/tag）用于日志/策略
- 明确 Linux-only 语义：
  - 非 Linux 平台应给出清晰的 stub 提示（配置层/运行时层一致）
- 在 `ResolvedTransport` 与 service 的职责边界上做一次复核：
  - 目标是 “D-Bus Manager 更新 -> RESOLVED_STATE 变更 -> ResolvedTransport 生效”
  - Resolve* 则是 “D-Bus Query -> DNSRouter 处理 -> 返回结果”

---

## 4. L3.4 Cache File 深度对齐（PX-013 / PX-009）

### 4.1 Rust 现状（已读代码定位）

- 配置 IR：`crates/sb-config/src/ir/experimental.rs` 的 `CacheFileIR`
  - 目前字段：`enabled/path/store_fakeip/store_rdrc/rdrc_timeout`
  - **缺失**：`cache_id`
- 实现：`crates/sb-core/src/services/cache_file.rs`
  - backend：sled（与 Go bbolt 不二进制兼容）
  - 已覆盖：FakeIP mapping + counters、RDRC entries、clash_mode/selected/expand、rule_sets（有存储接口但目前未见调用方）

### 4.2 关键差距（对照 Go 行为）

Go 参考：
- `go_fork_source/sing-box-1.12.14/experimental/cachefile/cache.go`
- `go_fork_source/sing-box-1.12.14/docs/configuration/experimental/cache-file.md`

差距要点：
- **cache_id 作用域**：Go 支持 `cache_id` 将同一 cache.db 下的数据按 ID 分桶；Rust IR 与实现均未体现该隔离能力。
- **FakeIP metadata 写盘节流**：Go 有 `saveMetadataTimer` 做 debounce（降低写盘抖动）；Rust 当前写入是“调用即写”（尤其是 FakeIP 分配与 counters）。
- **rule_set cache 的接线**：Rust `store_rule_set/get_rule_set` 目前无调用方；Go 的 bucketRuleSet 与 ruleset 下载/更新链路有明确关系。

### 4.3 落点建议（兼容 sled 的“等价语义”）

- IR 补齐 `cache_id: Option<String>`（语义同 Go）
- sled 侧的隔离策略（二选一）：
  - key 前缀：`{cache_id}\0{bucket}\0{key}`
  - 或者按 cache_id 开 tree：`db.open_tree(format!("cache/{cache_id}/selected"))`
- FakeIP metadata debounce：
  - 引入轻量定时器/批量写（例如 10s 合并写入 fakeip_meta 与 counters）
- rule_set caching：
  - 明确“以 CacheFileService 为准”还是“以 router/ruleset/remote.rs 的文件缓存为准”
  - 若对齐 Go，则在 ruleset 下载链路中接入 CacheFileService（tag -> bytes）

---

## 5. L3.5 ConnMetadata chain/rule 填充（L2.8 延后）

### 5.1 Rust 现状（已读代码定位）

- ConnMetadata 定义：`crates/sb-common/src/conntrack.rs`
  - 字段已有：`rule: Option<String>`, `chains: Vec<String>`
- 注册点：`crates/sb-core/src/router/conn.rs`
  - TCP/UDP 连接建立后注册 tracker，但只填充 `host/inbound_tag/outbound_tag`（未填 rule/chains/inbound_type）
- 路由结果结构：
  - `crates/sb-core/src/router/route_connection.rs` 的 `RouteResult` 具备 `matched_rule: Option<usize>`
  - 但 `crates/sb-core/src/router/engine.rs` 的 `RouterHandle` 实现 `ConnectionRouter` 时，仅将 `Decision -> RouteResult`，**未设置 matched_rule**

### 5.2 差距与阻塞点

- 需要“统一路由入口”把：
  - 命中规则（rule id/描述）
  - 出站链路（selector/urltest/loadbalance 的选择路径）
  在“路由决策阶段”产出并传给 ConnectionManager/ConnTracker。
- 当前 RouterHandle 的决策 API 返回 `Decision`，缺少可携带 rule/trace 的返回类型；因此 conn.rs 只能拿到 dialer tag。

### 5.3 落点建议（不破坏现有结构的最小方案）

- 路由 API 增量扩展：
  - 引入 `DecisionMeta { decision, rule_id: Option<String>, chains: Vec<String> }`
  - `ConnectionRouter::route_connection/route_packet` 返回该 meta（或在 `RouteResult` 中补齐并在 RouterHandle 路由时填写）
- chain 计算：
  - 首先落地 “最有用的链”：`[group_tag..., leaf_outbound_tag]`（至少能让 GUI 看见 selector/urltest 的当前成员）
  - 更完整链需要 OutboundManager/Bridge 在 resolve 时保留 parent->child 关系（已有 `compute_outbound_deps()`，可复用）

---

## 6. L3 质量保障（M3.1~M3.3）现状补充

来自 `agents-only/03-planning/06-STRATEGIC-ROADMAP.md`：
- M3.1 测试覆盖（进行中）
- M3.2 性能基准（未开始）
- M3.3 稳定性验证（未开始）

已存在的资产（可直接复用）：
- 覆盖盘点：`reports/TEST_COVERAGE.md`（2026-01-18）
- 性能基线守护：`docs/STATUS.md` 提到的 `scripts/test/bench/guard.sh`
- 压测/soak：`tests/stress/p0_protocols_stress.rs`（包含 24h endurance 类测试，依赖环境变量地址）

建议的“L3 开工前最小校验”：
1. 重新跑一遍 feature matrix（确保 L3 的 feature-gated 变更不破矩阵）
2. 确认 bench guard 在当前机器可跑（record/check 二选一）
3. 对 L3.1/3.3/3.4 的改动补齐“无网络依赖”的单元测试（避免 CI/本机环境差异）

---

## 7. 下一步（待用户确认后细化为工作包）

- 以 L3.5（ConnMetadata）与 L3.4（CacheFile cache_id/debounce）作为“低风险、收益高”的先手
- L3.1 SSMAPI 属于功能闭环缺口（需要做绑定与 cache 格式对齐），但更改面较集中，适合单独工作包推进
- L3.3 Resolved 在 Linux-only 上要谨慎推进，优先补齐 Resolve* 方法与 DNSRouter 接线，再处理 TCP/并行化等行为细节

