# L3 前置信息收集与差距分析（Polish / Edge Services + Quality）

> **日期**：2026-02-08  
> **更新**：2026-02-09（L3.1 SSMAPI PX-011 已实现，本文件第 1 节已同步为“现状/已修复/残留风险”）  
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

### 1.0 状态（2026-02-09）

**结论**: ✅ 已完成（按 Go `service/ssmapi` 的关键语义对齐）。

已落地能力：
- per-endpoint 绑定：`servers(endpoint -> inbound_tag)` 为每个 endpoint 创建独立 `TrafficManager/UserManager/ManagedSSMServer` 绑定闭环
- HTTP API 行为：路径/字段/状态码/错误体（text/plain）与 Go 对齐
- cache：读兼容 Go(snake_case) + 旧 Rust(camelCase)，写统一 Go(snake_case)，并实现 1min 定时保存 + diff-write
- Shadowsocks inbound：`set_tracker()`/`update_users()` 真正影响运行时鉴权与统计（含 TCP 多用户鉴权 + UDP correctness 修复）

### 1.1 Rust 现状（已实现落点定位）

- 实现位置：
  - `crates/sb-core/src/services/ssmapi/mod.rs`
  - `crates/sb-core/src/services/ssmapi/registry.rs`（ManagedSSMServer 注册表）
  - `crates/sb-core/src/services/ssmapi/server.rs`
  - `crates/sb-core/src/services/ssmapi/api.rs`
  - `crates/sb-core/src/services/ssmapi/user.rs`
  - `crates/sb-core/src/services/ssmapi/traffic.rs`
  - 入站侧：`crates/sb-adapters/src/inbound/shadowsocks.rs`（`ManagedSSMServer` + `TrafficTracker`）
- 配置字段（IR）：
  - `crates/sb-config/src/ir/mod.rs`：`ServiceIR.servers`（endpoint -> inbound_tag）, `ServiceIR.cache_path`, `ServiceIR.tls`, `ServiceIR.listen*`

### 1.2 已修复项（对照 Go 行为）

Go 参考：
- `go_fork_source/sing-box-1.12.14/service/ssmapi/server.go`
- `go_fork_source/sing-box-1.12.14/service/ssmapi/api.go`
- `go_fork_source/sing-box-1.12.14/service/ssmapi/cache.go`

修复点（原差距全部闭合）：
- **per-endpoint inbound 绑定**：采用全局注册表（tag -> Weak<dyn ManagedSSMServer>）在构建 Shadowsocks inbound 时注册，SSMAPI 启动时按 `servers` 逐条完成 `set_tracker()` + `UserManager::with_server()` 绑定，并在启动前校验 inbound tag 存在且类型为 shadowsocks（配置错误直接失败且包含 endpoint + inbound_tag）。
- **API 行为对齐**：路由前缀为 `{endpoint}/server/v1/...`，`GET /server/v1` 返回 `server: "sing-box <version>"` + `apiVersion: "v1"`，`GET /users` 包含密码字段，`GET /stats?clear=true` 返回 users 且不含密码；错误体为 `text/plain`，并对齐关键状态码（400/404）。
- **cache 读写与保存节奏**：读取顺序为 Go(snake_case) -> legacy Rust(camelCase)，两者都失败时按 Go 行为删除坏文件；写入统一 Go(snake_case)；实现 1min 定时保存（延迟首 tick）+ diff-write 避免无变更写盘。
- **流量统计语义可用**：Shadowsocks inbound 在 TCP/UDP 明文 payload 处记录 uplink/downlink bytes/packets，并对 TCP/UDP session 进行“只加一次”的计数。

### 1.3 残留风险与后续增强（非阻塞）

风险与建议：
- TCP 多用户鉴权通过“尝试解密 length chunk 选 key”的方式实现，建议后续补充更强的端到端集成测试（真实 SS client 连通 + 多用户切换）。
- registry 存储 Weak，upgrade 失败时会清理 entry；若未来引入 inbound 热重载/卸载，建议在 close/drop 处显式 unregister 以减少短期悬挂。
- 大用户量时每连接遍历 keys 的成本可能上升，若需要可引入更强的 key lookup（例如缓存近期成功 key 或更紧凑的数据结构），当前优先正确性与 parity。

### 1.4 最小验收（建议）

已落地验证（单测为主）：
- sb-core：registry / per-endpoint 绑定 / API 状态码与错误体 / cache 读写兼容
- sb-adapters：TCP 多用户鉴权选择正确 user / update_users 触发 key 重建

---

## 2. L3.2 DERP 配置对齐（PX-014）

> **状态**: ✅ 已完成（2026-02-09）  
> **关键落点**: `crates/sb-core/src/services/derp/server.rs`（runtime） / `crates/sb-config/src/ir/mod.rs`（IR） / `crates/sb-core/src/service.rs`（注入）  
> **验证**:
> - `CARGO_TARGET_DIR=target-alt cargo test -p sb-config`
> - `CARGO_TARGET_DIR=target-alt cargo test -p sb-core --features service_derp`

### 2.1 Rust 现状（已实现）

- 实现位置：
  - `crates/sb-core/src/services/derp/server.rs`
- 配置字段（IR）：
  - `crates/sb-config/src/ir/mod.rs`：`ServiceIR.verify_client_url/mesh_with/verify_client_endpoint/stun`（均已按 Go 语义对齐可解析形式）
- 当前行为要点：
  - `/bootstrap-dns` 使用注入的 `ServiceContext.dns_router`（无注入返回空 `{}` 并 warn）
  - `verify_client_url`：支持 string/object + Listable；每条 URL 独立 dialer，并通过 hyper 在 dialer stream 上执行 HTTP POST 验证
  - `mesh_with`：支持 string/object + Listable；per-peer dialer/TLS；PostStart 阶段启动 mesh；mesh_with 非空但缺 PSK 会报错
  - `verify_client_endpoint`：按 endpoint tag 语义，在 PostStart 解析 tailscale endpoint 并拿到 tailscaled LocalAPI unix socket path
  - STUN：仅当 `stun` 配置存在且 `enabled=true` 才启动；启用时默认 listen=`::`、listen_port=`3478`；bind fields 用 socket2 生效（netns 为 Linux-only）
  - ListenOptions：DERP TCP listener 与 STUN UDP socket 走 socket2 预绑定并 honor 关键字段（平台 gating）

### 2.2 已知差异/后续增强

- `domain_resolver`：当前落地为“按 server tag lookup 并选择首个 IP” 的最小语义（未实现更复杂策略）
- HTTP/2/h2c：runtime 以 hyper 路由为主；如未来需要与 Go `derphttp` 进一步 1:1 对齐，可单独再验证与收敛

---

## 3. L3.3 Resolved 完整化（PX-015）

### 3.1 状态（2026-02-09）

**结论**: ✅ 已完成（代码 + 单测/编译验收；Linux runtime/system bus 验证待做）。

已落地能力要点：
- Resolved service 作为 systemd-resolved 替代实现（严格 Go 对齐）：system bus 导出 `org.freedesktop.resolve1.Manager`，并以 `DoNotQueue` 请求 `org.freedesktop.resolve1` name（Exists 时启动失败）
- DNS stub listener：补齐 UDP + TCP，并统一走 `ServiceContext.dns_router.exchange()`（wire-format）
- resolve1 Manager：补齐 `ResolveHostname/ResolveAddress/ResolveRecord/ResolveService`，best-effort 采集 sender 进程元信息并写入 `DnsQueryContext`
- DNS 栈补齐 raw exchange：非 A/AAAA qtype（PTR/SRV/TXT 等）走规则路由决策后 raw passthrough 到 upstream.exchange；对非 A/AAAA 的 reject/hijack/predefined 固定返回 REFUSED
- 配置层补齐 dns server `type:"resolved"`（service + accept_default_resolvers），并接线到 `sb-core::dns::transport::resolved`（`RESOLVED_STATE`）
- ResolvedTransport 对齐：accept_default_resolvers 默认 false + bind_interface best-effort（Linux）+ Go 风格并行 fqdn racer

关键落点：
- service：`crates/sb-adapters/src/service/{resolved_impl.rs,resolve1.rs}`
- dns core：`crates/sb-core/src/dns/{dns_router.rs,rule_engine.rs,upstream.rs,message.rs}`
- transport：`crates/sb-core/src/dns/transport/{resolved.rs,dot.rs}`
- config：`crates/sb-config/src/{ir/mod.rs,validator/v2.rs}` + `crates/sb-core/src/dns/config_builder.rs`

### 3.2 验证与已知问题

已执行（本机）：
- `cargo test -p sb-core`
- `cargo test -p sb-config`
- `cargo test -p sb-adapters`
- `cargo check -p sb-core --features service_resolved`

已知环境问题（非逻辑回归）：
- `cargo test -p sb-core --features service_resolved` 在 macOS 上可能因 `DnsForwarderService` 相关测试触发 EPERM 失败。

### 3.3 待做（Linux runtime/system bus）

- systemd-resolved 运行中：请求 name 应失败且错误明确（提示停止/禁用真实 systemd-resolved）
- systemd-resolved 未运行：应成功请求 name 并处理 UDP/TCP stub DNS query（至少 A/AAAA）

---

## 4. L3.4 Cache File 深度对齐（PX-013 / PX-009）

### 4.1 状态更新（2026-02-09）

L3.4 已实现并通过验收；实现细节与验证记录见：
- `agents-only/dump/2026-02-09_report_L3.4-cachefile-impl.md`（实现落地报告，commit：`fc541ef`）

锁定决策（实现期不再变更，已落地）：
- `cache_id`：仅隔离 Clash 相关持久化（`clash_mode` + `selected` + `expand`）
- FakeIP：接线 mapping + metadata，并实现 metadata 写盘 10s strict debounce（对齐 Go）
- ruleset cache：维持 `crates/sb-core/src/router/ruleset/remote.rs` file cache 为权威；`CacheFileService` ruleset API 不接线下载链路（仅保留接口/注释）

### 4.2 关键交付（索引）

- 配置 IR：`crates/sb-config/src/ir/experimental.rs` 新增 `CacheFileIR.cache_id`
- CacheFileService：
  - `crates/sb-core/src/services/cache_file.rs`：Clash 三项按 namespace tree 隔离（default namespace 兼容旧 `cache.db`）
  - `crates/sb-core/src/services/cache_file.rs`：FakeIP metadata 存取 + debounce thread + `flush()` 强制落盘 + Drop join
- FakeIP 接线：
  - `crates/sb-core/src/dns/fakeip.rs`：metadata load/save（debounced），`set_storage()` 恢复指针并校验范围
  - `crates/sb-core/src/dns/config_builder.rs`：FakeIP env 注入后接线 `fakeip::set_storage(cache_file.clone())`
- ruleset 策略固定：
  - `crates/sb-core/src/router/ruleset/remote.rs`：注释声明 ruleset 缓存权威来源为 file cache

### 4.3 历史预研材料（已过时，但保留备查）

- `agents-only/dump/2026-02-09_analysis_L3.4-cachefile-prework.md`

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
