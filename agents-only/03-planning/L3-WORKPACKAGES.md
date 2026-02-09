# L3 一级工作包规划（Polish / Edge Services）

> **日期**：2026-02-08  
> **更新**：2026-02-09（L3.1 PX-011 + L3.2 PX-014 + L3.3 PX-015 已实现；本文件相关章节已同步为“已完成”记录）  
> **目标**：基于已收集到的差距信息，将 L3.1~L3.5 拆成可交付的一级工作包，明确范围、关键设计选择、验收与依赖。  
> **输入**：`agents-only/active_context.md`（L3 Scope 表）、`agents-only/05-analysis/L3-PREWORK-INFO.md`（差距与落点）、`agents-only/02-reference/GO_PARITY_MATRIX.md`（PX-011/013/014/015）。

---

## 总体策略与排序（建议）

按“风险最小 + GUI/可观测收益最大 + 依赖最少”排序建议：

1. **L3.5 ConnMetadata chain/rule 填充**（收益高，主要是接线与元信息传播，不涉及协议栈）
2. **L3.4 Cache File 深度对齐（cache_id + debounce + ruleset cache 接线）**（影响面可控，但需注意兼容旧 cache.db）
3. **L3.3 Resolved 完整化（resolve1 Resolve*）**（✅ 已完成 2026-02-09；Linux runtime/system bus 验证待补）
4. **L3.2 DERP 配置对齐**（✅ 已完成 2026-02-09）

已完成：
- **L3.1 SSMAPI 对齐（PX-011）**（✅ 2026-02-09）
- **L3.2 DERP 配置对齐（PX-014）**（✅ 2026-02-09）

并行原则：
- **L3.5 与 L3.4 可并行设计/实现**（互不依赖）
- **L3.1 与 L3.4 可能存在轻微耦合**（CacheFile 能否复用/扩展给 SSMAPI？暂不强耦合，先各自完成）
- **L3.3（Linux runtime）强平台/环境依赖**，建议在 Linux/system bus 环境补齐 smoke 验证

---

## L3.1 SSMAPI 对齐（PX-011）✅ 已完成

**日期**: 2026-02-09

### 交付范围（落地）

- per-endpoint 绑定闭环：
  - `service.ssm-api.servers` 按 `endpoint -> inbound_tag` 形成独立 EndpointCtx（每个 endpoint 独立 Traffic/User 管理器）
  - 启动时验证 inbound tag 存在且为 shadowsocks managed inbound，不满足直接报错（包含 endpoint + inbound_tag）
- HTTP API 行为对齐 Go：
  - `{endpoint}/server/v1/...` 路由
  - `GET /server/v1` 返回 `server: "sing-box <version>"` + `apiVersion: "v1"`
  - `GET /users` 返回 users 且包含密码字段
  - `GET /stats?clear=true` 返回 users 且不包含密码字段
  - 错误体统一为 `text/plain`，关键状态码（400/404）对齐
- cache 对齐与稳健保存：
  - 读取：优先 Go(snake_case)，失败回退旧 Rust(camelCase)
  - 写入：统一 Go(snake_case)
  - 后台 1min 定时保存 + diff-write（无变化不落盘）
- Shadowsocks inbound 接线：
  - `ManagedSSMServer::set_tracker()` + `update_users()` 真正影响鉴权与统计
  - TCP 多用户鉴权（解密 length chunk 选择用户 key）
  - UDP response 加密 key 修复与 tracker 统计接线（bytes/packets/sessions）

### 关键设计选择（已定案）

- 采用全局注册表最小接线：
  - Shadowsocks inbound 构建时注册 `tag -> Weak<dyn ManagedSSMServer>`
  - SSMAPI 构造时按 inbound tag 获取并绑定
- 不改造 InboundManager/Bridge 生命周期与 trait 体系，避免扩大改动面

### 主要落点文件

- `crates/sb-core/src/services/ssmapi/registry.rs`
- `crates/sb-core/src/services/ssmapi/server.rs`
- `crates/sb-core/src/services/ssmapi/api.rs`
- `crates/sb-adapters/src/register.rs`
- `crates/sb-adapters/src/inbound/shadowsocks.rs`

### 验收与验证（已执行）

- `cargo test -p sb-core --features service_ssmapi`
- `cargo test -p sb-adapters --features "adapter-shadowsocks,router,service_ssmapi"`
- `cargo check -p sb-core --all-features`

---

## L3.2 DERP 配置对齐（PX-014）✅ 已完成

**日期**: 2026-02-09

### 目标

对齐 Go 的 DERP 配置 schema 与关键行为（尤其是 verify_client_url/mesh_with 的 dialer/TLS 语义、ListenOptions honored、bootstrap-dns 解析路径）。

### 范围

- 配置 IR：将 `verify_client_url`、`mesh_with` 升级为结构体数组（包含 dialer options 等），保留旧字段兼容（解析时支持 string 列表）
- 运行时：按每条 verify URL 构建独立 http client + DialContext；mesh peer 连接使用其 dialer/TLS 选项
- `/bootstrap-dns`：改为使用可注入 resolver/DNSRouter（而不是全局 resolver）
- ListenOptions：至少 bind_interface/routing_mark/netns/reuse_addr 要影响 bind 路径（TCP + STUN/UDP）

非目标：
- 改写 DERP 协议实现（当前协议/mesh 基础已存在）
- 追求与 Go 的 bbolt/tsweb/derphttp 完全内部结构一致（以行为对齐为准）

### 关键设计选择

1. **IR 兼容策略**
   - 选项 A（推荐）：新字段 `verify_client_url`/`mesh_with` 支持“string 或 object”的反序列化（serde untagged），向前兼容
   - 选项 B：引入平行字段（例如 `verify_client_url_options`），旧字段保留但标记 deprecated（更清晰但更啰嗦）

2. **DNS 依赖注入**
   - 选项 A（推荐）：从 `ServiceContext` 注入 `dns_resolver`/`dns_router`，derp 用它处理 bootstrap-dns
   - 选项 B：继续使用全局，但允许按 tag 安装（仍然是 global，耦合更强）

### 子任务（落地）

- ✅ L3.2.1 IR 扩展（Listable/StringOrObj + DERP Dial/VerifyURL/MeshPeer/TLS；stun 支持 `bool|number|object`）
- ✅ L3.2.2 verify_client_url 行为对齐（per-URL dialer + hyper POST；detour/domain_resolver/netns）
- ✅ L3.2.3 mesh_with 行为对齐（per-peer dialer/TLS；PostStart 启动；缺 PSK 报错）
- ✅ L3.2.4 ListenOptions/STUN 默认值对齐（socket2 bind honor；STUN enable/defaults 对齐 Go）
- ✅ L3.2.5 /bootstrap-dns 对齐（注入 DNSRouter；无注入返回空并 warn）

### 验收标准（最小可验证）

- 配置兼容：旧 string 列表配置仍可解析，新结构体配置可解析
- verify_client_url：能根据 dialer options 决定连接路径（可用 mock dialer/trait 注入测试）
- /bootstrap-dns：不依赖 global resolver（测试中可注入 fake resolver）

### 主要文件落点（已落地）

- `crates/sb-config/src/ir/mod.rs`（ServiceIR 扩展）
- `crates/sb-config/src/validator/v2.rs`（旧 schema 兼容）
- `crates/sb-core/src/service.rs`（ServiceContext 注入：dns_router/outbounds/endpoints）
- `crates/sb-core/src/adapter/{bridge.rs,mod.rs}`（接线注入）
- `crates/sb-core/src/services/derp/server.rs`
- `crates/sb-core/src/services/derp/mesh_test.rs`（mesh 集成测试）
- `crates/sb-core/src/endpoint/tailscale.rs`（LocalAPI socket path 支持）
- `crates/sb-transport/src/{dialer.rs,builder.rs}`（dialer：connect_timeout/netns）

### 验收与验证（已执行）

- `CARGO_TARGET_DIR=target-alt cargo test -p sb-config`
- `CARGO_TARGET_DIR=target-alt cargo test -p sb-core --features service_derp`

---

## L3.3 Resolved 完整化（PX-015）

> **状态**：✅ 已完成（2026-02-09，代码 + 单测/编译验收；Linux runtime/system bus 验证待做）  
> **当前权威摘要**：`agents-only/workpackage_latest.md` + `agents-only/active_context.md` + `agents-only/05-analysis/L3.3-RESOLVED-PREWORK.md#0-当前实现状态快照2026-02-09`

### 实施结果（2026-02-09）

- Resolved service 运行模型对齐 Go：system bus 导出 `org.freedesktop.resolve1.Manager`，并以 `DoNotQueue` 请求 name `org.freedesktop.resolve1`（Exists 时启动失败且错误明确）
- DNS stub listener：补齐 UDP + TCP（同连接多 query），请求统一走 `ServiceContext.dns_router.exchange()`（wire-format）
- resolve1 Manager：补齐 `ResolveHostname/ResolveAddress/ResolveRecord/ResolveService`，并 best-effort 采集 sender 进程元信息写入 `DnsQueryContext`
- DNS 栈补齐 raw exchange：非 A/AAAA qtype（PTR/SRV/TXT 等）走规则路由决策后 raw passthrough 到 upstream.exchange；对非 A/AAAA 的 reject/hijack/predefined 固定返回 REFUSED
- 配置层补齐 dns server `type:"resolved"`（service + accept_default_resolvers），并接线到 ResolvedTransport（`RESOLVED_STATE`）
- ResolvedTransport 对齐：accept_default_resolvers 默认 false + bind_interface best-effort（Linux）+ 并行 fqdn racer

### 已执行验证

- `cargo test -p sb-core`
- `cargo test -p sb-config`
- `cargo test -p sb-adapters`
- `cargo check -p sb-core --features service_resolved`

### 待做验证（Linux runtime/system bus）

- systemd-resolved 运行中：请求 name 应失败且错误明确（提示停止/禁用真实 systemd-resolved）
- systemd-resolved 未运行：应成功请求 name 并处理 UDP/TCP stub DNS query（至少 A/AAAA）

### 目标

补齐 `org.freedesktop.resolve1.Manager` 的 Resolve* 方法族，使 resolved service 在 Linux 上达到 Go 的关键 API 面对齐：
- ResolveHostname / ResolveAddress / ResolveRecord / ResolveService
- Resolve* 走 DNSRouter（而不是绕过路由策略）
- 记录必要的请求元信息（至少 inbound tag/type，尽量与 Go 的 metadata/log 对齐）

### 范围

- D-Bus server：在 `resolve1.rs` 增加 Resolve* 方法实现
- 解析/响应：基于现有 DNSRouter/exchange/lookup 等统一入口
- Linux-only：非 Linux 下行为保持 stub，但错误信息明确

非目标：
- 追求 systemd-resolved 的完整行为仿真（只对齐 sing-box Go 的对外 API 语义）
- 额外实现更多 resolve1 非关键方法（保持按需补齐）

### 关键设计选择

1. **DNSRouter 获取方式**
   - 选项 A（推荐）：ResolvedService/resolve1 server 构造时从 `ServiceContext` 获取 dns_router（或 dns_resolver bridge）
   - 选项 B：使用全局 DNS router 单例（降低接线成本，但会引入全局耦合）

2. **Resolve* 与 Transport/resolved 状态的关系**
   - 选项 A（推荐）：Resolve* 完全走 DNSRouter；RESOLVED_STATE 仅用于 Transport（per-link 配置影响 upstream 选择）
   - 选项 B：Resolve* 直接读取 RESOLVED_STATE 并做简化解析（容易偏离 Go）

### 子任务（建议）

- L3.3.1 ResolveHostname：family -> lookup strategy，返回地址列表
- L3.3.2 ResolveAddress：PTR 查询（可复用 L2.10 的反向映射/或 DNSRouter exchange）
- L3.3.3 ResolveRecord/ResolveService：按 qtype/srv/txt 等构造请求并解析响应
- L3.3.4 Linux-only 行为与错误：平台 gate 与错误信息统一
- L3.3.5 测试：不依赖真实 D-Bus（以 mock state/router 的单元测试为主）

### 验收标准（最小可验证）

- Resolve* 方法在 Linux + `service_resolved` feature 下可编译并通过单测
- ResolveHostname/Address 能返回非空结果（mock DNSRouter/固定响应）

### 主要文件落点（预估）

- `crates/sb-adapters/src/service/resolve1.rs`
- `crates/sb-adapters/src/service/resolved_impl.rs`（注入与 glue）
- `crates/sb-core/src/dns/transport/resolved.rs`（如需要补齐辅助 API）

---

## L3.4 Cache File 深度对齐（PX-013 / PX-009/013）

### 目标

在保持 sled 后端的前提下，补齐 Go cachefile 的关键语义：
- `cache_id` 作用域隔离（同一 cache.db 内按 profile 分桶）
- FakeIP metadata 写盘去抖（减少写放大）
- ruleset cache 的“接线点”明确（CacheFileService vs file-based remote cache）

### 范围

- IR：为 `CacheFileIR` 增加 `cache_id: Option<String>`
- storage：实现 namespace（cache_id + bucket）
- write policy：FakeIP metadata 与 counters 增加 debounce（例如 10s 合并写）
- ruleset：明确是否接入 CacheFileService（若接入则加调用方；否则在文档中标记 Won't Wire）

非目标：
- sled 替换为 bbolt（不追求二进制兼容 Go）
- 强制迁移旧 cache.db（以向后兼容为主）

### 关键设计选择

1. **命名空间实现方式**
   - 选项 A（推荐）：以 tree 维度隔离（例如 `cache/{cache_id}/selected`），读写路径直观
   - 选项 B：key 前缀拼接（实现简单但容易出错/难以维护）

2. **兼容旧数据**
   - 选项 A（推荐）：`cache_id == None/""` 时继续使用旧 tree/key；非空 cache_id 走新 namespace
   - 选项 B：统一迁移（风险大，容易破坏已有用户数据）

3. **ruleset cache 接线**
   - 选项 A：保持 file cache（`router/ruleset/remote.rs`）为权威，CacheFileService 不接线（文档说明）
   - 选项 B：ruleset 下载后写入 CacheFileService（需要定义 tag<->url/format 的映射策略）

### 子任务（建议）

- L3.4.1 IR 扩展：`CacheFileIR.cache_id`
- L3.4.2 CacheFileService namespace：按 cache_id 分桶（Memory + Persistence）
- L3.4.3 FakeIP metadata debounce：合并写入 fakeip_meta/counters
- L3.4.4 ruleset 缓存策略定案并落地（A 或 B）
- L3.4.5 测试：cache_id 隔离 + debounce（时间可控的 tokio test）

### 验收标准（最小可验证）

- 配置含 `cache_id` 时，同一 DB 内不同 cache_id 的 mode/selected/expand 不互相覆盖
- FakeIP counters 的写盘频率显著降低（至少通过测试断言“触发多次 set 但持久化写次数受控”）

### 主要文件落点（预估）

- `crates/sb-config/src/ir/experimental.rs`
- `crates/sb-core/src/services/cache_file.rs`
- （可选）`crates/sb-core/src/router/ruleset/remote.rs`（若选择接线）

---

## L3.5 ConnMetadata chain/rule 填充（L2.8 延后项）

### 目标

让 `/connections` 面板能显示“命中规则 + 代理链路（至少 group -> leaf）”，将已存在的 `ConnMetadata.rule/chains` 从“字段存在但永远为空”补齐为可用。

### 范围

- 路由阶段：产出可用于连接展示的元信息（rule + chains）
- 连接注册阶段：将元信息写入 `sb-common::ConnMetadata`
- 最小链路：至少能显示 “最终 outbound tag” + “若经过 selector/urltest/loadbalance，显示 group -> member”

非目标：
- 完整 explain trace/每一步 matcher 的细粒度展示（那属于 `explain` feature 的范畴）
- 追求与 Go 内部 rule id 完全一致（以可读描述为优先）

### 关键设计选择

1. **元信息传播载体**
   - 选项 A（推荐）：扩展路由 API 返回结构（例如 `RouteResult` 增加 `matched_rule_id: Option<String>` 与 `chains: Vec<String>`），由 RouterHandle 填充
   - 选项 B：在 ConnectionManager 侧二次查询路由/索引（风险高，容易不一致）

2. **rule 表示形式**
   - 选项 A（推荐）：稳定的 `rule_id`/phase 字符串（例如 `rule#12` 或 explain phase），先保证“可定位”
   - 选项 B：完整序列化规则内容（太重且可能泄漏配置细节）

3. **chain 生成来源**
   - 选项 A（推荐）：在 outbound 选择点（group->member）记录链路，并附加到连接元信息
   - 选项 B：事后推断（不可行/不可靠）

### 子任务（建议）

- L3.5.1 路由结果扩展：RouterHandle 在 route_connection/packet 时填充 matched_rule（现状为 None）
- L3.5.2 连接注册接线：`router/conn.rs` 在注册 tracker 前把 rule/chains 写入 metadata（需要在 InboundContext 或 route_result 中携带）
- L3.5.3 selector/urltest 选择链路记录：在 group 决策点记录 parent->leaf（最小实现）
- L3.5.4 API 展示验证：/connections 返回的 rule/chains 非空（集成测试）

### 验收标准（最小可验证）

- 任意通过 RouterHandle 路由的连接，ConnMetadata.rule 或 chains 至少一个非空
- selector/urltest 组场景下，chains 至少包含 `[group_tag, selected_member_tag]`（顺序可约定）

### 主要文件落点（预估）

- `crates/sb-core/src/router/engine.rs`（RouterHandle::route_connection/route_packet）
- `crates/sb-core/src/router/route_connection.rs`（RouteResult 扩展）
- `crates/sb-core/src/router/conn.rs`（注册 tracker 时填充）
- `crates/sb-common/src/conntrack.rs`（仅在需要新增字段/约定时）

---

## 与 M3.*（质量保障）的关系（本次仅做定位，不拆新包）

L3.1~L3.5 更偏“边缘服务与 polish”。M3.* 属于质量里程碑，当前 repo 已有资产：
- 覆盖盘点：`reports/TEST_COVERAGE.md`
- bench guard：`scripts/test/bench/guard.sh`（见 `docs/STATUS.md`）
- 压测/soak：`tests/stress/p0_protocols_stress.rs`

建议等 L3.1~L3.5 中至少 2 个落地后，再把 M3.1/2/3 拆成可执行工作包，避免“测一堆但目标不断变”的浪费。
