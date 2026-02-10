# M2.4 服务补全与连接增强（历史 L3 工作包归档）

> **日期**：2026-02-08  
> **更新**：2026-02-10（服务补全已完成并归入 M2.4；L3 仅指质量里程碑）  
> **目标**：历史规划归档，记录原 L3.1~L3.5 的范围、关键设计选择与验收。当前状态以 `agents-only/workpackage_latest.md` 与 `agents-only/active_context.md` 为准。  
> **输入**：`agents-only/active_context.md`、`agents-only/05-analysis/L3-PREWORK-INFO.md`、`agents-only/02-reference/GO_PARITY_MATRIX.md`（PX-011/013/014/015）。

---

## 总体状态与结论（2026-02-10）

- M2.4 服务补全已完成（原 L3.1~L3.4）
- L2.8 连接增强已完成（原 L3.5）
- 后补项（不阻塞功能闭环）：
  - Resolved Linux runtime/system bus 验证（systemd-resolved 运行/未运行两场景）
  - M3.1~M3.3 质量里程碑（测试覆盖/性能基准/稳定验证）

---

## M2.4 SSMAPI 对齐（原 L3.1，PX-011）✅ 已完成

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

## M2.4 DERP 配置对齐（原 L3.2，PX-014）✅ 已完成

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

## M2.4 Resolved 完整化（原 L3.3，PX-015）

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

### 历史规划记录（已完成，仅供回溯）

- L3.3.1 ResolveHostname：family -> lookup strategy，返回地址列表
- L3.3.2 ResolveAddress：PTR 查询（可复用 L2.10 的反向映射/或 DNSRouter exchange）
- L3.3.3 ResolveRecord/ResolveService：按 qtype/srv/txt 等构造请求并解析响应
- L3.3.4 Linux-only 行为与错误：平台 gate 与错误信息统一
- L3.3.5 测试：不依赖真实 D-Bus（以 mock state/router 的单元测试为主）

### 历史验收标准（已完成，仅供回溯）

- Resolve* 方法在 Linux + `service_resolved` feature 下可编译并通过单测
- ResolveHostname/Address 能返回非空结果（mock DNSRouter/固定响应）

### 主要文件落点（已落地）

- `crates/sb-adapters/src/service/resolve1.rs`
- `crates/sb-adapters/src/service/resolved_impl.rs`（注入与 glue）
- `crates/sb-core/src/dns/transport/resolved.rs`（如需要补齐辅助 API）

---

## M2.4 Cache File 深度对齐（原 L3.4，PX-013 / PX-009/013）

**状态**: ✅ 已完成（2026-02-09，commit：`fc541ef`）  
**实现报告**: `agents-only/dump/2026-02-09_report_L3.4-cachefile-impl.md`

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

### 历史规划记录（已完成，仅供回溯）

- L3.4.1 IR 扩展：`CacheFileIR.cache_id`
- L3.4.2 CacheFileService namespace：按 cache_id 分桶（Memory + Persistence）
- L3.4.3 FakeIP metadata debounce：合并写入 fakeip_meta/counters
- L3.4.4 ruleset 缓存策略定案并落地（A 或 B）
- L3.4.5 测试：cache_id 隔离 + debounce（时间可控的 tokio test）

### 历史验收标准（已完成，仅供回溯）

- 配置含 `cache_id` 时，同一 DB 内不同 cache_id 的 mode/selected/expand 不互相覆盖
- FakeIP counters 的写盘频率显著降低（至少通过测试断言“触发多次 set 但持久化写次数受控”）

### 主要文件落点（已落地）

- `crates/sb-config/src/ir/experimental.rs`
- `crates/sb-core/src/services/cache_file.rs`
- `crates/sb-core/src/dns/fakeip.rs`
- `crates/sb-core/src/dns/config_builder.rs`
- `crates/sb-core/src/router/ruleset/remote.rs`（策略注释：file cache 权威；不接线 CacheFileService）

---

## L2.8 ConnMetadata chain/rule 填充（原 L3.5 延后项）✅ 已完成

**日期**：2026-02-10

**交付**：
- 规则元信息不改路由行为：新增 `Engine::decide_with_meta`、`ProcessRouter` meta helper、`RouterHandle::select_ctx_and_record_with_meta`，rule label 写入 `ConnMetadata.rule`
- TCP/UDP conntrack wiring：新增 `register_inbound_udp`，UDP NAT 生命周期接入 conntrack + cancel 传播
- `/connections` 可用性提升：chains/rule 非空，`DELETE /connections` 可中断 TCP/UDP 会话

**主要落点**：
- `crates/sb-core/src/router/{rules.rs,process_router.rs,engine.rs}`
- `crates/sb-core/src/conntrack/{inbound_tcp.rs,inbound_udp.rs,mod.rs}`
- `crates/sb-core/src/net/{datagram.rs,udp_nat.rs}`
- `crates/sb-core/src/inbound/{http_connect.rs,socks5.rs,direct.rs}`
- `crates/sb-adapters/src/inbound/{dns.rs,socks/udp.rs,socks/udp_enhanced.rs,tuic.rs,trojan.rs,shadowsocks.rs,...}`

**新增测试**：
- `crates/sb-core/tests/conntrack_wiring_udp.rs`
- `crates/sb-core/tests/router_rules_decide_with_meta.rs`
- `crates/sb-core/tests/router_select_ctx_meta.rs`
- `crates/sb-api/tests/connections_snapshot_test.rs`（UDP 断言）

**验证**：
- `cargo check -p sb-core -p sb-adapters -p sb-api`

**验收结果**：
- `/connections` 的 rule/chains 非空
- `DELETE /connections` 可中断 TCP/UDP
- selector/urltest 场景 chains 含 group → leaf

---

## 与 M3.*（质量保障）的关系（后补）

M2.4 与 L2.8 已完成并功能闭环。M3.* 属于质量里程碑，当前 repo 已有资产可复用：
- 覆盖盘点：`reports/TEST_COVERAGE.md`
- bench guard：`scripts/test/bench/guard.sh`（见 `docs/STATUS.md`）
- 压测/soak：`tests/stress/p0_protocols_stress.rs`

M3.1/2/3 作为后补项，后续再拆成可执行工作包，避免“测一堆但目标不断变”的浪费。
