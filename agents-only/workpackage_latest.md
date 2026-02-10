# 工作包追踪（Workpackage Latest）

> **最后更新**：2026-02-10
> **当前阶段**：L4 治理闭环执行中（先治理闭环，再实现）
> **Parity（权威口径）**：99.52%（208/209），以 `agents-only/02-reference/GO_PARITY_MATRIX.md`（2026-02-10 Recalibration）为准
> **Remaining**：1（`PX-015` Linux runtime/system bus 实机验证）
> **Boundary Gate**：✅ `check-boundaries.sh` exit 0（V4a=24/25，2026-02-10）

---

## ✅ 最新进展：L4.2 + L4.5 已落地

**日期**：2026-02-10  
**状态**：部分完成（L4.2 ✅、L4.5 ✅、L4.4 待 Linux 实机）

**已完成**：
- L4.2 门禁回归清零：`V4a` 从 `26` 收敛到 `24`，`check-boundaries.sh` 恢复 `exit 0`
- L4.5 质量复验证据固化：新增 `reports/L4_QUALITY_RECHECK_2026-02-10.md`，按 `PASS-STRICT / PASS-ENV-LIMITED` 标注四条复验命令

**进行中**：
- L4.1/L4.3/L4.6 文档口径统一与状态总线回填

**待执行**：
- L4.4 `PX-015` Linux 双场景最小闭环（见 `reports/PX015_LINUX_VALIDATION_2026-02-10.md`）

---

## ✅ L2 关闭决策（功能闭环）

**日期**：2026-02-10  
**结论**：L2 Tier 1~Tier 3 功能闭环完成（含 M2.4 服务补全），L2 阶段在“功能面”关闭。

**后补项（不阻塞 L3 关闭）**：
- M3.1~M3.3 质量里程碑（测试覆盖/性能基准/稳定验证）
- Resolved Linux runtime/system bus 验证（systemd-resolved 运行/未运行两场景）

## ✅ 最新完成：L2.8.x ConnMetadata Rule/Chain + TCP/UDP/QUIC Conntrack

**备注**：原文档编号为 L3.5.x，现归并为 L2.8 扩展（连接面板/conntrack 增强）。

**状态**：✅ 完成（代码 + `cargo check` 验证）
**交付**：
- 规则元信息不改路由行为：新增 `decide_with_meta`/`select_ctx_and_record_with_meta`，rule label 统一入 `ConnMetadata.rule`。
- TCP/UDP 全链路 conntrack wiring：新增 `register_inbound_udp`，UDP NAT 连接元数据与取消传播。
- `/connections` 可用性提升：chains/rule 非空，`DELETE /connections` 可中断 TCP/UDP 会话。
- UDP/QUIC 覆盖：SOCKS UDP（含增强版）、Trojan UDP、Shadowsocks UDP、TUIC UDP、DNS UDP（每查询短生命周期）。

**关键落点**：
- `crates/sb-core/src/router/{rules.rs,process_router.rs,engine.rs}`
- `crates/sb-core/src/conntrack/{inbound_tcp.rs,inbound_udp.rs,mod.rs}`
- `crates/sb-core/src/net/{datagram.rs,udp_nat.rs}`
- `crates/sb-core/src/inbound/{http_connect.rs,socks5.rs,direct.rs}`
- `crates/sb-adapters/src/inbound/{dns.rs,socks/udp.rs,socks/udp_enhanced.rs,tuic.rs,trojan.rs,shadowsocks.rs,...}`
- `crates/sb-api/tests/connections_snapshot_test.rs`

**新增测试**：
- `crates/sb-core/tests/conntrack_wiring_udp.rs`
- `crates/sb-core/tests/router_rules_decide_with_meta.rs`
- `crates/sb-core/tests/router_select_ctx_meta.rs`

**验证**：
- `cargo check -p sb-core -p sb-adapters -p sb-api`

---

## ✅ 最新完成：M2.4 Resolved 完整化（PX-015）

**状态**：✅ 完成（代码 + 单测；Linux runtime 验证待做）
**交付**：
- Resolved service 运行模型对齐 Go：在 system bus 导出 `org.freedesktop.resolve1.Manager` 并以 `DoNotQueue` 请求 name `org.freedesktop.resolve1`（name Exists 时启动失败且错误明确）
- DNS stub listener 支持 UDP + TCP（TCP 支持同连接多 query 循环），统一走 `ServiceContext.dns_router.exchange()`（wire-format）
- resolve1 D-Bus Manager 补齐 Resolve* 方法族：`ResolveHostname/ResolveAddress/ResolveRecord/ResolveService`，并 best-effort 采集 sender 进程元信息写入 `DnsQueryContext`
- DNS 规则/路由扩展：非 A/AAAA qtype（PTR/SRV/TXT 等）走 raw passthrough（route 后调用 upstream.exchange），并支持 per-rule ECS 注入；对非 A/AAAA 的 reject/hijack/predefined 固定返回 REFUSED
- 配置层补齐 dns server `type:"resolved"`（`service` + `accept_default_resolvers`），并接线到 `sb-core::dns::transport::resolved` + `RESOLVED_STATE`
- ResolvedTransport 行为对齐：best-effort bind_interface（Linux）+ Go 风格并行 fqdn racer + 默认值对齐（`accept_default_resolvers=false`）

**关键落点**：
- `crates/sb-adapters/src/service/{resolved_impl.rs,resolve1.rs}`
- `crates/sb-core/src/dns/{rule_engine.rs,message.rs,upstream.rs,dns_router.rs}`
- `crates/sb-core/src/dns/transport/{resolved.rs,dot.rs}`
- `crates/sb-config/src/{ir/mod.rs,validator/v2.rs}`
- `crates/sb-core/src/dns/config_builder.rs`

**验证**：
- `cargo test -p sb-core`
- `cargo test -p sb-config`
- `cargo test -p sb-adapters`
- `cargo check -p sb-core --features service_resolved`
**备注**：
- Linux-only runtime/system bus 验证待做（systemd-resolved 运行/未运行两种场景）。
- `cargo test -p sb-core --features service_resolved` 在 macOS 上存在 EPERM 环境失败（与 Resolved 逻辑无直接关系）。

---

## ✅ 最新完成：M2.4 SSMAPI 对齐（PX-011）

**状态**：✅ 完成
**交付**：
- per-endpoint 绑定闭环：`servers(endpoint -> inbound_tag)` 为每个 endpoint 创建独立 `TrafficManager/UserManager/ManagedSSMServer`，启动时验证 inbound tag 与类型
- API 行为对齐：`{endpoint}/server/v1/...` 路由，纯文本错误体（text/plain），关键字段与状态码对齐 Go
- cache：读兼容 Go(snake_case) + 旧 Rust(camelCase)，写统一 Go(snake_case)，1min 定时保存 + diff-write
- Shadowsocks inbound：`set_tracker()`/`update_users()` 真正影响鉴权与统计（TCP 多用户鉴权 + UDP correctness + tracker 统计接线）

**关键落点**：
- `crates/sb-core/src/services/ssmapi/registry.rs`
- `crates/sb-core/src/services/ssmapi/server.rs`
- `crates/sb-core/src/services/ssmapi/api.rs`
- `crates/sb-adapters/src/register.rs`
- `crates/sb-adapters/src/inbound/shadowsocks.rs`

**验证**：
- `cargo test -p sb-core --features service_ssmapi`
- `cargo test -p sb-adapters --features "adapter-shadowsocks,router,service_ssmapi"`
- `cargo check -p sb-core --all-features`

---

## ✅ 最新完成：M2.4 DERP 配置对齐（PX-014）

**状态**：✅ 完成
**交付**：
- 配置 schema：`verify_client_url`/`mesh_with` 支持 string/object + Listable，并引入 DERP Dial/TLS IR（Dial Fields flatten）
- runtime：`verify_client_url` 每条 URL 独立 dialer（detour/domain_resolver/netns/connect_timeout 等）并用 hyper POST 校验；`mesh_with` per-peer dial/TLS + PostStart 启动；`verify_client_endpoint` 按 tailscale endpoint tag 在 PostStart 解析 LocalAPI socket path
- STUN：仅当配置存在且 enabled=true 才启用；启用时默认 listen=`::`、port=`3478`；TCP/UDP bind honor listen fields（socket2）
- `/bootstrap-dns`：使用注入的 DNSRouter（无注入返回空 `{}` 并 warn）

**关键落点**：
- `crates/sb-config/src/ir/mod.rs`
- `crates/sb-config/src/validator/v2.rs`
- `crates/sb-core/src/service.rs` + `crates/sb-core/src/adapter/{bridge.rs,mod.rs}`
- `crates/sb-core/src/services/derp/{server.rs,mesh_test.rs}`
- `crates/sb-core/src/endpoint/tailscale.rs`
- `crates/sb-transport/src/{dialer.rs,builder.rs}`

**验证**：
- `CARGO_TARGET_DIR=target-alt cargo test -p sb-config`
- `CARGO_TARGET_DIR=target-alt cargo test -p sb-core --features service_derp`

---

## ✅ 已完成：WP-L2.1 Clash API 对接审计

**状态**：✅ 全部完成
**Commit**：`9bd745a`
**审计报告**：`agents-only/05-analysis/CLASH-API-AUDIT.md`
**优先级**：P0（在所有后续 Clash API / GUI 兼容工作之前必须完成）
**前置条件**：L2.2~L2.5 (Tier 1 初步) ✅ 已完成

### 执行结果

| Phase | 说明 | 状态 |
|-------|------|------|
| Phase 1 | 逐端点读取 Go/GUI/Rust 源码提取 JSON schema | ✅ |
| Phase 2 | 生成 CLASH-API-AUDIT.md (12 BREAK + 5 DEGRADE + 6 COSMETIC + 4 EXTRA) | ✅ |
| Phase 3 P0 | 8 项 GUI 硬依赖修复 | ✅ |
| Phase 3 P1 | 7 项功能正确性修复 | ✅ |
| Phase 3 P2 | 3 项完整性修复 | ✅ |

### 修复明细 (18 项)

**P0 GUI 硬依赖 (8):**
- B01 Config struct 重写与 Go configSchema 1:1 对齐
- B03 Proxy 补 udp 字段
- B04 Proxy 补 history 数组 + DelayHistory struct
- B05 get_proxies 注入 GLOBAL 虚拟 Fallback 组
- B08 get_connections 返回 {downloadTotal, uploadTotal, connections, memory}
- B09 根路径返回 {"hello":"clash"}
- D01 PATCH /configs 返回 204 NoContent
- D04 version premium:true, 格式 "sing-box X.Y.Z"

**P1 功能正确性 (7):**
- B07 delay 从 TCP connect 改为 HTTP/1.1 URL test (504/503 分级)
- B06 新增 GET /proxies/:name 路由 + handler
- B10 meta/group 改为 {"proxies": [array]}, 仅 OutboundGroup
- B11 group delay 并发测试全部成员, 返回 {tag: delay} map
- D02 PUT /configs 简化为 no-op 204
- D03 DELETE /connections 返回 204
- D05 去 meanDelay

**P2 完整性 (3):**
- B02 mode-list (随 B01)
- B12 /meta/memory 双模式 (WS 每秒推送 + HTTP fallback), 真实进程内存
- C06 错误格式统一为 {"message": "..."} (14处)

### 保留项 (不影响 GUI)

- C01-C05: 5 个 COSMETIC 级偏差保留
- E01-E04: 4 个 EXTRA 级偏差保留（E03 已随 B12 消除）

### 验收标准检查

| 标准 | 结果 |
|------|------|
| CLASH-API-AUDIT.md 覆盖所有 P0/P1 端点 | ✅ |
| 所有 BREAK 级偏差有修复方案 | ✅ 12/12 已修复 |
| /configs JSON 字段与 CoreApiConfig 匹配 | ✅ |
| /proxies JSON 字段与 CoreApiProxy 匹配 | ✅ |
| cargo test -p sb-api 通过 | ✅ 全部通过 |
| cargo check --workspace 通过 | ✅ |

---

## ✅ 已完成：WP-L2 Tier 1 初步功能对齐

**状态**：✅ 全部完成（4/4 工作项）
**Parity 增量**：88% → ~89%

### 任务清单

| 任务 | 状态 | 产出 |
|------|------|------|
| L2.2 maxminddb API 修复 | ✅ 完成 | `--features router` / `--features parity` 编译通过 |
| L2.3 Config schema 兼容 (PX-002) | ✅ 完成 | Go-format 配置端到端验证通过 |
| L2.4 Clash API 初步完善 (PX-010) | ✅ 完成 | 真实数据 + 真实延迟测试 + mode 字段 |
| L2.5 CLI 参数对齐 (M2.3) | ✅ 完成 | binary name + version JSON + completion 子命令 |

### 详细变更

#### L2.2 maxminddb 修复（原 L2.1）
- `app/src/cli/geoip.rs`: 3处 `lookup::<T>()` / `within::<T>()` → 新 API
- `app/Cargo.toml`: ipnetwork 0.18 → 0.21
- `app/src/inbound_starter.rs`: parse_listen_addr cfg gate 修复

#### L2.3 Config schema 兼容（原 L2.2）
- `crates/sb-config/src/lib.rs`: 新增 `test_go_format_config_with_schema` 测试

#### L2.4 Clash API 初步完善（原 L2.3）
- `crates/sb-core/src/context.rs`: CacheFile trait + get_clash_mode()
- `crates/sb-core/src/services/cache_file.rs`: impl get_clash_mode()
- `crates/sb-api/src/clash/handlers.rs`: get_configs/get_proxy_delay/get_meta_group_delay 重写
- `crates/sb-api/Cargo.toml`: 移除 rand

#### L2.5 CLI 参数对齐（原 L2.4）
- `app/src/cli/mod.rs`: name → "sing-box", GenCompletions → Completion
- `app/src/cli/version.rs`: Go-aligned VersionInfo
- `app/src/cli/completion.rs`: hints 更新
- `app/src/main.rs`: match arm
- `app/tests/version_*.rs` + golden file: 同步更新

### 验证结果

| 检查项 | 结果 |
|--------|------|
| `cargo check --workspace` | ✅ |
| `cargo check -p app --features router` | ✅ (从 ❌ 修复) |
| `cargo check -p app --features parity` | ✅ (从 ❌ 修复) |
| `cargo test --workspace` | ✅ 1432 passed, 0 failed |

---

## ✅ 已完成：WP-L2 Tier 2（L2.6~L2.10）

> **调整说明**（2026-02-08）：基于 L2.1 源码深度审查，原方案按 PX 编号分包
> 存在范围过广和交叉依赖问题。现重排为 5 个均匀工作包。
>
> **主要变化**：
> - 原 L2.8 CacheFile → 并入 L2.6（实现已有 14 个方法，缺的是 trait 扩展和联通）
> - 原 L2.6 Adapter 生命周期 → 拆为 L2.6(持久化) + L2.7(URLTest) + L2.9(Lifecycle)
> - 原 L2.7 DNS → 后移至 L2.10（GUI 短期不直接依赖）
> - 工作量从 2大+1大+1中 → 4中+1大，风险更可控

### L2.6 Selector 持久化 + Proxy 状态真实化（中）

**对应 PX**: PX-006, PX-013
**动机**: GUI 最直接可感知的缺陷——重启丢选择、proxy 列表无真实健康状态
**状态**: ✅ 完成
**前置**: L2.1 ✅

#### 信息收集发现（2026-02-08）

| 发现 | 详情 |
|------|------|
| CacheFile trait 仅 3 方法 | `context.rs:732-736`: get/set_clash_mode + set_selected，**缺 get_selected** |
| CacheFileService 有 14+ 方法 | sled 持久化实现完整，但大部分是 inherent method，未暴露到 trait |
| SelectorGroup 不接受 CacheFile | 三个构造函数均不含 CacheFile 参数，选择仅存 `Arc<RwLock<Option<String>>>` |
| Go 三阶段启动恢复 | CacheFile.LoadSelected > defaultTag > tags[0]，CacheFile 优先级最高 |
| Go OutboundGroup 接口 | `Now() string` + `All() []string`，Clash API 用类型断言检测 |
| Go Selector 内部持久化 | `SelectOutbound()` 内部直接调 StoreSelected，不由外部 handler 负责 |
| Rust get_proxies 硬编码 | `alive=Some(true)`, `delay=None`, `history=vec![]`; ProxyHealth 有真实数据但未暴露 |
| OutboundManager 未被使用 | Bridge + OutboundRegistryHandle 是实际注册表，OutboundManager 形同虚设 |

#### L2.6.1 CacheFile trait 扩展

**文件**: `crates/sb-core/src/context.rs`

将 CacheFile trait 从 3 个方法扩展到覆盖 Selector/Group 所需的读写操作：

```rust
pub trait CacheFile: Send + Sync + std::fmt::Debug {
    // 现有
    fn get_clash_mode(&self) -> Option<String>;
    fn set_clash_mode(&self, mode: String);
    fn set_selected(&self, group: &str, selected: &str);
    // 新增
    fn get_selected(&self, group: &str) -> Option<String>;
    fn get_expand(&self, group: &str) -> Option<bool>;
    fn set_expand(&self, group: &str, expand: bool);
}
```

**变更范围**: 仅 context.rs trait 定义 + cache_file.rs trait impl 块（方法已在 inherent 上实现，只需加到 trait impl）

**不在此步做**: FakeIP/RDRC/RuleSet 方法（属 L2.10 DNS 范围）

#### L2.6.2 OutboundGroup trait 定义

**文件**: `crates/sb-core/src/adapter/mod.rs`（或 `crates/sb-types/src/ports/mod.rs` 如需跨 crate 共享）

```rust
pub trait OutboundGroup: Send + Sync {
    fn now(&self) -> String;
    fn all(&self) -> Vec<String>;
}
```

- SelectorGroup 实现 OutboundGroup
- `get_proxies` handler 改用 `dyn OutboundGroup` trait 判断 group 身份，替代 `as_any().downcast_ref::<SelectorGroup>()`
- 设计考量：放 sb-core 即可（sb-types 中已有 OutboundConnector 等，但 OutboundGroup 只在 sb-core/sb-api 间使用，无需下沉）

#### L2.6.3 SelectorGroup 接入 CacheFile

**文件**: `crates/sb-core/src/outbound/selector_group.rs`

**方案 A（Go 模式：内部持久化）**: SelectorGroup 构造时接受 `Option<Arc<dyn CacheFile>>`，内部负责 load/store：
- `new_manual(name, members, default, cache_file)` — 构造时调 `cache_file.get_selected(name)` 恢复
- `select_by_name()` — 成功后调 `cache_file.set_selected(name, tag)` 持久化
- Clash API handler 不再需要单独调 `set_selected`

**方案 B（当前模式增强）**: SelectorGroup 不变，由外部（Bridge 构造 / Clash API handler）负责 load/store：
- 启动时 Bridge 构造 SelectorGroup 后调 `selector.select_by_name(cache.get_selected(name))`
- Clash API handler 继续调 `set_selected`（现状）

**推荐**: **方案 A**。与 Go 一致，且将持久化逻辑内聚到 SelectorGroup，减少外部协调点。

#### L2.6.4 启动恢复联通

**文件**: `crates/sb-core/src/adapter/bridge.rs` 或 `crates/sb-adapters/src/register.rs`

在 `assemble_selectors()` 中构造 SelectorGroup 时传入 CacheFile：

```
assemble_selectors(cfg, bridge):
  for each selector config:
    cache_file = bridge.context.cache_file.clone()  // Option<Arc<dyn CacheFile>>
    group = SelectorGroup::new_manual(name, members, default, cache_file)
    // SelectorGroup::new_manual 内部自动:
    //   1. cache_file.get_selected(name) -> Some("proxy-a")
    //   2. self.selected = "proxy-a"  (如果 "proxy-a" 在 members 中)
    //   3. 否则 fallback to default_member / members[0]
```

三阶段恢复逻辑（与 Go 对齐）：
1. `CacheFile.get_selected(group_name)` — 如有值且 member 存在 → 使用
2. `default_member` 配置项 — 如有值且 member 存在 → 使用
3. `members[0]` — 兜底

#### L2.6.5 get_proxies 暴露真实健康状态

**文件**: `crates/sb-api/src/clash/handlers.rs`

当前 `get_proxies` 硬编码 `alive: Some(true)`, `delay: None`。改为读取 ProxyHealth 真实数据：

- 对 SelectorGroup：遍历 `get_members()` 返回的 `(tag, is_alive, rtt_ms)`
- 映射到 Proxy struct：`alive = is_alive`, `delay = if rtt_ms > 0 { Some(rtt_ms as u16) } else { None }`
- `history` 暂留 `vec![]`（L2.7 URLTestHistoryStorage 范围）

需要给 OutboundGroup trait 增加一个 `member_health(tag) -> Option<(bool, u64)>` 方法，或在 SelectorGroup 上保留 inherent 方法 `get_members()` 供 handler 通过 downcast 调用。

**推荐**: 在 OutboundGroup trait 上新增 `members_health() -> Vec<(String, bool, u64)>`，保持多态。

#### 依赖关系

```
L2.6.1 (CacheFile trait)  ←─ 无依赖，第一步
         ↓
L2.6.2 (OutboundGroup)    ←─ 无依赖，可与 L2.6.1 并行
         ↓
L2.6.3 (SelectorGroup)    ←─ 依赖 L2.6.1
         ↓
L2.6.4 (启动恢复)          ←─ 依赖 L2.6.1 + L2.6.3
         ↓
L2.6.5 (get_proxies)      ←─ 依赖 L2.6.2 + L2.6.3
```

可并行执行：L2.6.1 ‖ L2.6.2 → L2.6.3 → L2.6.4 ‖ L2.6.5

#### 验收标准（已达成）

| 标准 | 检验方法 |
|------|---------|
| 重启后 proxy 选择保持 | 启动 → PUT /proxies/selector-a {"name":"proxy-b"} → 重启 → GET /proxies → selector-a.now == "proxy-b" |
| CacheFile trait 有 get_selected | `dyn CacheFile` 可调 get_selected / get_expand |
| OutboundGroup 替代 downcast | handlers.rs 不再 `downcast_ref::<SelectorGroup>()` 判断 group |
| cargo check --workspace | ✅ |
| cargo test --workspace | ✅ 无回归 |

### L2.7 URLTest 历史 + 健康检查对齐（中）

**对应 PX**: PX-006
**动机**: GUI proxies 面板的 history 始终为空，健康检查精度不够
**状态**: ✅ 完成

| 子任务 | 说明 |
|--------|------|
| URLTestHistoryStorage | per-proxy 延迟历史环形缓冲（Go 保留最近 N 条） |
| 健康检查升级 | TCP connect → 完整 HTTP URL test（复用 L2.1 `http_url_test` 逻辑） |
| tolerance sticky switching | 实现当前标记为 TODO 的 tolerance 阈值切换逻辑 |
| history 写入 | group delay 测试结果写入 URLTestHistoryStorage |
| history 读取 | get_proxies / get_proxy 填充 `history: Vec<DelayHistory>` |

**验收**: GET /proxies 的 history 有真实数据；URLTest 组自动切换遵循 tolerance

### L2.8 ConnectionTracker + 连接面板（中）

**对应 PX**: PX-005, PX-012
**动机**: GUI 连接面板为空，close connection 无实际效果
**状态**: ✅ 完成

| 子任务 | 说明 |
|--------|------|
| Router 级 connection table | ID, metadata, start time, rule, upload/download |
| Inbound 注册/注销 | connection open/close hook |
| close_connection 真实化 | 通过 CancellationToken 取消真实流 |
| Wire Clash API | GET /connections 返回真实连接列表 |
| V2Ray API 接入 | StatsService 接入连接级统计（可选） |

**验收**: GET /connections 返回真实连接列表；DELETE /connections/:id 断开真实连接

### L2.9 Lifecycle 编排（中）

**对应 PX**: PX-006
**动机**: 启动顺序随机可能导致依赖未就绪；`start_all()` 不调用已有的拓扑排序
**状态**: ✅ 完成

| 子任务 | 说明 |
|--------|------|
| start_all() 接入拓扑排序 | 调用 `get_startup_order()` 按依赖序逐 stage 启动 |
| Service/Endpoint 同理 | Service manager 和 Endpoint manager 应用 staged startup |
| 失败 rollback | 已启动的组件执行 close |
| Default outbound | 对齐 Go 的 default outbound resolution |

**验收**: 有循环依赖时报错而非死锁；启动顺序可预测

### L2.10 DNS 栈对齐（大，可延后）

**对应 PX**: PX-004, PX-008
**动机**: DNS 行为正确性，非 GUI 直接可感知但影响运行时正确性
**状态**: ✅ 完成

| 子任务 | 说明 |
|--------|------|
| DNSRouter / TransportManager | Go-style DNS 查询路由和传输管理 |
| EDNS0 | subnet / TTL rewrite |
| FakeIP 持久化 | FakeIP store/metadata 接入 CacheFile |
| RDRC | reject-cache 语义对齐 |

**验收**: DNS 查询遵循规则链 + 缓存语义与 Go 一致

### Parity 增量预估（已达成）

**实际**：99.52% (208/209)，详见 `agents-only/02-reference/GO_PARITY_MATRIX.md`（2026-02-10 Recalibration）。

| 完成包 | 预估 Parity | 增量 |
|--------|------------|------|
| L2.6 Selector 持久化 | ~91% | +2% |
| L2.7 URLTest 历史 | ~92% | +1% |
| L2.8 ConnectionTracker | ~93% | +1% |
| L2.9 Lifecycle 编排 | ~94% | +1% |
| L2.10 DNS 栈对齐 | ~96% | +2% |

---

## 📦 已完成工作包

### WP-L2.0 信息收集与缺口分析 ✅

**状态**: 完成 | **产出**: `agents-only/05-analysis/L2-PARITY-GAP-ANALYSIS.md`

### WP-L2 Tier 2（L2.6~L2.10）✅

**状态**: 完成 | **产出**: `agents-only/07-memory/implementation-history.md`（L2.6~L2.10）

### M2.4 服务补全（SSMAPI / DERP / Resolved）✅

**状态**: 完成（Linux runtime/system bus 验证后补）

### WP-L1.3 深度解耦 ✅

**状态**: 5/5 完成 | **违规**: 3→0 类 | `check-boundaries.sh exit 0`

### WP-L1.2 进阶依赖清理 ✅

**状态**: 6/6 完成 | **违规**: 5→3 类

### WP-L1.1 依赖边界硬化 ✅

**状态**: 6/6 完成 | **违规**: 7→5 类

### WP-L1.0 重构准备 ✅

**状态**: 全部完成

---

## 📊 进度历史

| 日期 | 工作包 | 状态 |
|------|--------|------|
| 2026-02-07 | WP-L1.0 | ✅ 完成 |
| 2026-02-07 | WP-L1.1 | ✅ 完成 (6/6) |
| 2026-02-07 | WP-L1.2 | ✅ 完成 (6/6) |
| 2026-02-07 | WP-L1.3 | ✅ 完成 (5/5) |
| 2026-02-08 | WP-L2.0 | ✅ 完成 (信息收集 + 缺口分析) |
| 2026-02-08 | WP-L2 Tier 1 初步 | ✅ 完成 (L2.2~L2.5) |
| 2026-02-08 | WP-L2.1 审计 | ✅ 完成 (Phase 1~3, 18 项修复) |
| 2026-02-08 | WP-L2 Tier 2 | ✅ 完成 (L2.6~L2.10) |
| 2026-02-09 | M2.4 服务补全 | ✅ 完成 (SSMAPI / DERP / Resolved) |

---

*此文件追踪当前活跃的工作包，完成后归档到历史记录。*
