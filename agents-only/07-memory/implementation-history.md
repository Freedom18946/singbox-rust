# 实施历史（Implementation History）

> **用途**：L1/L2 各阶段的详细实施记录，供需要回溯具体变更时查阅
> **来源**：从 CLAUDE.md 精简时迁出

---

## WP-L1.1 协议迁移（L1.1.5/L1.1.6）

### 核心架构

- `AdapterIoBridge<A>` 泛型桥接：将 `sb_adapters::traits::OutboundConnector`（返回 BoxedStream）适配为 `sb_core::adapter::OutboundConnector`（返回 IoStream）
- `connect_io()` 默认方法：在 `sb_core::adapter::OutboundConnector` trait 上新增，支持加密协议返回 IoStream

### 已迁移协议（10个，builder + dial 均独立）

| 协议 | 实现要点 |
|------|---------|
| trojan | adapter 层 TLS 握手 + 协议编码 |
| vmess | adapter 层 AES-128-GCM/ChaCha20 加密 |
| vless | adapter 层 VLESS 协议编码 |
| shadowsocks | adapter 层 AEAD 加密 |
| wireguard | boringtun + LazyWireGuardConnector（OnceCell 延迟初始化解决 sync/async 边界） |
| ssh | russh v0.49 SSH tunnel + 连接池 |
| shadowtls | sb-tls TLS 配置 + CONNECT 隧道 |
| tuic | QUIC + TUIC v5 协议握手 |
| hysteria v1 | QUIC + Hysteria v1 握手 + TCP tunnel |
| hysteria2 | QUIC + SHA256 认证 + 带宽控制 |

### Feature gate 变更

- `adapter-trojan/vmess/vless/shadowsocks`: 移除 `out_*` 依赖
- `adapter-wireguard-outbound`: 移除 `out_wireguard` 依赖
- 清理 dead feature forwarding: `out_ss`, `out_trojan`, `out_vmess`, `out_vless`
- register.rs 中 `sb_core::outbound::*` 引用: 12 → 5

---

## WP-L1.2 进阶依赖清理

### L1.2.1 reqwest 可选化 + sb-subscribe 解耦

**reqwest 可选化**:
- sb-core/Cargo.toml: reqwest → optional, behind `dns_doh` / `service_derp`
- supervisor.rs `download_file()` + router/ruleset/remote.rs: 改用 `sb_types::HttpClient` port + 全局注册
- app/src/reqwest_http.rs: `ReqwestHttpClient` 实现 + `install_global_http_client()`

**sb-subscribe 解耦**:
- sb-common/src/minijson.rs: 从 sb-core 复制（零依赖 JSON builder）
- sb-subscribe: sb-core → optional, 8 处 import 改为 sb_common::minijson

### L1.2.2 SSH dial() 内联

- sb-adapters/src/outbound/ssh.rs: 完全用 russh v0.49 重写
- adapter-ssh: 移除 sb-core/out_ssh 依赖
- 含连接池 SshPool、TOFU host key、password/pubkey 认证

### L1.2.3 sb-core tls/ → sb-tls

- sb_tls 新增: ensure_crypto_provider(), danger::{NoVerify, PinVerify}, global::{base_root_store, apply_extra_cas, get_effective}
- sb-core tls/ 变为薄委托层

### L1.2.4 TLS 工厂 + rustls 可选化

- sb-core 中 rustls/tokio-rustls 等全部 optional behind `tls_rustls`
- Cargo.toml 违规: 1→0

### L1.2.5 ShadowTLS dial() 内联

- 完全使用 sb-tls, 移除 sb-core/out_shadowtls

### L1.2.6 QUIC 共享 + TUIC/Hysteria v1/v2 内联

- 新增 quic_util.rs（QuicConfig + quic_connect() + QuicBidiStream）
- TUIC/Hysteria v1/Hysteria2 三个协议完全内联

---

## WP-L1.3 深度解耦

### L1.3.1 check-boundaries.sh V2/V3 feature-gate 感知

- V2: 新增 is_feature_gated_module() + is_line_feature_gated(), 43→0
- V3: 检查 outbound/mod.rs 中 pub mod 是否有 cfg 保护, 11→0

### L1.3.2 V4 重新分类

- V4a (outbound/ + register.rs): 22处, threshold 25, PASS
- V4b (inbound/ + service/): 192处, INFO only

### L1.3.3 Legacy 协议代码清理 × 8

移除 sb-core 中 8 个已被 sb-adapters 替代的协议实现:
- vless.rs, trojan.rs, ssh.rs, shadowtls.rs, wireguard.rs
- vmess.rs + vmess/aead.rs, shadowsocks.rs + ss/aead_tcp.rs + ss/aead_udp.rs
- tuic.rs + tuic/tests.rs
- outbound/mod.rs: 1305→835行(-36%), switchboard.rs: 1918→725行(-62%)
- out_* features 变为空数组 []（保留名称兼容）

### L1.3.4 V4a 评估

22 处全部为合法架构依赖（selector, urltest, direct, tailscale, register 等），纳入豁免列表。

---

## L1 回归验证

4 处回归修复:
1. xtests: 删除引用已删除协议的测试文件
2. shutdown_lifecycle: 添加显式 ensure_rustls_crypto_provider()
3. hyper dev-dep: 添加到 [dev-dependencies]
4. telemetry.rs: 移除 8 个 dead match arms（空 feature 仍激活 cfg blocks）

---

## WP-L2 Tier 1

### L2.2 maxminddb API 修复

- geoip.rs: reader.lookup::<T>() → reader.lookup()?.decode::<T>()?
- ipnetwork: 0.18→0.21
- parse_listen_addr: cfg gate 扩展

### L2.3 Config Schema (PX-002)

- 已有兼容性完好，新增 Go-format 端到端测试

### L2.4 Clash API 初步 (PX-010)

- get_configs: 真实数据替换硬编码
- CacheFile trait: 添加 get_clash_mode()
- 延迟测试: 真实 TCP 连接替代 simulate_proxy_delay()
- 移除 rand 依赖

### L2.5 CLI 对齐 (M2.3)

- binary name: app → sing-box
- version JSON: Go 格式对齐
- completion 子命令重命名

---

## WP-L2.1 Clash API 对接审计

### Phase 1: 信息收集

逐端点读取 Go/GUI/Rust 源码，提取完整 JSON schema：
- Go: 16 个 clashapi/*.go + 2 个 trafficontrol/*.go + adapter/experimental.go + common/urltest/
- GUI: kernel.d.ts, kernel.ts, kernelApi.ts, helper.ts, tray.ts
- Rust: handlers.rs, server.rs, types.rs

### Phase 2: 偏差报告

产出 `CLASH-API-AUDIT.md`，27 项偏差：12 BREAK + 5 DEGRADE + 6 COSMETIC + 4 EXTRA

### Phase 3 P0: GUI 硬依赖修复 (8)

**Config struct 重写** (`types.rs`):
- 旧: port, socks_port, mixed_port(Option), controller_port, external_controller, extra HashMap
- 新: port, socks_port, redir_port, tproxy_port, mixed_port, allow_lan, bind_address, mode, mode_list, log_level, ipv6, tun(Value)
- 与 Go configSchema 1:1 对齐

**Proxy struct 补全** (`types.rs`):
- 新增 `udp: bool` (默认 true, REJECT=false)
- 新增 `history: Vec<DelayHistory>` (当前空数组)
- 新增 `DelayHistory { time: String, delay: u16 }`
- `now` 字段改为 skip_serializing_if = String::is_empty

**GLOBAL 虚拟组** (`handlers.rs`):
- 收集所有非 Direct/Reject/DNS 的 outbound tags
- 注入 `{"type":"Fallback", "name":"GLOBAL", "udp":true, "all":[...], "now":first_tag}`

**Connections Snapshot** (`handlers.rs`):
- 返回 `{downloadTotal, uploadTotal, connections, memory}`
- totals 从当前连接累加, memory 用真实进程内存

**其他 P0**:
- 根路径: `{"hello":"clash"}`
- PATCH /configs: 只处理 mode → 204
- GET /version: `premium:true`, version 格式 `"sing-box X.Y.Z"`

### Phase 3 P1: 功能正确性修复 (7)

**HTTP URL test** (`handlers.rs`):
- 旧: `measure_outbound_delay()` — TCP connect only
- 新: `http_url_test()` — 通过 outbound 建连 → HTTP/1.1 GET → 读取响应
- `parse_url_components(url) → (host, port, path)`
- 超时→504, 连接失败→503, 成功→`{"delay": N}`

**GET /proxies/:name** (`server.rs`, `handlers.rs`):
- 新增 `get_proxy` handler, 返回单个 proxy 的 proxyInfo
- 路由: `get(get_proxy).put(select_proxy)`

**meta/group 修复** (`handlers.rs`):
- `get_meta_groups`: `{"groups":{map}}` → `{"proxies":[array]}`, 仅 OutboundGroup
- `get_meta_group_delay`: 单节点 → 并发测试全成员, 返回 `{tag:delay}` map

**简化/对齐**:
- PUT /configs → no-op 204 (Go 行为)
- DELETE /connections → 204
- 去 meanDelay

### Phase 3 P2: 完整性修复 (3)

**memory WS 端点** (`websocket.rs`):
- `memory_websocket` + `handle_memory_websocket_inner`
- WS: 每秒推送 `{"inuse":N,"oslimit":0}`, 首次 inuse=0
- `get_process_memory()`: Linux /proc/self/statm, 其他平台 0

**memory 双模式** (`handlers.rs`):
- `get_meta_memory`: `Option<WebSocketUpgrade>` → WS 或 HTTP fallback
- HTTP: 返回 `{"inuse":N,"oslimit":0}`

**错误格式统一** (`handlers.rs`):
- 14 处 `{"error":"...","message":"..."}` → `{"message":"..."}`
- 与 Go HTTPError struct 一致

## WP-L2.6 Selector 持久化 + Proxy 状态真实化

### 核心问题

两个关键缺陷同时修复：
1. **Latent bug**: `SelectorOutbound`/`UrlTestOutbound` 未覆盖 `as_any()`（默认返回 `None`），导致 handlers.rs 中所有 `downcast_ref::<SelectorGroup>()` **静默失败** — GUI 实际看不到任何 selector group 信息
2. **无持久化**: SelectorGroup 不接入 CacheFile，重启后代理选择丢失

### L2.6.1 CacheFile trait 扩展

- `crates/sb-core/src/context.rs`: CacheFile trait +3 methods (get_selected, get_expand, set_expand)
- `crates/sb-core/src/services/cache_file.rs`: CacheFileService impl 补齐 3 个转发（inherent 方法已存在）

### L2.6.2 OutboundGroup trait + as_group()

**新增 trait** (`crates/sb-core/src/adapter/mod.rs`):
- `OutboundGroup` trait: `now()`, `all()`, `group_type()`, `members_health()`, `select_outbound()`
- `OutboundConnector::as_group()` default method → `None`

**SelectorGroup 实现** (`selector_group.rs`):
- `group_type()` 根据 SelectMode 返回 "Selector"/"URLTest"/"LoadBalance"
- `now()` 用 `try_read()` 同步获取（非 async trait 约束）
- `select_outbound()` 返回 `Pin<Box<dyn Future>>` 委托到 `select_by_name()`

**Adapter 转发修复** (selector.rs, urltest.rs):
- SelectorOutbound/UrlTestOutbound 添加 `as_any()` + `as_group()` 转发到 inner
- **这是本次修复的核心**：之前缺少这两个转发，所有 downcast 静默失败

### L2.6.3 SelectorGroup CacheFile 集成

**Struct 变更**:
- 新增 `cache_file: Option<Arc<dyn CacheFile>>` 字段

**构造函数变更**:
- `new_manual()`: 增加 cache_file 参数 + 三阶段恢复 (cache → default → first member)
- `new_urltest()`: 增加 cache_file 参数（不做恢复，URLTest 不持久化选择）
- `new_load_balancer()`: 增加 cache_file 参数

**持久化写入**:
- `select_by_name()` 内部在赋值后调用 `cache.set_selected()`

**新增测试 (3)**:
- `test_cache_file_restore_on_construction` — MockCacheFile 预设 → 构造时恢复
- `test_cache_file_restore_ignores_nonexistent_member` — 缓存值对应不存在的成员 → 回退到 default
- `test_select_by_name_persists_to_cache` — 选择后验证 MockCacheFile 被写入

### L2.6.4 Builder 接线

- `crates/sb-adapters/src/outbound/selector.rs`: `ctx.context.cache_file.clone()` → new_manual
- `crates/sb-adapters/src/outbound/urltest.rs`: `ctx.context.cache_file.clone()` → new_urltest
- `app/src/bootstrap.rs`: `cache_service.clone()` → 两处构造函数

### L2.6.5 handlers.rs 重构

7 处 `downcast_ref::<SelectorGroup>()` → `as_group()`:
- `infer_proxy_type`: 使用 `group.group_type()` 动态返回类型名
- `get_proxies`: 使用 `group.all()` + `group.now()` + `group.group_type()`
- `get_proxy`: 同上
- `select_proxy`: 使用 `group.select_outbound()`，移除外部 cache.set_selected()
- `get_meta_groups`: 使用 as_group() 替代 downcast
- `get_meta_group`: 同上
- `get_meta_group_delay`: 使用 `group.all()` 获取成员列表

**Import 变更**: 移除 `use sb_core::outbound::selector_group::SelectorGroup;`

### 验证

| 构建 | 状态 |
|------|------|
| `cargo check --workspace` | ✅ |
| `cargo check -p app --features router` | ✅ |
| `cargo check -p app --features parity` | ✅ |
| `cargo test --workspace` | ✅ 1435 passed |
| `make boundaries` | ✅ exit 0 |

---

## WP-L2.7 URLTest 历史 + 健康检查对齐

### 核心问题

三个缺陷同时修复：
1. **无共享历史存储**：Go 有全局 `URLTestHistoryStorage`（`map[string]*URLTestHistory`），Rust 没有
2. **history 始终空**：API 返回 `history: []`，GUI 无法显示延迟/判断代理活性
3. **tolerance 未使用**：`select_by_latency()` 总取绝对最低延迟，无 sticky 防抖

### L2.7.1 URLTestHistoryStorage trait + URLTestHistoryService

**新增 trait** (`crates/sb-core/src/context.rs`):
- `URLTestHistory { time: SystemTime, delay: u16 }` — 与 Go `adapter.URLTestHistory` 对齐
- `URLTestHistoryStorage` trait: `load(tag)`, `store(tag, history)`, `delete(tag)`
- `Context` 和 `ContextRegistry` 新增 `urltest_history: Option<Arc<dyn URLTestHistoryStorage>>`
- `with_urltest_history()` builder method

**DashMap 实现** (`crates/sb-core/src/services/urltest_history.rs`，**新文件**):
- `URLTestHistoryService` 用 `DashMap<String, URLTestHistory>` — sb-core 已依赖 dashmap
- 每 tag 仅存最新一条（Go 对齐）
- 3 个单元测试：store_and_load, delete, overwrite

### L2.7.2 Bootstrap/ApiState 接线

**ApiState** (`crates/sb-api/src/clash/server.rs`):
- 新增 `urltest_history: Option<Arc<dyn URLTestHistoryStorage>>`
- `ClashApiServer::with_urltest_history()` builder

**Bootstrap** (`app/src/bootstrap.rs`):
- 在 `start_from_config()` 中创建 `URLTestHistoryService`
- 通过 `ctx.with_urltest_history()` 注入 Context
- 通过 `start_clash_api_server()` 新增参数传入 Clash API

### L2.7.3 健康检查写入 + 构造函数扩展

**SelectorGroup** (`crates/sb-core/src/outbound/selector_group.rs`):
- 新增 `urltest_history: Option<Arc<dyn URLTestHistoryStorage>>` 字段
- 三个构造函数 (`new_manual`, `new_urltest`, `new_load_balancer`) 各增加 `urltest_history` 参数
- `run_health_checks()`: 成功 → `store(tag, {time, delay})`; 失败 → `delete(tag)`

**Adapter 传入** (selector.rs, urltest.rs):
- `ctx.context.urltest_history.clone()` 传入构造函数

**全量 call site 更新 (~35 处)**:
- `selector_group_tests.rs`: 12 处
- `selector_integration_tests.rs`: 7 处
- `selector_urltest_adapter_contract.rs`: 5 处
- `selector_urltest_runtime.rs`: 5 处
- `selector_udp_test.rs`: 2 处
- `bootstrap.rs`: 2 处

### L2.7.4 API delay 端点写入

**`get_proxy_delay()`** (`handlers.rs`):
- 成功: `store(proxy_name, {now, delay})`
- 失败: `delete(proxy_name)`

**`get_meta_group_delay()`** (`handlers.rs`):
- spawn 前 clone `urltest_history`
- 每个成员：成功 store，失败 delete

### L2.7.5 proxyInfo 填充 history

**新增 helper** (`handlers.rs`):
- `lookup_proxy_history(storage, tag, outbound)` → `Vec<DelayHistory>`
- 对 group 类型用 `group.now()` 作为 lookup key（Go 行为：group 的 history 是当前活跃成员的 history）
- 用 `humantime::format_rfc3339()` 格式化时间戳

**4 处替换 `history: vec![]`**:
- `get_proxies()`: 使用 `lookup_proxy_history()`
- `get_proxy()`: 同上
- `get_meta_groups()`: 同上
- `get_meta_group()`: 同上

**新依赖**: `humantime = "2.1"` in sb-api/Cargo.toml

### L2.7.6 Tolerance 实现 + 默认值对齐

**select_by_latency 重写** (`selector_group.rs`):
- 找到健康成员中 RTT 最低的 `best`
- 用 `try_read()` 获取当前 `selected` tag
- 如果当前选择存在且 `current_rtt > 0 && current_rtt <= best_rtt + tolerance_ms` → 保持不变（sticky）
- 否则切换到 `best`
- `current_rtt == 0` 表示未测试，不 sticky

**默认值 Go 对齐**:
- `bootstrap.rs`: URL → https, interval → 180s, timeout → 15s
- `handlers.rs`: URL → https, timeout → 15s

**新增测试 (3)**:
- `test_tolerance_keeps_current_when_close` — 差值 < tolerance → 保持
- `test_tolerance_switches_when_far` — 差值 > tolerance → 切换
- `test_tolerance_with_zero_rtt_switches` — current_rtt=0 → 不 sticky

### 验证

| 构建 | 状态 |
|------|------|
| `cargo check --workspace` | ✅ |
| `cargo check -p app --features router` | ✅ |
| `cargo check -p app --features parity` | ✅ |
| `cargo test --workspace` | ✅ 1441 passed (+6) |
| `make boundaries` | ✅ exit 0 |

---

*最后更新：2026-02-08*
