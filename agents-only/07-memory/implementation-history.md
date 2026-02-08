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

## WP-L2.8 ConnectionTracker + 连接面板

### 核心问题

全链路断裂：sb-common 有完善的 ConnTracker 但从未被调用，sb-api 有 ConnectionManager 但从未被填充。

三个缺陷同时修复：
1. **I/O path 未注册**：`new_connection()`/`new_packet_connection()` 做 dial + 双向拷贝，不通知 tracker
2. **API 数据为空/mock**：`/connections` GET 返回空列表，`/traffic` WS 发送 +1000/+4000 mock 数据
3. **close 无效**：`close_connection()` 仅删 HashMap 记录，不关闭真实 socket

### L2.8.1 ConnMetadata 扩展 + CancellationToken

**sb-common/Cargo.toml**:
- 新增 `tokio-util = { version = "0.7", features = ["rt"] }`

**sb-common/src/conntrack.rs**:
- ConnMetadata 新增 5 字段: `host`, `rule`, `chains`, `inbound_type`, `cancel: CancellationToken`
- 新增 6 个 builder 方法: `with_host()`, `with_rule()`, `with_chains()`, `with_inbound_type()`, `with_inbound_tag()`, `with_outbound_tag()`
- `close()`: 先 `cancel()` token 再 `unregister()`
- `close_all()`: 遍历所有连接 cancel + unregister

### L2.8.2 I/O path 注册 + 字节计数

**sb-core/Cargo.toml**:
- 新增 `sb-common` 依赖

**sb-core/src/router/conn.rs**:

TCP (`new_connection`):
- dial 成功后调用 `global_tracker().register()` 注册 ConnMetadata
- clone cancel_token + upload_counter + download_counter
- upload/download spawn 中添加 `cancel_token.cancelled()` select 分支
- `copy_with_recording()` 签名新增 `conn_counter: Option<Arc<AtomicU64>>`，每次 read 后 `fetch_add`
- `copy_with_tls_fragment()` 同理新增 conn_counter 参数
- `tokio::join!` 完成后调用 `tracker.unregister(tracker_id)`

UDP (`new_packet_connection`):
- 同理注册 `Network::Udp`
- upload/download loop 中添加 cancel select 分支
- 每次 send/recv 后 counter.fetch_add
- 结束时 unregister

### L2.8.3 ApiState 接线

**sb-api/Cargo.toml**: 新增 `sb-common` 依赖

**sb-api/src/clash/server.rs**:
- 移除 `connection_manager: Option<Arc<ConnectionManager>>` 字段
- 移除 `use crate::managers::ConnectionManager`
- 两个构造函数移除 `connection_manager: None`
- `/connections` 路由: `get(handlers::get_connections)` → `get(handlers::get_connections_or_ws)`
- `/connectionsUpgrade` 路由: `get(handlers::upgrade_connections)` → `get(handlers::get_connections_or_ws)`

### L2.8.4 /connections WebSocket handler

**sb-api/src/clash/websocket.rs** — 新增两个公开函数:

- `handle_connections_websocket()`: 每秒推送 `build_connections_snapshot()` 结果
- `build_connections_snapshot()`: 遍历 `global_tracker().list()`，构建 Go Snapshot 兼容格式:
  ```json
  {
    "downloadTotal": N,
    "uploadTotal": N,
    "connections": [{ "id", "metadata": {...}, "upload", "download", "start", "chains", "rule" }],
    "memory": N
  }
  ```
- start 时间用 `humantime::format_rfc3339()` 格式化

### L2.8.5 handlers.rs 重写

- `get_connections_or_ws()`: `Option<WebSocketUpgrade>` 双模式（WS → snapshot stream，HTTP → 单次 snapshot）
- `close_connection()`: `global_tracker().close(id)` — cancel token + unregister，始终返回 204
- `close_all_connections()`: `global_tracker().close_all()` — 遍历 cancel + unregister
- 移除 `upgrade_connections()` stub
- 移除 `convert_connection()` 及关联 helper (`determine_connection_type`, `parse_destination_ip/port`)
- 移除未使用常量: `PROXY_TYPE_VLESS/VMESS/TROJAN/SHADOWSOCKS/RELAY`, `DEFAULT_INBOUND_*`, `DEFAULT_DNS_MODE`, `DEFAULT_PROCESS_NAME`, `DEFAULT_PORT`

### L2.8.6 /traffic WebSocket 真实化

- `handle_traffic_websocket()` 完全重写:
  - 旧: 复杂的 mock 数据生成 (welcome msg + heartbeat + mock_traffic_interval += 1000/4000 + broadcast)
  - 新: 简洁的 1s ticker + `global_tracker().total_upload()/total_download()` delta 计算
  - 输出格式: `{"up": delta, "down": delta}`（与 Go 完全一致）

### 验证

| 构建 | 状态 |
|------|------|
| `cargo check --workspace` | ✅ |
| `cargo check -p app --features router` | ✅ |
| `cargo check -p app --features parity` | ✅ |
| `cargo test --workspace` | ✅ all passed |
| `make boundaries` | ✅ exit 0 |

---

## WP-L2.9 Lifecycle 编排

### 核心问题

已有基础设施全部是死代码——OutboundManager 有完整的 Kahn's 拓扑排序但从未被调用：
1. **拓扑排序死代码**：`add_dependency()` 零调用，`get_startup_order()` 零调用，`start_all()` 不使用排序结果
2. **Outbound 未注册**：`populate_bridge_managers()` 显式跳过 outbound（"Skip for now" 注释），OutboundManager 始终为空
3. **无默认 outbound 解析**：Go 有 explicit tag → first → direct fallback，Rust 没有
4. **无启动失败回滚**：supervisor 中间阶段失败后不清理已启动组件

### L2.9.1 纯函数提取

**`crates/sb-core/src/outbound/manager.rs`**:

新增两个纯同步函数（无 RwLock/async，可测试，两路径直接复用）：
- `compute_outbound_deps(outbounds: &[OutboundIR]) → HashMap<String, Vec<String>>`
  - 遍历 IR，对 Selector/UrlTest 类型提取 `ob.members`
  - 跳过无名或空 members 的 outbound
- `validate_and_sort(all_tags: &[String], deps: &HashMap<String, Vec<String>>) → Result<Vec<String>, String>`
  - Kahn's 算法 with BinaryHeap (确定性排序)
  - 依赖 B→A 表示 "B 必须在 A 之前启动"
  - Missing deps（不在 all_tags 中）静默忽略（Go 对齐）
  - 循环依赖返回 Err with 参与节点列表

重构 `get_startup_order()` 委托到 `validate_and_sort()`。

### L2.9.2 Bridge 依赖追踪

**`crates/sb-core/src/adapter/mod.rs`**:
- Bridge struct 新增 `outbound_deps: HashMap<String, Vec<String>>`
- `Bridge::new()` 初始化为空 HashMap
- Debug impl 添加 deps 计数

**`crates/sb-core/src/adapter/bridge.rs`**:
- router 和 non-router 两个 `build_bridge()` 变体均在 assemble_outbounds + assemble_selectors 后调用 `compute_outbound_deps()` 填充 `br.outbound_deps`

### L2.9.3 Supervisor 接线

**`crates/sb-core/src/runtime/supervisor.rs`**:

`populate_bridge_managers()` 签名改为 `async fn(...) -> Result<()>`：
1. 注册 outbound tag 到 OutboundManager（用 DirectConnector 占位，因 Bridge 用 adapter::OutboundConnector trait 与 OutboundManager 的 traits::OutboundConnector 不兼容）
2. 注册依赖边 (`add_dependency`)
3. 调用 `validate_and_sort()` 验证拓扑（cycle → 快速失败）
4. 从 `ctx.network.route_options()` 提取 default tag，调用 `resolve_default()`
5. 日志 "OUTBOUND READY CHECKPOINT"

4 个调用处全部加 `?` 传播错误。

### L2.9.4 Legacy 接线

**`app/src/bootstrap.rs`**:
- `start_from_config()` 在 `build_outbound_registry_from_ir()` 之后：
  - 调用 `compute_outbound_deps()` + `validate_and_sort()` 验证
  - `ensure_fallback_direct()` + `set_default()` 解析默认 outbound

### L2.9.5 Default Outbound 解析

**`crates/sb-core/src/outbound/manager.rs`**:

新增 `resolve_default(config_tag: Option<&str>) → Result<String, String>`：
1. 显式 tag（`route.final` / `route.default`）→ 验证存在 → set_default
2. 无显式 tag → 取第一个已注册 outbound
3. 无 outbound → `ensure_fallback_direct()` + set_default("direct")
4. 每个分支均 info 日志标注 source（config/first_registered/fallback）

### L2.9.6-7 Startup Checkpoint + 失败回滚

**Supervisor router/non-router start()**:
- `run_context_stage(Start)` 失败 → `shutdown_context()`
- `populate_bridge_managers()` 失败 → error 日志 + `shutdown_context()`
- PostStart/Started 失败 → `request_shutdown()` all inbounds + `stop_endpoints()` + `stop_services()` + `shutdown_context()`

### L2.9.8 Startable 升级

**`crates/sb-core/src/context.rs`**:
- OutboundManager Startable impl：
  - Initialize → debug 日志
  - Start → info 日志
  - PostStart/Started → debug 日志
  - close → info 日志

### L2.9.9 测试（12 新测试）

| 测试 | 验证内容 |
|------|---------|
| `test_compute_outbound_deps_extracts_selector_members` | Selector/UrlTest → members 提取 |
| `test_compute_outbound_deps_skips_empty_members` | 空 members 跳过 |
| `test_validate_and_sort_linear` | A→B→C 线性，返回 C,B,A |
| `test_validate_and_sort_cycle_detected` | A↔B 循环，返回 Err |
| `test_validate_and_sort_missing_dep_ignored` | 依赖不存在的 X，静默忽略 |
| `test_validate_and_sort_no_deps` | 无依赖，字母序输出 |
| `test_validate_and_sort_diamond` | 菱形依赖 A←B,C←D |
| `test_resolve_default_explicit` | 配置显式 tag |
| `test_resolve_default_not_found` | 不存在的 tag → Err |
| `test_resolve_default_first_registered` | 无显式 → 取第一个 |
| `test_resolve_default_fallback_direct` | 无 outbound → 自动 direct |
| `test_get_startup_order_delegates_to_validate_and_sort` | 委托验证 |

### 关键发现：两套 OutboundConnector trait

Bridge 存储 `Arc<dyn adapter::OutboundConnector>`（有 `connect(host, port)`），OutboundManager 存储 `Arc<dyn traits::OutboundConnector>`（有 `connect_tcp(ctx)`）。两者类型不兼容。

解决方案：OutboundManager 在此阶段仅用于 **tag 追踪 + 依赖排序 + default 解析**，实际连接路由仍走 Bridge/OutboundRegistryHandle。注册时用 DirectConnector 占位。

### 验证

| 构建 | 状态 |
|------|------|
| `cargo check --workspace` | ✅ |
| `cargo check -p app --features router` | ✅ |
| `cargo check -p app --features parity` | ✅ |
| `cargo test -p sb-core -- manager::tests` | ✅ 16 passed (12 new) |
| `cargo test --workspace` | ✅ |
| `make boundaries` | ✅ exit 0 |

---

## WP-L2.10 DNS 栈对齐

### 核心问题

DNS 栈处于 "基础设施丰富但关键链路断裂" 状态（与 L2.8 同模式）：42+ 文件、10 种 transport、rule engine、FakeIP、cache、RDRC storage，但 `DnsRouter.exchange()` 返回 "not yet supported"，RDRC 未接入，FakeIP 全局 env-gated 而非规则驱动。

11 个缺口，4 Phase 逐步联通：

### Phase 1: 核心链路联通 (L2.10.1-L2.10.7)

#### L2.10.1 — message.rs wire-format 工具

**`crates/sb-core/src/dns/message.rs`** — 纯函数，无 I/O：
- `build_dns_response(query, ips, ttl, rcode) -> Option<Vec<u8>>` — 从 query 构建 DNS 应答，拷贝 question section，设 QR=1/RD=1/RA=1，用 name pointer (0xC00C) 指向 QNAME
- `extract_rcode(pkt) -> Option<u8>` — byte[3] & 0x0F
- `parse_all_answer_ips(pkt) -> Vec<IpAddr>` — 解析所有 A/AAAA answer records
- `get_query_id(pkt) -> Option<u16>` — 前 2 bytes
- `set_response_id(response, id)` — 设置前 2 bytes
- 7 个新单元测试（roundtrip, ipv6, nxdomain, set_id, short_packet）

#### L2.10.2 — DnsRuleEngine.exchange() 实现

**`crates/sb-core/src/dns/rule_engine.rs`** (lines 606-648):
1. `parse_question_key(message)` 提取 domain + qtype
2. qtype 映射: 1→A, 28→AAAA, 其他→空响应 rcode=4 (NotImpl)
3. 调用 `self.resolve_with_context(ctx, domain, record_type)`
4. Rcode 映射: NoError→0, NxDomain→3, Refused→5, ServFail→2
5. `build_dns_response(message, &answer.ips, ttl, rcode)` 构建 wire response
6. 保留原始 query transaction ID

#### L2.10.3-4 — RDRC transport-aware API

**`crates/sb-core/src/services/cache_file.rs`**:
- `check_rdrc_rejection(transport_tag, domain, qtype) -> bool` — key: `"{tag}\x00{domain}\x00{qtype}"`
- `save_rdrc_rejection(transport_tag, domain, qtype)` — 存储空 RdrcEntry + 过期时间
- 支持 Memory 和 Persistence (sled) 两种 backend
- 1 个新测试（transport 隔离验证）

#### L2.10.5 — DNS Inbound DnsRouter 路径

**`crates/sb-adapters/src/inbound/dns.rs`**:
- 新增 `dns_router: Option<Arc<dyn DnsRouter>>` 字段
- UDP 和 TCP handler 优先走 `router.exchange()` 路径
- 回退到 `ResolverHandle` 原路径（向后兼容）
- `with_dns_router()` builder 方法
- 手动 Debug impl（DnsRouter 非 Debug）

#### L2.10.7 — Bootstrap 接线

**`crates/sb-core/src/dns/config_builder.rs`**:
- `build_dns_components(ir, cache_file)` 新增 `Option<Arc<CacheFileService>>` 参数
- `resolver_from_ir(ir)` 内部传 `None`
- `crates/sb-core/src/adapter/bridge.rs`: 更新调用传 `None`

### Phase 2: Transport 类型补齐 (L2.10.8-L2.10.13)

#### L2.10.8 — DnsServerIR server_type 字段

**`crates/sb-config/src/ir/mod.rs`**:
- `server_type: Option<String>` — `#[serde(rename = "type")]`
- `inet4_range: Option<String>` / `inet6_range: Option<String>` — FakeIP 范围
- `hosts_path: Vec<String>` — hosts 文件路径
- `predefined: Option<serde_json::Value>` — 预定义 domain→IP 映射

#### L2.10.9 — FakeIpUpstream adapter

**`crates/sb-core/src/dns/upstream.rs`**:
- `FakeIpUpstream` struct — 实现 `DnsUpstream` trait
- `query(domain, A)` → `fakeip::allocate_v4(domain)`, TTL=600s
- `query(domain, AAAA)` → `fakeip::allocate_v6(domain)`, TTL=600s
- `health_check()` → 始终 true（本地，无故障）
- 可通过 env var 覆盖全局 FakeIP 范围
- 4 个新测试

#### L2.10.10 — HostsUpstream adapter

**`crates/sb-core/src/dns/upstream.rs`**:
- `HostsUpstream` struct — HashMap entries + hosts 文件解析
- `from_json_predefined(tag, json, hosts_paths)` — 从 JSON predefined + 文件加载
- `parse_hosts_file(content, map)` — /etc/hosts 格式解析（# 注释、多域名行）
- query 按 record_type 过滤 IPv4/IPv6，未找到返回 NxDomain
- 大小写不敏感 domain 查找
- 7 个新测试

#### L2.10.11 — Config builder fakeip/hosts 支持

**`crates/sb-core/src/dns/config_builder.rs`**:
- `build_upstream_from_server()`: server_type 优先判断，"fakeip" → FakeIpUpstream, "hosts" → HostsUpstream
- 回退到 address 前缀匹配（兼容旧配置）
- 跟踪 fakeip_tags: 构建后调用 `engine.mark_fakeip_upstream(tag)`

#### L2.10.12 — FakeIP 规则驱动

**`crates/sb-core/src/dns/rule_engine.rs`**:
- `fakeip_tags: HashSet<String>` 字段
- `mark_fakeip_upstream(tag)` / `is_fakeip_upstream(tag)` 方法
- `lookup()`: 通过 `resolve_dual_stack_with_context()` 走正常规则路径
- `lookup_default()`: 若 default upstream 是 FakeIP，自动找第一个非 FakeIP upstream

#### L2.10.13 — Reverse Mapping (IP→domain)

**`crates/sb-core/src/dns/dns_router.rs`**:
- `DnsRouter` trait 新增 `lookup_reverse_mapping(&self, ip: &IpAddr) -> Option<String>`（默认返回 None）

**`crates/sb-core/src/dns/rule_engine.rs`**:
- `reverse_mapping: parking_lot::Mutex<lru::LruCache<IpAddr, String>>` — 1024 entries
- `resolve_with_context()` 成功后存储每个 answer IP → domain
- `impl DnsRouter` 中实现 `lookup_reverse_mapping()`

### Phase 3: DNS 规则动作补齐 (L2.10.14-L2.10.17)

#### L2.10.14 — route-options 动作

**`crates/sb-core/src/dns/rule_engine.rs`**:
- `DnsRuleAction::RouteOptions` variant
- `route_domain()` 中遇到 RouteOptions → 累积 `disable_cache`/`rewrite_ttl`/`client_subnet` → **continue** 匹配后续规则
- `DnsRoutingRule` 新增 `disable_cache: Option<bool>`, `rewrite_ttl: Option<u32>`, `client_subnet: Option<String>`

#### L2.10.15 — predefined 动作

**`crates/sb-core/src/dns/rule_engine.rs`**:
- `DnsRuleAction::Predefined` variant
- `resolve_with_context()` 中与 `HijackDns` 共用处理路径（rewrite_ip + rcode）
- Config builder 解析 `action: "predefined"` → Predefined

#### L2.10.16 — Address-limit 结构

- 保留现有 `address_limit` 作为 IP 数量截断
- 两阶段匹配结构（route_domain loop）在 Phase 1 已部分建立
- RDRC 集成点已就绪（save_rdrc_rejection / check_rdrc_rejection）

#### L2.10.17 — DNS Hijack 路由动作

**`crates/sb-core/src/router/rules.rs`**:
- `Decision::HijackDns` variant（从 `Reject` 占位改为独立决策）
- `is_terminal()` 包含 HijackDns
- `as_str()` → "hijack-dns"

**5 处 match 穷尽修复**:
- `engine.rs`: decision_to_route_result
- `handler.rs`: decision_to_target
- `socks/mod.rs`, `socks/udp.rs`: SOCKS 路由
- `http.rs`, `anytls.rs`: HTTP/AnyTLS 路由（parity feature）

### Phase 4: 缓存增强 + EDNS0 (L2.10.18-L2.10.21)

#### L2.10.18 — Independent cache per-transport

**`crates/sb-core/src/dns/cache.rs`**:
- `Key` struct 新增 `transport_tag: Option<String>`
- 通过 Hash/Eq 自动隔离（None = 共享，Some("tag") = 独立）
- 所有现有 Key 构造处补充 `transport_tag: None`
- 4 个新测试（隔离、共享、混合）

#### L2.10.19 — disable_expire 支持

**`crates/sb-core/src/dns/cache.rs`**:
- `DnsCache` 新增 `disable_expire: bool` 字段 + `with_disable_expire()` builder
- `get()` 跳过 TTL 过期检查
- `cleanup_expired()` 变为 no-op
- `peek_remaining()` 返回原始 TTL
- LRU 淘汰不受影响
- 5 个新测试

**`crates/sb-config/src/ir/mod.rs`**: DnsIR 新增 `disable_expire: Option<bool>`

#### L2.10.20 — ECS wire-format 注入

**`crates/sb-core/src/dns/message.rs`**:
- `parse_subnet(subnet) -> Option<(family, prefix, addr_bytes)>` — 解析 "IP/prefix" 格式
- `inject_edns0_client_subnet(message, subnet) -> bool` — 注入 EDNS0 ECS option (code=8)
  - 有 OPT record → 追加 option + 更新 RDLENGTH
  - 无 OPT record → 追加新 OPT pseudo-RR (UDP payload 4096) + ARCOUNT++
- `parse_edns0_client_subnet(message) -> Option<String>` — 从 additional section 解析 ECS
- `skip_name(pkt, off)` — 高效跳过 DNS name（不 materialize 字符串）
- 11 个新测试（roundtrip IPv4/IPv6, inject/parse, edge cases）

#### L2.10.21 — Per-rule client_subnet 传播

**`crates/sb-core/src/dns/rule_engine.rs`**:
- `RoutingDecision` struct 新增 `client_subnet: Option<String>`
- RouteOptions accumulated_client_subnet 写入 decision
- 优先级: RouteOptions 累积 > 匹配规则自身 > None

### 修改文件总览

| 文件 | Phase | 变更 |
|------|-------|------|
| `sb-core/src/dns/message.rs` | 1,4 | +build_dns_response, +extract_rcode, +parse_all_answer_ips, +get/set_query_id, +inject/parse_edns0_client_subnet, +parse_subnet, +skip_name, +18 tests |
| `sb-core/src/dns/rule_engine.rs` | 1-4 | exchange() impl, +RouteOptions/Predefined actions, +fakeip_tags, +reverse_mapping, +client_subnet propagation |
| `sb-core/src/dns/config_builder.rs` | 1,2 | +cache_file param, +fakeip/hosts support, +mark_fakeip_upstream |
| `sb-core/src/dns/dns_router.rs` | 2 | +lookup_reverse_mapping() |
| `sb-core/src/dns/upstream.rs` | 2 | +FakeIpUpstream, +HostsUpstream, +11 tests |
| `sb-core/src/dns/cache.rs` | 4 | +transport_tag in Key, +disable_expire, +10 tests |
| `sb-core/src/services/cache_file.rs` | 1 | +check/save_rdrc_rejection(), +1 test |
| `sb-config/src/ir/mod.rs` | 2,4 | DnsServerIR +5 fields, DnsIR +disable_expire |
| `sb-adapters/src/inbound/dns.rs` | 1 | +dns_router field, +DnsRouter exchange path |
| `sb-core/src/router/rules.rs` | 3 | +Decision::HijackDns |
| `sb-core/src/router/engine.rs` | 3 | +HijackDns match |
| `sb-core/src/endpoint/handler.rs` | 3 | +HijackDns match |
| `sb-adapters/src/inbound/socks/{mod,udp}.rs` | 3 | +HijackDns match |
| `sb-adapters/src/inbound/{http,anytls}.rs` | 3 | +HijackDns match |
| `sb-config/src/validator/v2.rs` | 4 | +disable_expire parsing |
| `sb-core/src/dns/{mod,resolve,integration_tests}.rs` | 4 | +transport_tag: None in Key |
| `sb-core/tests/dns_{cache,steady,parse_ttl_qtype}.rs` | 4 | +transport_tag: None in Key |
| `sb-core/tests/dns_rule_{integration,routing_integration}.rs` | 3 | +new DnsRoutingRule fields |

### 验证

| 构建 | 状态 |
|------|------|
| `cargo check --workspace` | ✅ |
| `cargo check -p app --features router` | ✅ |
| `cargo check -p app --features parity` | ✅ |
| `cargo test --workspace` | ✅ 1492 passed (+51 new) |
| `make boundaries` | ✅ exit 0 |

---

*最后更新：2026-02-08（L2 Closed，L3 Scope 创建）*

---

## L2 里程碑关闭

**关闭日期**: 2026-02-08
**Parity**: 88% (183/209) → 99% (208/209)
**测试**: 1431 → 1492 (+61)

### 完成清单

| Tier | 包 | 关键交付 |
|------|-----|---------|
| T1 | L2.2 maxminddb | GeoIP 查询 |
| T1 | L2.3 Config schema | Go 1:1 对齐 |
| T1 | L2.4 Clash API 初步 | 端点 + GLOBAL |
| T1 | L2.5 CLI | 参数对齐 |
| T1 | L2.1 审计 | 18 项偏差修复 |
| T2 | L2.6 Selector 持久化 | OutboundGroup + CacheFile |
| T2 | L2.7 URLTest 历史 | History + tolerance |
| T2 | L2.8 ConnectionTracker | I/O 接入 + WS + close |
| T2 | L2.9 Lifecycle | 拓扑排序 + 回滚 |
| T2 | L2.10 DNS 栈 | 全链路 (11 缺口修复) |

### 移入 L3 的残余项

| 包 | 内容 | 来源 |
|----|------|------|
| L3.1 | SSMAPI (PX-011) | L2 Tier 3 |
| L3.2 | DERP (PX-014) | L2 Tier 3 |
| L3.3 | Resolved (PX-015) | L2 Tier 3 |
| L3.4 | Cache File 深度对齐 (PX-009/013) | PX-009 残余 |
| L3.5 | ConnMetadata chain/rule | L2.8 延后决策 |

### Won't Fix

- **PX-007 Adapter 接口抽象**: Rust IR-based 架构是合理差异
- **6 项 TLS/WireGuard**: rustls/平台库限制 (Accepted Limitation)
