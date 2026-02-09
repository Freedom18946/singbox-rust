# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护
> **优先级**：AI 启动时优先读取此文件

---

## 🔗 战略链接

**当前阶段**: **L3 Polish / Edge Services** （L1 ✅ Closed, L2 ✅ Closed）
**Parity**: ~99% (208/209)
**Tests**: 1492+ passed, boundaries clean

### 已关闭里程碑

| 里程碑 | 关闭日期 | 内容 |
|--------|---------|------|
| **L1 架构整固** | 2026-02-07 | M1.1 + M1.2 + M1.3，check-boundaries.sh exit 0 |
| **L2 功能对齐** | 2026-02-08 | Tier 1 (L2.1-L2.5) + Tier 2 (L2.6-L2.10)，88% → 99% parity |

### 关键参考

- **Clash API 审计报告**: `agents-only/05-analysis/CLASH-API-AUDIT.md`
- **L2 缺口分析**: `agents-only/05-analysis/L2-PARITY-GAP-ANALYSIS.md`
- **DNS 栈分析**: `agents-only/05-analysis/L2.10-DNS-STACK-ANALYSIS.md`
- **L3 Scope**: 见下方

---

<details>
<summary>L2 详细实施记录（已归档至 implementation-history.md）</summary>

## ✅ L2.10 DNS 栈对齐

**日期**: 2026-02-08
**Parity**: 94% → ~99%

### 修复的核心问题

1. **DnsRouter.exchange() 死代码** — 返回 "not yet supported"。实现: parse query → resolve_with_context → build_dns_response wire-format 往返
2. **RDRC 从未调用** — CacheFileService 有 RDRC 存储但无 transport-aware API。新增 `check_rdrc_rejection(transport, domain, qtype)` / `save_rdrc_rejection()`
3. **FakeIP 全局 env-gated 而非规则驱动** — 新增 `FakeIpUpstream` adapter 实现 DnsUpstream trait，由规则路由；lookup() 跳过 FakeIP
4. **无 Hosts upstream** — 新增 `HostsUpstream` adapter，支持 predefined JSON + /etc/hosts 文件
5. **DnsServerIR 缺 server_type** — GUI 生成 `type: "fakeip"/"hosts"` 等，IR 只有 address 前缀判断
6. **DNS 规则动作不完整** — 新增 RouteOptions（修改选项继续匹配）、Predefined（返回预定义响应）
7. **DNS hijack 路由动作为占位** — `Decision::HijackDns` 从 Reject 变为独立决策
8. **缓存无 transport 隔离** — 新增 independent_cache: Key 包含 transport_tag
9. **缓存无 disable_expire** — 新增 disable_expire: 跳过 TTL 过期检查
10. **ECS 仅 UDP 注入** — 新增 wire-format 层 `inject_edns0_client_subnet()` / `parse_edns0_client_subnet()`
11. **无反向映射** — 新增 reverse_mapping LruCache(1024) + `DnsRouter.lookup_reverse_mapping(ip)`

### 4 Phase 实施

| Phase | 内容 | 状态 |
|-------|------|------|
| Phase 1 | 核心链路联通 (exchange, RDRC, DNS inbound, bootstrap wiring) | ✅ |
| Phase 2 | Transport 类型补齐 (server_type, FakeIP, Hosts, 规则驱动, 反向映射) | ✅ |
| Phase 3 | DNS 规则动作补齐 (route-options, predefined, address-limit, hijack-dns) | ✅ |
| Phase 4 | 缓存增强 + EDNS0 (independent cache, disable_expire, ECS inject, per-rule subnet) | ✅ |

### 修改文件

| 文件 | 变更 |
|------|------|
| `crates/sb-core/src/dns/message.rs` | +build_dns_response(), +extract_rcode(), +parse_all_answer_ips(), +get_query_id(), +set_response_id(), +inject_edns0_client_subnet(), +parse_edns0_client_subnet(), +18 tests |
| `crates/sb-core/src/dns/rule_engine.rs` | exchange() 实现, +RouteOptions/Predefined actions, +fakeip_tags, +reverse_mapping, +client_subnet propagation |
| `crates/sb-core/src/dns/config_builder.rs` | +cache_file param, +fakeip/hosts support, +mark_fakeip_upstream, +route-options/predefined parsing |
| `crates/sb-core/src/dns/dns_router.rs` | +lookup_reverse_mapping() trait method |
| `crates/sb-core/src/dns/upstream.rs` | +FakeIpUpstream, +HostsUpstream, +11 tests |
| `crates/sb-core/src/dns/cache.rs` | +transport_tag in Key, +disable_expire, +10 tests |
| `crates/sb-core/src/services/cache_file.rs` | +check_rdrc_rejection(), +save_rdrc_rejection(), +1 test |
| `crates/sb-config/src/ir/mod.rs` | DnsServerIR +server_type/inet4_range/inet6_range/hosts_path/predefined, DnsIR +disable_expire |
| `crates/sb-adapters/src/inbound/dns.rs` | +dns_router field, +DnsRouter exchange path with fallback |
| `crates/sb-core/src/router/rules.rs` | +Decision::HijackDns variant |
| `crates/sb-core/src/router/engine.rs` | +HijackDns match arm |
| `crates/sb-core/src/endpoint/handler.rs` | +HijackDns match arm |
| `crates/sb-adapters/src/inbound/{socks,http,anytls}` | +HijackDns match arm |

### 构建验证

| 构建 | 状态 |
|------|------|
| `cargo check --workspace` | ✅ |
| `cargo check -p app --features router` | ✅ |
| `cargo check -p app --features parity` | ✅ |
| `cargo test --workspace` | ✅ 1492 passed (+51 new) |
| `make boundaries` | ✅ exit 0 |

---

## ✅ 已完成：L2.9 Lifecycle 编排

**日期**: 2026-02-08
**Parity**: 93% → 94%

### 修复的核心问题

1. **拓扑排序死代码** — `OutboundManager` 有完整的 Kahn's 算法和 `add_dependency()` 方法，但**从未被调用**。`get_startup_order()` 存在但 `start_all()` 不使用它
2. **Outbound 未注册到 OutboundManager** — `populate_bridge_managers()` 显式跳过 outbound 注册（"Skip for now" 注释），导致 dependency tracking 和 default resolution 无效
3. **无默认 outbound 解析** — Go 有完整的 default outbound 解析（explicit tag → first → direct fallback），Rust 没有
4. **无启动失败回滚** — supervisor `start()` 中间阶段失败后不清理已启动的组件

### 核心策略

提取纯函数 `compute_outbound_deps()` + `validate_and_sort()` 实现依赖解析和拓扑排序，在 `populate_bridge_managers()` 中接线到 OutboundManager，两路径（Supervisor + legacy bootstrap）同步改。

### 子任务

| 步骤 | 子任务 | 状态 |
|------|--------|------|
| L2.9.1 | compute_outbound_deps + validate_and_sort 纯函数 | ✅ |
| L2.9.2 | Bridge 新增 outbound_deps 字段 + build_bridge 填充 | ✅ |
| L2.9.3 | Supervisor populate_bridge_managers 接线 (Result + 注册 + 验证) | ✅ |
| L2.9.4 | Legacy bootstrap 依赖验证 + default 解析 | ✅ |
| L2.9.5 | OutboundManager::resolve_default() (Go parity) | ✅ |
| L2.9.6 | Startup checkpoint 日志 (OUTBOUND READY CHECKPOINT) | ✅ |
| L2.9.7 | 失败回滚 (shutdown_context + stop endpoints/services/inbounds) | ✅ |
| L2.9.8 | OutboundManager Startable impl 升级 (info 日志) | ✅ |
| L2.9.9 | 12 新测试 (topo sort, cycle, default, resolve) | ✅ |

### 修改文件

| 文件 | 变更 |
|------|------|
| `crates/sb-core/src/outbound/manager.rs` | +compute_outbound_deps(), +validate_and_sort(), +resolve_default(), 重构 get_startup_order(), +12 tests |
| `crates/sb-core/src/adapter/mod.rs` | Bridge +outbound_deps 字段, Bridge::new() 初始化, Debug impl |
| `crates/sb-core/src/adapter/bridge.rs` | build_bridge() 两变体: 调用 compute_outbound_deps() |
| `crates/sb-core/src/runtime/supervisor.rs` | populate_bridge_managers → Result + outbound 注册 + 验证 + default + 回滚 |
| `crates/sb-core/src/context.rs` | OutboundManager Startable: no-op → info 日志 |
| `app/src/bootstrap.rs` | +deps 验证 + default 解析 |

### 构建验证

| 构建 | 状态 |
|------|------|
| `cargo check --workspace` | ✅ |
| `cargo check -p app --features router` | ✅ |
| `cargo check -p app --features parity` | ✅ |
| `cargo test -p sb-core -- manager::tests` | ✅ 16 passed (12 new) |
| `cargo test --workspace` | ✅ |
| `make boundaries` | ✅ exit 0 |

---

## ✅ 已完成：L2.8 ConnectionTracker + 连接面板

**日期**: 2026-02-08
**Commit**: `d708ecb`
**Parity**: 92% → 93%

### 修复的核心问题

1. **全链路断裂** — `sb-common::ConnTracker` 有完善的 DashMap + 原子计数器，但从未被调用。`/connections` GET 始终返回空列表，`/traffic` WS 发送 mock 数据 (+1000/+4000)，`close_connection()` 仅删 HashMap 不关闭 socket
2. **I/O path 未注册** — `new_connection()`/`new_packet_connection()` 做 dial + 双向拷贝，但不通知任何 tracker
3. **ConnectionManager 空壳** — `sb-api/managers.rs::ConnectionManager` 从未被填充，是死代码

### 核心策略

复用 `sb-common::conntrack::ConnTracker` 作为全局连接跟踪器（已有 DashMap、per-connection `Arc<AtomicU64>` 计数器、proper register/unregister lifecycle、全局 upload/download 累计）。只需: (1) 在 I/O path 注册连接 + 传入 byte counters, (2) 暴露给 API 层, (3) 添加 CancellationToken close 能力。

### 子任务

| 步骤 | 子任务 | 状态 |
|------|--------|------|
| L2.8.1 | ConnMetadata 扩展 + CancellationToken (sb-common) | ✅ |
| L2.8.2 | I/O path 注册 + 字节计数 (sb-core/router/conn.rs) | ✅ |
| L2.8.3 | ApiState 接线 (移除 ConnectionManager, 添加 sb-common dep) | ✅ |
| L2.8.4 | /connections WebSocket handler | ✅ |
| L2.8.5 | handlers.rs 重写 (GET + DELETE) | ✅ |
| L2.8.6 | /traffic WebSocket 真实化 | ✅ |

### 修改文件

| 文件 | 变更 |
|------|------|
| `crates/sb-common/Cargo.toml` | +tokio-util (CancellationToken) |
| `crates/sb-common/src/conntrack.rs` | ConnMetadata +5 字段, +6 builder 方法, close/close_all cancel token |
| `crates/sb-core/Cargo.toml` | +sb-common 依赖 |
| `crates/sb-core/src/router/conn.rs` | new_connection/new_packet_connection 注册 tracker, copy_with_recording/tls_fragment +conn_counter, cancel token select 分支 |
| `crates/sb-api/Cargo.toml` | +sb-common 依赖 |
| `crates/sb-api/src/clash/server.rs` | 移除 connection_manager 字段, /connections 路由改为双模式 |
| `crates/sb-api/src/clash/handlers.rs` | 新增 get_connections_or_ws (双HTTP/WS), 重写 close_connection/close_all, 移除 convert_connection 及 dead helpers |
| `crates/sb-api/src/clash/websocket.rs` | 新增 handle_connections_websocket + build_connections_snapshot, 重写 handle_traffic_websocket (真实 delta) |
| `crates/sb-api/tests/clash_endpoints_integration.rs` | 移除 connection_manager 断言 |

### 构建验证

| 构建 | 状态 |
|------|------|
| `cargo check --workspace` | ✅ |
| `cargo check -p app --features router` | ✅ |
| `cargo check -p app --features parity` | ✅ |
| `cargo test --workspace` | ✅ all passed |
| `make boundaries` | ✅ exit 0 |

---

## ✅ 已完成：L2.7 URLTest 历史 + 健康检查对齐

**日期**: 2026-02-08
**Parity**: 91% → 92%

### 修复的核心问题

1. **无共享历史存储** — Go 有全局 `URLTestHistoryStorage`（`map[string]*URLTestHistory`），Rust 没有 → 新增 `URLTestHistoryStorage` trait + `URLTestHistoryService`（DashMap 实现）
2. **history 始终空** — API 返回 `history: []`，GUI 无法显示延迟/判断活性 → 健康检查 + delay 测试 + API 4 处端点均写入/删除历史，proxyInfo 填充真实 history
3. **tolerance 未使用** — `select_by_latency()` 总取绝对最低延迟，无 sticky 防抖 → 实现 Go 的 tolerance 逻辑：当前选择在容差范围内则保持不变

### 子任务

| 步骤 | 子任务 | 状态 |
|------|--------|------|
| L2.7.1 | URLTestHistoryStorage trait + URLTestHistoryService 实现 | ✅ |
| L2.7.2 | Bootstrap/ApiState 接线 | ✅ |
| L2.7.3 | 健康检查写入 + 构造函数扩展 (~35 call sites) | ✅ |
| L2.7.4 | API delay 端点写入 (get_proxy_delay, get_meta_group_delay) | ✅ |
| L2.7.5 | proxyInfo 填充 history (get_proxies, get_proxy, get_meta_groups, get_meta_group) | ✅ |
| L2.7.6 | Tolerance 实现 + 默认值 Go 对齐 | ✅ |

### 修改文件

| 文件 | 变更 |
|------|------|
| `crates/sb-core/src/context.rs` | 新增 URLTestHistory struct + URLTestHistoryStorage trait + urltest_history 字段 (Context/ContextRegistry) |
| `crates/sb-core/src/services/urltest_history.rs` | **新文件**: URLTestHistoryService (DashMap) + 3 单元测试 |
| `crates/sb-core/src/services/mod.rs` | 新增 pub mod urltest_history |
| `crates/sb-core/src/outbound/selector_group.rs` | +urltest_history 字段, 3 构造函数加参数, 健康检查写入历史, select_by_latency tolerance 重写 |
| `crates/sb-core/src/outbound/selector_group_tests.rs` | 12 处构造函数更新 + 3 新 tolerance 测试 |
| `crates/sb-api/src/clash/server.rs` | ApiState +urltest_history 字段, ClashApiServer +with_urltest_history() |
| `crates/sb-api/src/clash/handlers.rs` | +lookup_proxy_history() helper, 4 处 proxyInfo 填充, 2 处 delay 端点写入, 默认值对齐 (15s/https) |
| `crates/sb-api/Cargo.toml` | +humantime = "2.1" |
| `crates/sb-adapters/src/outbound/selector.rs` | 传入 urltest_history |
| `crates/sb-adapters/src/outbound/urltest.rs` | 传入 urltest_history |
| `app/src/bootstrap.rs` | 创建 URLTestHistoryService, 接线 Context + API, 默认值对齐 (180s/15s/https) |
| 5 个测试文件 (31 call sites) | 构造函数参数加 None |

### 默认值 Go 对齐

| 参数 | 旧值 | 新值 (Go 对齐) |
|------|------|----------------|
| test_url | `http://www.gstatic.com/generate_204` | `https://www.gstatic.com/generate_204` |
| interval | 60s | 180s (3 min) |
| timeout | 5s | 15s (Go TCPTimeout) |
| API delay timeout | 5s | 15s |

### 构建验证

| 构建 | 状态 |
|------|------|
| `cargo check --workspace` | ✅ |
| `cargo check -p app --features router` | ✅ |
| `cargo check -p app --features parity` | ✅ |
| `cargo test --workspace` | ✅ 1441 passed (+6 new tests) |
| `make boundaries` | ✅ exit 0 |

---

## ✅ 已完成：L2.6 Selector 持久化 + Proxy 状态真实化

**日期**: 2026-02-08
**Parity**: 89% → 91%

### 修复的核心问题

1. **Latent bug 修复**: `SelectorOutbound`/`UrlTestOutbound` 未覆盖 `as_any()`，导致 handlers.rs 中所有 `downcast_ref::<SelectorGroup>()` **静默失败** — GUI 看不到任何 selector group 信息
2. **CacheFile 持久化联通**: SelectorGroup 构造时从 CacheFile 恢复选择，select_by_name 时持久化到 CacheFile
3. **OutboundGroup trait**: 新增抽象 trait 替代 downcast，正确返回 "Selector"/"URLTest"/"LoadBalance" 类型名

---

## ✅ 已完成：WP-L2.1 Clash API 对接审计

**Commit**: `9bd745a`
**审计报告**: `agents-only/05-analysis/CLASH-API-AUDIT.md`

</details>

---

## 📋 L3 Scope: Polish / Edge Services

**目标**: 边缘服务补全 + 残余 polish，从 99% → 99.5%+ parity

**规划**: `agents-only/03-planning/L3-WORKPACKAGES.md`（一级工作包的范围/依赖/验收/排序）

### L3 工作包

| 包 | 名称 | 来源 PX | 工作量 | 优先级 | 说明 |
|----|------|---------|--------|--------|------|
| L3.1 | SSMAPI 对齐 | PX-011 | 中 | 低 | ✅ 已完成（2026-02-09）：per-endpoint 绑定闭环 + API 行为对齐 + cache 兼容 + Shadowsocks tracker 接线 |
| L3.2 | DERP 配置对齐 | PX-014 | 中 | 低 | ✅ 已完成（2026-02-09）：schema + runtime 语义对齐（verify_client_url/mesh_with/verify_client_endpoint tag/STUN/bootstrap-dns/ListenOptions） |
| L3.3 | Resolved 完整化 | PX-015 | 中 | 低 | Linux-only systemd-resolved D-Bus: resolve1 methods。macOS 不需要 |
| L3.4 | Cache File 深度对齐 | PX-009/013 | 中 | 中 | bbolt bucket 级别持久化: cache_id, FakeIP metadata 10s 去抖, rule_set caching。当前内存/简化持久化可工作 |
| L3.5 | ConnMetadata chain/rule 填充 | L2.8 延后 | 小 | 中 | 连接详情显示命中的规则链。需 Router 层统一路由入口 |

### ✅ 已完成：L3.1 SSMAPI 对齐（PX-011）

**日期**: 2026-02-09
**范围**: SSMAPI per-endpoint 绑定闭环 + HTTP API 行为对齐 + cache 读兼容/写 Go 格式 + Shadowsocks inbound 动态用户/多用户鉴权/流量统计接线。

**关键落点**:
- `crates/sb-core/src/services/ssmapi/registry.rs`：ManagedSSMServer 注册表（tag -> Weak<dyn ManagedSSMServer>）
- `crates/sb-adapters/src/register.rs`：Shadowsocks inbound build 时注册 managed server
- `crates/sb-core/src/services/ssmapi/server.rs`：按 endpoint 构建独立 EndpointCtx，并启动 1min 定时保存 cache（diff-write）
- `crates/sb-core/src/services/ssmapi/api.rs`：路由/状态码/错误体（text/plain）与字段行为对齐
- `crates/sb-adapters/src/inbound/shadowsocks.rs`：update_users 生效、TCP 多用户鉴权、UDP correctness 修复、tracker 统计接线

**验证**:
- `cargo test -p sb-core --features service_ssmapi`
- `cargo test -p sb-adapters --features "adapter-shadowsocks,router,service_ssmapi"`
- `cargo check -p sb-core --all-features`

### ✅ 已完成：L3.2 DERP 配置对齐（PX-014）

**日期**: 2026-02-09
**范围**: DERP 配置 schema + 关键运行时语义对齐（verify_client_url per-URL dialer；mesh_with per-peer dial/TLS + PostStart；verify_client_endpoint tag 语义；STUN enable/defaults；ListenOptions bind；bootstrap-dns 注入 DNSRouter）。

**关键落点**:
- `crates/sb-config/src/ir/mod.rs`：新增 `Listable`/`StringOrObj` + DERP IR（Dial/VerifyURL/MeshPeer/TLS；stun 支持 `bool|number|object`）
- `crates/sb-core/src/service.rs` + `crates/sb-core/src/adapter/{bridge.rs,mod.rs}`：ServiceContext 注入 `dns_router/outbounds/endpoints`
- `crates/sb-core/src/services/derp/server.rs`：dialer factory + verify/mesh/endpoint/bootstrap-dns/listen/stun 行为对齐
- `crates/sb-core/src/endpoint/tailscale.rs`：LocalAPI unix socket path 支持（daemon-only）
- `crates/sb-transport/src/{dialer.rs,builder.rs}`：connect_timeout 生效 + Linux netns 支持

**验证**:
- `CARGO_TARGET_DIR=target-alt cargo test -p sb-config`
- `CARGO_TARGET_DIR=target-alt cargo test -p sb-core --features service_derp`

### 已关闭 / Won't Fix

| 项目 | 决策 | 理由 |
|------|------|------|
| PX-007 Adapter 接口抽象 | **Won't Fix** | Rust 用 IR-based 架构替代 Go adapter.Router/RuleSet 接口，是合理的架构差异 |
| 6 项 TLS/WireGuard 限制 | **Accepted Limitation** | uTLS/REALITY/ECH/TLS fragment/WireGuard endpoint — rustls/平台库限制 |

---

## ✅ L2 关闭总结

**关闭日期**: 2026-02-08
**Parity 提升**: 88% (183/209) → 99% (208/209)
**新增测试**: +61 (1431 → 1492)

### L2 完成工作包

| Tier | 工作包 | 关键交付 |
|------|--------|---------|
| Tier 1 | L2.2 maxminddb | GeoIP 查询修复 |
| Tier 1 | L2.3 Config schema | Go configSchema 1:1 对齐 |
| Tier 1 | L2.4 Clash API 初步 | 基础端点 + GLOBAL 组注入 |
| Tier 1 | L2.5 CLI | `-c`/`-C`/`-D` 参数对齐 |
| Tier 1 | L2.1 审计 | 18 项偏差修复 (12 BREAK + 5 DEGRADE + 1 COSMETIC) |
| Tier 2 | L2.6 Selector 持久化 | OutboundGroup trait + CacheFile + as_group() fix |
| Tier 2 | L2.7 URLTest 历史 | URLTestHistoryStorage + tolerance 防抖 |
| Tier 2 | L2.8 ConnectionTracker | ConnTracker I/O 接入 + WS + 真实 close |
| Tier 2 | L2.9 Lifecycle 编排 | 拓扑排序 + 依赖验证 + default outbound + 回滚 |
| Tier 2 | L2.10 DNS 栈对齐 | exchange() + RDRC + FakeIP/Hosts + 规则动作 + 缓存 + ECS |

### L2 覆盖的 PX 项

PX-004 ✅, PX-005 ✅, PX-006 ✅, PX-008 ✅, PX-010 ✅, PX-012 ✅
PX-009 ◐ (核心功能完成，深度持久化移入 L3.4)
PX-007 Won't Fix (架构差异)

---

## 📝 重要决策记录

| 日期 | 决策 | 原因 |
|------|------|------|
| 2026-02-08 | **L2 关闭，创建 L3 scope** | Tier 1+2 全部完成，99% parity，GUI.for 兼容性目标达成；Tier 3 边缘服务移入 L3 |
| 2026-02-08 | PX-007 Won't Fix | Rust IR-based 架构是合理差异，非缺口 |
| 2026-02-08 | ConnMetadata chain/rule 延后至 L3.5 | 需 Router 层统一路由入口，不影响 GUI 显示 |
| 2026-02-08 | Cache File 深度对齐移入 L3.4 | 当前内存/简化持久化可工作，bbolt 级别是优化 |

<details>
<summary>L2 期间决策记录（已归档）</summary>

| 日期 | 决策 | 原因 |
|------|------|------|
| 2026-02-08 | L2.8 复用 sb-common::ConnTracker 而非 sb-api::ConnectionManager | ConnTracker 已有 DashMap + 原子计数 + register/unregister；ConnectionManager 从未被填充，是死代码 |
| 2026-02-08 | L2.8 handlers 直接调用 global_tracker() | 全局单例无需注入 ApiState，减少接线代码 |
| 2026-02-08 | L2.8 CancellationToken 替代 socket shutdown | tokio_util::CancellationToken 可从 API handler 触发，通过 select! 分支中断 I/O loop |
| 2026-02-08 | L2.8 copy_with_recording 添加 conn_counter 参数 | per-connection 原子计数器通过参数传入，每次 I/O 一次 fetch_add，性能影响可忽略 |
| 2026-02-08 | L2.9 拓扑排序提取为纯函数 validate_and_sort() | 同步、无 RwLock、可测试、两路径（Supervisor + legacy）直接复用 |
| 2026-02-08 | L2.9 OutboundManager 注册 DirectConnector 占位 | Bridge 用 adapter::OutboundConnector trait，OutboundManager 用 traits::OutboundConnector — 类型不兼容，注册占位即可满足 tag 跟踪需求 |
| 2026-02-08 | L2.9 populate_bridge_managers 改为 Result | 依赖验证（cycle detection）和 default 解析可能失败，需向调用方传播错误 |
| 2026-02-08 | L2.9 Startable impl 用轻量日志而非 try_read | tokio::sync::RwLock 无 try_read()，且 Startable::start() 是同步方法 |
| 2026-02-08 | L2.8 延后 chain/rule 字段填充 | 需要 Router 层统一路由入口，当前 inbound adapter 直连 outbound；L2.9 后自然填充 |
| 2026-02-08 | L2.7 URLTestHistoryStorage 用 DashMap | 已是 sb-core 依赖，无锁并发 map，与 Go sync.Map 语义一致 |
| 2026-02-08 | 每 tag 仅存最新一条历史 | Go 对齐：adapter.URLTestHistory 是单条而非数组 |
| 2026-02-08 | tolerance 使用 try_read() 读取 selected | 与 OutboundGroup::now() 同模式，非 async trait 约束 |
| 2026-02-08 | lookup_proxy_history 对 group 用 now() 作为 lookup key | Go 行为：group 的 history 实际是当前活跃成员的 history |
| 2026-02-08 | 默认值对齐 Go (180s/15s/https) | Go sing-box 默认: interval 3min, timeout=TCPTimeout=15s, URL https |
| 2026-02-08 | L2.6 使用 OutboundGroup trait 替代 downcast | downcast 依赖具体类型，跨 crate 时 as_any() 未转发导致静默失败；trait 方式更健壮 |
| 2026-02-08 | SelectorGroup 三阶段恢复 (cache → default → first) | 与 Go 对齐：CacheFile 优先，配置默认值次之，最后兜底第一个成员 |
| 2026-02-08 | OutboundGroup::now() 用 try_read() 而非 .await | OutboundGroup 是非 async trait，try_read() 在无竞争时总是成功，安全可用 |
| 2026-02-08 | 持久化写入在 SelectorGroup 内部完成 | 消除 handler 层重复调用 cache.set_selected() 的风险 |
| 2026-02-08 | WP-L2.1 Clash API 审计全部完成 | GUI.for 完全兼容保障 |
| 2026-02-08 | HTTP URL test 替代 TCP connect | Go 用 HTTP GET 测延迟，TCP connect 结果不等价 |
| 2026-02-08 | Config struct 与 Go configSchema 1:1 对齐 | GUI 直接读取 mode/allow-lan/tun 等字段 |
| 2026-02-08 | GLOBAL 虚拟 Fallback 组注入 | GUI tray 菜单硬依赖 proxies.GLOBAL |
| 2026-02-08 | Tier 2 规划重排 | 按 GUI 可感知度排序，CacheFile 并入 L2.6 |
| 2026-02-07 | B2: 共享契约放 sb-types | 最小依赖, 已有 Port traits 基础 |
| 2026-02-07 | AdapterIoBridge + connect_io() | 加密协议适配器返回 IoStream |

</details>

---

*最后更新：2026-02-09（L3.1 PX-011 SSMAPI 对齐完成）*
