<!-- tier: A -->
# 经验模式库（Learned Patterns）

> **用途**：记录项目中特殊的代码模式、约定和最佳实践
> **维护者**：AI Agent 在开发过程中主动更新

---

## 错误处理

| 模式 | 说明 | 示例 |
|------|------|------|
| 使用 `thiserror` | 所有公共 crate 错误类型 | `#[derive(thiserror::Error)]` |
| 避免 `.unwrap()` | 核心逻辑禁用，测试代码可用 | 用 `?` 或 `anyhow::Context` |
| 错误链保留 | 使用 `#[from]` 或 `#[source]` | 保留原始错误信息 |

---

## 异步模式

| 模式 | 说明 |
|------|------|
| `tokio::select!` | 多路复用时优先使用 |
| 避免 `async-trait` 热路径 | 使用 enum dispatch 替代 |
| `CancellationToken` | 优雅关闭使用 tokio_util |

---

## 依赖边界

| 规则 | 详情 |
|------|------|
| sb-types 零大依赖 | 禁止 tokio/hyper/axum |
| sb-core 内核合集治理 | 允许遗留协议/服务实现，但必须 feature-gated + 可审计 |
| 协议归属默认 | 新增协议默认放 sb-adapters；例外需 ADR |
| 控制面隔离 | sb-api 不直接依赖 sb-adapters；sb-core 的 web 依赖必须 optional |

---

## 有效工作流模式

| 模式 | 说明 |
|------|------|
| 先读后改 | sb-types 零依赖，改完可立即 `cargo check -p sb-types` 验证 |
| re-export 策略 | 迁移类型时用 `pub use sb_types::...` 保持 API 兼容，而非直接删除 |
| 逐步可选化 | 先 `optional = true`，再 feature 列表加 `dep:xxx`，最后 `cargo check` |
| 分层编译验证 | `cargo check -p sb-types` → `-p sb-core` → `--workspace` |
| feature gate 逐步卸载 | 先改 builder 不依赖 out_*，再检查 adapter，最后删 dead forwarding |

## 架构模式

| 模式 | 用途 |
|------|------|
| AdapterIoBridge<A> | 泛型桥接 BoxedStream→IoStream，避免每协议写 wrapper |
| LazyInit (OnceCell) | sync builder + async 初始化 → 首次 dial() 时延迟初始化 |
| BoxedStreamAdapter | pin-project adapter 桥接不同 trait object（非 transmute） |
| HttpClient port + 全局注册 | OnceLock 全局注册消除 reqwest 无条件依赖 |
| quic_util 共享模块 | QuicConfig + quic_connect() 供 TUIC/Hysteria 共用 |

## Clash API 对接模式

| 模式 | 说明 |
|------|------|
| Go configSchema 对齐 | Config struct 字段名、类型、默认值必须与 Go 1:1 对齐，GUI 直接读取 |
| proxyInfo 格式 | 每个 proxy 必须含 type/name/udp/history，group 额外含 now/all |
| GLOBAL 虚拟组注入 | GET /proxies 必须注入 Fallback 类型的 GLOBAL 组，GUI tray 硬依赖 |
| HTTP URL test | 延迟测试必须是完整 HTTP/1.1 GET（不是 TCP connect），结果差异大 |
| 双模式端点 (WS+HTTP) | axum `Option<WebSocketUpgrade>` 实现：有 Upgrade header → WS，否则 → HTTP |
| 错误格式 `{"message":"..."}` | Go 使用 HTTPError struct 只有 message 字段，不要加 error key |
| 204 NoContent 惯例 | Go 的 PATCH/PUT/DELETE 成功操作普遍返回 204，不返回 JSON body |
| 并发 group delay | Go 用 goroutine 并发测试 group 全部成员，Rust 用 tokio::spawn + join |
| history 填充用 lookup key | group 的 history 应查 group.now()（当前活跃成员），而非 group 自身 tag |
| 默认值必须与 Go 对齐 | Go defaults: test_url=https, interval=180s, timeout=15s(TCPTimeout) |

## 共享状态注入模式

| 模式 | 说明 |
|------|------|
| Context builder chain | `Context::new().with_cache_file(c).with_urltest_history(h)` — 每个服务一个 builder 方法 |
| ContextRegistry 自动同步 | `From<&Context> for ContextRegistry` 确保新增字段自动传播到 adapter 层 |
| ApiState 可选字段 + builder | `ApiState { field: Option<Arc<dyn Trait>> }` + `ClashApiServer::with_xxx()` — 模式一致 |
| DashMap 共享历史 | 无锁并发 map 适合高频读少量写场景，每 tag 仅保存最新值（与 Go sync.Map 对齐） |
| 健康检查写入历史 | spawn 前 clone Arc，Ok → store，Err → delete |

## 连接跟踪模式

| 模式 | 说明 |
|------|------|
| 全局 ConnTracker 单例 | `global_tracker()` 返回 `&ConnTracker`（OnceLock），handlers 直接调用，无需注入 ApiState |
| CancellationToken 连接关闭 | 每个连接一个 `CancellationToken`，I/O 热路径用 `tokio::select! { _ = cancel.cancelled() => break }`，API handler 调用 `cancel()` 立即中断 |
| per-connection 原子计数器 | `Arc<AtomicU64>` 传入 copy 函数，每次 read 后 `fetch_add(n, Relaxed)`，开销极低（<1ns per operation） |
| 全局累计 = 注册时快照 + 活跃连接求和 | `total_upload()` = `total_upload(atomic)` + `Σ connection.upload_bytes`，避免高频全局 fetch_add |
| builder pattern 构造 ConnMetadata | `ConnMetadata::new(...).with_host(h).with_inbound_tag(t)` — 新字段全有默认值（None/vec![]/CancellationToken::new()），不破坏现有调用 |
| 复用已有基础设施 > 新建 | sb-common::ConnTracker 已有完善实现，只需接线；sb-api::ConnectionManager 从未被填充 → 直接移除 |
| copy 函数签名扩展用 Option | `conn_counter: Option<Arc<AtomicU64>>` — 现有调用传 None 即可，无需修改 |

---

## Lifecycle 编排模式

| 模式 | 说明 |
|------|------|
| 纯函数提取 > 方法内嵌 | `validate_and_sort()` 是同步纯函数，不依赖 RwLock/async，可被两路径直接调用，可单元测试 |
| BinaryHeap 确定性排序 | Kahn's 算法用 `BinaryHeap<Reverse<&String>>` 而非 Vec + sort，保证输出顺序确定 |
| 占位注册模式 | 当 trait 类型不兼容时（adapter::OutboundConnector ≠ traits::OutboundConnector），用 DirectConnector 占位注册满足 tag 追踪需求 |
| populate → Result 传播 | 注册/验证函数可能失败时，签名改为 `→ Result<()>`，调用处加 `?` 或 `.map_err()` |
| rollback 按阶段渐进 | 越后期的失败需要清理越多组件：Initialize 失败仅需 shutdown_context，PostStart 失败需关闭 inbound+endpoint+service+context |
| Missing dep 静默忽略 | 拓扑排序中依赖项不在 all_tags 中时跳过（Go 对齐），不报错 |
| resolve_default 三阶段 | Go parity: explicit config tag → first registered → "direct" fallback，每阶段 info 日志标注 source |
| Bridge 是连接 source of truth | OutboundManager 用于生命周期管理（tag 追踪/依赖/default），实际连接路由走 Bridge/OutboundRegistryHandle |

---

## 规划模式

| 模式 | 说明 |
|------|------|
| 按 GUI 可感知度排序 | Tier 2 优先做用户直接能看到的改善（持久化/状态真实化），基础设施（lifecycle 编排）靠后 |
| 源码确认再规划 | L2.1 后对 handlers/cache_file/selector 等做源码级确认，发现原规划有范围交叉和粒度不均 |
| CacheFile trait 先扩展再联通 | 实现层已有 14 个方法，瓶颈在 trait 只暴露 3 个方法，dyn CacheFile 读不回 selected |
| 已有代码未接入 ≠ 未实现 | OutboundManager 有 Kahn 排序但 start_all 不调用；SelectorGroup 有持久化 API 但构造时不恢复 |

## 跨 Crate Trait 转发模式

| 模式 | 说明 |
|------|------|
| Wrapper 必须转发 trait 默认方法 | `SelectorOutbound` wraps `SelectorGroup` 但未覆盖 `as_any()` → downcast 静默失败，不会报错 |
| 优先用 trait 抽象而非 downcast | `as_group() → Option<&dyn OutboundGroup>` 比 `as_any() → downcast_ref::<T>()` 更健壮，不依赖具体类型 |
| 非 async trait 中的同步 RwLock 读取 | `OutboundGroup::now()` 用 `try_read()` 替代 `.await`（非 async trait 约束），无竞争时总成功 |
| Lifetime 参数对齐 `select_outbound` | 返回 `Pin<Box<dyn Future + 'a>>` 时需要 `&'a self` 和 `&'a str` 同一生命周期 |
| 持久化职责内聚 | 缓存写入放在 SelectorGroup 内部（select_by_name 中），而非 handler 层外部调用，避免遗漏和重复 |
| 三阶段恢复与 Go 对齐 | SelectorGroup 构造: cache → config default → first member，且验证成员存在性 |
| Tolerance sticky 防抖 | select_by_latency: 当前选择在 `best_rtt + tolerance` 范围内则保持不变，current_rtt=0 (未测试) 不 sticky |
| 构造函数参数扩展模式 | 新增 Option 字段时：struct + 3 个构造函数各加参数，adapter builder 传入，test 全传 None。与 L2.6 cache_file 模式一致 |

## DNS 栈对齐模式

| 模式 | 说明 |
|------|------|
| wire-format 翻译层 | `exchange()` 不做端到端 wire-format 处理；解析 query → 提取 domain+qtype → 走高层 `resolve_with_context()` → 用 `build_dns_response()` 构建 wire 响应。复用已有解析管线 |
| name pointer 0xC00C | DNS wire response 中 answer record 的 name 字段用指针 `0xC00C` 指向 question section 的 domain，而非重复写入完整域名，节省空间且符合 RFC 1035 |
| FakeIP adapter 模式 > Transport 改造 | 实现 `DnsUpstream` trait 的 `FakeIpUpstream` adapter，被规则路由选择。比改造为完整 Transport 更安全（不影响现有 transport 层），向后兼容 env-var 短路 |
| HostsUpstream 双源加载 | `from_json_predefined()` + `parse_hosts_file()`：先加载 JSON predefined 条目，再解析 /etc/hosts 格式文件。case-insensitive 查找，未找到返回 NxDomain |
| Decision enum 扩展清单 | 新增 enum variant 必须检查: `rules.rs` (is_terminal, as_str, label), `engine.rs` match, `handler.rs` match, 各 inbound adapter (socks/http/anytls) match, **特别是 parity feature 下的文件** |
| RouteOptions 累积模式 | `DnsRuleAction::RouteOptions` 不选择 transport，而是在 rule matching loop 中累积选项 (`accumulated_disable_cache`, `accumulated_rewrite_ttl`, `accumulated_client_subnet`)，然后 `continue` 匹配下一条规则 |
| transport-tag 扩展 Key | 缓存 Key 新增 `transport_tag: Option<String>` 实现 per-transport 隔离（`independent_cache: true`）。默认 None = 共享缓存。所有 Key 构造处需同步更新 |
| disable_expire 修改 get/cleanup | 设置 `disable_expire: true` 时：`get()` 跳过 TTL 过期检查，`cleanup_expired()` 变为 no-op，`peek_remaining()` 返回原始 TTL。仅靠 LRU 淘汰控制缓存大小 |
| EDNS0 OPT record 操作 | OPT pseudo-RR: TYPE=41, NAME=0x00 (root), CLASS=UDP payload size. ECS option: code=8, family=1(IPv4)/2(IPv6), source prefix length, scope=0. 注入时检查已有 OPT → 追加 option vs 新建 OPT record |
| fakeip_tags HashSet 注册 | config_builder 构建 FakeIP upstream 后调用 `engine.mark_fakeip_upstream(tag)` 注册到 HashSet，`is_fakeip_upstream()` O(1) 查找。避免运行时类型检查 (nightly `type_name_of_val`) |
| RDRC transport-aware key | key 格式 `"{transport_tag}\x00{domain}\x00{qtype}"`，用 NUL 分隔避免歧义。check_rdrc_rejection() 在 upstream query 前调用，save_rdrc_rejection() 在 address_limit 拒绝后调用 |
| reverse_mapping 用 parking_lot::Mutex | `parking_lot::Mutex<lru::LruCache<IpAddr, String>>`（1024 entries）。非 async，同步短锁。每次成功解析后存储 IP→domain 映射，由 `lookup_reverse_mapping()` 暴露 |
| lookup 跳过 FakeIP | `DnsRouter.lookup()` / `lookup_default()` 禁止 FakeIP upstream（Go: `allowFakeIP = false`）。若 default 是 FakeIP，找第一个非 FakeIP upstream 替代 |

### Interop-Lab Case 编写模式（L5-L7）

| 模式 | 说明 |
|------|------|
| CaseSpec schema 严格匹配 | GuiStep 必须用 `kind:` (非 `type:`)，`name:` (非 `label:`)；`traffic_plan` 是平铺列表 `[]` (非 `{ steps: [] }`)；assertions 用 `expected:` (非 `value:`)；`upstream_topology` (非 `upstreams:`) |
| 每 case 独立端口 | admin port + base_url port 必须全局唯一，避免并行运行端口冲突 |
| bootstrap 必须完整 | `command`, `args`, `startup_timeout_ms`, `ready_path`, `api.base_url` 全部必填 |
| env_class 分层 | `strict` = 自包含无外部依赖，`env_limited` = 需要外部服务/网络 |
| oracle 容忍配置 | `tolerate_counter_jitter: true` + `counter_jitter_abs` 处理计数器抖动 |
| payload_size 大包生成 | TrafficAction 中 `payload_size` 字段触发确定性 payload 生成 + hash 校验 |
| JSONL 历史追踪 | `trend_history.jsonl` 每行一个 JSON 对象（含 ISO 时间戳），`>>` 追加模式 |
| 回归检测阈值 | 最近 5 次运行 score 退化 >10% 或 zero→nonzero 变化触发 REGRESSION_WARNING |

### 弃用检测与迁移模式（L12）

| 模式 | 说明 |
|------|------|
| 静态弃用目录 > 分散硬编码 | `deprecation_directory()` 返回 `&'static [DeprecatedField]`，所有弃用信息集中管理 |
| JSON pointer 通配符匹配 | `/outbounds/*/tag` 用 `*` 匹配数组索引，`/outbounds/*/type=wireguard` 用 `key=value` 匹配特定类型 |
| Severity 分级 | Info（信息性提示）→ Warning（建议迁移）→ Error（即将移除） |
| 迁移诊断元组返回 | `migrate_to_v2()` 返回 `(Value, Vec<MigrationDiagnostic>)` 而非修改原值+静默转换 |
| CLI severity 提升 | validator "info" → CLI Warning（使 --strict 可操作弃用字段） |
| 调用方全面更新 | 改变公共函数签名时 grep 所有调用方（7 处），否则编译失败 |

### 认证中间件模式（L13）

| 模式 | 说明 |
|------|------|
| Go parity 鉴权 | axum middleware 完全复刻 Go clashapi/server.go：None→跳过，WS→?token= query，HTTP→Authorization: Bearer |
| 401 响应格式 | `{"message": "Unauthorized"}` + `Content-Type: application/json`（与 Go 一致） |
| 跨服务认证复用 | Clash API 和 SSMAPI 使用相同 Bearer 模式但独立 token 配置 |
| 非 localhost 安全警告 | `is_localhost_addr()` 检查 127.0.0.1/::1/localhost/[::1]/空串，绑定非 localhost 无 secret→InsecureBinding |
| ServiceStatus 四态隔离 | Starting/Running/Failed(String)/Stopped，start_all() 捕获失败继续其他服务 |

### TLS 证书管理模式（L14）

| 模式 | 说明 |
|------|------|
| 三模式证书存储 | System（OS 证书+Mozilla 回退）/ Mozilla（webpki_roots）/ None（空池+仅自定义 CA） |
| feature gate 隔离 | `native-certs` gate `rustls-native-certs`，`cert-watch` gate `notify`+`tokio-util` |
| 递归 PEM 目录加载 | `load_pem_directory()` 递归遍历，过滤 .pem/.crt/.cer 后缀 |
| 文件监听热重载 | `notify::recommended_watcher()` + `CancellationToken`，变化时重建 root store |
| TLS 能力矩阵诊断 | uTLS/ECH/REALITY 配置产生 info 级诊断说明支持状态（而非静默忽略） |
| 阈值配置三层回退 | 显式环境变量 > YAML 配置文件（sed 解析）> 硬编码默认值 |

### 边界检查与 CI 模式（L11）

| 模式 | 说明 |
|------|------|
| dev-dependencies 也受边界检查 | sb-core 的 `[dev-dependencies]` 中的 tower/axum 等同样触发 boundary violation |
| YAML 阈值无 yq | `_yaml_val()` 用 sed 提取 YAML 值，避免 CI 环境安装 yq |
| 命名模板选择 | `THRESHOLD_TEMPLATE` 环境变量选择配置文件中的命名模板节，不需要多个配置文件 |

---

### 能力口径与宣称门禁模式（L19）

| 模式 | 说明 |
|------|------|
| 能力四元字段 | `compile_state/runtime_state/verification_state/overall_state` 必须同时给出，避免“单状态”误导 |
| overall 优先级折叠 | 优先命中 `stubbed/absent` 与 `unsupported/blocked`，命中即 `scaffold_stub`；仅 runtime=verified 且有集成或 e2e 证据时为 `implemented_verified` |
| 证据最小基线 | 每个 capability 至少 1 条 `evidence{kind,path,line,note}`；缺证据应落入 `compile_only` 或 `no_evidence` |
| 文档事实源单点 | `README/STATUS` 只引用 `docs/capabilities.md`，不再独立定义完成度事实 |
| 高风险宣称必映射 | `high-risk claim` 必须绑定 capability id；未映射或映射到非 `implemented_verified` 由 CI claim guard 阻断 |
| 209/209 口径 | 可保留，但必须附带 `includes accepted limitations` 并可追溯至 capabilities 报告 |

---

*最后更新：2026-03-04（新增 L19 能力口径与宣称门禁模式）*
