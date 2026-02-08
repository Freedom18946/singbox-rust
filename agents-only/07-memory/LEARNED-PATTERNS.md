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
| sb-core 无协议实现 | 协议只在 sb-adapters |
| 控制面隔离 | sb-api 不能把 axum 带入 sb-core |

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

---

*最后更新：2026-02-08（L2.8 ConnectionTracker 模式）*
