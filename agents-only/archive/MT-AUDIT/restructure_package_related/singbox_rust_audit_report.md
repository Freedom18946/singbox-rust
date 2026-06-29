# singbox-rust 主项目静态审计报告

## 1. 审计结论

**结论一句话**：当前主项目离你给定的 Rust 规则基线还有明显距离，且问题不是零散 lint，而是“全局状态 + 生命周期 + 边界类型 + 工具链治理”四个层面的系统性偏移。按本轮静态审计结果，项目尚未满足 Layer 1-4 的整体要求，尤其是 Layer 1 与 Layer 3 的基础约束尚未收口。

最突出的结构性风险有六类：

1. **隐藏单例网**：`http_client`、`geoip`、`metrics`、`logging`、`admin_debug/prefetch`、`security_metrics` 等存在大量 `OnceLock/LazyLock/OnceCell` 静态状态。
2. **异步生命周期失控**：大量 `tokio::spawn(...)` 返回的 `JoinHandle` 直接被丢弃，关停、取消、panic 观测、资源回收都不可证。
3. **锁跨 await**：AnyTLS、SSH、prefetch 以及更多路径命中“持锁跨 `await`”模式，属于典型联调期不稳定源。
4. **热路径 panic 面**：`tun`、`optimizations`、`cache_file`、`http_util` 等路径仍有 `unwrap/expect/unreachable`。
5. **边界类型债务**：配置与 API 入口大量 `Deserialize` 类型缺少 `deny_unknown_fields`，同时语义字段仍以 `String/Option<String>` 裸奔。
6. **组合根过厚**：`main.rs`、`bootstrap.rs`、`run_engine.rs` 与多处 mega-file 已经把运行时装配、配置、日志、服务启动、调试面耦在一起。

## 2. 审计基线、范围、方法与限制

- **审计基线**：以你上传的 Rust ruleset 为准，按 Layer 1-4 分层审计。fileciteturn0file0
- **范围**：仅审计主项目 Rust 生产源码：`app/src/**/*.rs` 与 `crates/**/src/**/*.rs`。
- **明确排除**：`deployments/`、Go 代码、非主项目部署/脚本资产、`examples/`、`benches/`、外部归档材料。
- **方法**：
  - 对生产源码做结构化静态扫描，提取规则命中点。
  - 对 `#[cfg(test)]` 块做了 best-effort 过滤，尽量不把测试代码混进生产问题统计。
  - 抽读主链路模块和内部 spec / parity 文档，判断是否存在系统性设计偏差。
- **限制**：
  - 本容器网络解析失败，无法安装 Rust toolchain，因此**未执行** `cargo check / clippy / test`；本报告属于**全仓静态审计**，不是一次 feature-resolved 编译审计。
  - 对 feature-gated 分支、宏展开、平台专属 cfg 分支，只能按源码表面形态判读，不能替代真实编译矩阵。

## 3. 审计摘要（按规则层归档）

| 项目 | 数量 | 判定 | 对应层 | 备注 |
| --- | --- | --- | --- | --- |
| 生产源码文件数 | 649 | 范围 | app/src + crates/**/src；排除 deployments/ 与 Go |
| unwrap | 185 | 确定命中 | Layer 1 |
| expect | 69 | 确定命中 | Layer 1 |
| panic! | 1 | 确定命中 | Layer 1 |
| todo/unimplemented/unreachable | 1 | 确定命中 | Layer 1 |
| 静态全局 OnceLock | 29 | 确定命中 | Layer 1 |
| 静态全局 LazyLock | 14 | 确定命中 | Layer 1 |
| 静态全局 OnceCell | 34 | 确定命中 | Layer 1 spirit |
| super:: 路径 | 302 | 需复核/大多应替换 | Layer 1 |
| pub use | 188 | 需复核/需声明 facade 意图 | Layer 1 |
| 通配符导入 | 52 | 确定命中 | Layer 2 |
| println/eprintln/print/dbg | 275 | 确定命中 | Layer 2 |
| &PathBuf 参数 | 10 | 确定命中 | Layer 2 |
| let _ = 丢弃结果 | 571 | 确定命中 | Layer 2 |
| 未跟踪 tokio::spawn | 152 | 高风险静态命中 | Layer 3 |
| 锁跨 await | 127 | 高风险静态命中 | Layer 3 |
| Arc<Mutex<_>> | 50 | 并发设计复核面 | Layer 3 |
| 公开 anyhow 签名 | 42 | 确定命中 | Layer 3 |
| pub fn(Result/Option) 缺 #[must_use] | 1030 | 规范命中 | Layer 4 |
| Deserialize 缺 deny_unknown_fields | 261 | 边界卫生命中 | Layer 4 |
| unsafe 缺 SAFETY 注释 | 40 | 确定命中 | Layer 4 |
| 未文档化公开项 | 1555 | 确定命中 | Layer 4 |
| 本地 #[allow(clippy::...)] 逃逸 | 28 | 治理命中 | Layer 4 |

### 3.1 规模与集中度

- 生产源码文件总数：**649**
- 大文件密集区说明已经不是“代码量大”这么简单，而是**职责边界失真**。最大的 20 个文件如下：

| LOC | 文件 |
| --- | --- |
| 5375 | crates/sb-config/src/validator/v2.rs |
| 5122 | crates/sb-core/src/services/derp/server.rs |
| 3860 | crates/sb-adapters/src/register.rs |
| 3756 | crates/sb-config/src/ir/mod.rs |
| 3485 | crates/sb-core/src/dns/upstream.rs |
| 3332 | crates/sb-core/src/router/mod.rs |
| 2657 | crates/sb-transport/src/tls.rs |
| 2405 | app/src/admin_debug/endpoints/subs.rs |
| 2319 | crates/sb-core/src/router/rules.rs |
| 2310 | crates/sb-api/src/clash/handlers.rs |
| 2291 | crates/sb-core/src/router/engine.rs |
| 2166 | crates/sb-adapters/src/inbound/tun_enhanced.rs |
| 2147 | crates/sb-adapters/src/inbound/tun/mod.rs |
| 1766 | crates/sb-core/src/runtime/supervisor.rs |
| 1731 | crates/sb-core/src/router/conn.rs |
| 1723 | app/src/bootstrap.rs |
| 1722 | crates/sb-core/src/outbound/hysteria2.rs |
| 1602 | crates/sb-adapters/src/inbound/socks/udp.rs |
| 1595 | crates/sb-adapters/src/inbound/shadowsocks.rs |
| 1571 | crates/sb-core/src/dns/mod.rs |

### 3.2 重点类别的集中度

#### unwrap

| crate | 数量 |
| --- | --- |
| sb-core | 113 |
| sb-adapters | 36 |
| app | 22 |
| sb-metrics | 9 |
| sb-transport | 5 |

| 文件 | 数量 |
| --- | --- |
| crates/sb-core/src/inbound/tun.rs | 17 |
| crates/sb-core/src/outbound/optimizations.rs | 15 |
| crates/sb-core/src/adapter/registry.rs | 11 |
| crates/sb-adapters/src/inbound/tun/platform/linux.rs | 10 |
| crates/sb-metrics/src/lib.rs | 9 |
| crates/sb-core/src/context.rs | 8 |
| crates/sb-core/src/inbound/loopback.rs | 8 |
| crates/sb-adapters/src/inbound/tun/platform/macos.rs | 6 |

#### 全局静态状态（OnceLock/LazyLock/OnceCell）

| crate | 数量 |
| --- | --- |
| sb-core | 44 |
| app | 13 |
| sb-adapters | 8 |
| sb-tls | 5 |
| sb-metrics | 4 |
| sb-transport | 2 |
| sb-common | 1 |

| 文件 | 数量 |
| --- | --- |
| crates/sb-core/src/metrics/registry_ext.rs | 9 |
| crates/sb-tls/src/global.rs | 5 |
| crates/sb-adapters/src/inbound/http.rs | 4 |
| crates/sb-metrics/src/lib.rs | 3 |
| crates/sb-adapters/src/inbound/socks/udp.rs | 3 |
| crates/sb-core/src/geoip/mod.rs | 2 |
| crates/sb-core/src/http_client.rs | 2 |
| crates/sb-core/src/log/mod.rs | 2 |

#### 未跟踪 tokio::spawn

| crate | 数量 |
| --- | --- |
| sb-adapters | 71 |
| sb-core | 48 |
| sb-transport | 11 |
| app | 9 |
| sb-api | 5 |
| sb-test-utils | 3 |
| sb-metrics | 2 |
| sb-runtime | 1 |

| 文件 | 数量 |
| --- | --- |
| crates/sb-adapters/src/inbound/socks/udp.rs | 7 |
| crates/sb-adapters/src/inbound/shadowsocks.rs | 6 |
| crates/sb-core/src/services/derp/server.rs | 6 |
| crates/sb-adapters/src/inbound/anytls.rs | 5 |
| crates/sb-adapters/src/inbound/socks/mod.rs | 5 |
| app/src/admin_debug/http_server.rs | 4 |
| crates/sb-adapters/src/inbound/tun_macos.rs | 4 |
| crates/sb-adapters/src/inbound/ssh.rs | 4 |

#### 锁跨 await

| crate | 数量 |
| --- | --- |
| sb-core | 73 |
| sb-api | 20 |
| sb-transport | 18 |
| sb-adapters | 13 |
| sb-tls | 2 |
| app | 1 |

| 文件 | 数量 |
| --- | --- |
| crates/sb-core/src/outbound/manager.rs | 14 |
| crates/sb-api/src/managers.rs | 11 |
| crates/sb-transport/src/wireguard.rs | 10 |
| crates/sb-core/src/runtime/supervisor.rs | 9 |
| crates/sb-core/src/inbound/manager.rs | 7 |
| crates/sb-api/src/monitoring/bridge.rs | 7 |
| crates/sb-core/src/service.rs | 6 |
| crates/sb-core/src/net/udp_processor.rs | 5 |

#### pub fn(Result/Option) 缺 #[must_use]

| crate | 数量 |
| --- | --- |
| sb-core | 498 |
| sb-adapters | 131 |
| app | 128 |
| sb-transport | 65 |
| sb-platform | 50 |
| sb-api | 46 |
| sb-tls | 39 |
| sb-subscribe | 17 |

| 文件 | 数量 |
| --- | --- |
| crates/sb-core/src/router/mod.rs | 23 |
| crates/sb-core/src/dns/upstream.rs | 19 |
| crates/sb-api/src/managers.rs | 18 |
| crates/sb-core/src/router/engine.rs | 15 |
| app/src/admin_debug/http_util.rs | 14 |
| crates/sb-adapters/src/inbound/tun/mod.rs | 12 |
| crates/sb-core/src/dns/message.rs | 12 |
| crates/sb-core/src/runtime/supervisor.rs | 11 |

#### Deserialize 缺 deny_unknown_fields

| crate | 数量 |
| --- | --- |
| sb-config | 103 |
| sb-api | 48 |
| sb-core | 37 |
| app | 16 |
| sb-types | 15 |
| sb-runtime | 14 |
| sb-adapters | 11 |
| sb-subscribe | 5 |

| 文件 | 数量 |
| --- | --- |
| crates/sb-config/src/ir/mod.rs | 51 |
| crates/sb-api/src/v2ray/mod.rs | 27 |
| crates/sb-config/src/outbound.rs | 16 |
| crates/sb-api/src/types.rs | 12 |
| crates/sb-config/src/model.rs | 9 |
| crates/sb-runtime/src/scenario.rs | 8 |
| crates/sb-core/src/geoip/mmdb.rs | 8 |
| crates/sb-core/src/routing/ir.rs | 7 |

#### 未文档化公开项

| crate | 数量 |
| --- | --- |
| sb-core | 833 |
| app | 361 |
| sb-adapters | 149 |
| sb-api | 44 |
| sb-transport | 43 |
| sb-metrics | 32 |
| sb-config | 31 |
| sb-subscribe | 20 |

| 文件 | 数量 |
| --- | --- |
| app/src/admin_debug/security_metrics.rs | 80 |
| crates/sb-core/src/metrics/outbound.rs | 46 |
| crates/sb-api/src/v2ray/mod.rs | 39 |
| app/src/router/mod.rs | 28 |
| crates/sb-metrics/src/lib.rs | 25 |
| crates/sb-core/src/router/advanced.rs | 25 |
| crates/sb-core/src/metrics/dns.rs | 24 |
| app/src/admin_debug/http_util.rs | 23 |

## 4. 已确认的系统性问题

### 4.1 隐藏单例与全局可变状态是“成网存在”，不是个别漏网鱼

这一点是本仓最核心的 Layer 1 违例。不是只有一两个 `OnceLock`，而是多个基础设施子系统都通过静态状态共享依赖和运行时对象。这样做在联调阶段最容易制造三类问题：

- 调用方不知道某函数是否依赖进程级全局初始化。
- 测试与热重载互相污染，隔离性变差。
- 生命周期边界不透明，关闭顺序和替换顺序不可证。

典型证据：

```rust
static GLOBAL_HTTP_CLIENT: OnceLock<Box<dyn HttpClient>> = OnceLock::new();
static DEFAULT_HTTP_CLIENT: LazyLock<Mutex<Option<Weak<dyn HttpClient>>>> =
    LazyLock::new(|| Mutex::new(None));
```
文件: `crates/sb-core/src/http_client.rs`

```rust
static GEOIP_SERVICE: OnceLock<GeoIpService> = OnceLock::new();
static DEFAULT_GEOIP_SERVICE: LazyLock<Mutex<Option<Weak<GeoIpService>>>> =
    LazyLock::new(|| Mutex::new(None));
```
文件: `crates/sb-core/src/geoip/mod.rs`

```rust
static INT_GAUGE_MAP: OnceCell<DashMap<String, &'static IntGaugeVec>> = OnceCell::new();
static GAUGE_MAP: OnceCell<DashMap<String, &'static GaugeVec>> = OnceCell::new();
static COUNTER_MAP: OnceCell<DashMap<String, &'static IntCounterVec>> = OnceCell::new();
static HISTOGRAM_MAP: OnceCell<DashMap<String, &'static HistogramVec>> = OnceCell::new();
```
文件: `crates/sb-core/src/metrics/registry_ext.rs`

```rust
static ACTIVE_RUNTIME: LazyLock<StdMutex<Weak<LoggingRuntime>>> =
    LazyLock::new(|| StdMutex::new(Weak::new()));

tokio::spawn(async move {
    use tokio::signal::unix::{signal, SignalKind};
    ...
});
```
文件: `app/src/logging.rs`

```rust
static GLOBAL: OnceCell<Prefetcher> = OnceCell::new();
static DEFAULT_PREFETCHER: LazyLock<StdMutex<Option<Weak<Prefetcher>>>> =
    LazyLock::new(|| StdMutex::new(None));

let mut guard = rx.lock().await;
match guard.recv().await { ... }

tokio::spawn(worker_loop(id, rx_clone));
```
文件: `app/src/admin_debug/prefetch.rs`

`crates/sb-metrics/src/lib.rs` 的模块文档甚至明确写了“通过使用 `LazyLock` 和全局静态变量，它允许任何模块在不传递上下文的情况下记录指标”。这说明当前实现**是有意设计成与规则集相反的方向**。

这类问题与 PX-006 / PX-007 / PX-009 的 parity 差距是同源的：manager、service、adapter 没有成为显式注入的 runtime surface，而是被全局注册器和隐式兼容层替代。

### 4.2 异步生命周期管理没有收口，后台 task 大量“放飞”

规则要求所有 `tokio::spawn` 返回的 `JoinHandle` 都要持有、可 await、可取消。当前仓库大量直接 `tokio::spawn(...)`，造成：

- task panic 无法被上层观测；
- 优雅关闭无法 join 完所有后台任务；
- 资源可能在后台悄悄存活，联调时出现“上一个 runtime 的幽灵”。

代表性例子：

```rust
let mut guard = self.session.lock().await;
...
let session = self.connect_session().await?;
...
tokio::spawn(async move { ... });
tokio::spawn(async move { ... });
```
文件: `crates/sb-adapters/src/outbound/anytls.rs`

```rust
static ACTIVE_RUNTIME: LazyLock<StdMutex<Weak<LoggingRuntime>>> =
    LazyLock::new(|| StdMutex::new(Weak::new()));

tokio::spawn(async move {
    use tokio::signal::unix::{signal, SignalKind};
    ...
});
```
文件: `app/src/logging.rs`

`app/src/admin_debug/http_server.rs` 的 accept loop 内也存在 per-connection `tokio::spawn(async move { ... })`，没有纳入统一 task 生命周期管理。

扫描层面命中了 **152** 处未跟踪 `spawn`；最密集的是 `sb-adapters` 与 `sb-core`。这不是一个局部 bug，而是运行时治理模型缺失。

### 4.3 锁跨 await 在运行时关键链路已实锤存在

这类问题是 Layer 3 的硬雷。典型实锤：

```rust
let mut guard = self.session.lock().await;
...
let session = self.connect_session().await?;
...
tokio::spawn(async move { ... });
tokio::spawn(async move { ... });
```
文件: `crates/sb-adapters/src/outbound/anytls.rs`

```rust
let session = self.session.lock().await;
let channel = session
    .channel_open_direct_tcpip(host, port as u32, "127.0.0.1", 0)
    .await?;

let mut pool = self.pool.lock().await;
let conn = Arc::new(SshConnection::new(&self.config).await?);
```
文件: `crates/sb-adapters/src/outbound/ssh.rs`

```rust
static GLOBAL: OnceCell<Prefetcher> = OnceCell::new();
static DEFAULT_PREFETCHER: LazyLock<StdMutex<Option<Weak<Prefetcher>>>> =
    LazyLock::new(|| StdMutex::new(None));

let mut guard = rx.lock().await;
match guard.recv().await { ... }

tokio::spawn(worker_loop(id, rx_clone));
```
文件: `app/src/admin_debug/prefetch.rs`

按规则集，**任何** `Mutex/RwLock` guard 都不应跨 `await`。即使在 Tokio mutex 上语义上“可工作”，它也会扩大临界区、放大背压、让关闭顺序更难推理。

静态扫描共命中 **127** 处锁跨 await 模式，手工确认的高风险样本至少包括 AnyTLS、SSH、prefetch。

### 4.4 热路径仍保留 panic 风格路径

典型例子：

```rust
let sessions = self.sessions.read().unwrap();
let mut sessions = self.sessions.write().unwrap();
sessions.retain(|_, v| !v.read().unwrap().is_expired(self.timeout));
```
文件: `crates/sb-core/src/inbound/tun.rs`

```rust
pub static PROTOCOL_BUFFER_POOL: once_cell::sync::Lazy<BufferPool> =
    once_cell::sync::Lazy::new(|| { ... });

let mut buffers = self.buffers.lock().unwrap();
```
文件: `crates/sb-core/src/outbound/optimizations.rs`

```rust
_ => unreachable!("shadowtls detour wrapper version is prevalidated"),
```
文件: `crates/sb-adapters/src/outbound/shadowtls.rs`

`app/src/http_util.rs` 还存在多处 `.expect("response builder failed")`。

其中 `crates/sb-core/src/inbound/tun.rs` 是热路径组件，`RwLock::read().unwrap()` / `write().unwrap()` / 内层 `v.read().unwrap()` 大量出现，意味着 poisoning 或状态异常时会直接把问题放大成 panic。

### 4.5 配置与外部输入边界还没有完成“原始输入 -> 验证域模型”的转换

`crates/sb-config/src/outbound.rs` 这类配置模型广泛使用裸 `String` / `Option<String>` 表达语义字段，例如 `server: String`、`tag: Option<String>`、`uuid: String`、`security: String`。同时大量 `Deserialize` 类型缺少显式 `#[serde(deny_unknown_fields)]`。

这会导致两个问题叠在一起：

1. 上游新增字段时，系统可能静默吞下不兼容输入。
2. 语义不变量没有编码进类型系统，只能在后续业务路径里零散校验。

这正是 PX-002 / PX-003 / PX-004 / PX-008 大量 parity 与行为差异的源头之一。当前更像是“serde 结构体直接参与业务”，而不是“RawConfig 先过门禁再进入领域层”。

### 4.6 组合根过厚，联调时会把无关责任绑在一起

`app/src/main.rs` 不是“极薄入口”。它同时承担 CLI 解析、环境变量修改、配置探测、日志初始化、命令分发与部分配置读取逻辑，且 `app/src/bootstrap.rs`（1722 LOC）、`app/src/run_engine.rs`（1496 LOC）已经形成厚组合根。


再叠加以下 mega-file：

- `crates/sb-config/src/validator/v2.rs` — 5375 LOC
- `crates/sb-core/src/services/derp/server.rs` — 5122 LOC
- `crates/sb-adapters/src/register.rs` — 3860 LOC
- `crates/sb-config/src/ir/mod.rs` — 3756 LOC
- `crates/sb-core/src/dns/upstream.rs` — 3485 LOC
- `crates/sb-core/src/router/mod.rs` — 3332 LOC
- `crates/sb-transport/src/tls.rs` — 2657 LOC
- `app/src/admin_debug/endpoints/subs.rs` — 2405 LOC
- `crates/sb-core/src/router/rules.rs` — 2319 LOC
- `crates/sb-api/src/clash/handlers.rs` — 2310 LOC
- `crates/sb-core/src/router/engine.rs` — 2291 LOC
- `crates/sb-adapters/src/inbound/tun_enhanced.rs` — 2166 LOC
- `crates/sb-adapters/src/inbound/tun/mod.rs` — 2147 LOC
- `crates/sb-core/src/runtime/supervisor.rs` — 1766 LOC
- `crates/sb-core/src/router/conn.rs` — 1731 LOC
- `app/src/bootstrap.rs` — 1723 LOC
- `crates/sb-core/src/outbound/hysteria2.rs` — 1722 LOC
- `crates/sb-adapters/src/inbound/socks/udp.rs` — 1602 LOC
- `crates/sb-adapters/src/inbound/shadowsocks.rs` — 1595 LOC
- `crates/sb-core/src/dns/mod.rs` — 1571 LOC

这意味着联调时你很难只替换某个 manager 或某类 service，而不牵动 CLI、日志、调试面、配置加载、启动顺序。项目需要的不是“继续把功能塞进大文件”，而是**建立可替换的装配层**。

### 4.7 工具链治理与仓内 spec 存在漂移

已观察到三类治理问题：

1. 根 `Cargo.toml` 中 `missing_docs = "allow"`，与 Layer 4 的文档强制覆盖目标相反。
2. `clippy::pedantic` / `clippy::nursery` 仍是 `warn`，不是 `deny`。
3. 生产代码存在 **28** 处本地 `#[allow(clippy::unwrap_used/expect_used/panic/...)]` 逃逸。

另外，`SPECS/rust/10-build-testing.md` 里写的是 `lto = "fat"` + `codegen-units = 1`，而实际根 `Cargo.toml` 为 `lto = "thin"` + `codegen-units = 16`。这说明**规范与实现已经漂移**，也会让“按 spec 验收”变得含糊。

## 5. 面向联调稳定性的目标架构

建议不要做“大爆炸重写”，而是采用 **strangler + compat shell** 的方式，先建立新骨架，再逐块迁移旧实现。目标架构如下：

### 5.1 运行时四层

1. **Raw Input Layer**
   负责 serde 反序列化，只承认 `Raw*` 结构体，全部 `deny_unknown_fields`。

2. **Validation / Planning Layer**
   `RawConfig -> ValidatedConfig -> RuntimePlan`。这一层完成 tag 唯一性、依赖解析、默认值填充、协议枚举、FakeIP/DNS/route 规划。

3. **Runtime Kernel Layer**
   由 `RuntimeContext` / `KernelRuntime` 显式持有依赖：
   - `HttpClientProvider`
   - `GeoIpProvider`
   - `MetricsSink` / `MetricsRegistryOwner`
   - `TimeService` / `CertStore` / `CacheFile`
   - `DnsManager` / `RouteManager` / `InboundManager` / `OutboundManager` / `ServiceManager`
   - `TaskRegistry` / `CancellationToken` / `ShutdownCoordinator`

4. **Control Plane Layer**
   `sb-api` 与 `admin_debug` 不直接偷读全局状态，而是通过只读查询接口访问 runtime owners。

### 5.2 manager 统一 actor 化

不要再让 manager 只是“注册表”。应让 manager 成为**有生命周期的 owner task**：

- 状态机：`Constructed -> Prepared -> Started -> Stopping -> Stopped`
- 外部通过 `mpsc`/`oneshot` 发送命令或查询
- manager 内部拥有真实状态；外部不共享 `Arc<Mutex<T>>`
- 所有后台任务统一在 `TaskRegistry` 注册

这样才能把 PX-006 / PX-007 / PX-009 收敛到同一个 runtime discipline 上。

### 5.3 globals 的渐进清理方式

为了避免一次性把仓库掀翻，建议为 `http_client/geoip/metrics/logging/prefetch` 建立过渡兼容壳：

- **新代码** 只允许读取 `RuntimeContext`。
- **旧调用点** 暂时经过 `compat::*` 包装层。
- `compat::*` 先“context 优先，legacy global 兜底”，等调用点迁移完再删兜底。

这样联调链路不会被一次性重构打断。

### 5.4 大文件拆分不是形式主义，而是稳定性工程

建议优先拆分：

- `app/src/bootstrap.rs` -> `bootstrap/{config,compose,services,startup}.rs`
- `app/src/run_engine.rs` -> `run_engine/{load,build,run,report}.rs`
- `crates/sb-config/src/validator/v2.rs` -> `validator/v2/{root,dns,route,inbound,outbound,service,endpoint}.rs`
- `crates/sb-config/src/ir/mod.rs` -> `ir/{raw,validated,planned,normalize}.rs`
- `crates/sb-core/src/dns/upstream.rs` -> `dns/upstream/{exchange,cache,transport,rules}.rs`
- `crates/sb-core/src/router/mod.rs` -> `router/{engine,planner,context,conn,rules}.rs`

拆分之后，很多 `super::` 路径、`pub use` 混乱、文档缺失、must_use 缺失会自然下降。

## 6. 阶段性规划：如何缓步稳定实现 Layer 1-4

| 阶段 | 目标 | 关键动作 |
| --- | --- | --- |
| Phase 0: 基线与护栏 | 冻结债务继续扩张 | 生成并提交静态审计脚本/基线；CI 对新增 unwrap/global/static spawn drop 直接失败；建立 debt ratchet |
| Phase 1: Layer 1 硬约束收口 | 去 panic / 去全局可变状态 / 去隐式单例 | 优先改 metrics/http_client/geoip/logging/prefetch/security_metrics/tun/optimizations；兼容层仅保留薄包装 |
| Phase 2: Layer 2 代码卫生 | 把接口边界和输出纪律收正 | 清零 wildcard/&PathBuf；将 let _ 变成显式处理；CLI 输出沉到最外层 writer/formatter；继续拆 mega files |
| Phase 3: Layer 3 运行时与生命周期 | 让联调链路稳定且可关停 | 引入 RuntimeContext + TaskRegistry + CancellationToken；manager actor 化；清零锁跨 await 和未跟踪 spawn |
| Phase 4: Layer 4 工具链强制化 | 把规则从“靠人记”变成“机器卡” | missing_docs/unused_must_use/clippy pedantic+nursery 升级为 deny；统一 allowlist；spec 与 Cargo 配置对齐 |

### 6.1 每阶段的硬性出口标准

| 关口 | 判定标准 |
| --- | --- |
| Layer 1 出口 | 生产代码 unwrap/expect/panic/todo/unreachable = 0；静态 OnceLock/LazyLock/OnceCell 全清零或隔离到显式兼容层；lint allow 逃逸清零 |
| Layer 2 出口 | wildcard/debug_output/&PathBuf 清零；let _ 全部具名处理；边界 Deserialize 明确 deny_unknown_fields/default/Option |
| Layer 3 出口 | 未跟踪 spawn = 0；锁跨 await = 0；关键 manager 支持 start/stop/reload/shutdown 生命周期测试 |
| Layer 4 出口 | missing_docs=deny、unused_must_use=deny、clippy -D warnings；自定义静态审计脚本纳入 CI |

### 6.2 为什么这个顺序更稳

这个顺序不是按 lint 数量排，而是按**联调风险传导链**排：

1. 先切断 panic + globals + dropped tasks，否则后面任何 refactor 都会带着幽灵状态。
2. 再清边界类型和代码卫生，否则 API/配置仍会在联调时偷偷进脏数据。
3. 再做 manager / runtime 重构，否则只是把旧耦合换个地方放。
4. 最后再把工具链阀门关紧，防止旧债回潮。

## 7. 建议的优先级 backlog（按联调收益排序）

| 模块 | 首要问题 | 第一步动作 |
| --- | --- | --- |
| crates/sb-metrics/src/lib.rs | 全局 LazyLock + 本地 lint 逃逸 + unwrap 兜底构造 | 改成 MetricsContext/RegistryOwner 注入，移除全局默认 registry |
| crates/sb-core/src/metrics/registry_ext.rs | OnceCell + Box::leak + 全局 map | 改成 RegistryHandle owned cache，避免全局泄漏 |
| crates/sb-core/src/http_client.rs | GLOBAL_HTTP_CLIENT / DEFAULT_HTTP_CLIENT 隐式单例 | 引入 HttpClientProvider 到 RuntimeContext |
| crates/sb-core/src/geoip/mod.rs | GEOIP_SERVICE / DEFAULT_GEOIP_SERVICE 隐式单例 | 引入 GeoIpProvider 到 RuntimeContext |
| app/src/logging.rs | ACTIVE_RUNTIME 全局弱引用 + 未跟踪 signal task | 改成 LoggingSupervisor + handle registry |
| app/src/admin_debug/prefetch.rs | GLOBAL/DEFAULT_PREFETCHER + 锁跨 await + 直接 spawn | 改成 PrefetchService actor + owned receiver task |
| app/src/admin_debug/security_metrics.rs | DEFAULT_STATE 全局弱引用 | 改成显式 MetricsState 依赖注入 |
| app/src/admin_debug/http_server.rs | accept loop 内 per-connection spawn 未跟踪 | 纳入 TaskRegistry，支持取消与 join |
| crates/sb-adapters/src/outbound/anytls.rs | session 锁跨 await + 后台 task handle 丢弃 | 拆成 SessionOwner task，显式 join/cancel |
| crates/sb-adapters/src/outbound/ssh.rs | pool/session 锁跨 await + 连接桥接 task 丢弃 | 连接池 owner task + oneshot/mpsc 查询 |
| crates/sb-core/src/inbound/tun.rs | 热路径大量 unwrap on RwLock | 显式处理 poisoning/容量/状态错误；抽出 SessionTable |
| crates/sb-core/src/outbound/optimizations.rs | 全局 buffer pool + Mutex unwrap | 改成 per-runtime buffer arena / owned pool |
| crates/sb-config/src/outbound.rs | 外部配置大量原始 String/Option + 无 deny_unknown_fields | 拆 RawOutbound* -> ValidatedOutbound* |
| crates/sb-config/src/ir/mod.rs | IR 巨石 + 51 个 Deserialize 缺 deny_unknown_fields | 拆模块并建立 Raw/Validated/Planned 三相模型 |
| crates/sb-config/src/validator/v2.rs | 5375 LOC 巨石校验器 | 按 root/dns/route/inbound/outbound/service/endpoint 拆分 |
| crates/sb-core/src/dns/upstream.rs | 3485 LOC + must_use/let_/super_path 高密度 | 拆 transport/cache/rules/resolve pipeline |
| crates/sb-core/src/router/mod.rs | 3332 LOC + must_use/pub_use/super_path 高密度 | 拆 engine/planner/context/conn/rules |
| app/src/bootstrap.rs | 1722 LOC 组合根过厚 | 拆 compose/config/services/runtime/startup |
| app/src/run_engine.rs | 1496 LOC + eprintln + config/run 混杂 | 拆 load/build/run/report 四层 |

## 8. 与 repo 当前 parity / spec 状态的对接建议

结合仓内 parity 文档，建议把重构流分成 4 条并行但在统一 runtime 契约下推进：

1. **配置流**：对齐 PX-002 / PX-003。目标是 `Raw -> Validated -> Planned`，不再让 serde struct 直接下沉到 router/dns。
2. **DNS/Route 流**：对齐 PX-004 / PX-005 / PX-008。目标是 DNS manager、transport manager、FakeIP/RDRC/TTL/caching 走统一 owner-task 模式。
3. **Manager/Lifecycle 流**：对齐 PX-006 / PX-007。目标是 Inbound/Outbound/Endpoint/Service manager 变成带状态机的 runtime owner。
4. **Service Surface 流**：对齐 PX-009 / PX-010 / PX-012 / PX-013。目标是 time/cert/cache/clash/v2ray 等全部从 global 兼容层迁移到显式 service ports。

这四条流如果各自为战，联调会再次打架；只有先统一 `RuntimeContext + TaskRegistry + ConfigPlan` 三个中轴，才不会反复回滚。

## 9. 审计总评

这份仓库不是“坏代码堆”，而是**功能推进速度快于架构收口速度**的典型样子。已经有不少能力和 parity 资产，但基础纪律没有完全跟上，所以出现了：

- 用全局静态绕过依赖注入；
- 用 spawn 绕过生命周期管理；
- 用 `String/Option<String>` 绕过类型建模；
- 用局部 `#[allow]` 绕过工具链治理。

这也是为什么我不建议把整改理解成“批量修 lint”。正确做法是：**先重建运行时骨架，再按流迁移功能，再用工具链封口**。

---

## 附录 A：本轮静态审计记录到的全部“确定命中 / 高风险命中”

说明：以下为**本轮静态审计全部命中**，已对 `#[cfg(test)]` 做 best-effort 过滤。`spawn_unhandled` 与 `lock_cross_await` 属高风险静态命中，建议逐条复核。

### unwrap (185)
- 判定：确定命中
- 对应层：Layer 1

- `app/src/admin_debug/cache.rs:159` `let base_path = self.disk_backing.as_ref().unwrap();`
- `app/src/bin/handshake.rs:829` `writeln!(w, "{}", serde_json::to_string(&f).unwrap()).ok();`
- `app/src/bin/metrics-serve.rs:21` `tracing::info!(addr = %std::env::var("SB_METRICS_ADDR").unwrap(), "metrics exporter up");`
- `app/src/bin/preflight.rs:43` `println!("{}", serde_json::to_string_pretty(&obj).unwrap());`
- `app/src/bin/sb-bench.rs:64` `println!("{}", serde_json::to_string_pretty(&report).unwrap());`
- `app/src/bin/sb-explaind.rs:232` `.unwrap())`
- `app/src/bin/sb-explaind.rs:265` `hyper::Server::bind(&addr).serve(svc).await.unwrap();`
- `app/src/bin/sb-rule-coverage.rs:15` `println!("{}", serde_json::to_string_pretty(&snap).unwrap());`
- `app/src/bin/sb-version.rs:19` `println!("{}", serde_json::to_string(&obj).unwrap());`
- `app/src/bin/subs.rs:40` `fs::write(&out, serde_json::to_string_pretty(&merged).unwrap()).expect("write out");`
- `app/src/bin/subs.rs:45` `})).unwrap());`
- `app/src/bin/subs.rs:58` `.unwrap()`
- `app/src/bin/version.rs:33` `println!("{}", serde_json::to_string(&obj).unwrap());`
- `app/src/cli/fs_scan.rs:128` `let re_text_plain = Regex::new(r"(?i)(content[-_ ]?type).{0,40}text/plain").unwrap();`
- `app/src/cli/fs_scan.rs:129` `let re_build_single = Regex::new(r"\bbuild_single_patch\s*\(").unwrap();`
- `app/src/cli/fs_scan.rs:131` `let re_match_kw = Regex::new(r"\bmatch\s+").unwrap();`
- `app/src/cli/fs_scan.rs:132` `let re_admin_portfile = Regex::new(r"SB_ADMIN_PORTFILE").unwrap();`
- `app/src/cli/generate.rs:221` `pem.push_str(std::str::from_utf8(chunk).unwrap());`
- `app/src/cli/geoip.rs:178` `let net: ipnetwork::IpNetwork = net_str.parse().unwrap();`
- `app/src/cli/json.rs:15` `println!("{}", serde_json::to_string(&obj).unwrap());`
- `app/src/cli/json.rs:27` `eprintln!("{}", serde_json::to_string(&obj).unwrap());`
- `app/src/cli/tools.rs:492` `.unwrap();`
- `crates/sb-adapters/src/inbound/naive.rs:246` `.unwrap();`
- `crates/sb-adapters/src/inbound/shadowtls.rs:256` `let mut guard = hash_state.lock().unwrap();`
- `crates/sb-adapters/src/inbound/shadowtls.rs:770` `let mut guard = hash_state.lock().unwrap();`
- `crates/sb-adapters/src/inbound/shadowtls.rs:801` `let guard = hash_state.lock().unwrap();`
- `crates/sb-adapters/src/inbound/shadowtls.rs:1139` `*self.stop_tx.lock().unwrap() = Some(tx);`
- `crates/sb-adapters/src/inbound/shadowtls.rs:1146` `if let Some(tx) = self.stop_tx.lock().unwrap().take() {`
- `crates/sb-adapters/src/inbound/socks/mod.rs:1217` `let mut guard = self.stop_tx.lock().unwrap();`
- `crates/sb-adapters/src/inbound/socks/mod.rs:1231` `let _ = self.stop_tx.lock().unwrap().take();`
- `crates/sb-adapters/src/inbound/socks/mod.rs:1236` `let mut guard = self.stop_tx.lock().unwrap();`
- `crates/sb-adapters/src/inbound/trojan.rs:932` `let mut guard = self.stop_tx.lock().unwrap();`
- `crates/sb-adapters/src/inbound/trojan.rs:937` `let _ = self.stop_tx.lock().unwrap().take();`
- `crates/sb-adapters/src/inbound/trojan.rs:942` `let mut guard = self.stop_tx.lock().unwrap();`
- `crates/sb-adapters/src/inbound/tuic.rs:913` `let mut guard = self.stop_tx.lock().unwrap();`
- `crates/sb-adapters/src/inbound/tuic.rs:918` `let _ = self.stop_tx.lock().unwrap().take();`
- `crates/sb-adapters/src/inbound/tuic.rs:923` `let mut guard = self.stop_tx.lock().unwrap();`
- `crates/sb-adapters/src/inbound/tun/platform/linux.rs:91` `self.configured_routes.lock().unwrap().push(RouteEntry {`
- `crates/sb-adapters/src/inbound/tun/platform/linux.rs:112` `self.configured_routes.lock().unwrap().push(RouteEntry {`
- `crates/sb-adapters/src/inbound/tun/platform/linux.rs:185` `self.configured_rules.lock().unwrap().push(format!(`
- `crates/sb-adapters/src/inbound/tun/platform/linux.rs:206` `self.configured_rules.lock().unwrap().push(format!(`
- `crates/sb-adapters/src/inbound/tun/platform/linux.rs:317` `.unwrap()`
- `crates/sb-adapters/src/inbound/tun/platform/linux.rs:321` `.unwrap()`
- `crates/sb-adapters/src/inbound/tun/platform/linux.rs:325` `.unwrap()`
- `crates/sb-adapters/src/inbound/tun/platform/linux.rs:385` `.unwrap()`
- `crates/sb-adapters/src/inbound/tun/platform/linux.rs:428` `let rules = self.configured_rules.lock().unwrap().clone();`
- `crates/sb-adapters/src/inbound/tun/platform/linux.rs:435` `self.configured_rules.lock().unwrap().clear();`
- `crates/sb-adapters/src/inbound/tun/platform/macos.rs:105` `self.configured_routes.lock().unwrap().push(RouteEntry {`
- `crates/sb-adapters/src/inbound/tun/platform/macos.rs:220` `*self.pf_enabled.lock().unwrap() = true;`
- `crates/sb-adapters/src/inbound/tun/platform/macos.rs:288` `let routes = self.configured_routes.lock().unwrap().clone();`
- `crates/sb-adapters/src/inbound/tun/platform/macos.rs:306` `self.configured_routes.lock().unwrap().clear();`
- `crates/sb-adapters/src/inbound/tun/platform/macos.rs:319` `if *self.pf_enabled.lock().unwrap() {`
- `crates/sb-adapters/src/inbound/tun/platform/macos.rs:321` `*self.pf_enabled.lock().unwrap() = false;`
- `crates/sb-adapters/src/inbound/tun/platform/windows.rs:200` `self.configured_routes.lock().unwrap().push(RouteEntry {`
- `crates/sb-adapters/src/inbound/tun/platform/windows.rs:298` `let routes = self.configured_routes.lock().unwrap().clone();`
- `crates/sb-adapters/src/inbound/tun/platform/windows.rs:321` `self.configured_routes.lock().unwrap().clear();`
- `crates/sb-adapters/src/service/resolve1.rs:529` `let b: [u8; 4] = address[..4].try_into().unwrap();`
- `crates/sb-adapters/src/service/resolve1.rs:532` `let b: [u8; 16] = address[..16].try_into().unwrap();`
- `crates/sb-core/src/adapter/registry.rs:104` `let mut g = INBOUND_REG.write().unwrap();`
- `crates/sb-core/src/adapter/registry.rs:111` `let mut g = OUTBOUND_REG.write().unwrap();`
- `crates/sb-core/src/adapter/registry.rs:117` `let mut inbound = INBOUND_REG.write().unwrap();`
- `crates/sb-core/src/adapter/registry.rs:120` `let mut outbound = OUTBOUND_REG.write().unwrap();`
- `crates/sb-core/src/adapter/registry.rs:126` `let g = INBOUND_REG.read().unwrap();`
- `crates/sb-core/src/adapter/registry.rs:132` `let g = OUTBOUND_REG.read().unwrap();`
- `crates/sb-core/src/adapter/registry.rs:138` `let mut g = RUNTIME_OUTBOUNDS.write().unwrap();`
- `crates/sb-core/src/adapter/registry.rs:144` `let mut g = RUNTIME_INBOUNDS.write().unwrap();`
- `crates/sb-core/src/adapter/registry.rs:150` `let g = RUNTIME_INBOUNDS.read().unwrap();`
- `crates/sb-core/src/adapter/registry.rs:156` `let g = RUNTIME_OUTBOUNDS.read().unwrap();`
- `crates/sb-core/src/adapter/registry.rs:162` `let g = OUTBOUND_REG.read().unwrap();`
- `crates/sb-core/src/bin/rule-hot-reload.rs:57` `.unwrap()`
- `crates/sb-core/src/context.rs:295` `let mut opts = self.route_options.write().unwrap();`
- `crates/sb-core/src/context.rs:330` `self.route_options.read().unwrap().clone()`
- `crates/sb-core/src/context.rs:337` `self.wifi_ssid.read().unwrap().clone()`
- `crates/sb-core/src/context.rs:342` `*self.wifi_ssid.write().unwrap() = ssid;`
- `crates/sb-core/src/context.rs:347` `self.wifi_bssid.read().unwrap().clone()`
- `crates/sb-core/src/context.rs:352` `*self.wifi_bssid.write().unwrap() = bssid;`
- `crates/sb-core/src/context.rs:357` `*self.wifi_ssid.write().unwrap() = ssid;`
- `crates/sb-core/src/context.rs:358` `*self.wifi_bssid.write().unwrap() = bssid;`
- `crates/sb-core/src/dns/global.rs:14` `let mut g = lock.write().unwrap();`
- `crates/sb-core/src/dns/global.rs:22` `let mut g = lock.write().unwrap();`
- `crates/sb-core/src/dns/global.rs:29` `lock.read().unwrap().as_ref().cloned()`
- `crates/sb-core/src/dns/hosts.rs:113` `let mut locked_hosts = self.hosts.write().unwrap();`
- `crates/sb-core/src/dns/hosts.rs:165` `let hosts = self.hosts.read().unwrap();`
- `crates/sb-core/src/dns/hosts.rs:176` `self.hosts.read().unwrap().len()`
- `crates/sb-core/src/dns/rule_engine.rs:527` `decision.upstream_tag.as_ref().unwrap()`
- `crates/sb-core/src/dns/upstream.rs:1964` `let addr = "0.0.0.0:53".parse().unwrap();`
- `crates/sb-core/src/dns/upstream.rs:2614` `let addr: SocketAddr = "100.100.100.100:53".parse().unwrap();`
- `crates/sb-core/src/endpoint/tailscale.rs:751` `IpAddr::V4(_) => IpNet::new(ip, 32).unwrap(),`
- `crates/sb-core/src/endpoint/tailscale.rs:752` `IpAddr::V6(_) => IpNet::new(ip, 128).unwrap(),`
- `crates/sb-core/src/geoip/mmdb.rs:162` `let cap = std::num::NonZeroUsize::new(10000).unwrap();`
- `crates/sb-core/src/geoip/mmdb.rs:175` `let cap = std::num::NonZeroUsize::new(10000).unwrap();`
- `crates/sb-core/src/geoip/mmdb.rs:381` `.unwrap_or(std::num::NonZeroUsize::new(1024).unwrap()),`
- `crates/sb-core/src/geoip/multi.rs:80` `let cap = std::num::NonZeroUsize::new(5000).unwrap();`
- `crates/sb-core/src/inbound/loopback.rs:43` `self.inbound_addrs.write().unwrap().insert(addr);`
- `crates/sb-core/src/inbound/loopback.rs:48` `self.inbound_addrs.write().unwrap().remove(addr);`
- `crates/sb-core/src/inbound/loopback.rs:72` `if self.inbound_addrs.read().unwrap().contains(&addr) {`
- `crates/sb-core/src/inbound/loopback.rs:78` `let inbounds = self.inbound_addrs.read().unwrap();`
- `crates/sb-core/src/inbound/loopback.rs:92` `let inbounds = self.inbound_addrs.read().unwrap();`
- `crates/sb-core/src/inbound/loopback.rs:109` `if self.local_addrs.read().unwrap().contains(&ip) {`
- `crates/sb-core/src/inbound/loopback.rs:150` `*self.local_addrs.write().unwrap() = addrs;`
- `crates/sb-core/src/inbound/loopback.rs:155` `self.inbound_addrs.read().unwrap().len()`
- `crates/sb-core/src/inbound/tun.rs:187` `let sessions = self.sessions.read().unwrap();`
- `crates/sb-core/src/inbound/tun.rs:194` `let mut sessions = self.sessions.write().unwrap();`
- `crates/sb-core/src/inbound/tun.rs:204` `sessions.retain(|_, v| !v.read().unwrap().is_expired(self.timeout));`
- `crates/sb-core/src/inbound/tun.rs:224` `self.sessions.read().unwrap().get(key).cloned()`
- `crates/sb-core/src/inbound/tun.rs:229` `self.sessions.write().unwrap().remove(key)`
- `crates/sb-core/src/inbound/tun.rs:234` `self.sessions.read().unwrap().len()`
- `crates/sb-core/src/inbound/tun.rs:244` `let mut sessions = self.sessions.write().unwrap();`
- `crates/sb-core/src/inbound/tun.rs:246` `sessions.retain(|_, v| !v.read().unwrap().is_expired(self.timeout));`
- `crates/sb-core/src/inbound/tun.rs:466` `let mut r = self.router.write().unwrap();`
- `crates/sb-core/src/inbound/tun.rs:472` `let mut s = self.stats.write().unwrap();`
- `crates/sb-core/src/inbound/tun.rs:478` `let mut m = self.outbound_manager.write().unwrap();`
- `crates/sb-core/src/inbound/tun.rs:530` `let stats = self.stats.read().unwrap().clone();`
- `crates/sb-core/src/inbound/tun.rs:715` `let router = self.router.read().unwrap().clone();`
- `crates/sb-core/src/inbound/tun.rs:716` `let outbound_manager = self.outbound_manager.read().unwrap().clone();`
- `crates/sb-core/src/inbound/tun.rs:948` `let router = self.router.read().unwrap().clone();`
- `crates/sb-core/src/inbound/tun.rs:949` `let outbound_manager = self.outbound_manager.read().unwrap().clone();`
- `crates/sb-core/src/inbound/tun.rs:1147` `.unwrap()`
- `crates/sb-core/src/metrics/dns_v2.rs:15` `IntCounterVec::new(Opts::new("dns_cache_hit_total", "DNS cache hit"), &["kind"]).unwrap();`
- `crates/sb-core/src/metrics/dns_v2.rs:20` `.unwrap();`
- `crates/sb-core/src/metrics/dns_v2.rs:25` `.unwrap();`
- `crates/sb-core/src/metrics/registry_ext.rs:355` `let v = h.join().unwrap();`
- `crates/sb-core/src/net/rate_limit_metrics.rs:16` `.unwrap()`
- `crates/sb-core/src/net/rate_limit_metrics.rs:27` `.unwrap()`
- `crates/sb-core/src/net/rate_limit_metrics.rs:38` `.unwrap()`
- `crates/sb-core/src/net/tcp_rate_limit.rs:87` `NonZeroUsize::new(config.max_tracked_ips).unwrap_or(NonZeroUsize::new(10000).unwrap());`
- `crates/sb-core/src/outbound/mod.rs:266` `self.inner.read().unwrap()`
- `crates/sb-core/src/outbound/optimizations.rs:32` `let mut buffers = self.buffers.lock().unwrap();`
- `crates/sb-core/src/outbound/optimizations.rs:54` `let mut buffers = self.buffers.lock().unwrap();`
- `crates/sb-core/src/outbound/optimizations.rs:62` `self.buffers.lock().unwrap().len()`
- `crates/sb-core/src/outbound/optimizations.rs:193` `.unwrap()`
- `crates/sb-core/src/outbound/optimizations.rs:229` `let connections = self.connections.lock().unwrap();`
- `crates/sb-core/src/outbound/optimizations.rs:253` `let mut connections = self.connections.lock().unwrap();`
- `crates/sb-core/src/outbound/optimizations.rs:269` `let mut connections = self.connections.lock().unwrap();`
- `crates/sb-core/src/outbound/optimizations.rs:275` `self.connections.lock().unwrap().len()`
- `crates/sb-core/src/outbound/optimizations.rs:280` `self.connections.lock().unwrap().clear();`
- `crates/sb-core/src/outbound/optimizations.rs:309` `let cache = self.cache.lock().unwrap();`
- `crates/sb-core/src/outbound/optimizations.rs:322` `let mut cache = self.cache.lock().unwrap();`
- `crates/sb-core/src/outbound/optimizations.rs:345` `let mut cache = self.cache.lock().unwrap();`
- `crates/sb-core/src/outbound/optimizations.rs:360` `let mut cache = self.cache.lock().unwrap();`
- `crates/sb-core/src/outbound/optimizations.rs:366` `self.cache.lock().unwrap().len()`
- `crates/sb-core/src/outbound/optimizations.rs:371` `self.cache.lock().unwrap().clear();`
- `crates/sb-core/src/router/analyze.rs:276` `let rules = rules.unwrap();`
- `crates/sb-core/src/router/cache_wire.rs:83` `NonZeroUsize::new(cap.max(1)).unwrap(),`
- `crates/sb-core/src/router/cache_wire.rs:93` `u64::from_le_bytes(hasher.finalize().as_bytes()[..8].try_into().unwrap())`
- `crates/sb-core/src/router/cache_wire.rs:96` `let mut g = self.inner.lock().unwrap();`
- `crates/sb-core/src/router/cache_wire.rs:107` `let mut g = self.inner.lock().unwrap();`
- `crates/sb-core/src/router/cache_wire.rs:113` `self.inner.lock().unwrap().len()`
- `crates/sb-core/src/router/cache_wire.rs:125` `let g = self.inner.lock().unwrap();`
- `crates/sb-core/src/router/conn.rs:379` `.field("connection_count", &self.connections.lock().unwrap().len())`
- `crates/sb-core/src/router/conn.rs:440` `let conns = self.connections.lock().unwrap();`
- `crates/sb-core/src/router/conn.rs:447` `let mut conns = self.connections.lock().unwrap();`
- `crates/sb-core/src/router/conn.rs:478` `let mut conns = self.connections.lock().unwrap();`
- `crates/sb-core/src/router/conn.rs:712` `let mut conns = self.connections.lock().unwrap();`
- `crates/sb-core/src/router/conn.rs:983` `let mut conns = self.connections.lock().unwrap();`
- `crates/sb-core/src/router/ruleset/adguard.rs:107` `let dollar_pos = working.find('$').unwrap();`
- `crates/sb-core/src/router/ruleset/matcher.rs:65` `std::num::NonZeroUsize::new(10000).unwrap(),`
- `crates/sb-core/src/router/ruleset/mod.rs:349` `node.right.as_mut().unwrap()`
- `crates/sb-core/src/router/ruleset/mod.rs:359` `node.left.as_mut().unwrap()`
- `crates/sb-core/src/router/ruleset/remote.rs:195` `.unwrap()`
- `crates/sb-core/src/runtime/switchboard.rs:429` `"[::]:0".parse().unwrap()`
- `crates/sb-core/src/runtime/switchboard.rs:431` `"0.0.0.0:0".parse().unwrap()`
- `crates/sb-core/src/services/derp/server.rs:577` `hyper::header::HeaderValue::from_str(home).unwrap(),`
- `crates/sb-core/src/services/derp/server.rs:774` `hyper::header::HeaderValue::from_str(&hex::encode(server_public_key)).unwrap(),`
- `crates/sb-core/src/services/derp/server.rs:839` `hyper::header::HeaderValue::from_str(&accept_key).unwrap(),`
- `crates/sb-core/src/services/dns_forwarder.rs:33` `"127.0.0.53:53".parse().unwrap()`
- `crates/sb-core/src/services/ntp.rs:139` `let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();`
- `crates/sb-core/src/services/tailscale/coordinator.rs:216` `let builder = snow::Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap());`
- `crates/sb-core/src/services/tailscale/coordinator.rs:217` `let server_pair = builder.generate_keypair().unwrap();`
- `crates/sb-core/src/services/tailscale/crypto.rs:32` `let builder = Builder::new(NOISE_PARAMS.parse().unwrap());`
- `crates/sb-core/src/services/tailscale/crypto.rs:49` `let builder = Builder::new(NOISE_PARAMS.parse().unwrap());`
- `crates/sb-metrics/src/lib.rs:85` `IntCounterVec::new(Opts::new("dummy_counter", "dummy"), &["label"]).unwrap()`
- `crates/sb-metrics/src/lib.rs:92` `IntCounter::new("dummy_counter", "dummy").unwrap()`
- `crates/sb-metrics/src/lib.rs:99` `IntGauge::new("dummy_gauge", "dummy").unwrap()`
- `crates/sb-metrics/src/lib.rs:112` `HistogramVec::new(opts, labels).unwrap()`
- `crates/sb-metrics/src/lib.rs:118` `Histogram::with_opts(HistogramOpts::new("dummy_histogram", "dummy")).unwrap()`
- `crates/sb-metrics/src/lib.rs:584` `IntGaugeVec::new(prometheus::Opts::new("dummy_gauge", "dummy"), &["proxy"]).unwrap()`
- `crates/sb-metrics/src/lib.rs:695` `IntGaugeVec::new(Opts::new("dummy_gauge", "dummy"), &["tag"]).unwrap()`
- `crates/sb-metrics/src/lib.rs:895` `GaugeVec::new(Opts::new("dummy_gauge", "dummy"), &["label"]).unwrap()`
- `crates/sb-metrics/src/lib.rs:908` `GaugeVec::new(Opts::new("dummy_gauge", "dummy"), &["label"]).unwrap()`
- `crates/sb-transport/src/derp/client.rs:105` `.map(|c| c > addr_str.rfind(']').unwrap())`
- `crates/sb-transport/src/http2.rs:554` `.unwrap();`
- `crates/sb-transport/src/metrics_ext.rs:53` `IntCounterVec::new(Opts::new("dummy_counter", "dummy"), &["label"]).unwrap()`
- `crates/sb-transport/src/metrics_ext.rs:80` `GaugeVec::new(Opts::new("dummy_gauge", "dummy"), &["label"]).unwrap()`
- `crates/sb-transport/src/sip003.rs:59` `local_addr: "127.0.0.1:0".parse().unwrap(),`

### expect (69)
- 判定：确定命中
- 对应层：Layer 1

- `app/src/admin_debug/endpoints/subs.rs:159` `let sem_lock = MAX_CONC.get().expect("limiter initialized");`
- `app/src/admin_debug/prefetch.rs:102` `.expect("build tokio runtime");`
- `app/src/bin/sb-bench.rs:69` `let target: SocketAddr = addr.parse().expect("invalid SB_BENCH_TCP address");`
- `app/src/bin/sb-bench.rs:114` `let target: SocketAddr = addr.parse().expect("invalid SB_BENCH_UDP address");`
- `app/src/bin/sb-bench.rs:117` `.expect("failed to bind UDP probe socket");`
- `app/src/bin/sb-bench.rs:134` `.expect("failed to bind socket");`
- `app/src/bin/sb-bench.rs:169` `let target: SocketAddr = addr.parse().expect("invalid SB_BENCH_DNS address");`
- `app/src/bin/sb-bench.rs:170` `let name = Name::from_ascii(qname).expect("invalid SB_BENCH_DNS_NAME");`
- `app/src/bin/sb-bench.rs:186` `.expect("failed to bind DNS socket");`
- `app/src/bin/sb-bench.rs:195` `.expect("failed to encode DNS query");`
- `app/src/bin/sb-bench.rs:230` `Histogram::new_with_bounds(1, 60_000, 3).expect("failed to create histogram")`
- `app/src/bin/sb-explaind.rs:250` `.expect("SB_DEBUG_ADDR");`
- `app/src/bin/subs.rs:29` `let b = fs::read(p).expect("read file");`
- `app/src/bin/subs.rs:30` `serde_json::from_slice(&b).expect("parse json")`
- `app/src/bin/subs.rs:40` `fs::write(&out, serde_json::to_string_pretty(&merged).unwrap()).expect("write out");`
- `app/src/http_util.rs:122` `.expect("response builder failed")`
- `app/src/http_util.rs:145` `.expect("response builder failed")`
- `app/src/http_util.rs:158` `.expect("response builder failed")`
- `app/src/http_util.rs:171` `.expect("response builder failed")`
- `app/src/http_util.rs:183` `.expect("response builder failed")`
- `app/src/http_util.rs:196` `.expect("response builder failed")`
- `crates/sb-adapters/src/inbound/shadowsocks.rs:560` `let master_key = master_key.expect("set alongside auth_user");`
- `crates/sb-adapters/src/inbound/shadowsocks.rs:561` `let decrypted = decrypted.expect("set alongside auth_user");`
- `crates/sb-adapters/src/inbound/shadowtls.rs:717` `hasher: HmacSha1::new_from_slice(password.as_bytes()).expect("hmac init"),`
- `crates/sb-adapters/src/inbound/shadowtls.rs:931` `let mut hmac = HmacSha1::new_from_slice(password.as_bytes()).expect("hmac init");`
- `crates/sb-adapters/src/inbound/shadowtls.rs:938` `let mut hmac = HmacSha1::new_from_slice(password.as_bytes()).expect("hmac init");`
- `crates/sb-adapters/src/inbound/shadowtls.rs:973` `let mut hmac = HmacSha1::new_from_slice(password.as_bytes()).expect("hmac init");`
- `crates/sb-adapters/src/inbound/tun_session.rs:136` `if let Some(tx) = self.shutdown_tx.lock().expect("lock shutdown_tx").take() {`
- `crates/sb-adapters/src/outbound/shadowsocksr/protocol.rs:123` `.expect("HMAC can take any key length");`
- `crates/sb-adapters/src/outbound/shadowtls.rs:171` `.expect("hmac accepts any key length"),`
- `crates/sb-adapters/src/outbound/shadowtls.rs:321` `HmacSha1::new_from_slice(self.password.as_bytes()).expect("hmac init");`
- `crates/sb-adapters/src/outbound/shadowtls.rs:683` `let mut hmac = HmacSha1::new_from_slice(password.as_bytes()).expect("hmac init");`
- `crates/sb-adapters/src/outbound/shadowtls.rs:691` `let mut hmac = HmacSha1::new_from_slice(password.as_bytes()).expect("hmac init");`
- `crates/sb-adapters/src/outbound/tailscale.rs:253` `.expect("Managed mode requires auth_key");`
- `crates/sb-core/src/config/types_route.rs:336` `serde_json::to_value(&schema).expect("Failed to serialize schema to JSON")`
- `crates/sb-core/src/dns/transport/mod.rs:176` `DhcpUpstream::from_spec("dhcp", None).expect("DhcpUpstream fallback")`
- `crates/sb-core/src/metrics/mod.rs:45` `.expect("gaugevec");`
- `crates/sb-core/src/metrics/udp.rs:37` `.expect("Failed to create udp_nat_size_prom gauge");`
- `crates/sb-core/src/metrics/udp.rs:42` `.expect("Failed to create udp_nat_heap_len_prom gauge");`
- `crates/sb-core/src/metrics/udp.rs:47` `.expect("Failed to create udp_nat_gen_mismatch_total_prom counter");`
- `crates/sb-core/src/metrics/udp.rs:52` `.expect("Failed to create udp_flow_bytes_in_total_prom counter");`
- `crates/sb-core/src/metrics/udp.rs:57` `.expect("Failed to create udp_flow_bytes_out_total_prom counter");`
- `crates/sb-core/src/metrics/udp.rs:63` `.expect("Failed to create udp_nat_ttl_seconds histogram");`
- `crates/sb-core/src/metrics/udp_v2.rs:18` `.expect("Failed to create udp_nat_size gauge");`
- `crates/sb-core/src/metrics/udp_v2.rs:20` `.expect("Failed to create udp_nat_heap_len gauge");`
- `crates/sb-core/src/metrics/udp_v2.rs:25` `.expect("Failed to create udp_nat_evicted_total counter");`
- `crates/sb-core/src/metrics/udp_v2.rs:30` `.expect("Failed to create udp_nat_gen_mismatch_total counter");`
- `crates/sb-core/src/metrics/udp_v2.rs:32` `.expect("Failed to create udp_flow_bytes_in_total counter");`
- `crates/sb-core/src/metrics/udp_v2.rs:35` `.expect("Failed to create udp_flow_bytes_out_total counter");`
- `crates/sb-core/src/outbound/ss/hkdf.rs:39` `.expect("HKDF expand should never fail with valid parameters");`
- `crates/sb-core/src/outbound/ss/hkdf.rs:48` `.expect("HKDF expand should never fail with valid parameters");`
- `crates/sb-core/src/router/mod.rs:1922` `super::router_build_index_from_str(text, 1 << 24).expect("bench build index")`
- `crates/sb-core/src/runtime/transport.rs:498` `.expect("invalid client auth cert/key")`
- `crates/sb-core/src/services/cache_file.rs:78` `*me.worker.lock().expect("worker mutex poisoned") = Some(handle);`
- `crates/sb-core/src/services/cache_file.rs:83` `let mut st = self.inner.mu.lock().expect("debouncer mutex poisoned");`
- `crates/sb-core/src/services/cache_file.rs:95` `let mut st = self.inner.mu.lock().expect("debouncer mutex poisoned");`
- `crates/sb-core/src/services/cache_file.rs:106` `let mut st = self.inner.mu.lock().expect("debouncer mutex poisoned");`
- `crates/sb-core/src/services/cache_file.rs:110` `if let Some(handle) = self.worker.lock().expect("worker mutex poisoned").take() {`
- `crates/sb-core/src/services/cache_file.rs:125` `let mut st = inner.mu.lock().expect("debouncer mutex poisoned");`
- `crates/sb-core/src/services/cache_file.rs:127` `st = inner.cv.wait(st).expect("debouncer condvar poisoned");`
- `crates/sb-core/src/services/cache_file.rs:146` `.expect("debouncer condvar poisoned");`
- `crates/sb-core/src/services/cache_file.rs:158` `let st = inner.mu.lock().expect("debouncer mutex poisoned");`
- `crates/sb-core/src/services/ssmapi/server.rs:343` `let tls = ir.tls.as_ref().expect("checked above");`
- `crates/sb-core/src/services/ssmapi/server.rs:745` `.expect("ssm-api: endpoints non-empty")`
- `crates/sb-metrics/src/lib.rs:1102` `.expect("Prometheus encoding should never fail");`
- `crates/sb-metrics/src/lib.rs:1103` `String::from_utf8(buf).expect("Prometheus output should be valid UTF-8")`
- `crates/sb-transport/src/multiplex.rs:550` `.expect("Failed to get local address");`
- `crates/sb-transport/src/wireguard.rs:358` `let state = self.read_state.as_mut().expect("read_state should be Some");`
- `crates/sb-transport/src/wireguard.rs:411` `.expect("write_state should be Some");`

### panic (1)
- 判定：确定命中
- 对应层：Layer 1

- `crates/sb-core/src/util/failpoint.rs:59` `Action::Panic => panic!("failpoint hit: {site}"),`

### todo_unimpl_unreachable (1)
- 判定：确定命中
- 对应层：Layer 1

- `crates/sb-adapters/src/outbound/shadowtls.rs:1072` `_ => unreachable!("shadowtls detour wrapper version is prevalidated"),`

### static_once_lock (29)
- 判定：确定命中
- 对应层：Layer 1

- `app/src/admin_debug/http_util.rs:301` `static KINDS: OnceLock<Vec<String>> = OnceLock::new();`
- `crates/sb-adapters/src/inbound/http.rs:33` `static HTTP_FLAG_SMOKE_405: OnceLock<bool> = OnceLock::new();`
- `crates/sb-adapters/src/inbound/http.rs:35` `static HTTP_FLAG_DISABLE_STOP: OnceLock<bool> = OnceLock::new();`
- `crates/sb-adapters/src/inbound/http.rs:49` `static HTTP_FLAG_LEGACY_WRITE: OnceLock<bool> = OnceLock::new();`
- `crates/sb-common/src/conntrack.rs:313` `static GLOBAL_TRACKER: std::sync::OnceLock<Arc<ConnTracker>> = std::sync::OnceLock::new();`
- `crates/sb-core/src/dns/fakeip.rs:159` `static STATE: OnceLock<Mutex<State>> = OnceLock::new();`
- `crates/sb-core/src/dns/global.rs:5` `static GLOBAL: OnceLock<RwLock<Option<Arc<dyn Resolver>>>> = OnceLock::new();`
- `crates/sb-core/src/dns/resolve.rs:447` `static CACHE: OnceLock<DnsCache> = OnceLock::new();`
- `crates/sb-core/src/dns/stub.rs:77` `static GLOBAL: OnceLock<DnsCache> = OnceLock::new();`
- `crates/sb-core/src/geoip/mod.rs:81` `static GEOIP_SERVICE: OnceLock<GeoIpService> = OnceLock::new();`
- `crates/sb-core/src/http_client.rs:11` `static GLOBAL_HTTP_CLIENT: OnceLock<Box<dyn HttpClient>> = OnceLock::new();`
- `crates/sb-core/src/inbound/loopback.rs:160` `static DETECTOR: std::sync::OnceLock<LoopbackDetector> = std::sync::OnceLock::new();`
- `crates/sb-core/src/log/mod.rs:54` `static CONFIG: OnceLock<RwLock<LogConfig>> = OnceLock::new();`
- `crates/sb-core/src/log/mod.rs:122` `static TARGET: OnceLock<String> = OnceLock::new();`
- `crates/sb-core/src/net/metered.rs:19` `static RELAY_BUF_POOL: OnceLock<parking_lot::Mutex<Vec<Vec<u8>>>> = OnceLock::new();`
- `crates/sb-core/src/net/ratelimit.rs:36` `static START: OnceLock<Instant> = OnceLock::new();`
- `crates/sb-core/src/net/ratelimit.rs:84` `static B: OnceLock<Bucket> = OnceLock::new();`
- `crates/sb-core/src/outbound/direct_connector.rs:416` `static SEM: OnceLock<tokio::sync::Semaphore> = OnceLock::new();`
- `crates/sb-core/src/outbound/udp.rs:58` `static LIM: OnceLock<Option<RateLimiter>> = OnceLock::new();`
- `crates/sb-core/src/outbound/udp.rs:76` `static DNS: OnceLock<DnsClient> = OnceLock::new();`
- `crates/sb-core/src/outbound/udp_balancer.rs:17` `static C: OnceLock<AtomicUsize> = OnceLock::new();`
- `crates/sb-core/src/outbound/udp_balancer.rs:163` `static M: OnceLock<AsyncRwLock<HashMap<SocketAddr, UpState>>> = OnceLock::new();`
- `crates/sb-core/src/outbound/udp_proxy_glue.rs:31` `static M: OnceLock<RwLock<HashMap<SocketAddr, Assoc>>> = OnceLock::new();`
- `crates/sb-core/src/outbound/udp_socks5.rs:31` `static R: OnceLock<SocketAddr> = OnceLock::new();`
- `crates/sb-core/src/router/cache_wire.rs:25` `static SRC: OnceLock<&'static dyn DecisionCacheSource> = OnceLock::new();`
- `crates/sb-core/src/router/decision_intern.rs:33` `static G: OnceLock<Mutex<Pool>> = OnceLock::new();`
- `crates/sb-core/src/router/mod.rs:386` `static ONCE: OnceLock<(AtomicU64, Mutex<suffix_trie::SuffixTrie>)> = OnceLock::new();`
- `crates/sb-core/src/testutil.rs:6` `static LOCK: OnceLock<ReentrantMutex<()>> = OnceLock::new();`
- `crates/sb-core/src/util/failpoint.rs:11` `static FP_CFG: OnceLock<String> = OnceLock::new();`

### static_lazy_lock (14)
- 判定：确定命中
- 对应层：Layer 1

- `app/src/admin_debug/prefetch.rs:31` `static DEFAULT_PREFETCHER: LazyLock<StdMutex<Option<Weak<Prefetcher>>>> =`
- `app/src/admin_debug/security_metrics.rs:105` `static DEFAULT_STATE: LazyLock<StdMutex<Weak<SecurityMetricsState>>> =`
- `app/src/logging.rs:29` `static ACTIVE_RUNTIME: LazyLock<StdMutex<Weak<LoggingRuntime>>> =`
- `crates/sb-core/src/geoip/mod.rs:82` `static DEFAULT_GEOIP_SERVICE: LazyLock<Mutex<Option<Weak<GeoIpService>>>> =`
- `crates/sb-core/src/http_client.rs:12` `static DEFAULT_HTTP_CLIENT: LazyLock<Mutex<Option<Weak<dyn HttpClient>>>> =`
- `crates/sb-metrics/src/labels.rs:18` `static ALLOWED_LABEL_KEYS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {`
- `crates/sb-metrics/src/lib.rs:169` `static ERROR_RATE_LIMITER: LazyLock<ErrorRateLimiter> = LazyLock::new(ErrorRateLimiter::new);`
- `crates/sb-metrics/src/lib.rs:170` `static DEFAULT_REGISTRY: LazyLock<Mutex<Option<Weak<Registry>>>> =`
- `crates/sb-metrics/src/lib.rs:173` `static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::new);`
- `crates/sb-tls/src/global.rs:11` `static TLS_OVERRIDE: LazyLock<RwLock<Option<Arc<ClientConfig>>>> =`
- `crates/sb-tls/src/global.rs:14` `static EXTRA_CA_PATHS: LazyLock<RwLock<Vec<String>>> = LazyLock::new(|| RwLock::new(Vec::new()));`
- `crates/sb-tls/src/global.rs:16` `static EXTRA_CA_PEMS: LazyLock<RwLock<Vec<String>>> = LazyLock::new(|| RwLock::new(Vec::new()));`
- `crates/sb-tls/src/global.rs:18` `static CERT_DIRS: LazyLock<RwLock<Vec<String>>> = LazyLock::new(|| RwLock::new(Vec::new()));`
- `crates/sb-tls/src/global.rs:20` `static STORE_MODE: LazyLock<RwLock<CertificateStoreMode>> =`

### static_once_cell (34)
- 判定：确定命中
- 对应层：Layer 1 精神

- `app/src/admin_debug/audit.rs:20` `static AUDIT_LOG: OnceCell<Mutex<VecDeque<AuditEntry>>> = OnceCell::new();`
- `app/src/admin_debug/breaker.rs:26` `static CLOCK: OnceCell<std::sync::Arc<dyn Clock>> = OnceCell::new();`
- `app/src/admin_debug/breaker.rs:375` `static BREAKER: OnceCell<Mutex<HostBreaker>> = OnceCell::new();`
- `app/src/admin_debug/cache.rs:341` `static LRU: OnceCell<Mutex<Lru>> = OnceCell::new();`
- `app/src/admin_debug/endpoints/subs.rs:37` `static MAX_CONC: OnceCell<RwLock<Arc<Semaphore>>> = OnceCell::new();`
- `app/src/admin_debug/endpoints/subs.rs:39` `static RPS_TOKENS: OnceCell<(AtomicU64, AtomicU64, AtomicU64)> = OnceCell::new(); // (current, capacity, last_tick)`
- `app/src/admin_debug/prefetch.rs:30` `static GLOBAL: OnceCell<Prefetcher> = OnceCell::new();`
- `app/src/admin_debug/reloadable.rs:170` `static CONFIG: OnceCell<ArcSwap<EnvConfig>> = OnceCell::new();`
- `app/src/admin_debug/reloadable.rs:171` `static VERSION: OnceCell<AtomicU64> = OnceCell::new();`
- `crates/sb-adapters/src/inbound/http.rs:89` `static SELECTOR: OnceCell<PoolSelector> = OnceCell::new();`
- `crates/sb-adapters/src/inbound/socks/mod.rs:40` `static SELECTOR: OnceCell<PoolSelector> = OnceCell::new();`
- `crates/sb-adapters/src/inbound/socks/udp.rs:39` `static NAT_MAP: OnceCell<Arc<UdpNatMap>> = OnceCell::const_new();`
- `crates/sb-adapters/src/inbound/socks/udp.rs:40` `static UPSTREAM_MAP: OnceCell<Arc<UdpUpstreamMap>> = OnceCell::const_new();`
- `crates/sb-adapters/src/inbound/socks/udp.rs:828` `static SELECTOR: SyncOnceCell<PoolSelector> = SyncOnceCell::new();`
- `crates/sb-core/src/metrics/mod.rs:25` `static REGISTRY: OnceCell<prometheus::Registry> = OnceCell::new();`
- `crates/sb-core/src/metrics/registry_ext.rs:17` `static INT_GAUGE_MAP: OnceCell<DashMap<String, &'static IntGaugeVec>> = OnceCell::new();`
- `crates/sb-core/src/metrics/registry_ext.rs:18` `static GAUGE_MAP: OnceCell<DashMap<String, &'static GaugeVec>> = OnceCell::new();`
- `crates/sb-core/src/metrics/registry_ext.rs:19` `static COUNTER_MAP: OnceCell<DashMap<String, &'static IntCounterVec>> = OnceCell::new();`
- `crates/sb-core/src/metrics/registry_ext.rs:20` `static HISTOGRAM_MAP: OnceCell<DashMap<String, &'static HistogramVec>> = OnceCell::new();`
- `crates/sb-core/src/metrics/registry_ext.rs:23` `static CELL: OnceCell<&'static IntGaugeVec> = OnceCell::new();`
- `crates/sb-core/src/metrics/registry_ext.rs:45` `static CELL: OnceCell<&'static GaugeVec> = OnceCell::new();`
- `crates/sb-core/src/metrics/registry_ext.rs:66` `static CELL: OnceCell<&'static HistogramVec> = OnceCell::new();`
- `crates/sb-core/src/metrics/registry_ext.rs:177` `static CELL: OnceCell<&'static IntCounterVec> = OnceCell::new();`
- `crates/sb-core/src/metrics/registry_ext.rs:202` `static LAST_RESORT: OnceCell<&'static IntCounterVec> = OnceCell::new();`
- `crates/sb-core/src/outbound/health.rs:50` `static STATUS: once_cell::sync::OnceCell<HealthStatus> = once_cell::sync::OnceCell::new();`
- `crates/sb-core/src/outbound/health.rs:51` `static STATES: once_cell::sync::OnceCell<DashMap<String, EpState>> =`
- `crates/sb-core/src/outbound/registry.rs:32` `static GLOBAL: OnceCell<Arc<Registry>> = OnceCell::new();`
- `crates/sb-core/src/router/cache_hot.rs:12` `static REG: OnceCell<Provider> = OnceCell::new();`
- `crates/sb-core/src/router/cache_hot.rs:30` `static HOT_SRC: OnceCell<&'static dyn CacheHotSource> = OnceCell::new();`
- `crates/sb-core/src/router/cache_stats.rs:14` `static REG: OnceCell<Provider> = OnceCell::new();`
- `crates/sb-core/src/router/explain_index.rs:12` `static EXPLAIN_INDEX: OnceCell<RwLock<ExplainIndex>> = OnceCell::new();`
- `crates/sb-core/src/router/rules.rs:2096` `static GLOBAL_RULES: OnceCell<Arc<Engine>> = OnceCell::new();`
- `crates/sb-transport/src/metrics_ext.rs:25` `static COUNTER_VECS: OnceCell<Mutex<HashMap<String, IntCounterVec>>> = OnceCell::new();`
- `crates/sb-transport/src/metrics_ext.rs:26` `static GAUGE_VECS: OnceCell<Mutex<HashMap<String, GaugeVec>>> = OnceCell::new();`

### wildcard_import (52)
- 判定：确定命中
- 对应层：Layer 2

- `app/src/bin/handshake.rs:20` `use sb_runtime::prelude::*;`
- `crates/sb-adapters/src/inbound/http.rs:318` `use std::io::ErrorKind::*;`
- `crates/sb-adapters/src/inbound/socks/error.rs:40` `use io::ErrorKind::*;`
- `crates/sb-adapters/src/inbound/ssh.rs:128` `use super::*;`
- `crates/sb-adapters/src/outbound/anytls.rs:7` `use crate::outbound::prelude::*;`
- `crates/sb-adapters/src/outbound/detour.rs:1` `use crate::outbound::prelude::*;`
- `crates/sb-adapters/src/outbound/dns.rs:6` `use crate::outbound::prelude::*;`
- `crates/sb-adapters/src/outbound/http.rs:8` `use crate::outbound::prelude::*;`
- `crates/sb-adapters/src/outbound/http.rs:11` `use base64::prelude::*;`
- `crates/sb-adapters/src/outbound/hysteria.rs:2` `use crate::outbound::prelude::*;`
- `crates/sb-adapters/src/outbound/hysteria2.rs:5` `use crate::outbound::prelude::*;`
- `crates/sb-adapters/src/outbound/shadowsocks.rs:11` `use crate::outbound::prelude::*;`
- `crates/sb-adapters/src/outbound/shadowtls.rs:13` `use crate::outbound::prelude::*;`
- `crates/sb-adapters/src/outbound/socks4.rs:17` `use crate::outbound::prelude::*;`
- `crates/sb-adapters/src/outbound/socks5.rs:9` `use crate::outbound::prelude::*;`
- `crates/sb-adapters/src/outbound/ssh.rs:7` `use crate::outbound::prelude::*;`
- `crates/sb-adapters/src/outbound/ssh.rs:95` `use super::*;`
- `crates/sb-adapters/src/outbound/tailscale.rs:23` `use crate::outbound::prelude::*;`
- `crates/sb-adapters/src/outbound/trojan.rs:7` `use crate::outbound::prelude::*;`
- `crates/sb-adapters/src/outbound/tuic.rs:9` `use crate::outbound::prelude::*;`
- `crates/sb-adapters/src/outbound/vless.rs:11` `use crate::outbound::prelude::*;`
- `crates/sb-adapters/src/outbound/vmess.rs:9` `use crate::outbound::prelude::*;`
- `crates/sb-adapters/src/outbound/wireguard.rs:13` `use crate::outbound::prelude::*;`
- `crates/sb-adapters/src/register.rs:1353` `use crate::transport_config::*;`
- `crates/sb-adapters/src/service/resolve1.rs:19` `use super::*;`
- `crates/sb-adapters/src/service/resolve1.rs:810` `use super::*;`
- `crates/sb-adapters/src/service/resolved_impl.rs:12` `use super::*;`
- `crates/sb-api/src/v2ray/mod.rs:176` `use super::*;`
- `crates/sb-api/src/v2ray/mod.rs:258` `use super::*;`
- `crates/sb-api/src/v2ray/mod.rs:355` `use super::*;`
- `crates/sb-api/src/v2ray/mod.rs:437` `use super::*;`
- `crates/sb-api/src/v2ray/server.rs:16` `use super::*;`
- `crates/sb-api/src/v2ray/server.rs:17` `use crate::v2ray::services::*;`
- `crates/sb-api/src/v2ray/server.rs:79` `use super::*;`
- `crates/sb-api/src/v2ray/services.rs:12` `use crate::v2ray::generated::*;`
- `crates/sb-config/src/de.rs:32` `use super::*;`
- `crates/sb-core/src/net/metered.rs:76` `use io::ErrorKind::*;`
- `crates/sb-core/src/outbound/optimizations.rs:378` `use super::*;`
- `crates/sb-core/src/router/cache_wire.rs:67` `use super::*;`
- `crates/sb-core/src/router/mod.rs:1918` `use super::*;`
- `crates/sb-core/src/router/normalize.rs:120` `use Kind::*;`
- `crates/sb-core/src/router/preview.rs:2` `use super::*;`
- `crates/sb-core/src/router/ruleset/binary.rs:5` `use super::*;`
- `crates/sb-core/src/router/ruleset/matcher.rs:9` `use super::*;`
- `crates/sb-core/src/router/ruleset/remote.rs:12` `use super::*;`
- `crates/sb-platform/src/system_proxy.rs:496` `use winreg::enums::*;`
- `crates/sb-platform/src/system_proxy.rs:531` `use winreg::enums::*;`
- `crates/sb-platform/src/tun/windows.rs:291` `use super::*;`
- `crates/sb-platform/src/wininet.rs:126` `use winreg::enums::*;`
- `crates/sb-platform/src/wininet.rs:215` `use winreg::enums::*;`
- `crates/sb-tls/src/danger.rs:92` `use x509_parser::prelude::*;`
- `crates/sb-transport/src/resource_pressure.rs:287` `use super::*;`

### debug_output (275)
- 判定：确定命中
- 对应层：Layer 2

- `app/src/admin_debug/http_server.rs:629` `println!("ADMIN_LISTEN={actual_addr}");`
- `app/src/admin_debug/http_server.rs:812` `println!("ADMIN_LISTEN={actual_addr}");`
- `app/src/admin_debug/http_server.rs:995` `println!("ADMIN_LISTEN={actual_addr}");`
- `app/src/bin/coverage-http.rs:13` `eprintln!("invalid SB_COV_ADDR: {e}");`
- `app/src/bin/coverage-http.rs:47` `eprintln!("server error: {e}");`
- `app/src/bin/diag.rs:78` `println!("{}", out);`
- `app/src/bin/diag.rs:99` `println!("{}", out);`
- `app/src/bin/diag.rs:140` `println!("{}", out);`
- `app/src/bin/dsl.rs:55` `println!("{out}");`
- `app/src/bin/dsl.rs:80` `println!(`
- `app/src/bin/dsl.rs:89` `println!("--- EXPANDED ---\n{expanded}");`
- `app/src/bin/dsl.rs:101` `println!("PACK_OK: {}", output.display());`
- `app/src/bin/handshake.rs:7` `eprintln!("sb-handshake: built without `--features handshake_alpha` — stub running.");`
- `app/src/bin/handshake.rs:8` `eprintln!(`
- `app/src/bin/handshake.rs:474` `println!(`
- `app/src/bin/handshake.rs:488` `println!(`
- `app/src/bin/handshake.rs:514` `println!("HS_OK: {}", out.display());`
- `app/src/bin/handshake.rs:545` `println!(`
- `app/src/bin/handshake.rs:554` `println!(`
- `app/src/bin/handshake.rs:571` `println!("HS_OK: metrics path='{}'", out.display());`
- `app/src/bin/handshake.rs:585` `println!(`
- `app/src/bin/handshake.rs:672` `println!(`
- `app/src/bin/handshake.rs:717` `eprintln!("WARN: --var expects KEY=VAL, got: {}", kv);`
- `app/src/bin/handshake.rs:728` `println!(`
- `app/src/bin/handshake.rs:734` `println!("{json_str}");`
- `app/src/bin/handshake.rs:743` `println!(`
- `app/src/bin/handshake.rs:751` `println!("{summary}");`
- `app/src/bin/handshake.rs:757` `println!("HS_OK: report '{}'", rp.display());`
- `app/src/bin/handshake.rs:771` `println!(`
- `app/src/bin/handshake.rs:835` `println!(`
- `app/src/bin/handshake.rs:901` `println!("HS_OK: io_local addr='{}' bytes_tx={} bytes_rx={} out='{}' chaos={{tx_ms:{},rx_ms:{},drop:{},trim:{},xor:{}}}",`
- `app/src/bin/handshake.rs:917` `println!(`
- `app/src/bin/handshake.rs:935` `eprintln!("handshake failed: {e}");`
- `app/src/bin/metrics-serve.rs:28` `println!("READY");`
- `app/src/bin/preflight.rs:43` `println!("{}", serde_json::to_string_pretty(&obj).unwrap());`
- `app/src/bin/preview.rs:67` `println!("{}", ex.decision);`
- `app/src/bin/preview.rs:85` `Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap_or(s)),`
- `app/src/bin/preview.rs:86` `Err(_) => println!("{j}"),`
- `app/src/bin/preview.rs:89` `println!("{j}");`
- `app/src/bin/probe-outbound.rs:58` `eprintln!("transport_chain={}", chain.join(","));`
- `app/src/bin/probe-outbound.rs:60` `eprintln!("outbound not found: {}", args.outbound);`
- `app/src/bin/probe-outbound.rs:65` `eprintln!(`
- `app/src/bin/probe-outbound.rs:104` `println!(`
- `app/src/bin/route.rs:209` `println!(`
- `app/src/bin/route.rs:214` `println!("{s}");`
- `app/src/bin/route.rs:217` `_ => println!("{s}"),`
- `app/src/bin/route.rs:624` `OutFmt::Min => println!("{}", ex.decision),`
- `app/src/bin/route.rs:638` `println!("{}", j);`
- `app/src/bin/route.rs:695` `println!(`
- `app/src/bin/route.rs:736` `eprintln!(`
- `app/src/bin/route.rs:742` `eprintln!("[warn] 分析结果解析失败：{e}; 回退输出完整 JSON");`
- `app/src/bin/route.rs:770` `_ => println!("{finalized}"),`
- `app/src/bin/route.rs:780` `println!(`
- `app/src/bin/route.rs:804` `println!(`
- `app/src/bin/route.rs:823` `println!("ANALYZE_KEYS_OUT: path='{}' keys_top={}", p.display(), topk);`
- `app/src/bin/route.rs:913` `println!(`
- `app/src/bin/route.rs:952` `println!(`
- `app/src/bin/route.rs:963` `println!(`
- `app/src/bin/route.rs:1012` `println!(`
- `app/src/bin/route.rs:1031` `println!("COMPARE_OUT: samples='{}' count={}", p.display(), n);`
- `app/src/bin/route.rs:1045` `println!("COVER_OK: {} ({} targets)", p.display(), targets.len());`
- `app/src/bin/route.rs:1048` `println!("{t}");`
- `app/src/bin/sb-bench.rs:64` `println!("{}", serde_json::to_string_pretty(&report).unwrap());`
- `app/src/bin/sb-explaind.rs:251` `eprintln!("[explaind] listen http://{}", addr);`
- `app/src/bin/sb-rule-coverage.rs:8` `eprintln!("sb-rule-coverage: build without `--features rule_coverage` — stub running.");`
- `app/src/bin/sb-rule-coverage.rs:9` `eprintln!("Hint: enable the feature to output JSON coverage snapshot.");`
- `app/src/bin/sb-rule-coverage.rs:15` `println!("{}", serde_json::to_string_pretty(&snap).unwrap());`
- `app/src/bin/sb-version.rs:19` `println!("{}", serde_json::to_string(&obj).unwrap());`
- `app/src/bin/subs.rs:41` `println!("{}", serde_json::to_string_pretty(&serde_json::json!({`
- `app/src/bin/subs.rs:51` `println!(`
- `app/src/bin/transport-plan.rs:25` `println!("transport-plan for: {}", args.config.display());`
- `app/src/bin/transport-plan.rs:36` `println!(`
- `app/src/bin/version.rs:33` `println!("{}", serde_json::to_string(&obj).unwrap());`
- `app/src/cli/auth.rs:276` `println!("Authorization: SB-HMAC key_id=\"{key_id}\", ts={ts}, nonce=\"{nonce}\"");`
- `app/src/cli/auth.rs:277` `println!("X-SB-Signature: {sig_b64}");`
- `app/src/cli/auth.rs:279` `println!("--- canonical ---\n{canon_str}");`
- `app/src/cli/auth.rs:382` `eprintln!("semaphore acquire failed, skipping request");`
- `app/src/cli/auth.rs:399` `eprintln!("invalid HMAC key length, skipping request");`
- `app/src/cli/auth.rs:465` `println!(`
- `app/src/cli/auth.rs:474` `println!(`
- `app/src/cli/bench.rs:117` `println!(`
- `app/src/cli/bench.rs:125` `eprintln!("bench io requires feature 'reqwest'\nHint: {}", hint);`
- `app/src/cli/bench.rs:400` `println!("{}", serde_json::to_string(&fixed)?);`
- `app/src/cli/bench.rs:402` `println!(`
- `app/src/cli/bench.rs:417` `eprintln!(`
- `app/src/cli/check/run.rs:85` `eprintln!("MINIMIZE_SKIPPED: negation_present=true");`
- `app/src/cli/check/run.rs:92` `println!("{}", serde_json::to_string_pretty(&out_json)?);`
- `app/src/cli/check/run.rs:99` `println!("{fingerprint}");`
- `app/src/cli/check/run.rs:151` `println!("{}", serde_json::to_string_pretty(&schema_v1())?);`
- `app/src/cli/check/run.rs:157` `println!("{}", serde_json::to_string_pretty(&schema)?);`
- `app/src/cli/check/run.rs:161` `eprintln!("schema v2 not available (build without feature)");`
- `app/src/cli/check/run.rs:173` `eprintln!("--diff-config OLD NEW");`
- `app/src/cli/check/run.rs:304` `eprintln!(`
- `app/src/cli/check/run.rs:315` `eprintln!(`
- `app/src/cli/check/run.rs:1000` `println!("Configs are identical (no differences found)");`
- `app/src/cli/check/run.rs:1004` `println!("Config differences detected:");`
- `app/src/cli/check/run.rs:1005` `println!(`
- `app/src/cli/check/run.rs:1010` `println!(`
- `app/src/cli/check/run.rs:1015` `println!();`
- `app/src/cli/check/run.rs:1074` `println!("{description}: MODIFIED");`
- `app/src/cli/check/run.rs:1079` `println!("{description}: REMOVED");`
- `app/src/cli/check/run.rs:1082` `println!("{description}: ADDED");`
- `app/src/cli/check/run.rs:1099` `println!(" + {section}.{key}");`
- `app/src/cli/check/run.rs:1103` `println!(" - {section}.{key}");`
- `app/src/cli/check/run.rs:1108` `println!(" ~ {section}.{key}");`
- `app/src/cli/check/run.rs:1114` `println!(`
- `app/src/cli/check/run.rs:1124` `println!(" {section} value changed");`
- `app/src/cli/completion.rs:60` `eprintln!("# completions written to {}", dir.display());`
- `app/src/cli/completion.rs:99` `eprintln!("# install hints (macOS/Linux)");`
- `app/src/cli/completion.rs:100` `eprintln!("# Bash : ~/.bashrc -> source <(./{exe} completion --shell bash)");`
- `app/src/cli/completion.rs:101` `eprintln!("# Zsh : ~/.zshrc -> source <(./{exe} completion --shell zsh)");`
- `app/src/cli/completion.rs:102` `eprintln!("# Fish : ~/.config/fish/completions/{exe}.fish (mkdir -p 其目录后拷贝生成文件)");`
- `app/src/cli/completion.rs:103` `eprintln!("# PowerSh: $PROFILE -> 取生成的 ps1 并 dot-source");`
- `app/src/cli/completion.rs:104` `eprintln!("# Elvish : ~/.elvish/lib/completions/{exe}.elv (拷贝后 use completions/{exe})");`
- `app/src/cli/format.rs:91` `eprintln!("{}", abs.display());`
- `app/src/cli/format.rs:93` `eprintln!("{}", path.display());`
- `app/src/cli/format.rs:96` `eprintln!("{}", entry.path);`
- `app/src/cli/generate.rs:83` `println!("{id}");`
- `app/src/cli/generate.rs:104` `println!("{encoded}");`
- `app/src/cli/generate.rs:107` `println!("{encoded}");`
- `app/src/cli/generate.rs:122` `print!("{config_pem}");`
- `app/src/cli/generate.rs:123` `print!("{key_pem}");`
- `app/src/cli/generate.rs:253` `println!("PrivateKey: {private_base64}");`
- `app/src/cli/generate.rs:254` `println!("PublicKey: {public_base64}");`
- `app/src/cli/generate.rs:270` `println!("Certificate:\n{}", cert_pem.trim_end());`
- `app/src/cli/generate.rs:271` `println!("PrivateKey:\n{}", key_pem.trim_end());`
- `app/src/cli/generate.rs:290` `println!("PrivateKey: {}", base64::Engine::encode(&b64url, &sk_bytes));`
- `app/src/cli/generate.rs:291` `println!("PublicKey: {}", base64::Engine::encode(&b64url, &pk_bytes));`
- `app/src/cli/generate.rs:303` `println!("PrivateKey: {}", base64::Engine::encode(b64, sk.to_bytes()));`
- `app/src/cli/generate.rs:304` `println!("PublicKey: {}", base64::Engine::encode(b64, pk.as_bytes()));`
- `app/src/cli/geoip.rs:68` `println!("{l}");`
- `app/src/cli/geoip.rs:79` `println!("{c}");`
- `app/src/cli/geoip.rs:89` `println!("private");`
- `app/src/cli/geoip.rs:98` `println!("{}", code);`
- `app/src/cli/geoip.rs:121` `println!("{}", code);`
- `app/src/cli/geoip.rs:126` `println!("unknown");`
- `app/src/cli/geoip.rs:134` `Some(code) => println!("{}", code),`
- `app/src/cli/geoip.rs:135` `None => println!("unknown"),`
- `app/src/cli/geoip.rs:202` `println!("{}", serde_json::to_string_pretty(&out_json)?);`
- `app/src/cli/geoip.rs:231` `println!("{}", serde_json::to_string_pretty(&out_json)?);`
- `app/src/cli/geosite.rs:88` `println!("{cat} ({n})");`
- `app/src/cli/geosite.rs:102` `println!("{cat} ({n})");`
- `app/src/cli/geosite.rs:124` `println!("Match code ({cat}) {desc}");`
- `app/src/cli/geosite.rs:147` `println!("Match code ({cat}) {desc}");`
- `app/src/cli/geosite.rs:274` `Some(desc) => println!("{line}\t{desc}"),`
- `app/src/cli/geosite.rs:275` `None => println!("{line}\t(no match)"),`
- `app/src/cli/geosite.rs:294` `Some(desc) => println!("{line}\t{desc}"),`
- `app/src/cli/geosite.rs:295` `None => println!("{line}\t(no match)"),`
- `app/src/cli/geosite.rs:341` `println!("{}", serde_json::to_string_pretty(&out_json)?);`
- `app/src/cli/help.rs:78` `println!(`
- `app/src/cli/json.rs:15` `println!("{}", serde_json::to_string(&obj).unwrap());`
- `app/src/cli/json.rs:27` `eprintln!("{}", serde_json::to_string(&obj).unwrap());`
- `app/src/cli/json.rs:36` `Ok(s) => println!("{s}"),`
- `app/src/cli/json.rs:37` `Err(_) => println!("{{}}"),`
- `app/src/cli/json.rs:44` `eprintln!("error: {error} hint: {hint}");`
- `app/src/cli/man.rs:33` `println!(".\\\" {name} {ver} {date}"); // 摘要行`
- `app/src/cli/merge.rs:56` `eprintln!("{}", abs.display());`
- `app/src/cli/merge.rs:58` `eprintln!("{}", args.output.display());`
- `app/src/cli/output.rs:7` `Format::Human => println!("{}", human()),`
- `app/src/cli/output.rs:8` `Format::Json => println!(`
- `app/src/cli/output.rs:12` `Format::Sarif => println!(`
- `app/src/cli/prefetch/mod.rs:245` `println!("{}", serde_json::to_string(&response)?);`
- `app/src/cli/prefetch/mod.rs:250` `println!("{}", stats_data);`
- `app/src/cli/prefetch/mod.rs:254` `println!("{stats_data}");`
- `app/src/cli/prefetch/mod.rs:258` `println!("sb_prefetch_queue_depth {depth}");`
- `app/src/cli/prefetch/mod.rs:259` `println!("sb_prefetch_queue_high_watermark {high}");`
- `app/src/cli/prefetch/mod.rs:260` `println!("sb_prefetch_jobs_total{{event=enq}} {enq}");`
- `app/src/cli/prefetch/mod.rs:261` `println!("sb_prefetch_jobs_total{{event=drop}} {drop}");`
- `app/src/cli/prefetch/mod.rs:262` `println!("sb_prefetch_jobs_total{{event=done}} {done}");`
- `app/src/cli/prefetch/mod.rs:263` `println!("sb_prefetch_jobs_total{{event=fail}} {fail}");`
- `app/src/cli/prefetch/mod.rs:264` `println!("sb_prefetch_jobs_total{{event=retry}} {retry}");`
- `app/src/cli/prefetch/mod.rs:294` `println!("enqueued: {_url}");`
- `app/src/cli/prefetch/mod.rs:378` `println!("heat finished: enq={total_enq} drop={total_drop}");`
- `app/src/cli/prefetch/mod.rs:442` `println!("{line}");`
- `app/src/cli/prefetch/mod.rs:444` `print!("\r\x1b[2K"); // clear line`
- `app/src/cli/prefetch/mod.rs:446` `print!(`
- `app/src/cli/prefetch/mod.rs:451` `println!(`
- `app/src/cli/prefetch/mod.rs:463` `println!();`
- `app/src/cli/prefetch/mod.rs:503` `println!("queue drained");`
- `app/src/cli/prefetch/mod.rs:509` `eprintln!("timeout waiting for drain; depth={d}");`
- `app/src/cli/prefetch/mod.rs:578` `println!("{}", serde_json::to_string(&response)?);`
- `app/src/cli/prefetch/mod.rs:583` `println!("{}", serde_json::to_string(&out)?);`
- `app/src/cli/prefetch/mod.rs:587` `println!("{}", serde_json::to_string(&out)?);`
- `app/src/cli/prefetch/mod.rs:590` `println!("trigger: {}", if ok { "enqueued" } else { "drop" });`
- `app/src/cli/prefetch/mod.rs:591` `println!("queue: before={before} peak={peak} after={after}");`
- `app/src/cli/prefetch/mod.rs:592` `println!("enqueue_cost_ms={}", t1.as_millis());`
- `app/src/cli/probe.rs:215` `eprintln!("UDP ASSOCIATE testing not yet implemented");`
- `app/src/cli/probe.rs:367` `println!("{}", serde_json::to_string_pretty(result)?);`
- `app/src/cli/probe.rs:371` `println!("✓ Connection successful to {} via {}", result.target, result.adapter_type);`
- `app/src/cli/probe.rs:372` `println!(" Connect time: {}ms", result.connect_time_ms);`
- `app/src/cli/probe.rs:374` `println!(" Total time: {}ms", total_time);`
- `app/src/cli/probe.rs:377` `println!(" Response size: {} bytes", size);`
- `app/src/cli/probe.rs:380` `println!("✗ Connection failed to {} via {}", result.target, result.adapter_type);`
- `app/src/cli/probe.rs:382` `println!(" Error: {}", error);`
- `app/src/cli/probe.rs:414` `println!("{}", serde_json::to_string_pretty(&sarif)?);`
- `app/src/cli/prom.rs:197` `println!("{}", serde_json::to_string(last)?);`
- `app/src/cli/prom.rs:214` `println!("{}", xs.join("\t"));`
- `app/src/cli/prom.rs:218` `println!(`
- `app/src/cli/prom.rs:393` `println!(`
- `app/src/cli/prom.rs:398` `println!(`
- `app/src/cli/prom.rs:406` `println!("{}", serde_json::to_string_pretty(&outs)?);`
- `app/src/cli/report.rs:104` `println!("{}", serde_json::to_string(&payload)?);`
- `app/src/cli/ruleset.rs:210` `println!("Validating rule-set: {}", file.display());`
- `app/src/cli/ruleset.rs:216` `println!("Format: {format:?}");`
- `app/src/cli/ruleset.rs:223` `println!("✓ Rule-set is valid!");`
- `app/src/cli/ruleset.rs:224` `println!(" Rules: {}", ruleset.rules.len());`
- `app/src/cli/ruleset.rs:225` `println!(" Version: {}", ruleset.version);`
- `app/src/cli/ruleset.rs:228` `println!(" ETag: {etag}");`
- `app/src/cli/ruleset.rs:245` `println!("Rule-Set Information");`
- `app/src/cli/ruleset.rs:246` `println!("====================");`
- `app/src/cli/ruleset.rs:247` `println!("File: {}", file.display());`
- `app/src/cli/ruleset.rs:248` `println!("Format: {:?}", ruleset.format);`
- `app/src/cli/ruleset.rs:249` `println!("Version: {}", ruleset.version);`
- `app/src/cli/ruleset.rs:250` `println!("Total Rules: {}", ruleset.rules.len());`
- `app/src/cli/ruleset.rs:263` `println!(" Default Rules: {default_count}");`
- `app/src/cli/ruleset.rs:264` `println!(" Logical Rules: {logical_count}");`
- `app/src/cli/ruleset.rs:266` `println!("Domain Index: Optimized matching enabled");`
- `app/src/cli/ruleset.rs:267` `println!("IP Prefix Tree: Optimized CIDR matching");`
- `app/src/cli/ruleset.rs:270` `println!("ETag: {etag}");`
- `app/src/cli/ruleset.rs:273` `println!("Last Updated: {:?}", ruleset.last_updated);`
- `app/src/cli/ruleset.rs:301` `println!("Formatted rule-set written to: {}", output_file.display());`
- `app/src/cli/ruleset.rs:304` `println!("Formatted rule-set written to: {}", file.display());`
- `app/src/cli/ruleset.rs:306` `println!("{formatted}");`
- `app/src/cli/ruleset.rs:348` `println!("{}", out.display());`
- `app/src/cli/ruleset.rs:350` `println!("{pretty}");`
- `app/src/cli/ruleset.rs:507` `println!("matched: {is_matched}");`
- `app/src/cli/ruleset.rs:525` `println!("{}", output.display());`
- `app/src/cli/ruleset.rs:558` `println!(`
- `app/src/cli/ruleset.rs:573` `println!("{}", output.display());`
- `app/src/cli/ruleset.rs:590` `println!("{}", output.display());`
- `app/src/cli/ruleset.rs:646` `println!("{}", output.display());`
- `app/src/cli/ruleset.rs:655` `println!("{}", output.display());`
- `app/src/cli/ruleset.rs:672` `println!("{}", output.display());`
- `app/src/cli/ruleset.rs:681` `println!("{}", output.display());`
- `app/src/cli/tools.rs:300` `eprintln!(`
- `app/src/cli/tools.rs:308` `eprintln!("{} {} ({} bytes)", status.as_u16(), url, bytes.len());`
- `app/src/cli/tools.rs:345` `println!("ntp_server={server} offset_seconds={offset:.6}");`
- `app/src/cli/tools.rs:463` `eprintln!(`
- `app/src/cli/tools.rs:470` `eprintln!("manifest: {}", manifest_path.display());`
- `app/src/cli/tools.rs:541` `eprintln!(`
- `app/src/cli/tools.rs:549` `eprintln!("{} {} ({} bytes)", status.as_u16(), url, bytes.len());`
- `app/src/cli/tools.rs:608` `println!("{}", serde_json::to_string_pretty(&output)?);`
- `app/src/cli/tools.rs:614` `println!("{ip}");`
- `app/src/env_dump.rs:57` `print!("{{ ");`
- `app/src/env_dump.rs:60` `print!(", ");`
- `app/src/env_dump.rs:64` `print!("\"{k}\":\"{vs}\"");`
- `app/src/env_dump.rs:66` `println!(" }}");`
- `app/src/panic.rs:36` `eprintln!("[PANIC] {info}");`
- `app/src/panic.rs:45` `eprintln!("Failed to create crash directory: {e}");`
- `app/src/panic.rs:75` `eprintln!("env 'SB_PANIC_LOG_MAX' value '{t}' is not a valid usize; silent parse fallback is disabled; using default 10: {e}");`
- `app/src/panic.rs:105` `eprintln!("Failed to write crash log to {file}: {e}");`
- `app/src/run_engine.rs:618` `eprintln!("{}", serde_json::to_string(&obj).unwrap_or_default());`
- `app/src/run_engine.rs:630` `eprintln!("{}", serde_json::to_string(&obj).unwrap_or_default());`
- `app/src/run_engine.rs:641` `eprintln!("{}", serde_json::to_string(&obj).unwrap_or_default());`
- `app/src/run_engine.rs:756` `eprintln!("{}", serde_json::to_string(&obj).unwrap_or_default());`
- `app/src/run_engine.rs:1030` `println!(`
- `app/src/run_engine.rs:1043` `println!("{}", serde_json::to_string_pretty(&obj).unwrap_or_default());`
- `crates/sb-adapters/src/inbound/http.rs:308` `eprintln!("serve_http: stop signal received");`
- `crates/sb-adapters/src/register.rs:3596` `eprintln!("HttpInboundAdapter::request_shutdown called");`
- `crates/sb-core/src/bin/rule-hot-reload.rs:110` `println!("Rules reloaded successfully");`
- `crates/sb-core/src/log/mod.rs:96` `eprintln!("WARN: {reason}; using default false");`
- `crates/sb-core/src/metrics/registry_ext.rs:102` `eprintln!(`
- `crates/sb-core/src/metrics/registry_ext.rs:136` `eprintln!("metrics: failed to construct GaugeVec '{}': {}", name, err);`
- `crates/sb-core/src/metrics/registry_ext.rs:171` `eprintln!(`
- `crates/sb-core/src/metrics/registry_ext.rs:201` `eprintln!("metrics: critical failure, cannot create any IntCounterVec: {}", e);`
- `crates/sb-core/src/metrics/registry_ext.rs:210` `eprintln!("CRITICAL: System metrics completely unusable, creating unregistered fallback");`
- `crates/sb-core/src/metrics/registry_ext.rs:216` `eprintln!("FATAL: Cannot create any metrics - system may be in degraded state");`
- `crates/sb-core/src/metrics/registry_ext.rs:269` `eprintln!(`
- `crates/sb-core/src/obs/access.rs:48` `eprintln!("{out}");`
- `crates/sb-core/src/router/dns_integration.rs:136` `eprintln!("Warning: DNS resolver is configured but DNS routing is disabled");`
- `crates/sb-core/src/router/mod.rs:996` `eprintln!("router rule: duplicate default (last-wins)");`
- `crates/sb-core/src/router/mod.rs:2786` `eprintln!("RwLock poisoned; proceeding with inner guard");`
- `crates/sb-runtime/src/tcp_local.rs:141` `eprintln!("tcp_local echo write failed: {err}");`
- `crates/sb-test-utils/src/skip.rs:19` `eprintln!("skipping {}: {}", context, reason);`
- `crates/sb-test-utils/src/socks5.rs:195` `eprintln!("SOCKS5 handshake error: {e}");`

### pathbuf_param (10)
- 判定：确定命中
- 对应层：Layer 2

- `app/src/cli/geoip.rs:62` `async fn geoip_list(path: &PathBuf) -> Result<()> {`
- `app/src/cli/geoip.rs:84` `async fn geoip_lookup(path: &PathBuf, address: &str) -> Result<()> {`
- `app/src/cli/geoip.rs:171` `async fn geoip_export(path: &PathBuf, country: &str, output: &str) -> Result<()> {`
- `app/src/cli/geosite.rs:79` `async fn geosite_list(path: &PathBuf) -> Result<()> {`
- `app/src/cli/geosite.rs:107` `async fn geosite_lookup(path: &PathBuf, category: Option<String>, domain: String) -> Result<()> {`
- `app/src/cli/geosite.rs:218` `async fn geosite_export(path: &PathBuf, category: &str, output: &str) -> Result<()> {`
- `app/src/cli/geosite.rs:261` `async fn geosite_matcher(path: &PathBuf, category: &str) -> Result<()> {`
- `app/src/cli/geosite.rs:371` `fn parse(path: &PathBuf) -> Result<Self> {`
- `crates/sb-core/src/services/tailscale/coordinator.rs:126` `fn load_state(path: &PathBuf) -> Option<State> {`
- `crates/sb-core/src/services/tailscale/coordinator.rs:139` `fn save_state(path: &PathBuf, state: &State) -> io::Result<()> {`

### let_underscore (571)
- 判定：确定命中
- 对应层：Layer 2

- `app/src/admin_debug/cache.rs:115` `let _ = std::fs::create_dir_all(path);`
- `app/src/admin_debug/cache.rs:254` `let _ = std::fs::remove_file(&path);`
- `app/src/admin_debug/endpoints/metrics.rs:62` `let _ = writeln!(`
- `app/src/admin_debug/endpoints/metrics.rs:67` `let _ = writeln!(`
- `app/src/admin_debug/endpoints/metrics.rs:75` `let _ = writeln!(`
- `app/src/admin_debug/endpoints/metrics.rs:80` `let _ = writeln!(`
- `app/src/admin_debug/endpoints/metrics.rs:100` `let _ = writeln!(`
- `app/src/admin_debug/endpoints/metrics.rs:109` `let _ = writeln!(`
- `app/src/admin_debug/endpoints/metrics.rs:129` `let _ = writeln!(`
- `app/src/admin_debug/endpoints/metrics.rs:134` `let _ = writeln!(`
- `app/src/admin_debug/endpoints/metrics.rs:140` `let _ = writeln!(`
- `app/src/admin_debug/endpoints/metrics.rs:149` `let _ = writeln!(`
- `app/src/admin_debug/endpoints/metrics.rs:160` `let _ = writeln!(`
- `app/src/admin_debug/endpoints/metrics.rs:179` `let _ = writeln!(buf, "sb_subs_fetch_seconds_bucket{{le=\"{bucket}\"}} {c}");`
- `app/src/admin_debug/endpoints/metrics.rs:181` `let _ = writeln!(buf, "sb_subs_fetch_seconds_count {}", h.latency_count);`
- `app/src/admin_debug/endpoints/metrics.rs:183` `let _ = writeln!(`
- `app/src/admin_debug/endpoints/metrics.rs:191` `let _ = writeln!(buf, "sb_prefetch_queue_depth {}", h.prefetch_queue_depth);`
- `app/src/admin_debug/endpoints/metrics.rs:194` `let _ = writeln!(`
- `app/src/admin_debug/endpoints/metrics.rs:201` `let _ = writeln!(`
- `app/src/admin_debug/endpoints/metrics.rs:206` `let _ = writeln!(`
- `app/src/admin_debug/endpoints/metrics.rs:211` `let _ = writeln!(`
- `app/src/admin_debug/endpoints/metrics.rs:216` `let _ = writeln!(`
- `app/src/admin_debug/endpoints/metrics.rs:221` `let _ = writeln!(`
- `app/src/admin_debug/endpoints/metrics.rs:235` `let _ = writeln!(buf, "sb_prefetch_run_seconds_bucket{{le=\"{bucket}\"}} {c}");`
- `app/src/admin_debug/endpoints/normalize.rs:250` `let _ = writeln!(output, "cidr: {net} -> {to}");`
- `app/src/admin_debug/endpoints/normalize.rs:266` `let _ = writeln!(output, "suffix: {domain} -> {to}");`
- `app/src/admin_debug/endpoints/normalize.rs:282` `let _ = writeln!(output, "exact: {host} -> {to}");`
- `app/src/admin_debug/endpoints/normalize.rs:291` `let _ = write!(output, "# Default Route\ndefault: -> {default}\n");`
- `app/src/admin_debug/endpoints/subs.rs:851` `let _ = if let Some(metrics) = metrics.as_ref() {`
- `app/src/admin_debug/endpoints/subs.rs:1216` `let _ = if let Some(metrics) = metrics.as_ref() {`
- `app/src/admin_debug/endpoints/subs.rs:1341` `let _ = if let Some(metrics) = metrics.as_ref() {`
- `app/src/admin_debug/endpoints/subs.rs:1372` `let _ = &metrics;`
- `app/src/admin_debug/endpoints/subs.rs:2014` `let _ = if let Some(metrics) = metrics {`
- `app/src/admin_debug/reloadable.rs:447` `let _ = apply_to_config(&mut new_cfg, delta)?;`
- `app/src/admin_debug/security_metrics.rs:220` `let _ = &self.prefetch_run_counts;`
- `app/src/bin/check.rs:32` `let _ = std::io::stdout().flush();`
- `app/src/bin/check.rs:33` `let _ = std::io::stderr().flush();`
- `app/src/bin/dsl.rs:92` `let _ = idx; // build 仅用于校验`
- `app/src/bin/metrics-serve.rs:11` `let _ = tracing_subscriber::fmt()`
- `app/src/bin/sb-bench.rs:84` `let _ = timeout(Duration::from_secs(2), attempt).await;`
- `app/src/bin/sb-bench.rs:90` `let _ = hist.record(ms);`
- `app/src/bin/sb-bench.rs:107` `let _ = std::fs::write(format!("{}_tcp", path), csv_content);`
- `app/src/bin/sb-bench.rs:137` `let _ = sock.send_to(&msg, target).await;`
- `app/src/bin/sb-bench.rs:139` `let _ = timeout(Duration::from_millis(500), sock.recv_from(&mut buf)).await;`
- `app/src/bin/sb-bench.rs:145` `let _ = hist.record(ms);`
- `app/src/bin/sb-bench.rs:162` `let _ = std::fs::write(path, csv_content);`
- `app/src/bin/sb-bench.rs:198` `let _ = sock.send_to(&data, target).await;`
- `app/src/bin/sb-bench.rs:200` `let _ = timeout(Duration::from_secs(1), sock.recv_from(&mut buf)).await;`
- `app/src/bin/sb-bench.rs:206` `let _ = hist.record(ms);`
- `app/src/bin/sb-bench.rs:223` `let _ = std::fs::write(format!("{}_dns", path), csv_content);`
- `app/src/bin/sb-explaind.rs:32` `let _ = write!(`
- `app/src/bin/sb-explaind.rs:38` `let _ = write!(s, "n{} -> n{}; ", i - 1, i);`
- `app/src/bin/sb-udp-echo.rs:10` `let _ = sock.send_to(&buf[..n], peer);`
- `app/src/bootstrap.rs:93` `let _ = self.shutdown.send(());`
- `app/src/bootstrap.rs:94` `let _ = self.join.await;`
- `app/src/cli/auth.rs:451` `let _ = t.await;`
- `app/src/cli/bench.rs:344` `let _ = j.await;`
- `app/src/cli/fs_scan.rs:122` `let _ = Regex::new(r"\brespond_json_error\s*\(");`
- `app/src/cli/generate.rs:262` `let _ = days; // rcgen simple API doesn't expose validity; ignore for now.`
- `app/src/cli/health.rs:71` `let _ = stream.set_read_timeout(Some(Duration::from_millis(timeout_ms)));`
- `app/src/cli/health.rs:72` `let _ = stream.set_write_timeout(Some(Duration::from_millis(timeout_ms)));`
- `app/src/cli/merge.rs:49` `let _ = fs::create_dir_all(parent);`
- `app/src/cli/ruleset.rs:588` `let _ = std::fs::remove_file(&tmp_json); // cleanup`
- `app/src/cli/tools.rs:197` `let _ = wo.shutdown().await;`
- `app/src/cli/tools.rs:202` `let _ = stdout.flush().await;`
- `app/src/cli/tools.rs:204` `let _ = tokio::join!(a, b);`
- `app/src/cli/tools.rs:282` `let _ = tokio::io::AsyncWriteExt::flush(&mut stdout).await;`
- `app/src/cli/tools.rs:284` `let _ = tokio::join!(s1, s2);`
- `app/src/panic.rs:59` `let _ = writeln!(body, "ts={ts}");`
- `app/src/panic.rs:60` `let _ = writeln!(body, "git={git}");`
- `app/src/panic.rs:61` `let _ = writeln!(body, "thread={thread}");`
- `app/src/panic.rs:63` `let _ = writeln!(body, "trace_id={tid}");`
- `app/src/panic.rs:65` `let _ = writeln!(body, "panic={info}");`
- `app/src/panic.rs:66` `let _ = writeln!(body, "backtrace={:?}", Backtrace::capture());`
- `app/src/panic.rs:99` `let _ = std::fs::remove_file(entry.path());`
- `app/src/run_engine.rs:731` `let _ = sb_core::metrics::http_exporter::run_exporter(&addr_clone);`
- `app/src/telemetry.rs:55` `let _ = deps;`
- `crates/sb-adapters/src/endpoint/tailscale.rs:26` `let _ = ctx;`
- `crates/sb-adapters/src/inbound/anytls.rs:150` `let _ = tx.blocking_send(());`
- `crates/sb-adapters/src/inbound/dns.rs:680` `let _ = tokio::try_join!(udp_handle, tcp_handle);`
- `crates/sb-adapters/src/inbound/dns.rs:682` `let _ = udp_handle.await;`
- `crates/sb-adapters/src/inbound/http.rs:232` `let _ = std::process::Command::new("networksetup")`
- `crates/sb-adapters/src/inbound/http.rs:235` `let _ = std::process::Command::new("networksetup")`
- `crates/sb-adapters/src/inbound/http.rs:255` `let _ = std::process::Command::new("networksetup")`
- `crates/sb-adapters/src/inbound/http.rs:279` `let _ = tx.send(());`
- `crates/sb-adapters/src/inbound/http.rs:297` `let _ = hb.tick().await;`
- `crates/sb-adapters/src/inbound/http.rs:341` `let _ = c.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;`
- `crates/sb-adapters/src/inbound/http.rs:342` `let _ = c.flush().await;`
- `crates/sb-adapters/src/inbound/http.rs:344` `let _ = c.shutdown().await;`
- `crates/sb-adapters/src/inbound/http.rs:916` `let _ = stream.shutdown().await;`
- `crates/sb-adapters/src/inbound/http.rs:949` `let _ = tokio::io::AsyncWriteExt::shutdown(&mut s).await;`
- `crates/sb-adapters/src/inbound/http.rs:967` `let _ = tokio::io::AsyncWriteExt::shutdown(&mut s).await;`
- `crates/sb-adapters/src/inbound/http.rs:1015` `let _ = stream.shutdown().await;`
- `crates/sb-adapters/src/inbound/http.rs:1042` `let _ = tokio::io::AsyncWriteExt::shutdown(&mut s).await;`
- `crates/sb-adapters/src/inbound/http.rs:1052` `let _ = tokio::io::AsyncWriteExt::shutdown(&mut s).await;`
- `crates/sb-adapters/src/inbound/hysteria2.rs:349` `let _ = stream.write_all(&[0x03, 0x00]).await;`
- `crates/sb-adapters/src/inbound/hysteria2.rs:360` `let _ = stream.write_all(&[code, 0x00]).await;`
- `crates/sb-adapters/src/inbound/mixed.rs:63` `let _ = tx.send(());`
- `crates/sb-adapters/src/inbound/naive.rs:195` `let _ = respond.send_response(response, true);`
- `crates/sb-adapters/src/inbound/naive.rs:213` `let _ = respond.send_response(response, true);`
- `crates/sb-adapters/src/inbound/naive.rs:237` `let _ = respond.send_response(response, true);`
- `crates/sb-adapters/src/inbound/naive.rs:247` `let _ = respond.send_response(response, true);`
- `crates/sb-adapters/src/inbound/naive.rs:383` `let _ = h2_recv.flow_control().release_capacity(data.len());`
- `crates/sb-adapters/src/inbound/naive.rs:543` `let _ = tx.blocking_send(());`
- `crates/sb-adapters/src/inbound/shadowsocks.rs:274` `let _ = plen;`
- `crates/sb-adapters/src/inbound/shadowsocks.rs:632` `let _ = (&auth_user, &shared);`
- `crates/sb-adapters/src/inbound/shadowsocks.rs:814` `let _ = tx.send(actual);`
- `crates/sb-adapters/src/inbound/shadowsocks.rs:975` `let _ = &auth_user_uplink;`
- `crates/sb-adapters/src/inbound/shadowsocks.rs:1028` `let _ = &auth_user_downlink;`
- `crates/sb-adapters/src/inbound/shadowsocks.rs:1198` `let _ = method;`
- `crates/sb-adapters/src/inbound/shadowsocks.rs:1313` `let _ = tx.try_send(());`
- `crates/sb-adapters/src/inbound/shadowsocks.rs:1373` `let _ = host;`
- `crates/sb-adapters/src/inbound/shadowtls.rs:171` `let _ = stop_tx.send(());`
- `crates/sb-adapters/src/inbound/shadowtls.rs:249` `let _ = stop_tx.send(());`
- `crates/sb-adapters/src/inbound/shadowtls.rs:259` `let _ = stop_tx.send(());`
- `crates/sb-adapters/src/inbound/shadowtls.rs:267` `let _ = stop_tx.send(());`
- `crates/sb-adapters/src/inbound/shadowtls.rs:268` `let _ = server_task.await;`
- `crates/sb-adapters/src/inbound/shadowtls.rs:314` `let _ = stop_tx.send(());`
- `crates/sb-adapters/src/inbound/shadowtls.rs:864` `let _ = tokio::try_join!(client_to_local, local_to_client);`
- `crates/sb-adapters/src/inbound/shadowtls.rs:879` `let _ = read_exact_or_eof(reader, length).await?;`
- `crates/sb-adapters/src/inbound/shadowtls.rs:1070` `let _ = tokio::try_join!(client_to_local, local_to_client);`
- `crates/sb-adapters/src/inbound/shadowtls.rs:1147` `let _ = tx.try_send(());`
- `crates/sb-adapters/src/inbound/socks/mod.rs:116` `let _ = tx.send(());`
- `crates/sb-adapters/src/inbound/socks/mod.rs:1231` `let _ = self.stop_tx.lock().unwrap().take();`
- `crates/sb-adapters/src/inbound/socks/mod.rs:1238` `let _ = tx.try_send(());`
- `crates/sb-adapters/src/inbound/socks/udp.rs:297` `let _ = natc.evict_expired().await;`
- `crates/sb-adapters/src/inbound/socks/udp.rs:928` `let _ = sock.send_to(pkt, client_addr).await;`
- `crates/sb-adapters/src/inbound/socks/udp.rs:1110` `let _ = up_map.evict_expired().await;`
- `crates/sb-adapters/src/inbound/socks/udp.rs:1165` `let _ = sock.send_to(pkt, src).await?;`
- `crates/sb-adapters/src/inbound/socks/udp.rs:1510` `let _ = map_clone.get(&key_clone).await;`
- `crates/sb-adapters/src/inbound/ssh.rs:298` `let _ = session_handle.close(channel_id).await;`
- `crates/sb-adapters/src/inbound/ssh.rs:310` `let _ = session_handle.close(channel_id).await;`
- `crates/sb-adapters/src/inbound/ssh.rs:322` `let _ = session_handle_cancel.close(channel_id).await;`
- `crates/sb-adapters/src/inbound/ssh.rs:342` `let _ = session.close(channel);`
- `crates/sb-adapters/src/inbound/ssh.rs:376` `let _ = session.close(channel);`
- `crates/sb-adapters/src/inbound/trojan.rs:540` `let _ = tokio::io::copy_bidirectional(stream, &mut remote).await;`
- `crates/sb-adapters/src/inbound/trojan.rs:937` `let _ = self.stop_tx.lock().unwrap().take();`
- `crates/sb-adapters/src/inbound/trojan.rs:944` `let _ = tx.try_send(());`
- `crates/sb-adapters/src/inbound/tuic.rs:333` `let _ = send.write_all(&[0x01; 16]).await;`
- `crates/sb-adapters/src/inbound/tuic.rs:406` `let _ = send.write_all(&[0x01]).await;`
- `crates/sb-adapters/src/inbound/tuic.rs:918` `let _ = self.stop_tx.lock().unwrap().take();`
- `crates/sb-adapters/src/inbound/tuic.rs:925` `let _ = tx.try_send(());`
- `crates/sb-adapters/src/inbound/tun/mod.rs:632` `let _ = session`
- `crates/sb-adapters/src/inbound/tun/mod.rs:771` `let _ = session`
- `crates/sb-adapters/src/inbound/tun/platform/linux.rs:221` `let _ = self.run_command("iptables", &["-t", "mangle", "-N", CHAIN_NAME]);`
- `crates/sb-adapters/src/inbound/tun/platform/linux.rs:285` `let _ = self.run_command("ip6tables", &["-t", "mangle", "-N", CHAIN_NAME]);`
- `crates/sb-adapters/src/inbound/tun/platform/linux.rs:420` `let _ = self.run_command("ip", &["route", "flush", "table", &table_str]);`
- `crates/sb-adapters/src/inbound/tun/platform/linux.rs:421` `let _ = self.run_command("ip", &["-6", "route", "flush", "table", &table_str]);`
- `crates/sb-adapters/src/inbound/tun/platform/linux.rs:432` `let _ = Command::new(parts[0]).args(&parts[1..]).output();`
- `crates/sb-adapters/src/inbound/tun/platform/macos.rs:303` `let _ = Command::new("route").args(&args).output();`
- `crates/sb-adapters/src/inbound/tun/platform/macos.rs:313` `let _ = self.run_command("pfctl", &["-a", PF_ANCHOR_NAME, "-F", "all"]);`
- `crates/sb-adapters/src/inbound/tun/platform/macos.rs:316` `let _ = fs::remove_file(PF_RULES_FILE);`
- `crates/sb-adapters/src/inbound/tun/platform/macos.rs:320` `let _ = self.run_command("pfctl", &["-d"]);`
- `crates/sb-adapters/src/inbound/tun/platform/windows.rs:318` `let _ = Command::new("netsh").args(&args).output();`
- `crates/sb-adapters/src/inbound/tun/stack.rs:107` `let _ = self.tx.try_send(buffer);`
- `crates/sb-adapters/src/inbound/tun/stack.rs:159` `let _ = self`
- `crates/sb-adapters/src/inbound/tun_enhanced.rs:390` `let _ = device;`
- `crates/sb-adapters/src/inbound/tun_enhanced.rs:391` `let _ = rx;`
- `crates/sb-adapters/src/inbound/tun_enhanced.rs:392` `let _ = writer;`
- `crates/sb-adapters/src/inbound/tun_macos.rs:125` `let _ = tun_async.read(&mut buf);`
- `crates/sb-adapters/src/inbound/tun_macos.rs:143` `let _ = tx.send(());`
- `crates/sb-adapters/src/inbound/tun_macos.rs:150` `let _ = handle.join();`
- `crates/sb-adapters/src/inbound/tun_macos.rs:153` `let _ = self.socks_task.await;`
- `crates/sb-adapters/src/inbound/tun_macos.rs:732` `let _ = router`
- `crates/sb-adapters/src/inbound/tun_session.rs:137` `let _ = tx.send(());`
- `crates/sb-adapters/src/inbound/tun_session.rs:306` `let _ = outbound_write.shutdown().await;`
- `crates/sb-adapters/src/inbound/tun_session.rs:380` `let _ = tun_writer.write_packet(&fin_packet).await;`
- `crates/sb-adapters/src/inbound/vless.rs:345` `let _ = tokio::io::copy_bidirectional(stream, &mut remote).await;`
- `crates/sb-adapters/src/inbound/vless.rs:644` `let _ = tx.try_send(());`
- `crates/sb-adapters/src/inbound/vmess.rs:155` `let _ = stream.shutdown().await;`
- `crates/sb-adapters/src/inbound/vmess.rs:177` `let _ = tokio::io::copy_bidirectional(stream, &mut remote).await;`
- `crates/sb-adapters/src/inbound/vmess.rs:628` `let _ = tx.try_send(());`
- `crates/sb-adapters/src/outbound/anytls.rs:235` `let _ = local_write.shutdown().await;`
- `crates/sb-adapters/src/outbound/quic_util.rs:95` `let _ = roots.add(der);`
- `crates/sb-adapters/src/outbound/quic_util.rs:104` `let _ = roots.add(der);`
- `crates/sb-adapters/src/outbound/ssh.rs:168` `let _ = std::fs::create_dir_all(dir);`
- `crates/sb-adapters/src/outbound/ssh.rs:176` `let _ = f.write_all(format!("{} {}\n", host, fp).as_bytes());`
- `crates/sb-adapters/src/outbound/ssh.rs:191` `let _ = tx.send(data.to_vec()).await;`
- `crates/sb-adapters/src/outbound/ssh.rs:336` `let _ = ch_writer.data(&mut rd).await;`
- `crates/sb-adapters/src/outbound/ssh.rs:337` `let _ = ch_writer.eof().await;`
- `crates/sb-adapters/src/outbound/ssh.rs:346` `let _ = wr.shutdown().await;`
- `crates/sb-adapters/src/outbound/ssh.rs:348` `let _ = tokio::join!(a, b);`
- `crates/sb-adapters/src/outbound/tor.rs:101` `let _ = config_builder`
- `crates/sb-adapters/src/outbound/tor.rs:154` `let _ = self.get_client().await?;`
- `crates/sb-adapters/src/register.rs:272` `let _ = snapshot.register_outbound("http", build_http_outbound);`
- `crates/sb-adapters/src/register.rs:276` `let _ = snapshot.register_outbound("socks", build_socks_outbound);`
- `crates/sb-adapters/src/register.rs:277` `let _ = snapshot.register_outbound("socks4", build_socks4_outbound);`
- `crates/sb-adapters/src/register.rs:281` `let _ = snapshot.register_outbound("shadowsocks", build_shadowsocks_outbound);`
- `crates/sb-adapters/src/register.rs:282` `let _ = snapshot.register_outbound("shadowsocksr", build_shadowsocksr_outbound);`
- `crates/sb-adapters/src/register.rs:286` `let _ = snapshot.register_outbound("trojan", build_trojan_outbound);`
- `crates/sb-adapters/src/register.rs:290` `let _ = snapshot.register_outbound("vmess", build_vmess_outbound);`
- `crates/sb-adapters/src/register.rs:294` `let _ = snapshot.register_outbound("vless", build_vless_outbound);`
- `crates/sb-adapters/src/register.rs:297` `let _ = snapshot.register_outbound("direct", build_direct_outbound);`
- `crates/sb-adapters/src/register.rs:300` `let _ = snapshot.register_outbound("block", build_block_outbound);`
- `crates/sb-adapters/src/register.rs:303` `let _ = snapshot.register_outbound("dns", build_dns_outbound);`
- `crates/sb-adapters/src/register.rs:306` `let _ = snapshot.register_outbound("tor", build_tor_outbound);`
- `crates/sb-adapters/src/register.rs:309` `let _ = snapshot.register_outbound("anytls", build_anytls_outbound);`
- `crates/sb-adapters/src/register.rs:312` `let _ = snapshot.register_outbound("wireguard", build_wireguard_outbound);`
- `crates/sb-adapters/src/register.rs:315` `let _ = snapshot.register_outbound("tailscale", build_tailscale_outbound);`
- `crates/sb-adapters/src/register.rs:318` `let _ = snapshot.register_outbound("hysteria", build_hysteria_outbound);`
- `crates/sb-adapters/src/register.rs:321` `let _ = snapshot.register_outbound("tuic", build_tuic_outbound);`
- `crates/sb-adapters/src/register.rs:324` `let _ = snapshot.register_outbound("hysteria2", build_hysteria2_outbound);`
- `crates/sb-adapters/src/register.rs:327` `let _ = snapshot.register_outbound("ssh", build_ssh_outbound);`
- `crates/sb-adapters/src/register.rs:330` `let _ = snapshot.register_outbound("shadowtls", build_shadowtls_outbound);`
- `crates/sb-adapters/src/register.rs:334` `let _ = snapshot.register_outbound("selector", build_selector_outbound);`
- `crates/sb-adapters/src/register.rs:337` `let _ = snapshot.register_outbound("urltest", build_urltest_outbound);`
- `crates/sb-adapters/src/register.rs:342` `let _ = snapshot.register_inbound("http", build_http_inbound);`
- `crates/sb-adapters/src/register.rs:347` `let _ = snapshot.register_inbound("socks", build_socks_inbound);`
- `crates/sb-adapters/src/register.rs:357` `let _ = snapshot.register_inbound("mixed", build_mixed_inbound);`
- `crates/sb-adapters/src/register.rs:362` `let _ = snapshot.register_inbound("shadowsocks", build_shadowsocks_inbound);`
- `crates/sb-adapters/src/register.rs:367` `let _ = snapshot.register_inbound("vmess", build_vmess_inbound);`
- `crates/sb-adapters/src/register.rs:372` `let _ = snapshot.register_inbound("vless", build_vless_inbound);`
- `crates/sb-adapters/src/register.rs:376` `let _ = snapshot.register_inbound("trojan", build_trojan_inbound);`
- `crates/sb-adapters/src/register.rs:379` `let _ = snapshot.register_inbound("naive", build_naive_inbound);`
- `crates/sb-adapters/src/register.rs:382` `let _ = snapshot.register_inbound("shadowtls", build_shadowtls_inbound);`
- `crates/sb-adapters/src/register.rs:385` `let _ = snapshot.register_inbound("hysteria", build_hysteria_inbound);`
- `crates/sb-adapters/src/register.rs:388` `let _ = snapshot.register_inbound("hysteria2", build_hysteria2_inbound);`
- `crates/sb-adapters/src/register.rs:391` `let _ = snapshot.register_inbound("tuic", build_tuic_inbound);`
- `crates/sb-adapters/src/register.rs:394` `let _ = snapshot.register_inbound("anytls", build_anytls_inbound);`
- `crates/sb-adapters/src/register.rs:398` `let _ = snapshot.register_inbound("direct", build_direct_inbound);`
- `crates/sb-adapters/src/register.rs:403` `let _ = snapshot.register_inbound("tun", build_tun_inbound);`
- `crates/sb-adapters/src/register.rs:408` `let _ = snapshot.register_inbound("redirect", build_redirect_inbound);`
- `crates/sb-adapters/src/register.rs:409` `let _ = snapshot.register_inbound("tproxy", build_tproxy_inbound);`
- `crates/sb-adapters/src/register.rs:414` `let _ = snapshot.register_inbound("dns", build_dns_inbound);`
- `crates/sb-adapters/src/register.rs:419` `let _ = snapshot.register_inbound("ssh", build_ssh_inbound);`
- `crates/sb-adapters/src/register.rs:1772` `let _ = (param, ctx);`
- `crates/sb-adapters/src/register.rs:1901` `let _ = (param, ctx);`
- `crates/sb-adapters/src/register.rs:2173` `let _ = (param, ctx);`
- `crates/sb-adapters/src/register.rs:2308` `let _ = (param, ctx);`
- `crates/sb-adapters/src/register.rs:2746` `let _ = ir;`
- `crates/sb-adapters/src/register.rs:3587` `let _ = self`
- `crates/sb-adapters/src/register.rs:3599` `let _ = tx.try_send(());`
- `crates/sb-adapters/src/register.rs:3688` `let _ = self`
- `crates/sb-adapters/src/register.rs:3699` `let _ = tx.try_send(());`
- `crates/sb-adapters/src/register.rs:3758` `let _ = self`
- `crates/sb-adapters/src/register.rs:3769` `let _ = tx.try_send(());`
- `crates/sb-adapters/src/register.rs:3826` `let _ = self`
- `crates/sb-adapters/src/register.rs:3837` `let _ = tx.try_send(());`
- `crates/sb-adapters/src/service/resolved_impl.rs:143` `let _ = socket.send_to(&resp, peer).await;`
- `crates/sb-adapters/src/service_stubs.rs:51` `let _ = ctx;`
- `crates/sb-adapters/src/service_stubs.rs:75` `let _ = ctx;`
- `crates/sb-adapters/src/service_stubs.rs:97` `let _ = ctx;`
- `crates/sb-adapters/src/testsupport/mod.rs:47` `let _ = serve_udp_datagrams(s, None, None, None, conn_tracker).await;`
- `crates/sb-api/src/clash/server.rs:263` `let _ = shutdown.await;`
- `crates/sb-api/src/clash/server.rs:264` `let _ = shutdown_tx.send(true);`
- `crates/sb-api/src/clash/websocket.rs:98` `let _ = send_ws_message(`
- `crates/sb-api/src/clash/websocket.rs:157` `let _ = send_ws_message(`
- `crates/sb-api/src/clash/websocket.rs:364` `let _ = send_ws_message(`
- `crates/sb-api/src/clash/websocket.rs:475` `let _ = send_ws_message(`
- `crates/sb-api/src/monitoring/collector.rs:58` `let _ = &collector.total_connections;`
- `crates/sb-api/src/monitoring/collector.rs:83` `let _ = &bytes_transferred;`
- `crates/sb-api/src/monitoring/collector.rs:279` `let _ = self.connection_tx.send(connection.clone());`
- `crates/sb-api/src/v2ray/services.rs:427` `let _ = self.routing_broadcast.send(ctx);`
- `crates/sb-api/src/v2ray/services.rs:493` `let _ = self.log_broadcast.send(entry);`
- `crates/sb-api/src/v2ray/services.rs:521` `let _ = self.log_broadcast.send(restart_log);`
- `crates/sb-api/src/v2ray/services.rs:548` `let _ = self.log_broadcast.send(welcome_log);`
- `crates/sb-api/src/v2ray/simple.rs:104` `let _ = &self.monitoring;`
- `crates/sb-api/src/v2ray/simple.rs:143` `let _ = broadcast_clone.send(stat_update);`
- `crates/sb-api/src/v2ray/simple.rs:155` `let _ = &self.monitoring;`
- `crates/sb-api/src/v2ray/simple.rs:187` `let _ = broadcast_clone.send(stat_update);`
- `crates/sb-api/src/v2ray/simple.rs:278` `let _ = self.stats_broadcast.send(stat_update);`
- `crates/sb-common/src/interrupt.rs:40` `let _ = self.rx.recv().await;`
- `crates/sb-common/src/interrupt.rs:85` `let _ = self.tx.send(());`
- `crates/sb-common/src/pipelistener.rs:63` `let _ = path;`
- `crates/sb-config/src/lib.rs:553` `let _ = e;`
- `crates/sb-core/src/adapter/bridge.rs:62` `let _ = db.add_rule_set(rs.tag.clone(), path, &rs.format);`
- `crates/sb-core/src/admin/http.rs:345` `let _ = write_json(&mut cli, 429, &body);`
- `crates/sb-core/src/admin/http.rs:358` `let _ = write_json(&mut cli, 431, &body);`
- `crates/sb-core/src/admin/http.rs:361` `let _ = write_json(&mut cli, 408, &body);`
- `crates/sb-core/src/admin/http.rs:375` `let _ = write_json(&mut cli, 431, &body);`
- `crates/sb-core/src/admin/http.rs:512` `let _ = write_json(&mut cli, 400, &body);`
- `crates/sb-core/src/admin/http.rs:899` `let _ = s.set_nodelay(true);`
- `crates/sb-core/src/admin/http.rs:907` `let _ = write_json(&mut s, 429, &body);`
- `crates/sb-core/src/admin/http.rs:923` `let _ = handle(s, &eng, &brc, tok.as_deref(), sup.as_ref(), rth.as_ref());`
- `crates/sb-core/src/conntrack/inbound_tcp.rs:28` `let _ = self.tracker.unregister(self.id);`
- `crates/sb-core/src/diagnostics/http_server.rs:67` `let _ = tx.send(());`
- `crates/sb-core/src/diagnostics/http_server.rs:70` `let _ = handle.await;`
- `crates/sb-core/src/diagnostics/http_server.rs:237` `let _ = tx.send(());`
- `crates/sb-core/src/dns/cache_v2.rs:92` `let _ = clamp_dir;`
- `crates/sb-core/src/dns/cache_v2.rs:115` `let _ = clamp_dir;`
- `crates/sb-core/src/dns/client.rs:300` `let _ = sock.send_to(&req, upstream).await?;`
- `crates/sb-core/src/dns/client.rs:332` `let _ = sock.send_to(&req, upstream).await?;`
- `crates/sb-core/src/dns/client.rs:344` `let _ = sock.send_to(&req, upstream).await?;`
- `crates/sb-core/src/dns/mod.rs:544` `let _ = handle.resolve_via_pool_or_system(&key_spawn).await;`
- `crates/sb-core/src/dns/mod.rs:546` `let _ = s.remove(&key_spawn);`
- `crates/sb-core/src/dns/mod.rs:855` `let _ = sock.send_to(&req, sa).await?;`
- `crates/sb-core/src/dns/mod.rs:871` `let _ = sock.send_to(&req, sa).await?;`
- `crates/sb-core/src/dns/mod.rs:1054` `let _ = sa; // Suppress unused warning when feature is disabled`
- `crates/sb-core/src/dns/mod.rs:1167` `let _ = txc.send(res).await;`
- `crates/sb-core/src/dns/rule_engine.rs:788` `let _ = inject_edns0_client_subnet(&mut packet, subnet);`
- `crates/sb-core/src/dns/stub.rs:79` `let _ = GLOBAL.set(DnsCache::new(ttl_secs));`
- `crates/sb-core/src/dns/transport/doh3.rs:61` `let _ = roots.add(der);`
- `crates/sb-core/src/dns/transport/doh3.rs:68` `let _ = roots.add(der);`
- `crates/sb-core/src/dns/transport/doh3.rs:144` `let _ = futures::future::poll_fn(|cx| driver.poll_close(cx)).await;`
- `crates/sb-core/src/dns/transport/doq.rs:55` `let _ = roots.add(der);`
- `crates/sb-core/src/dns/transport/doq.rs:62` `let _ = roots.add(der);`
- `crates/sb-core/src/dns/transport/doq.rs:127` `let _ = send.finish();`
- `crates/sb-core/src/dns/transport/dot.rs:62` `let _ = roots.add(der);`
- `crates/sb-core/src/dns/transport/dot.rs:69` `let _ = roots.add(der);`
- `crates/sb-core/src/dns/transport/dot.rs:129` `let _ = socket.bind_device(Some(iface.as_bytes()));`
- `crates/sb-core/src/dns/transport/dot.rs:236` `let _ = packet; // Acknowledge parameter usage`
- `crates/sb-core/src/dns/transport/resolved.rs:499` `let _ = socket.bind_device(Some(servers.if_name.as_bytes()));`
- `crates/sb-core/src/dns/transport/resolved.rs:531` `let _ = servers;`
- `crates/sb-core/src/dns/transport/resolved.rs:570` `let _ = (addr, server_name, packet);`
- `crates/sb-core/src/dns/transport/udp.rs:180` `let _ = tx.send(buf);`
- `crates/sb-core/src/dns/transport/udp.rs:187` `let _ = tx.send(Vec::new());`
- `crates/sb-core/src/dns/transport/udp.rs:198` `let _ = tx.send(Vec::new());`
- `crates/sb-core/src/dns/transport/udp.rs:368` `let _ = tx.send(Vec::new());`
- `crates/sb-core/src/dns/upstream.rs:313` `let _ = (kind, upstream, result, members);`
- `crates/sb-core/src/dns/upstream.rs:327` `let _ = (kind, upstream, reason);`
- `crates/sb-core/src/dns/upstream.rs:343` `let _ = (kind, upstream, error);`
- `crates/sb-core/src/dns/upstream.rs:471` `let _ = inject_edns0_client_subnet(&mut packet, ecs.trim());`
- `crates/sb-core/src/dns/upstream.rs:666` `let _ = inject_edns0_client_subnet(&mut req, ecs.trim());`
- `crates/sb-core/src/dns/upstream.rs:825` `let _ = t_clone`
- `crates/sb-core/src/dns/upstream.rs:868` `let _ = self.reload_servers();`
- `crates/sb-core/src/dns/upstream.rs:1300` `let _ = self.reload_servers();`
- `crates/sb-core/src/dns/upstream.rs:1591` `let _ = (&self.server, &self.server_name, &self.timeout);`
- `crates/sb-core/src/dns/upstream.rs:1611` `let _ = (domain, record_type);`
- `crates/sb-core/src/dns/upstream.rs:1621` `let _ = inject_edns0_client_subnet(&mut req, ecs.trim());`
- `crates/sb-core/src/dns/upstream.rs:1643` `let _ = packet;`
- `crates/sb-core/src/dns/upstream.rs:1687` `let _ = roots.add(der);`
- `crates/sb-core/src/dns/upstream.rs:1694` `let _ = roots.add(der);`
- `crates/sb-core/src/dns/upstream.rs:1995` `let _ = (domain, record_type);`
- `crates/sb-core/src/dns/upstream.rs:2005` `let _ = inject_edns0_client_subnet(&mut req, ecs.trim());`
- `crates/sb-core/src/dns/upstream.rs:2027` `let _ = packet;`
- `crates/sb-core/src/dns/upstream.rs:2138` `let _ = (&self.url, &self.timeout);`
- `crates/sb-core/src/dns/upstream.rs:2145` `let _ = (domain, record_type);`
- `crates/sb-core/src/dns/upstream.rs:2155` `let _ = inject_edns0_client_subnet(&mut req, ecs.trim());`
- `crates/sb-core/src/dns/upstream.rs:2183` `let _ = packet;`
- `crates/sb-core/src/dns/upstream.rs:2343` `let _ = (&self.server, &self.server_name, &self.path, &self.timeout);`
- `crates/sb-core/src/dns/upstream.rs:2350` `let _ = (domain, record_type);`
- `crates/sb-core/src/dns/upstream.rs:2361` `let _ = inject_edns0_client_subnet(&mut req, ecs.trim());`
- `crates/sb-core/src/dns/upstream.rs:2369` `let _ = packet;`
- `crates/sb-core/src/dns/upstream.rs:2585` `let _ = upstream.refresh();`
- `crates/sb-core/src/dns/upstream.rs:2629` `let _ = self.refresh();`
- `crates/sb-core/src/dns/upstream.rs:2719` `let _ = (self.inet4_range.as_deref(), self.inet6_range.as_deref());`
- `crates/sb-core/src/endpoint/handler.rs:422` `let _ = tokio::join!(upload, download);`
- `crates/sb-core/src/endpoint/handler.rs:502` `let _ = tokio::join!(upload, download);`
- `crates/sb-core/src/endpoint/tailscale.rs:797` `let _ = tokio::runtime::Handle::try_current().map(|h| h.block_on(cp.stop()));`
- `crates/sb-core/src/geoip/mod.rs:88` `let _ = GEOIP_SERVICE.set(GeoIpService::new(Box::new(provider)));`
- `crates/sb-core/src/geoip/multi.rs:282` `let _ = tx_clone.send((idx, info, duration, provider_name));`
- `crates/sb-core/src/geoip/multi.rs:309` `let _ = handle.join();`
- `crates/sb-core/src/health/mod.rs:50` `let _ = t0; // 预留耗时：若需要可上报 histogram`
- `crates/sb-core/src/inbound/http_connect.rs:323` `let _ = cli`
- `crates/sb-core/src/inbound/http_connect.rs:330` `let _ = cli`
- `crates/sb-core/src/inbound/socks5.rs:449` `let _ = relay.send_to(&pkt, ep).await;`
- `crates/sb-core/src/inbound/socks5.rs:664` `let _ = upstream.write_all(&first_payload).await;`
- `crates/sb-core/src/inbound/tun.rs:511` `let _ = std::mem::replace(&mut self.stats, Arc::new(RwLock::new(stats)));`
- `crates/sb-core/src/inbound/tun.rs:565` `let _ = ip_addrs.push(IpCidr::new(`
- `crates/sb-core/src/inbound/tun.rs:691` `let _ = device.get_mut().write(&tx_packet);`
- `crates/sb-core/src/inbound/tun.rs:838` `let _ = wo.shutdown().await;`
- `crates/sb-core/src/inbound/tun.rs:903` `let _ = bridge.tx.try_send(data);`
- `crates/sb-core/src/inbound/tun.rs:1113` `let _ = bridge.tx.try_send(data.to_vec());`
- `crates/sb-core/src/inbound/tun.rs:1126` `let _ = socket.send_slice(&data, (client_ip, key.src.port()));`
- `crates/sb-core/src/log/mod.rs:124` `let _ = TARGET.set(target.to_string());`
- `crates/sb-core/src/log/mod.rs:156` `let _ = writeln!(stderr, "{out}");`
- `crates/sb-core/src/metrics/http_exporter.rs:18` `let _ = s.read(&mut buf); // 读请求（忽略）`
- `crates/sb-core/src/metrics/http_exporter.rs:65` `let _ = handle_conn_with_registry(s, &registry);`
- `crates/sb-core/src/metrics/mod.rs:46` `let _ = reg.register(Box::new(gv.clone()));`
- `crates/sb-core/src/metrics/registry_ext.rs:31` `let _ = reg().register(Box::new((*leaked).clone()));`
- `crates/sb-core/src/metrics/registry_ext.rs:36` `let _ = reg().register(Box::new((*leaked).clone()));`
- `crates/sb-core/src/metrics/registry_ext.rs:52` `let _ = reg().register(Box::new((*leaked).clone()));`
- `crates/sb-core/src/metrics/registry_ext.rs:57` `let _ = reg().register(Box::new((*leaked).clone()));`
- `crates/sb-core/src/metrics/registry_ext.rs:73` `let _ = reg().register(Box::new((*leaked).clone()));`
- `crates/sb-core/src/metrics/registry_ext.rs:78` `let _ = reg().register(Box::new((*leaked).clone()));`
- `crates/sb-core/src/metrics/registry_ext.rs:98` `let _ = reg().register(Box::new((*leaked).clone()));`
- `crates/sb-core/src/metrics/registry_ext.rs:132` `let _ = reg().register(Box::new((*leaked).clone()));`
- `crates/sb-core/src/metrics/registry_ext.rs:167` `let _ = reg().register(Box::new((*leaked).clone()));`
- `crates/sb-core/src/metrics/registry_ext.rs:184` `let _ = reg().register(Box::new((*leaked).clone()));`
- `crates/sb-core/src/metrics/registry_ext.rs:190` `let _ = reg().register(Box::new((*leaked).clone()));`
- `crates/sb-core/src/metrics/registry_ext.rs:265` `let _ = reg().register(Box::new((*leaked).clone()));`
- `crates/sb-core/src/metrics/udp.rs:68` `let _ = reg.register(Box::new(size_gauge.clone()));`
- `crates/sb-core/src/metrics/udp.rs:69` `let _ = reg.register(Box::new(heap_len.clone()));`
- `crates/sb-core/src/metrics/udp.rs:70` `let _ = reg.register(Box::new(gen_mismatch.clone()));`
- `crates/sb-core/src/metrics/udp.rs:71` `let _ = reg.register(Box::new(bytes_in.clone()));`
- `crates/sb-core/src/metrics/udp.rs:72` `let _ = reg.register(Box::new(bytes_out.clone()));`
- `crates/sb-core/src/metrics/udp.rs:73` `let _ = reg.register(Box::new(ttl_histogram.clone()));`
- `crates/sb-core/src/net/metered.rs:67` `let _ = packets;`
- `crates/sb-core/src/net/metered.rs:70` `let _ = packets;`
- `crates/sb-core/src/net/metered.rs:98` `let _ = copy_bidirectional_streaming(a, b, _label, Duration::from_secs(1)).await?;`
- `crates/sb-core/src/net/metered.rs:185` `let _ = (up.clone(), down.clone(), stop.clone(), interval_dur);`
- `crates/sb-core/src/net/metered.rs:235` `let _ = w.flush().await;`
- `crates/sb-core/src/net/metered.rs:236` `let _ = tokio::io::AsyncWriteExt::shutdown(&mut w).await;`
- `crates/sb-core/src/net/metered.rs:276` `let _ = w.flush().await;`
- `crates/sb-core/src/net/metered.rs:316` `let _ = ticker_handle.await;`
- `crates/sb-core/src/net/metered.rs:320` `let _ = ticker_handle.await;`
- `crates/sb-core/src/net/metered.rs:374` `let _ = self.label;`
- `crates/sb-core/src/net/metered.rs:396` `let _ = self.label;`
- `crates/sb-core/src/net/udp_nat.rs:394` `let _ = self.try_evict_inner(item, now, Some("capacity")).await;`
- `crates/sb-core/src/net/udp_nat_v2.rs:205` `let _ = self.try_evict_inner(item, now, Some("capacity")).await;`
- `crates/sb-core/src/outbound/direct_connector.rs:302` `let _ = s.set_tcp_fastopen_connect(true);`
- `crates/sb-core/src/outbound/direct_connector.rs:383` `let _ = s.set_tcp_fastopen_connect(true);`
- `crates/sb-core/src/outbound/health.rs:93` `let _ = STATES.get_or_init(DashMap::new);`
- `crates/sb-core/src/outbound/health.rs:102` `let _ = one_check(&st, &ep).await;`
- `crates/sb-core/src/outbound/health.rs:103` `let _ = one_check_ep("default", &ep).await;`
- `crates/sb-core/src/outbound/health.rs:109` `let _ = one_check_ep(&key, ep).await;`
- `crates/sb-core/src/outbound/health.rs:119` `let _ = label(ep.kind);`
- `crates/sb-core/src/outbound/health.rs:168` `let _ = label(ep.kind);`
- `crates/sb-core/src/outbound/hysteria/v1.rs:456` `let _ = send.write_all(&[0x01]).await;`
- `crates/sb-core/src/outbound/mod.rs:148` `let _ = sock.set_nodelay(true);`
- `crates/sb-core/src/outbound/mod.rs:150` `let _ = sock.set_keepalive(keepalive.is_some());`
- `crates/sb-core/src/outbound/mod.rs:157` `let _ = sref.set_keepalive(true);`
- `crates/sb-core/src/outbound/mod.rs:164` `let _ = sref.set_tcp_keepalive(&ka);`
- `crates/sb-core/src/outbound/naive_h2.rs:131` `let _ = connection.await;`
- `crates/sb-core/src/outbound/quic/common.rs:81` `let _ = roots.add(der);`
- `crates/sb-core/src/outbound/quic/common.rs:89` `let _ = roots.add(der);`
- `crates/sb-core/src/outbound/registry.rs:35` `let _ = GLOBAL.set(Arc::new(r));`
- `crates/sb-core/src/outbound/socks5_udp.rs:84` `let _ = tx.try_send((addr, payload.to_vec()));`
- `crates/sb-core/src/outbound/udp_proxy_glue.rs:73` `let _ = listen_dup.send_to(&reply, client).await;`
- `crates/sb-core/src/outbound/udp_proxy_glue.rs:123` `let _ = a.listen.send_to(&reply, a.client).await;`
- `crates/sb-core/src/outbound/udp_socks5.rs:51` `let _ = cached_udp_relay().set(relay);`
- `crates/sb-core/src/router/analyze_fix.rs:44` `let _ = writeln!(`
- `crates/sb-core/src/router/analyze_fix.rs:192` `let _ = writeln!(&mut patch_text, "# Fix: {}", suggestion);`
- `crates/sb-core/src/router/analyze_fix.rs:196` `let _ = writeln!(&mut patch_text, "-rule[{}]", rule_idx);`
- `crates/sb-core/src/router/analyze_fix.rs:200` `let _ = writeln!(&mut patch_text, "# Fix: {}", suggestion);`
- `crates/sb-core/src/router/analyze_fix.rs:204` `let _ = writeln!(`
- `crates/sb-core/src/router/analyze_fix.rs:212` `let _ = writeln!(&mut patch_text, "# Optimization: {}", suggestion);`
- `crates/sb-core/src/router/analyze_fix.rs:216` `let _ = writeln!(`
- `crates/sb-core/src/router/analyze_fix.rs:223` `let _ = writeln!(&mut patch_text, "# Style fix: {}", suggestion);`
- `crates/sb-core/src/router/analyze_fix.rs:234` `let _ = writeln!(&mut patch_text, "# Fix deprecated usage: {}", suggestion);`
- `crates/sb-core/src/router/analyze_fix.rs:238` `let _ = writeln!(&mut patch_text, "# Performance improvement: {}", suggestion);`
- `crates/sb-core/src/router/analyze_fix.rs:245` `let _ = writeln!(&mut patch_text, "# Reduce complexity by reorganizing rules");`
- `crates/sb-core/src/router/analyze_fix.rs:277` `let _ = writeln!(patch_text, "# Fix indentation");`
- `crates/sb-core/src/router/analyze_fix.rs:279` `let _ = writeln!(patch_text, "# Fix spacing");`
- `crates/sb-core/src/router/analyze_fix.rs:281` `let _ = writeln!(patch_text, "# Standardize quotes");`
- `crates/sb-core/src/router/analyze_fix.rs:288` `let _ = writeln!(patch_text, "# Update to new syntax");`
- `crates/sb-core/src/router/analyze_fix.rs:290` `let _ = writeln!(patch_text, "# Replace deprecated field");`
- `crates/sb-core/src/router/cache_hot.rs:35` `let _ = register_hot_provider(|limit| {`
- `crates/sb-core/src/router/cache_wire.rs:12` `let _ = src;`
- `crates/sb-core/src/router/cache_wire.rs:28` `let _ = SRC.set(src);`
- `crates/sb-core/src/router/cache_wire.rs:108` `let _ = g.put(Self::h(k), v);`
- `crates/sb-core/src/router/conn.rs:634` `let _ = remote_writer.shutdown().await;`
- `crates/sb-core/src/router/conn.rs:652` `let _ = local_writer.shutdown().await;`
- `crates/sb-core/src/router/conn.rs:954` `let _ = (network_type, fallback_network_type); // Reserved for future use`
- `crates/sb-core/src/router/engine.rs:661` `let _ = host_norm;`
- `crates/sb-core/src/router/engine.rs:682` `let _ = (host_norm, dec);`
- `crates/sb-core/src/router/engine.rs:736` `let _ = (host, timeout_ms);`
- `crates/sb-core/src/router/hot_reload.rs:140` `let _ = self.shutdown_tx.send(true);`
- `crates/sb-core/src/router/hot_reload.rs:200` `let _ = event_tx.send(HotReloadEvent::FileChanged { path });`
- `crates/sb-core/src/router/hot_reload.rs:256` `let _ = event_tx.send(HotReloadEvent::FileChanged { path: path.clone() });`
- `crates/sb-core/src/router/hot_reload.rs:370` `let _ = event_tx.send(HotReloadEvent::ValidationSucceeded {`
- `crates/sb-core/src/router/hot_reload.rs:382` `let _ = event_tx.send(HotReloadEvent::Applied {`
- `crates/sb-core/src/router/hot_reload.rs:395` `let _ = event_tx.send(HotReloadEvent::ValidationFailed {`
- `crates/sb-core/src/router/mod.rs:1115` `let _ = decision_intern::intern_decision(v);`
- `crates/sb-core/src/router/mod.rs:2081` `let _ = spawn_rules_hot_reload(shared.clone()).await;`
- `crates/sb-core/src/router/mod.rs:2424` `let _ = spawn_rules_hot_reload(s).await;`
- `crates/sb-core/src/router/mod.rs:2774` `let _ = write!(&mut s, "{:02x}", b);`
- `crates/sb-core/src/router/route_connection.rs:140` `let _ = ctx;`
- `crates/sb-core/src/router/rules.rs:1705` `let _ = krule; // keep label for metrics-disabled builds`
- `crates/sb-core/src/router/rules.rs:1804` `let _ = krule; // keep label for metrics-disabled builds`
- `crates/sb-core/src/router/rules.rs:2101` `let _ = GLOBAL_RULES.set(Arc::new(engine));`
- `crates/sb-core/src/runtime/mod.rs:111` `let _ = i.serve();`
- `crates/sb-core/src/runtime/mod.rs:134` `let _ = self;`
- `crates/sb-core/src/runtime/supervisor.rs:522` `let _ = &new_ir; // mark as used in minimal path`
- `crates/sb-core/src/runtime/supervisor.rs:989` `let _ = &self.cancel;`
- `crates/sb-core/src/runtime/supervisor.rs:1003` `let _ = &self.cancel;`
- `crates/sb-core/src/runtime/supervisor.rs:1021` `let _ = &new_ir;`
- `crates/sb-core/src/runtime/supervisor.rs:1028` `let _ = &self.cancel;`
- `crates/sb-core/src/runtime/transport.rs:416` `let _ = roots.add(der);`
- `crates/sb-core/src/runtime/transport.rs:424` `let _ = roots.add(der);`
- `crates/sb-core/src/services/cache_file.rs:111` `let _ = handle.join();`
- `crates/sb-core/src/services/cache_file.rs:173` `let _ = tree.insert("next_v4", &metadata.inet4_current_u32.to_be_bytes());`
- `crates/sb-core/src/services/cache_file.rs:174` `let _ = tree.insert("next_v6", &metadata.inet6_current_u128.to_be_bytes());`
- `crates/sb-core/src/services/cache_file.rs:218` `let _ = std::fs::create_dir_all(parent);`
- `crates/sb-core/src/services/cache_file.rs:312` `let _ = db.open_tree("fakeip_domain").and_then(|t| {`
- `crates/sb-core/src/services/cache_file.rs:316` `let _ = db.open_tree("fakeip_ip").and_then(|t| {`
- `crates/sb-core/src/services/cache_file.rs:379` `let _ = tree.insert("next_v4", &next_v4.to_be_bytes());`
- `crates/sb-core/src/services/cache_file.rs:380` `let _ = tree.insert("next_v6", &next_v6.to_be_bytes());`
- `crates/sb-core/src/services/cache_file.rs:457` `let _ = tree.insert(domain, val);`
- `crates/sb-core/src/services/cache_file.rs:548` `let _ = tree.insert(key.as_bytes(), val);`
- `crates/sb-core/src/services/cache_file.rs:567` `let _ = tree.insert("clash_mode", mode.as_bytes());`
- `crates/sb-core/src/services/cache_file.rs:605` `let _ = tree.insert(group, selected.as_bytes());`
- `crates/sb-core/src/services/cache_file.rs:648` `let _ = tree.insert(group, &[if expand { 1 } else { 0 }]);`
- `crates/sb-core/src/services/cache_file.rs:687` `let _ = tree.insert(tag, content);`
- `crates/sb-core/src/services/cache_file.rs:714` `let _ = db.flush();`
- `crates/sb-core/src/services/cache_file.rs:793` `let _ = tree.insert("next_v4", &metadata.inet4_current_u32.to_be_bytes());`
- `crates/sb-core/src/services/cache_file.rs:794` `let _ = tree.insert("next_v6", &metadata.inet6_current_u128.to_be_bytes());`
- `crates/sb-core/src/services/cache_file.rs:813` `let _ = tree.clear();`
- `crates/sb-core/src/services/cache_file.rs:816` `let _ = tree.clear();`
- `crates/sb-core/src/services/cache_file.rs:819` `let _ = tree.clear();`
- `crates/sb-core/src/services/derp/server.rs:1201` `let _ = (&self.bind_interface, self.routing_mark, self.tcp_fast_open);`
- `crates/sb-core/src/services/derp/server.rs:1579` `let _ = stream`
- `crates/sb-core/src/services/derp/server.rs:1582` `let _ = stream.shutdown().await;`
- `crates/sb-core/src/services/derp/server.rs:1608` `let _ = prefixed_stream`
- `crates/sb-core/src/services/derp/server.rs:1611` `let _ = prefixed_stream.shutdown().await;`
- `crates/sb-core/src/services/derp/server.rs:2039` `let _ = netns;`
- `crates/sb-core/src/services/derp/server.rs:2758` `let _ = derp.flush().await;`
- `crates/sb-core/src/services/derp/server.rs:2826` `let _ = tx_for_read.send(DerpFrame::Pong { data });`
- `crates/sb-core/src/services/derp/server.rs:2861` `let _ = tokio::io::copy_bidirectional(&mut stream, &mut other).await;`
- `crates/sb-core/src/services/derp/server.rs:2876` `let _ = stale_stream.shutdown().await;`
- `crates/sb-core/src/services/ssmapi/server.rs:502` `let _ = std::fs::remove_file(path);`
- `crates/sb-core/src/services/ssmapi/server.rs:578` `let _ = ctx.user_manager.set_users(users_map);`
- `crates/sb-core/src/services/ssmapi/server.rs:967` `let _ = shutdown_rx.await;`
- `crates/sb-core/src/services/ssmapi/server.rs:975` `let _ = l.set_nonblocking(true); // axum_server expects this IIRC or handles it`
- `crates/sb-core/src/services/ssmapi/server.rs:1012` `let _ = shutdown_rx.await;`
- `crates/sb-core/src/services/ssmapi/server.rs:1059` `let _ = tx.send(());`
- `crates/sb-core/src/services/tailscale/coordinator.rs:239` `let _ = server`
- `crates/sb-core/src/services/tailscale/coordinator.rs:250` `let _ = client`
- `crates/sb-core/src/services/tailscale/coordinator.rs:278` `let _ = self.netmap_tx.send(Some(mock_map));`
- `crates/sb-core/src/services/v2ray_api.rs:426` `let _ = shutdown_rx.await;`
- `crates/sb-core/src/services/v2ray_api.rs:451` `let _ = tx.send(());`
- `crates/sb-core/src/telemetry.rs:182` `let _ = kind; // 值不再作为标签输出，避免高基数`
- `crates/sb-core/src/telemetry/dial.rs:39` `let _ = (kind, phase, t0);`
- `crates/sb-core/src/telemetry/dial.rs:55` `let _ = (kind, phase, t0, class);`
- `crates/sb-core/src/util/failpoint.rs:16` `let _ = FP_CFG.set(cfg);`
- `crates/sb-core/src/util/fs_atomic.rs:39` `let _ = unsafe { libc::fsync(f.as_raw_fd()) };`
- `crates/sb-core/src/util/fs_atomic.rs:53` `let _ = fs::remove_file(path);`
- `crates/sb-core/src/util/fs_atomic.rs:58` `let _ = fs::remove_file(&tmp);`
- `crates/sb-metrics/src/lib.rs:341` `let _ = shared_registry().register_cloned(metric, collector);`
- `crates/sb-platform/src/system_proxy.rs:260` `let _ = update_macos_proxy(&iface.name, port, support_socks);`
- `crates/sb-platform/src/system_proxy.rs:394` `let _ = Command::new("gsettings")`
- `crates/sb-platform/src/system_proxy.rs:397` `let _ = Command::new("gsettings")`
- `crates/sb-platform/src/system_proxy.rs:400` `let _ = Command::new("gsettings")`
- `crates/sb-platform/src/system_proxy.rs:403` `let _ = Command::new("gsettings")`
- `crates/sb-platform/src/system_proxy.rs:407` `let _ = Command::new("gsettings")`
- `crates/sb-platform/src/system_proxy.rs:410` `let _ = Command::new("gsettings")`
- `crates/sb-platform/src/system_proxy.rs:413` `let _ = Command::new("gsettings")`
- `crates/sb-platform/src/system_proxy.rs:417` `let _ = Command::new("gsettings")`
- `crates/sb-platform/src/system_proxy.rs:428` `let _ = Command::new(&kcmd)`
- `crates/sb-platform/src/system_proxy.rs:439` `let _ = Command::new("dbus-send")`
- `crates/sb-platform/src/system_proxy.rs:463` `let _ = Command::new("gsettings")`
- `crates/sb-platform/src/system_proxy.rs:469` `let _ = Command::new(&kcmd)`
- `crates/sb-platform/src/system_proxy.rs:480` `let _ = Command::new("dbus-send")`
- `crates/sb-platform/src/system_proxy.rs:555` `let _ = InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0);`
- `crates/sb-platform/src/system_proxy.rs:556` `let _ = InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0);`
- `crates/sb-platform/src/system_proxy.rs:617` `let _ = Command::new("networksetup")`
- `crates/sb-platform/src/system_proxy.rs:621` `let _ = Command::new("networksetup")`
- `crates/sb-platform/src/system_proxy.rs:624` `let _ = Command::new("networksetup")`
- `crates/sb-platform/src/system_proxy.rs:642` `let _ = Command::new("networksetup")`
- `crates/sb-platform/src/system_proxy.rs:646` `let _ = Command::new("networksetup")`
- `crates/sb-platform/src/system_proxy.rs:649` `let _ = Command::new("networksetup")`
- `crates/sb-platform/src/system_proxy.rs:687` `let _ = Command::new(cmd)`
- `crates/sb-platform/src/tun/linux.rs:308` `let _ = self.close();`
- `crates/sb-platform/src/tun/macos.rs:382` `let _ = self.close();`
- `crates/sb-platform/src/tun/windows.rs:284` `let _ = self.close();`
- `crates/sb-subscribe/src/convert_full.rs:52` `let _ = s; // Silence unused variable warning`
- `crates/sb-subscribe/src/convert_full.rs:94` `let _ = (input, use_keyword); // Silence unused warnings`
- `crates/sb-subscribe/src/convert_full.rs:106` `let _ = (input, use_keyword); // Silence unused warnings`
- `crates/sb-subscribe/src/convert_full.rs:123` `let _ = prof; // Silence unused warning`
- `crates/sb-subscribe/src/convert_full.rs:137` `let _ = prof; // Silence unused warning`
- `crates/sb-subscribe/src/lint.rs:165` `let _ = v; // unused`
- `crates/sb-test-utils/src/socks5.rs:176` `let _ = udp.send_to(&out, from).await;`
- `crates/sb-tls/src/acme.rs:557` `let _ = challenger.remove_record(&fqdn).await;`
- `crates/sb-tls/src/acme.rs:688` `let _ = tx.send(());`
- `crates/sb-tls/src/ech_keygen.rs:123` `let _ = writeln!(&mut pem, "-----END {label}-----");`
- `crates/sb-tls/src/global.rs:71` `let _ = roots.add(cert);`
- `crates/sb-tls/src/global.rs:114` `let _ = roots.add(der);`
- `crates/sb-tls/src/global.rs:130` `let _ = roots.add(der);`
- `crates/sb-tls/src/lib.rs:41` `let _ = rustls::crypto::ring::default_provider().install_default();`
- `crates/sb-transport/src/dialer.rs:505` `let _ = socket.set_tcp_fastopen_connect(true);`
- `crates/sb-transport/src/dialer.rs:583` `let _ = setns(self.0.as_raw_fd(), 0);`
- `crates/sb-transport/src/dialer.rs:601` `let _ = socket.set_reuse_address(true);`
- `crates/sb-transport/src/dialer.rs:603` `let _ = socket.set_reuse_port(true);`
- `crates/sb-transport/src/dialer.rs:609` `let _ = socket.bind(&sa.into());`
- `crates/sb-transport/src/dialer.rs:613` `let _ = socket.bind(&sa.into());`
- `crates/sb-transport/src/dialer.rs:617` `let _ = socket.bind_device(Some(iface.as_bytes()));`
- `crates/sb-transport/src/dialer.rs:620` `let _ = socket.set_mark(mark);`
- `crates/sb-transport/src/http2.rs:317` `let _ = self.recv_stream.flow_control().release_capacity(data.len());`
- `crates/sb-transport/src/http2.rs:555` `let _ = respond.send_response(resp, true);`
- `crates/sb-transport/src/multiplex.rs:363` `let _ = tx.send(Ok(stream));`
- `crates/sb-transport/src/multiplex.rs:366` `let _ = tx.send(Err(DialError::Other(e.to_string())));`
- `crates/sb-transport/src/multiplex.rs:384` `let _ = tx.send(Ok(stream));`
- `crates/sb-transport/src/multiplex.rs:387` `let _ = tx.send(Err(DialError::Other(e.to_string())));`
- `crates/sb-transport/src/simple_obfs.rs:225` `let _ = self.read_buffer.split_to(pos + 4);`
- `crates/sb-transport/src/simple_obfs.rs:244` `let _ = self.read_buffer.split_to(5 + record_len);`
- `crates/sb-transport/src/simple_obfs.rs:335` `let _ = this.write_buffer.split_to(n);`
- `crates/sb-transport/src/sip003.rs:223` `let _ = child.start_kill();`
- `crates/sb-transport/src/tls.rs:33` `let _ = rustls::crypto::ring::default_provider().install_default();`
- `crates/sb-transport/src/trojan.rs:390` `let _ = buf.split_to(payload_offset);`
- `crates/sb-transport/src/wireguard.rs:247` `let _ = self.inner.socket.send_to(response, endpoint).await;`
- `crates/sb-transport/src/wireguard.rs:345` `let _ = transport.socket.send_to(response, endpoint).await;`

### anyhow_pub_fn (42)
- 判定：确定命中
- 对应层：Layer 3

- `app/src/admin_debug/endpoints/subs.rs:426` `pub async fn fetch_with_limits(url: &str) -> anyhow::Result<String> {`
- `app/src/cli/fs_scan.rs:94` `pub fn run(&self) -> anyhow::Result<FsReport> {`
- `app/src/cli/prefetch/mod.rs:113` `pub fn main(a: PrefetchArgs) -> anyhow::Result<()> {`
- `app/src/cli/prefetch/mod.rs:148` `pub fn main(_a: PrefetchArgs) -> anyhow::Result<()> {`
- `app/src/cli/report.rs:40` `pub fn main(args: Args) -> anyhow::Result<()> {`
- `crates/sb-adapters/src/inbound/socks/mod.rs:1107` `pub async fn run(&self) -> anyhow::Result<()> {`
- `crates/sb-adapters/src/inbound/ssh.rs:383` `pub async fn get_server_key(&self) -> Result<ssh_key::PrivateKey, anyhow::Error> {`
- `crates/sb-adapters/src/outbound/quic_util.rs:82` `pub async fn quic_connect(cfg: &QuicConfig) -> anyhow::Result<quinn::Connection> {`
- `crates/sb-config/src/json_norm.rs:59` `pub fn normalize_file_to_string(path: impl AsRef<Path>) -> anyhow::Result<String> {`
- `crates/sb-core/src/adapter/mod.rs:501` `pub fn new_from_config(ir: &sb_config::ir::ConfigIR, context: Context) -> anyhow::Result<Self> {`
- `crates/sb-core/src/dns/client.rs:101` `pub async fn resolve(&self, host: &str, default_port: u16) -> anyhow::Result<Vec<SocketAddr>> {`
- `crates/sb-core/src/geoip/mmdb.rs:22` `pub fn new() -> anyhow::Result<Self> {`
- `crates/sb-core/src/geoip/mmdb.rs:159` `pub fn new() -> anyhow::Result<Self> {`
- `crates/sb-core/src/geoip/mmdb.rs:318` `pub fn new() -> anyhow::Result<Self> {`
- `crates/sb-core/src/geoip/mod.rs:86` `pub fn init() -> anyhow::Result<()> {`
- `crates/sb-core/src/geoip/multi.rs:52` `pub fn from_env() -> anyhow::Result<Self> {`
- `crates/sb-core/src/inbound/socks5.rs:851` `pub async fn greet_noauth(stream: &mut AsyncTcpStream) -> anyhow::Result<()> {`
- `crates/sb-core/src/inbound/socks5.rs:950` `pub fn decode_udp_reply(packet: &[u8]) -> anyhow::Result<(SocketAddr, Vec<u8>)> {`
- `crates/sb-core/src/outbound/hysteria/v1.rs:93` `pub fn new(config: HysteriaV1Config) -> anyhow::Result<Self> {`
- `crates/sb-core/src/outbound/hysteria2.rs:156` `pub fn new(config: Hysteria2Config) -> anyhow::Result<Self> {`
- `crates/sb-core/src/outbound/naive_h2.rs:39` `pub fn new(config: NaiveH2Config) -> anyhow::Result<Self> {`
- `crates/sb-core/src/outbound/quic/common.rs:70` `pub async fn connect(cfg: &QuicConfig) -> anyhow::Result<Connection> {`
- `crates/sb-core/src/outbound/tcp.rs:6` `pub async fn connect_direct(authority: &str) -> anyhow::Result<TcpStream> {`
- `crates/sb-core/src/outbound/tcp.rs:17` `pub async fn connect_via_http_proxy(authority: &str) -> anyhow::Result<TcpStream> {`
- `crates/sb-core/src/outbound/tcp.rs:54` `pub async fn connect_auto(authority: &str, decision: &str) -> anyhow::Result<TcpStream> {`
- `crates/sb-core/src/outbound/udp_proxy_glue.rs:44` `pub async fn ensure_client_assoc(listen: Arc<UdpSocket>, client: SocketAddr) -> anyhow::Result<()> {`
- `crates/sb-core/src/outbound/udp_socks5.rs:26` `pub async fn create_upstream_socket() -> anyhow::Result<UdpSocket> {`
- `crates/sb-core/src/outbound/udp_socks5.rs:35` `pub async fn ensure_udp_relay() -> anyhow::Result<SocketAddr> {`
- `crates/sb-core/src/outbound/udp_socks5.rs:58` `pub async fn ensure_udp_relay_at(proxy: SocketAddr) -> anyhow::Result<SocketAddr> {`
- `crates/sb-core/src/outbound/udp_socks5.rs:173` `pub async fn recv_from_via_socks5(sock: &UdpSocket) -> anyhow::Result<(SocketAddr, Vec<u8>)> {`
- `crates/sb-core/src/pipeline.rs:35` `pub async fn run(self) -> anyhow::Result<()> {`
- `crates/sb-core/src/router/geo.rs:64` `pub fn export_country(&self, _country: &str) -> anyhow::Result<Vec<String>> {`
- `crates/sb-core/src/router/geo.rs:376` `pub fn category_rules(&self, category: &str) -> anyhow::Result<CategoryRules> {`
- `crates/sb-core/src/router/matcher.rs:177` `pub fn load<I>(&mut self, cidrs: I) -> anyhow::Result<()>`
- `crates/sb-core/src/router/ruleset/adguard.rs:39` `pub fn parse_adguard_rules(input: &str) -> anyhow::Result<Vec<serde_json::Value>> {`
- `crates/sb-core/src/routing/explain.rs:61` `pub fn from_config(cfg: &sb_config::Config) -> anyhow::Result<ExplainEngine> {`
- `crates/sb-core/src/runtime/mod.rs:143` `pub fn engine(&self) -> Result<(), anyhow::Error> {`
- `crates/sb-core/src/runtime/mod.rs:175` `pub fn dummy_engine() -> Result<(), anyhow::Error> {`
- `crates/sb-core/src/socks5/mod.rs:8` `pub async fn greet_noauth(stream: &mut TcpStream) -> anyhow::Result<()> {`
- `crates/sb-core/src/socks5/mod.rs:20` `pub async fn udp_associate(stream: &mut TcpStream, bind: SocketAddr) -> anyhow::Result<SocketAddr> {`
- `crates/sb-core/src/socks5/mod.rs:117` `pub fn decode_udp_reply(buf: &[u8]) -> anyhow::Result<(SocketAddr, &[u8])> {`
- `crates/sb-test-utils/src/socks5.rs:89` `pub async fn start_mock_socks5() -> anyhow::Result<(SocketAddr, SocketAddr)> {`

### spawn_unhandled (152)
- 判定：高风险静态命中
- 对应层：Layer 3

- `app/src/admin_debug/http_server.rs:648` `tokio::spawn(async move {`
- `app/src/admin_debug/http_server.rs:791` `tokio::spawn(async move {`
- `app/src/admin_debug/http_server.rs:851` `tokio::spawn(async move {`
- `app/src/admin_debug/http_server.rs:1017` `tokio::spawn(async move {`
- `app/src/admin_debug/mod.rs:93` `tokio::spawn(async move {`
- `app/src/admin_debug/prefetch.rs:96` `tokio::spawn(worker_loop(id, rx_clone));`
- `app/src/admin_debug/reloadable.rs:490` `tokio::spawn(async {`
- `app/src/cli/auth.rs:336` `tokio::spawn(async move {`
- `app/src/logging.rs:455` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/anytls.rs:172` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/anytls.rs:219` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/anytls.rs:224` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/anytls.rs:233` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/anytls.rs:240` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/dns.rs:206` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/dns.rs:528` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/http.rs:295` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/http.rs:349` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/hysteria2.rs:165` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/mixed.rs:120` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/naive.rs:114` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/naive.rs:170` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/redirect.rs:62` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/shadowsocks.rs:590` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/shadowsocks.rs:833` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/shadowsocks.rs:885` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/shadowsocks.rs:978` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/shadowsocks.rs:1031` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/shadowsocks.rs:1083` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/shadowtls.rs:119` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/shadowtls.rs:840` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/shadowtls.rs:1028` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/socks/mod.rs:137` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/socks/mod.rs:185` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/socks/mod.rs:1136` `tokio::spawn({`
- `crates/sb-adapters/src/inbound/socks/mod.rs:1166` `tokio::spawn({`
- `crates/sb-adapters/src/inbound/socks/mod.rs:1185` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/socks/tcp.rs:28` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/socks/udp.rs:760` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/socks/udp.rs:865` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/socks/udp.rs:1040` `tokio::spawn(run_nat_evictor(rt.map.clone(), rt.ttl, rt.scan));`
- `crates/sb-adapters/src/inbound/socks/udp.rs:1072` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/socks/udp.rs:1094` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/socks/udp.rs:1107` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/socks/udp.rs:1473` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/socks/udp_enhanced.rs:205` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/socks/udp_enhanced.rs:412` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/ssh.rs:288` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/ssh.rs:320` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/ssh.rs:452` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/ssh.rs:509` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/tproxy.rs:89` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/trojan.rs:261` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/trojan.rs:297` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/tuic.rs:205` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/tuic.rs:251` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/tun/udp.rs:141` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/tun/udp.rs:169` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/tun_macos.rs:182` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/tun_macos.rs:479` `tokio::spawn(manager.clone().inbound_loop());`
- `crates/sb-adapters/src/inbound/tun_macos.rs:495` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/tun_macos.rs:754` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/tun_session.rs:209` `tokio::spawn(relay_tun_to_outbound(`
- `crates/sb-adapters/src/inbound/tun_session.rs:275` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/vless.rs:203` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/vless.rs:232` `tokio::spawn(async move {`
- `crates/sb-adapters/src/inbound/vmess.rs:146` `tokio::spawn(async move {`
- `crates/sb-adapters/src/outbound/anytls.rs:63` `tokio::spawn(async move {`
- `crates/sb-adapters/src/outbound/anytls.rs:70` `tokio::spawn(async move {`
- `crates/sb-adapters/src/outbound/anytls.rs:224` `tokio::spawn(async move {`
- `crates/sb-adapters/src/outbound/anytls.rs:246` `tokio::spawn(async move {`
- `crates/sb-adapters/src/outbound/shadowtls.rs:641` `tokio::spawn(async move {`
- `crates/sb-adapters/src/outbound/shadowtls.rs:808` `tokio::spawn(async move {`
- `crates/sb-adapters/src/outbound/ssh.rs:327` `tokio::spawn(async move {`
- `crates/sb-adapters/src/outbound/tailscale.rs:263` `tokio::spawn(async move {`
- `crates/sb-adapters/src/outbound/tailscale.rs:270` `tokio::spawn(async move {`
- `crates/sb-adapters/src/outbound/wireguard.rs:107` `tokio::spawn(async move {`
- `crates/sb-adapters/src/service/resolved_impl.rs:125` `tokio::spawn(async move {`
- `crates/sb-adapters/src/service/resolved_impl.rs:230` `tokio::spawn(Self::handle_tcp_conn(stream, peer, inbound, dns_router));`
- `crates/sb-adapters/src/testsupport/mod.rs:46` `tokio::spawn(async move {`
- `crates/sb-api/src/monitoring/collector.rs:334` `tokio::spawn(async move {`
- `crates/sb-api/src/monitoring/reporter.rs:143` `tokio::spawn(async move {`
- `crates/sb-api/src/monitoring/reporter.rs:210` `tokio::spawn(async move {`
- `crates/sb-api/src/monitoring/reporter.rs:246` `tokio::spawn(async move {`
- `crates/sb-api/src/monitoring/reporter.rs:276` `tokio::spawn(async move {`
- `crates/sb-core/src/diagnostics/http_server.rs:85` `tokio::spawn(Self::handle_connection(stream, peer));`
- `crates/sb-core/src/dns/cache.rs:469` `tokio::spawn(async move {`
- `crates/sb-core/src/dns/mod.rs:542` `tokio::spawn(async move {`
- `crates/sb-core/src/dns/mod.rs:1162` `tokio::spawn(async move {`
- `crates/sb-core/src/dns/transport/dhcp.rs:570` `tokio::spawn(cloned.run_background());`
- `crates/sb-core/src/dns/transport/doh3.rs:143` `tokio::spawn(async move {`
- `crates/sb-core/src/dns/transport/udp.rs:162` `tokio::spawn(async move {`
- `crates/sb-core/src/dns/upstream.rs:824` `tokio::spawn(async move {`
- `crates/sb-core/src/health/mod.rs:40` `tokio::spawn(async move {`
- `crates/sb-core/src/inbound/direct.rs:179` `tokio::spawn(async move {`
- `crates/sb-core/src/inbound/direct.rs:327` `tokio::spawn(async move {`
- `crates/sb-core/src/inbound/http.rs:312` `tokio::spawn(async move {`
- `crates/sb-core/src/inbound/http_connect.rs:475` `tokio::spawn(async move {`
- `crates/sb-core/src/inbound/mixed.rs:126` `tokio::spawn(async move {`
- `crates/sb-core/src/inbound/socks5.rs:140` `tokio::spawn(async move {`
- `crates/sb-core/src/inbound/socks5.rs:355` `tokio::spawn(async move {`
- `crates/sb-core/src/inbound/socks5.rs:782` `tokio::spawn(async move {`
- `crates/sb-core/src/inbound/tun.rs:724` `tokio::spawn(async move {`
- `crates/sb-core/src/inbound/tun.rs:957` `tokio::spawn(async move {`
- `crates/sb-core/src/metrics/mod.rs:61` `tokio::spawn(async move {`
- `crates/sb-core/src/net/metered.rs:151` `tokio::spawn(async move {`
- `crates/sb-core/src/net/metered.rs:187` `tokio::spawn(async {})`
- `crates/sb-core/src/net/udp_processor.rs:165` `tokio::spawn(async move {`
- `crates/sb-core/src/outbound/health.rs:96` `tokio::spawn(async move {`
- `crates/sb-core/src/outbound/hysteria2.rs:608` `tokio::spawn(async move { listener.accept().await.map(|(stream, _)| stream) });`
- `crates/sb-core/src/outbound/hysteria2.rs:615` `tokio::spawn(async move {`
- `crates/sb-core/src/outbound/naive_h2.rs:130` `tokio::spawn(async move {`
- `crates/sb-core/src/outbound/selector_group.rs:407` `tokio::spawn(async move {`
- `crates/sb-core/src/outbound/selector_group.rs:434` `tokio::spawn(async move {`
- `crates/sb-core/src/router/hot_reload.rs:244` `tokio::spawn(async move {`
- `crates/sb-core/src/router/hot_reload.rs:287` `tokio::spawn(async move {`
- `crates/sb-core/src/router/hot_reload_cli.rs:78` `tokio::spawn(async move {`
- `crates/sb-core/src/router/mod.rs:1822` `tokio::spawn(async move {`
- `crates/sb-core/src/router/mod.rs:2423` `tokio::spawn(async move {`
- `crates/sb-core/src/router/ruleset/mod.rs:476` `tokio::spawn(async move {`
- `crates/sb-core/src/runtime/supervisor.rs:1081` `tokio::spawn(async move {`
- `crates/sb-core/src/services/derp/server.rs:728` `tokio::spawn(async move {`
- `crates/sb-core/src/services/derp/server.rs:797` `tokio::spawn(async move {`
- `crates/sb-core/src/services/derp/server.rs:869` `tokio::spawn(async move {`
- `crates/sb-core/src/services/derp/server.rs:1383` `tokio::spawn(async move {`
- `crates/sb-core/src/services/derp/server.rs:1799` `tokio::spawn(async move {`
- `crates/sb-core/src/services/derp/server.rs:2869` `tokio::spawn(async move {`
- `crates/sb-core/src/services/dns_forwarder.rs:67` `tokio::spawn(async move {`
- `crates/sb-core/src/services/dns_forwarder.rs:212` `tokio::spawn(async move {`
- `crates/sb-core/src/services/ssmapi/server.rs:920` `tokio::spawn(async move {`
- `crates/sb-core/src/services/ssmapi/server.rs:966` `tokio::spawn(async move {`
- `crates/sb-core/src/services/v2ray_api.rs:403` `tokio::spawn(async move {`
- `crates/sb-core/src/services/v2ray_api.rs:422` `tokio::spawn(async move {`
- `crates/sb-metrics/src/lib.rs:1021` `tokio::spawn(async move {`
- `crates/sb-metrics/src/lib.rs:1040` `tokio::spawn(async move {`
- `crates/sb-platform/src/monitor.rs:192` `tokio::spawn(connection);`
- `crates/sb-runtime/src/tcp_local.rs:132` `tokio::spawn(async move {`
- `crates/sb-test-utils/src/socks5.rs:112` `tokio::spawn(async move {`
- `crates/sb-test-utils/src/socks5.rs:186` `tokio::spawn(async move {`
- `crates/sb-test-utils/src/socks5.rs:193` `tokio::spawn(async move {`
- `crates/sb-tls/src/acme.rs:649` `tokio::spawn(async move {`
- `crates/sb-transport/src/grpc.rs:254` `tokio::spawn(async move {`
- `crates/sb-transport/src/grpc.rs:446` `tokio::spawn(async move {`
- `crates/sb-transport/src/grpc.rs:530` `tokio::spawn(async move {`
- `crates/sb-transport/src/grpc.rs:549` `tokio::spawn(async move {`
- `crates/sb-transport/src/http2.rs:187` `tokio::spawn(async move {`
- `crates/sb-transport/src/http2.rs:546` `tokio::spawn(async move {`
- `crates/sb-transport/src/multiplex.rs:233` `tokio::spawn(async move {`
- `crates/sb-transport/src/multiplex.rs:337` `tokio::spawn(async move {`
- `crates/sb-transport/src/multiplex.rs:589` `tokio::spawn(async move {`
- `crates/sb-transport/src/multiplex.rs:604` `tokio::spawn(async move {`
- `crates/sb-transport/src/wireguard.rs:178` `tokio::spawn(async move {`

### lock_cross_await (127)
- 判定：高风险静态命中
- 对应层：Layer 3

- `app/src/admin_debug/prefetch.rs:169` `let mut guard = rx.lock().await;`
- `crates/sb-adapters/src/inbound/anytls.rs:337` `let mut guard = stream_reader.lock().await;`
- `crates/sb-adapters/src/inbound/anytls.rs:409` `let mut guard = reader.lock().await;`
- `crates/sb-adapters/src/inbound/tun_process_aware.rs:169` `*self.runtime.lock().await = Some(runtime);`
- `crates/sb-adapters/src/inbound/tun_process_aware.rs:174` `if let Some(runtime) = self.runtime.lock().await.take() {`
- `crates/sb-adapters/src/outbound/anytls.rs:49` `let mut guard = self.session.lock().await;`
- `crates/sb-adapters/src/outbound/anytls.rs:228` `let mut guard = reader_clone.lock().await;`
- `crates/sb-adapters/src/outbound/hysteria2.rs:184` `let mut last_reset = self.last_reset.lock().await;`
- `crates/sb-adapters/src/outbound/hysteria2.rs:190` `let mut up_tokens = self.up_tokens.lock().await;`
- `crates/sb-adapters/src/outbound/ssh.rs:190` `if let Some(tx) = self.shared.rx_map.lock().await.get(&channel).cloned() {`
- `crates/sb-adapters/src/outbound/ssh.rs:304` `let session = self.session.lock().await;`
- `crates/sb-adapters/src/outbound/ssh.rs:319` `let mut map = self.shared.rx_map.lock().await;`
- `crates/sb-adapters/src/outbound/ssh.rs:358` `let mut pool = self.pool.lock().await;`
- `crates/sb-adapters/src/outbound/tailscale.rs:302` `let guard = wg_clone.lock().await;`
- `crates/sb-api/src/managers.rs:172` `let mut connections = self.connections.write().await;`
- `crates/sb-api/src/managers.rs:180` `let mut connections = self.connections.write().await;`
- `crates/sb-api/src/managers.rs:187` `let connections = self.connections.read().await;`
- `crates/sb-api/src/managers.rs:194` `let connections = self.connections.read().await;`
- `crates/sb-api/src/managers.rs:312` `let cache = self.cache.read().await;`
- `crates/sb-api/src/managers.rs:584` `let mut providers = self.proxy_providers.write().await;`
- `crates/sb-api/src/managers.rs:592` `let mut providers = self.rule_providers.write().await;`
- `crates/sb-api/src/managers.rs:600` `let providers = self.proxy_providers.read().await;`
- `crates/sb-api/src/managers.rs:607` `let providers = self.rule_providers.read().await;`
- `crates/sb-api/src/managers.rs:614` `let providers = self.proxy_providers.read().await;`
- `crates/sb-api/src/managers.rs:637` `let lock = providers.read().await;`
- `crates/sb-api/src/monitoring/bridge.rs:177` `let mut connections = self.connections.write().await;`
- `crates/sb-api/src/monitoring/bridge.rs:183` `let mut connections = self.connections.write().await;`
- `crates/sb-api/src/monitoring/bridge.rs:189` `let connections = self.connections.read().await;`
- `crates/sb-api/src/monitoring/bridge.rs:195` `let mut cache = self.outbound_metrics.lock().await;`
- `crates/sb-api/src/monitoring/bridge.rs:201` `let mut cache = self.dns_metrics.lock().await;`
- `crates/sb-api/src/monitoring/bridge.rs:207` `let outbound_metrics = self.outbound_metrics.lock().await;`
- `crates/sb-api/src/monitoring/bridge.rs:208` `let dns_metrics = self.dns_metrics.lock().await;`
- `crates/sb-api/src/monitoring/collector.rs:182` `let mut bytes = self.bytes_transferred.lock().await;`
- `crates/sb-api/src/monitoring/reporter.rs:342` `self.v2ray_stats.lock().await.clone()`
- `crates/sb-core/src/context.rs:285` `self.interfaces.read().await.values().cloned().collect()`
- `crates/sb-core/src/dns/handle.rs:16` `self.0.read().await.clone()`
- `crates/sb-core/src/dns/transport/dhcp.rs:128` `let _guard = self.probe_lock.lock().await;`
- `crates/sb-core/src/dns/transport/udp.rs:179` `if let Some(tx) = conn.callbacks.lock().await.remove(&id) {`
- `crates/sb-core/src/dns/transport/udp.rs:297` `let mut callbacks = conn.callbacks.lock().await;`
- `crates/sb-core/src/dns/transport/udp.rs:322` `let mut callbacks = conn.callbacks.lock().await;`
- `crates/sb-core/src/dns/transport/udp.rs:362` `let mut guard = self.shared.lock().await;`
- `crates/sb-core/src/endpoint/handler.rs:374` `*last_client_up.lock().await = Some(addr);`
- `crates/sb-core/src/endpoint/handler.rs:402` `let client = { *last_client_down.lock().await };`
- `crates/sb-core/src/endpoint/handler.rs:452` `*last_client_up.lock().await = Some(addr);`
- `crates/sb-core/src/endpoint/handler.rs:482` `let client = { *last_client_down.lock().await };`
- `crates/sb-core/src/inbound/direct.rs:381` `let mut sessions = self.udp_sessions.lock().await;`
- `crates/sb-core/src/inbound/manager.rs:56` `let mut handlers = self.handlers.write().await;`
- `crates/sb-core/src/inbound/manager.rs:63` `let handlers = self.handlers.read().await;`
- `crates/sb-core/src/inbound/manager.rs:70` `let mut handlers = self.handlers.write().await;`
- `crates/sb-core/src/inbound/manager.rs:77` `let handlers = self.handlers.read().await;`
- `crates/sb-core/src/inbound/manager.rs:84` `let handlers = self.handlers.read().await;`
- `crates/sb-core/src/inbound/manager.rs:91` `let handlers = self.handlers.read().await;`
- `crates/sb-core/src/inbound/manager.rs:98` `let handlers = self.handlers.read().await;`
- `crates/sb-core/src/net/datagram.rs:174` `self.inner.lock().await.len()`
- `crates/sb-core/src/net/datagram.rs:178` `self.inner.lock().await.is_empty()`
- `crates/sb-core/src/net/udp_nat.rs:351` `let mut h = self.heap.lock().await;`
- `crates/sb-core/src/net/udp_nat.rs:391` `let mut h = self.heap.lock().await;`
- `crates/sb-core/src/net/udp_nat_v2.rs:162` `let mut h = self.heap.lock().await;`
- `crates/sb-core/src/net/udp_nat_v2.rs:202` `let mut h = self.heap.lock().await;`
- `crates/sb-core/src/net/udp_processor.rs:128` `let nat = self.nat.lock().await;`
- `crates/sb-core/src/net/udp_processor.rs:135` `let mut nat = self.nat.lock().await;`
- `crates/sb-core/src/net/udp_processor.rs:141` `let nat = self.nat.lock().await;`
- `crates/sb-core/src/net/udp_processor.rs:147` `let mut nat = self.nat.lock().await;`
- `crates/sb-core/src/net/udp_processor.rs:153` `let mut nat = self.nat.lock().await;`
- `crates/sb-core/src/outbound/hysteria/v1.rs:115` `let existing_conn = self.connection_pool.lock().await.clone();`
- `crates/sb-core/src/outbound/hysteria/v1.rs:386` `let mut ep_lock = self.endpoint.lock().await;`
- `crates/sb-core/src/outbound/hysteria/v1.rs:611` `let sessions = self.sessions.lock().await;`
- `crates/sb-core/src/outbound/hysteria2.rs:136` `let mut last_reset = self.last_reset.lock().await;`
- `crates/sb-core/src/outbound/hysteria2.rs:142` `let mut up_tokens = self.up_tokens.lock().await;`
- `crates/sb-core/src/outbound/manager.rs:168` `let mut adapters = self.adapters.write().await;`
- `crates/sb-core/src/outbound/manager.rs:193` `let connectors = self.legacy_connectors.read().await;`
- `crates/sb-core/src/outbound/manager.rs:200` `let adapters = self.adapters.read().await;`
- `crates/sb-core/src/outbound/manager.rs:272` `let mut legacy = self.legacy_connectors.write().await;`
- `crates/sb-core/src/outbound/manager.rs:285` `self.adapters.write().await.remove(&tag);`
- `crates/sb-core/src/outbound/manager.rs:289` `let mut legacy = self.legacy_connectors.write().await;`
- `crates/sb-core/src/outbound/manager.rs:296` `let adapters = self.adapters.read().await;`
- `crates/sb-core/src/outbound/manager.rs:313` `let connectors = self.legacy_connectors.read().await;`
- `crates/sb-core/src/outbound/manager.rs:320` `let adapters = self.adapters.read().await;`
- `crates/sb-core/src/outbound/manager.rs:321` `let connectors = self.legacy_connectors.read().await;`
- `crates/sb-core/src/outbound/manager.rs:338` `let mut connectors = self.legacy_connectors.write().await;`
- `crates/sb-core/src/outbound/manager.rs:345` `let mut default = self.default_tag.write().await;`
- `crates/sb-core/src/outbound/manager.rs:405` `let adapters = self.adapters.read().await;`
- `crates/sb-core/src/outbound/manager.rs:406` `let legacy = self.legacy_connectors.read().await;`
- `crates/sb-core/src/outbound/selector_group.rs:293` `self.selected.read().await.clone()`
- `crates/sb-core/src/outbound/socks5_udp.rs:169` `rx.lock().await.recv(),`
- `crates/sb-core/src/outbound/udp_proxy_glue.rs:51` `let g = assoc_map().read().await;`
- `crates/sb-core/src/outbound/udp_proxy_glue.rs:56` `let mut g = assoc_map().write().await;`
- `crates/sb-core/src/outbound/udp_proxy_glue.rs:109` `let g = assoc_map().read().await;`
- `crates/sb-core/src/router/hot_reload.rs:145` `let mut metadata = self.file_metadata.write().await;`
- `crates/sb-core/src/router/hot_reload.rs:250` `let metadata = file_metadata.read().await;`
- `crates/sb-core/src/router/process_router.rs:137` `let engine = self.engine.read().await;`
- `crates/sb-core/src/routing/router.rs:36` `let guard = self.ir.read().await;`
- `crates/sb-core/src/runtime/supervisor.rs:267` `state.write().await.health = Some(health_handle);`
- `crates/sb-core/src/runtime/supervisor.rs:271` `let ntp_cfg = { state.read().await.current_ir.ntp.clone() };`
- `crates/sb-core/src/runtime/supervisor.rs:305` `state_clone.write().await.provider_overlay = overlay;`
- `crates/sb-core/src/runtime/supervisor.rs:404` `let ntp_cfg = { state.read().await.current_ir.ntp.clone() };`
- `crates/sb-core/src/runtime/supervisor.rs:464` `state_clone.write().await.provider_overlay = overlay;`
- `crates/sb-core/src/runtime/supervisor.rs:497` `let state_guard = self.state.read().await;`
- `crates/sb-core/src/runtime/supervisor.rs:672` `let ntp_cfg = { state.read().await.current_ir.ntp.clone() };`
- `crates/sb-core/src/runtime/supervisor.rs:780` `let ntp_cfg = { state.read().await.current_ir.ntp.clone() };`
- `crates/sb-core/src/runtime/supervisor.rs:1007` `let state_guard = self.state.read().await;`
- `crates/sb-core/src/service.rs:217` `let mut guard = self.services.write().await;`
- `crates/sb-core/src/service.rs:223` `let guard = self.services.read().await;`
- `crates/sb-core/src/service.rs:229` `let mut guard = self.services.write().await;`
- `crates/sb-core/src/service.rs:235` `let guard = self.services.read().await;`
- `crates/sb-core/src/service.rs:241` `let guard = self.services.read().await;`
- `crates/sb-core/src/service.rs:252` `let mut guard = self.services.write().await;`
- `crates/sb-tls/src/acme.rs:174` `self.tokens.read().await.get(token).cloned()`
- `crates/sb-tls/src/reality/server.rs:403` `let guard = self.target_chain.read().await;`
- `crates/sb-transport/src/circuit_breaker.rs:456` `self.state.lock().await.state`
- `crates/sb-transport/src/derp/client.rs:203` `let mut guard = self.stream.lock().await;`
- `crates/sb-transport/src/derp/client.rs:226` `let mut guard = self.stream.lock().await;`
- `crates/sb-transport/src/grpc.rs:568` `let mut stream_rx = self.stream_rx.lock().await;`
- `crates/sb-transport/src/multiplex.rs:177` `*self.last_used.lock().await = Instant::now();`
- `crates/sb-transport/src/multiplex.rs:238` `let mut pool = pool.lock().await;`
- `crates/sb-transport/src/multiplex.rs:666` `let mut stream_rx = self.stream_rx.lock().await;`
- `crates/sb-transport/src/resource_pressure.rs:184` `let mut tracker = self.fd_tracker.write().await;`
- `crates/sb-transport/src/wireguard.rs:191` `let mut tunn = inner.tunn.lock().await;`
- `crates/sb-transport/src/wireguard.rs:194` `let endpoint = *inner.peer_endpoint.lock().await;`
- `crates/sb-transport/src/wireguard.rs:210` `let mut tunn = self.inner.tunn.lock().await;`
- `crates/sb-transport/src/wireguard.rs:214` `let endpoint = *self.inner.peer_endpoint.lock().await;`
- `crates/sb-transport/src/wireguard.rs:246` `let endpoint = *self.inner.peer_endpoint.lock().await;`
- `crates/sb-transport/src/wireguard.rs:260` `let mut tunn = self.inner.tunn.lock().await;`
- `crates/sb-transport/src/wireguard.rs:264` `let endpoint = *self.inner.peer_endpoint.lock().await;`
- `crates/sb-transport/src/wireguard.rs:344` `let endpoint = *transport.peer_endpoint.lock().await;`
- `crates/sb-transport/src/wireguard.rs:389` `let mut tunn = transport.tunn.lock().await;`
- `crates/sb-transport/src/wireguard.rs:393` `let endpoint = *transport.peer_endpoint.lock().await;`

### pub_fn_missing_must_use (1030)
- 判定：规范命中
- 对应层：Layer 4

- `app/src/admin_debug/auth/jwt.rs:53` `pub fn from_str(s: &str) -> Result<Self, AuthError> {`
- `app/src/admin_debug/auth/jwt.rs:194` `pub fn new(config: JwtConfig) -> Result<Self, AuthError> {`
- `app/src/admin_debug/auth/jwt.rs:243` `pub fn extract_token(&self, auth_header: &str) -> Result<String, AuthError> {`
- `app/src/admin_debug/auth/mod.rs:171` `pub fn from_config(config: &AuthConfig) -> Result<Box<dyn AuthProvider>, AuthError> {`
- `app/src/admin_debug/auth/mod.rs:198` `pub fn from_config(_config: &AuthConfig) -> Result<Box<dyn AuthProvider>, AuthError> {`
- `app/src/admin_debug/cache.rs:74` `pub async fn get_body(&self) -> Result<Vec<u8>, std::io::Error> {`
- `app/src/admin_debug/cache.rs:131` `pub fn get(&mut self, key: &str) -> Option<TierEntry> {`
- `app/src/admin_debug/endpoints/analyze.rs:46` `pub async fn handle( path_q: &str, sock: &mut (impl AsyncWriteExt + Unpin), state: &crate::admin_debug::AdminDebugState, ) -> std::io::Result<()> {`
- `app/src/admin_debug/endpoints/config.rs:55` `pub async fn handle_get(sock: &mut (impl AsyncWrite + Unpin)) -> std::io::Result<()> {`
- `app/src/admin_debug/endpoints/config.rs:64` `pub async fn handle_put<S>( sock: &mut (impl AsyncRead + AsyncWrite + Unpin), body: bytes::Bytes, headers: &std::collections::HashMap<String, String, S>, ) -> std::io::Result<()> where S: std::hash::BuildHasher, {`
- `app/src/admin_debug/endpoints/geoip.rs:6` `pub async fn handle(path_q: &str, sock: &mut (impl AsyncWriteExt + Unpin)) -> std::io::Result<()> {`
- `app/src/admin_debug/endpoints/health.rs:27` `pub async fn handle( sock: &mut (impl AsyncWriteExt + Unpin), state: &crate::admin_debug::AdminDebugState, ) -> std::io::Result<()> {`
- `app/src/admin_debug/endpoints/metrics.rs:10` `pub async fn handle( sock: &mut (impl AsyncWriteExt + Unpin), state: &crate::admin_debug::AdminDebugState, ) -> std::io::Result<()> {`
- `app/src/admin_debug/endpoints/normalize.rs:13` `pub async fn handle(path_q: &str, sock: &mut (impl AsyncWriteExt + Unpin)) -> std::io::Result<()> {`
- `app/src/admin_debug/endpoints/route_dryrun.rs:5` `pub async fn handle(path_q: &str, sock: &mut (impl AsyncWriteExt + Unpin)) -> std::io::Result<()> {`
- `app/src/admin_debug/endpoints/subs.rs:426` `pub async fn fetch_with_limits(url: &str) -> anyhow::Result<String> {`
- `app/src/admin_debug/endpoints/subs.rs:433` `pub async fn fetch_with_limits_with_metrics( url: &str, metrics: Arc<SecurityMetricsState>, ) -> anyhow::Result<String> {`
- `app/src/admin_debug/endpoints/subs.rs:870` `pub async fn fetch_with_limits_to_cache( url: &str, etag: Option<String>, is_prefetch: bool, ) -> anyhow::Result<crate::admin_debug::cache::CacheEntry> {`
- `app/src/admin_debug/endpoints/subs.rs:879` `pub async fn fetch_with_limits_to_cache_with_metrics( url: &str, etag: Option<String>, is_prefetch: bool, metrics: Arc<SecurityMetricsState>, ) -> anyhow::Result<crate::admin_debug::cache::CacheEntry> {`
- `app/src/admin_debug/endpoints/subs.rs:1355` `pub async fn handle_with_metrics( path_q: &str, sock: &mut (impl AsyncWriteExt + Unpin), metrics: Arc<SecurityMetricsState>, ) -> std::io::Result<()> {`
- `app/src/admin_debug/endpoints/subs.rs:1363` `pub async fn handle(path_q: &str, sock: &mut (impl AsyncWriteExt + Unpin)) -> std::io::Result<()> {`
- `app/src/admin_debug/endpoints/subs.rs:1991` `pub fn cache_control_max_age(h: &reqwest::header::HeaderMap) -> Option<u64> {`
- `app/src/admin_debug/http_server.rs:177` `pub fn check_auth_contract( headers: &HashMap<String, String>, path: &str, auth_conf: &AuthConf, request_id: Option<&str>, ) -> Result<(), sb_admin_contract::ResponseEnvelope<()>> {`
- `app/src/admin_debug/http_server.rs:225` `pub fn check_auth_contract( headers: &HashMap<String, String>, path: &str, auth_conf: &AuthConf, _request_id: Option<&str>, ) -> Result<(), sb_admin_contract::ResponseEnvelope<()>> {`
- `app/src/admin_debug/http_server.rs:618` `pub async fn serve( addr: &str, state: Arc<crate::admin_debug::AdminDebugState>, ) -> std::io::Result<()> {`
- `app/src/admin_debug/http_server.rs:784` `pub fn spawn( addr: std::net::SocketAddr, tls: Option<TlsConf>, auth: AuthConf, state: Arc<crate::admin_debug::AdminDebugState>, ) -> std::io::Result<()> {`
- `app/src/admin_debug/http_server.rs:986` `pub async fn serve_plain( addr: &str, state: Arc<crate::admin_debug::AdminDebugState>, ) -> std::io::Result<()> {`
- `app/src/admin_debug/http_util.rs:52` `pub async fn respond( sock: &mut (impl AsyncWriteExt + Unpin), code: u16, ctype: &str, body: &str, ) -> std::io::Result<()> {`
- `app/src/admin_debug/http_util.rs:76` `pub async fn respond_json_ok( sock: &mut (impl AsyncWriteExt + Unpin), body: &impl Serialize, ) -> std::io::Result<()> {`
- `app/src/admin_debug/http_util.rs:152` `pub async fn respond_json_error( sock: &mut (impl AsyncWriteExt + Unpin), code: u16, msg: &str, hint: Option<&str>, ) -> std::io::Result<()> {`
- `app/src/admin_debug/http_util.rs:166` `pub async fn respond_admin_success<T: Serialize>( sock: &mut (impl AsyncWriteExt + Unpin), data: T, ) -> std::io::Result<()> {`
- `app/src/admin_debug/http_util.rs:173` `pub async fn respond_admin_success_with_request_id<T: Serialize>( sock: &mut (impl AsyncWriteExt + Unpin), data: T, request_id: String, ) -> std::io::Result<()> {`
- `app/src/admin_debug/http_util.rs:185` `pub async fn respond_admin_error( sock: &mut (impl AsyncWriteExt + Unpin), code: u16, error: AdminError, ) -> std::io::Result<()> {`
- `app/src/admin_debug/http_util.rs:193` `pub async fn respond_admin_error_with_request_id( sock: &mut (impl AsyncWriteExt + Unpin), code: u16, error: AdminError, request_id: String, ) -> std::io::Result<()> {`
- `app/src/admin_debug/http_util.rs:208` `pub async fn respond_admin_parse_error( sock: &mut (impl AsyncWriteExt + Unpin), msg: impl Into<String>, ptr: Option<impl Into<String>>, hint: Option<impl Into<String>>, ) -> std::io::Result<()> {`
- `app/src/admin_debug/http_util.rs:224` `pub async fn respond_admin_not_found( sock: &mut (impl AsyncWriteExt + Unpin), resource: impl Into<String>, hint: Option<impl Into<String>>, ) -> std::io::Result<()> {`
- `app/src/admin_debug/http_util.rs:236` `pub async fn respond_admin_conflict( sock: &mut (impl AsyncWriteExt + Unpin), msg: impl Into<String>, ptr: Option<impl Into<String>>, ) -> std::io::Result<()> {`
- `app/src/admin_debug/http_util.rs:252` `pub fn validate_inline_size_estimate(b64_content: &str) -> Result<(), &'static str> {`
- `app/src/admin_debug/http_util.rs:291` `pub fn validate_format(format: &str) -> Result<(), &'static str> {`
- `app/src/admin_debug/http_util.rs:333` `pub fn validate_url_scheme(url: &str) -> Result<(), &'static str> {`
- `app/src/admin_debug/http_util.rs:353` `pub fn validate_kinds(kinds_str: &str) -> Result<Vec<String>, String> {`
- `app/src/admin_debug/middleware/auth.rs:18` `pub fn from_config(config: &AuthConfig) -> Result<Self, AuthError> {`
- `app/src/admin_debug/middleware/auth.rs:25` `pub fn from_config(config: &AuthConfig) -> Result<Self, AuthError> {`
- `app/src/admin_debug/middleware/auth.rs:31` `pub fn from_env() -> Result<Self, AuthError> {`
- `app/src/admin_debug/middleware/auth.rs:59` `pub fn disabled() -> Result<Self, AuthError> {`
- `app/src/admin_debug/middleware/mod.rs:75` `pub fn execute(&self, ctx: &mut RequestContext) -> MiddlewareResult<()> {`
- `app/src/admin_debug/middleware/mod.rs:90` `pub async fn send_error_response<W: AsyncWrite + Unpin>( writer: &mut W, envelope: sb_admin_contract::ResponseEnvelope<()>, status_code: u16, ) -> std::io::Result<()> {`
- `app/src/admin_debug/reloadable.rs:187` `pub fn apply(delta: &crate::admin_debug::endpoints::config::ConfigDelta) -> Result<String, String> {`
- `app/src/admin_debug/reloadable.rs:416` `pub fn apply_with_dryrun( delta: &crate::admin_debug::endpoints::config::ConfigDelta, dry_run: bool, ) -> Result<ApplyResult, String> {`
- `app/src/admin_debug/security.rs:7` `pub fn normalize_host(host: &str) -> Result<String> {`
- `app/src/admin_debug/security.rs:81` `pub fn forbid_private_host(url: &Url) -> Result<()> {`
- `app/src/admin_debug/security.rs:99` `pub fn forbid_private_host_or_resolved(url: &Url) -> Result<()> {`
- `app/src/admin_debug/security.rs:184` `pub fn forbid_private_host_or_resolved_with_allowlist(url: &Url) -> Result<()> {`
- `app/src/admin_debug/security_async.rs:81` `pub async fn resolve_checked(host: &str) -> Result<Vec<IpAddr>> {`
- `app/src/admin_debug/security_async.rs:88` `pub async fn resolve_checked_with_metrics( host: &str, metrics: &SecurityMetricsState, ) -> Result<Vec<IpAddr>> {`
- `app/src/admin_debug/security_async.rs:95` `pub async fn resolve_host_checked(host: &str) -> Result<Vec<IpAddr>> {`
- `app/src/admin_debug/security_async.rs:125` `pub async fn forbid_private_host_or_resolved_async(url: &Url) -> Result<()> {`
- `app/src/admin_debug/security_async.rs:130` `pub async fn forbid_private_host_or_resolved_async_with_metrics( url: &Url, metrics: &SecurityMetricsState, ) -> Result<()> {`
- `app/src/admin_debug/security_metrics.rs:368` `pub fn snapshot(&self) -> Result<SecuritySnapshot> {`
- `app/src/admin_debug/security_metrics.rs:645` `pub fn snapshot() -> Result<SecuritySnapshot> { current()?.snapshot() }`
- `app/src/analyze/registry.rs:45` `pub fn build_by_kind(&self, kind: &str, input: &Value) -> Result<Value> {`
- `app/src/analyze/registry.rs:69` `pub async fn build_by_kind_async(&self, kind: &str, input: &Value) -> Result<Value> {`
- `app/src/bin/handshake.rs:460` `pub fn main() -> Result<()> {`
- `app/src/bootstrap.rs:101` `pub async fn shutdown(self, timeout: Duration) -> Result<()> {`
- `app/src/bootstrap.rs:766` `pub fn build_router_index_from_config(cfg: &Config) -> Result<Arc<sb_core::router::RouterIndex>> {`
- `app/src/bootstrap.rs:815` `pub async fn start_from_config(cfg: Config) -> Result<Runtime> {`
- `app/src/capability_probe.rs:72` `pub fn write_report(report: &CapabilityProbeReport, out_path: &Path) -> Result<()> {`
- `app/src/cli/auth.rs:107` `pub fn main(a: AuthArgs) -> Result<()> {`
- `app/src/cli/bench.rs:74` `pub async fn main(a: BenchArgs) -> Result<()> {`
- `app/src/cli/check/run.rs:42` `pub fn run(global: &GlobalArgs, args: CheckArgs) -> Result<i32> {`
- `app/src/cli/completion.rs:40` `pub fn main(a: CompletionArgs) -> Result<()> {`
- `app/src/cli/dns_cli.rs:48` `pub fn run(global: &GlobalArgs, args: DnsArgs) -> Result<()> {`
- `app/src/cli/format.rs:27` `pub fn run(global: &GlobalArgs, args: FormatArgs) -> Result<()> {`
- `app/src/cli/fs_scan.rs:94` `pub fn run(&self) -> anyhow::Result<FsReport> {`
- `app/src/cli/generate.rs:59` `pub fn run(args: GenerateArgs) -> Result<()> {`
- `app/src/cli/geoip.rs:54` `pub async fn run(args: GeoipArgs) -> Result<()> {`
- `app/src/cli/geosite.rs:66` `pub async fn run(args: GeositeArgs) -> Result<()> {`
- `app/src/cli/man.rs:16` `pub fn main(a: ManArgs) -> Result<()> {`
- `app/src/cli/merge.rs:23` `pub fn run(global: &GlobalArgs, args: MergeArgs) -> Result<()> {`
- `app/src/cli/mod.rs:156` `pub fn apply_global_options(global: &GlobalArgs) -> Result<()> {`
- `app/src/cli/prefetch/mod.rs:113` `pub fn main(a: PrefetchArgs) -> anyhow::Result<()> {`
- `app/src/cli/prefetch/mod.rs:148` `pub fn main(_a: PrefetchArgs) -> anyhow::Result<()> {`
- `app/src/cli/probe.rs:148` `pub async fn main(args: ProbeArgs) -> Result<()> {`
- `app/src/cli/prom.rs:80` `pub fn main(a: PromArgs) -> Result<()> {`
- `app/src/cli/report.rs:40` `pub fn main(args: Args) -> anyhow::Result<()> {`
- `app/src/cli/route.rs:26` `pub fn run(global: &GlobalArgs, args: RouteArgs) -> Result<()> {`
- `app/src/cli/ruleset.rs:164` `pub async fn run(args: RulesetArgs) -> Result<()> {`
- `app/src/cli/run.rs:63` `pub async fn run(global: &GlobalArgs, args: RunArgs) -> Result<()> {`
- `app/src/cli/tools.rs:105` `pub async fn run(global: &GlobalArgs, args: ToolsArgs) -> Result<()> {`
- `app/src/cli/version.rs:17` `pub fn run(args: VersionArgs) -> Result<()> {`
- `app/src/config_loader.rs:41` `pub fn collect_config_entries( config_paths: &[PathBuf], config_dirs: &[PathBuf], ) -> Result<Vec<ConfigEntry>> {`
- `app/src/config_loader.rs:92` `pub fn load_merged_value(entries: &[ConfigEntry]) -> Result<Value> {`
- `app/src/config_loader.rs:107` `pub fn load_config(entries: &[ConfigEntry]) -> Result<sb_config::Config> {`
- `app/src/config_loader.rs:138` `pub fn check_only( config_paths: &[PathBuf], config_dirs: &[PathBuf], ) -> Result<(usize, usize, usize)> {`
- `app/src/http_util.rs:31` `pub fn write_200_json( s: &mut std::net::TcpStream, body: &serde_json::Value, ) -> std::io::Result<()> {`
- `app/src/http_util.rs:47` `pub fn write_503_json( s: &mut std::net::TcpStream, body: &serde_json::Value, ) -> std::io::Result<()> {`
- `app/src/http_util.rs:63` `pub fn write_200_octet(s: &mut std::net::TcpStream, mime: &str, buf: &[u8]) -> std::io::Result<()> {`
- `app/src/http_util.rs:76` `pub fn write_400(s: &mut std::net::TcpStream, msg: &str) -> std::io::Result<()> {`
- `app/src/http_util.rs:97` `pub fn write_404(s: &mut std::net::TcpStream) -> std::io::Result<()> {`
- `app/src/logging.rs:190` `pub fn init_logging(redactor: Arc<app::redact::Redactor>) -> Result<()> {`
- `app/src/logging.rs:198` `pub fn init_logging_with_owner(redactor: Arc<app::redact::Redactor>) -> Result<LoggingOwner> {`
- `app/src/redact.rs:25` `pub fn new() -> Result<Self, regex::Error> {`
- `app/src/router/mod.rs:47` `pub fn build_index_from_rules(_rules: &str) -> Result<()> {`
- `app/src/router/mod.rs:53` `pub fn build_index_from_rules_plus(_rules: &str, _cwd: Option<&std::path::Path>) -> Result<()> {`
- `app/src/router/mod.rs:59` `pub fn preview_decide_http(_idx: &(), _target: &str) -> Result<PreviewResult> {`
- `app/src/router/mod.rs:65` `pub fn preview_decide_udp(_idx: &(), _target: &str) -> Result<PreviewResult> {`
- `app/src/router/mod.rs:123` `pub fn expand_dsl_plus(_text: &str, _cwd: Option<&std::path::Path>) -> Result<String> {`
- `app/src/router/mod.rs:135` `pub fn explain_decision(_query: &ExplainQuery) -> Result<ExplainResult> {`
- `app/src/router/mod.rs:211` `pub fn build_plan(_old: &str, _new: &str, _ctx: Option<&str>) -> Result<()> {`
- `app/src/router/mod.rs:260` `pub fn from_config(_cfg: &sb_config::Config) -> Result<Self> {`
- `app/src/run_engine.rs:69` `pub fn load_config_with_import( entries: &[ConfigEntry], import_path: Option<&Path>, ) -> Result<(sb_config::Config, ConfigIR)> {`
- `app/src/run_engine.rs:100` `pub fn load_config_with_import_raw( entries: &[ConfigEntry], import_path: Option<&Path>, ) -> Result<(sb_config::Config, ConfigIR, serde_json::Value)> {`
- `app/src/run_engine.rs:135` `pub async fn reload_with_supervisor( entries: &[ConfigEntry], import_path: Option<&Path>, supervisor: &Arc<sb_core::runtime::supervisor::Supervisor>, ) -> Result<()> {`
- `app/src/run_engine.rs:706` `pub async fn run_supervisor(opts: RunOptions) -> Result<()> {`
- `app/src/run_go.rs:17` `pub async fn run_go1124(ir: &ConfigIr) -> Result<()> {`
- `app/src/runtime_deps.rs:11` `pub fn build_redactor() -> Result<Arc<crate::redact::Redactor>> {`
- `app/src/runtime_deps.rs:38` `pub fn new() -> Result<Self> {`
- `app/src/telemetry.rs:34` `pub fn init_tracing(_deps: &crate::runtime_deps::AppRuntimeDeps) -> Result<()> {`
- `app/src/telemetry.rs:48` `pub fn init_metrics_exporter(deps: &crate::runtime_deps::AppRuntimeDeps) -> Result<()> {`
- `app/src/tls_provider.rs:35` `pub fn ensure_default_provider() -> Result<TlsProviderDecision> {`
- `app/src/tracing_init.rs:16` `pub fn init_tracing_once() -> Result<()> {`
- `app/src/tracing_init.rs:26` `pub fn init_tracing_once_with_filter(filter: &str) -> Result<()> {`
- `app/src/tracing_init.rs:57` `pub fn init_metrics_exporter_once(registry: sb_metrics::MetricsRegistryHandle) -> Result<()> {`
- `app/src/tracing_init.rs:72` `pub fn init_metrics_exporter_once(_registry: ()) -> Result<()> {`
- `app/src/tracing_init.rs:86` `pub fn init_observability_once(deps: &app::runtime_deps::AppRuntimeDeps) -> Result<()> {`
- `app/src/tracing_init.rs:94` `pub fn init_observability_once(_deps: &app::runtime_deps::AppRuntimeDeps) -> Result<()> {`
- `app/src/util.rs:11` `pub fn write_atomic<P: AsRef<Path>>(path: P, contents: &[u8]) -> Result<()> {`
- `app/src/util.rs:49` `pub async fn spawn_core_admin_from_supervisor( listen: &str, token: Option<String>, supervisor: std::sync::Arc<sb_core::runtime::supervisor::Supervisor>, ) -> anyhow::Result<()> {`
- `crates/sb-adapters/src/endpoint/tailscale.rs:12` `pub fn build_tailscale_endpoint( ir: &EndpointIR, ctx: &EndpointContext, ) -> Option<Arc<dyn Endpoint>> {`
- `crates/sb-adapters/src/endpoint/wireguard.rs:11` `pub fn build_wireguard_endpoint( ir: &EndpointIR, ctx: &EndpointContext, ) -> Option<Arc<dyn Endpoint>> {`
- `crates/sb-adapters/src/endpoint_stubs.rs:41` `pub fn build_wireguard_endpoint( ir: &EndpointIR, _ctx: &EndpointContext, ) -> Option<Arc<dyn Endpoint>> {`
- `crates/sb-adapters/src/endpoint_stubs.rs:62` `pub fn build_tailscale_endpoint( ir: &EndpointIR, _ctx: &EndpointContext, ) -> Option<Arc<dyn Endpoint>> {`
- `crates/sb-adapters/src/inbound/anytls.rs:78` `pub fn new( param: &InboundParam, router: Arc<router::RouterHandle>, outbounds: Arc<OutboundRegistryHandle>, ) -> std::io::Result<Box<dyn InboundService>> {`
- `crates/sb-adapters/src/inbound/direct.rs:27` `pub fn create( param: &InboundParam, stats: Option<Arc<StatsManager>>, ) -> std::io::Result<Box<dyn InboundService>> {`
- `crates/sb-adapters/src/inbound/dns.rs:103` `pub fn new(config: DnsInboundConfig) -> std::io::Result<Self> {`
- `crates/sb-adapters/src/inbound/dns.rs:138` `pub fn create( param: &sb_core::adapter::InboundParam, stats: Option<Arc<StatsManager>>, ) -> std::io::Result<Box<dyn InboundService>> {`
- `crates/sb-adapters/src/inbound/http.rs:270` `pub async fn serve_http( cfg: HttpProxyConfig, mut stop_rx: mpsc::Receiver<()>, ready_tx: Option<oneshot::Sender<()>>, ) -> Result<()> {`
- `crates/sb-adapters/src/inbound/http.rs:385` `pub async fn run_http(cfg: HttpProxyConfig, stop_rx: mpsc::Receiver<()>) -> Result<()> {`
- `crates/sb-adapters/src/inbound/http.rs:391` `pub async fn serve(cfg: HttpProxyConfig, stop_rx: mpsc::Receiver<()>) -> Result<()> {`
- `crates/sb-adapters/src/inbound/http.rs:397` `pub async fn run(cfg: HttpProxyConfig, stop_rx: mpsc::Receiver<()>) -> Result<()> {`
- `crates/sb-adapters/src/inbound/http.rs:401` `pub async fn serve_conn<S>(mut cli: S, peer: SocketAddr, cfg: &HttpProxyConfig) -> Result<()> where S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send, {`
- `crates/sb-adapters/src/inbound/http.rs:868` `pub fn parse_request_line(line: &[u8]) -> Result<(String, String, String)> {`
- `crates/sb-adapters/src/inbound/hysteria.rs:58` `pub fn new(config: HysteriaInboundConfig) -> Result<Self> {`
- `crates/sb-adapters/src/inbound/hysteria.rs:81` `pub async fn start_server(&self) -> Result<()> {`
- `crates/sb-adapters/src/inbound/hysteria.rs:127` `pub async fn start(&self) -> Result<()> {`
- `crates/sb-adapters/src/inbound/hysteria.rs:137` `pub async fn accept(&self) -> Result<(BoxedStream, SocketAddr)> {`
- `crates/sb-adapters/src/inbound/hysteria2.rs:101` `pub fn new(config: Hysteria2InboundConfig) -> Result<Self> {`
- `crates/sb-adapters/src/inbound/hysteria2.rs:126` `pub async fn start_server(&self) -> Result<()> {`
- `crates/sb-adapters/src/inbound/hysteria2.rs:413` `pub async fn start(&self) -> Result<()> {`
- `crates/sb-adapters/src/inbound/hysteria2.rs:423` `pub async fn accept(&self) -> Result<(BoxedStream, SocketAddr)> {`
- `crates/sb-adapters/src/inbound/mixed.rs:53` `pub async fn serve_mixed( cfg: MixedInboundConfig, mut stop_rx: mpsc::Receiver<()>, ready_tx: Option<oneshot::Sender<()>>, ) -> io::Result<()> {`
- `crates/sb-adapters/src/inbound/naive.rs:73` `pub async fn serve(cfg: NaiveInboundConfig, mut stop_rx: mpsc::Receiver<()>) -> Result<()> {`
- `crates/sb-adapters/src/inbound/naive.rs:334` `pub fn parse_target(target: &str) -> Result<(String, u16)> {`
- `crates/sb-adapters/src/inbound/naive.rs:436` `pub fn create( param: &sb_core::adapter::InboundParam, router: Arc<router::RouterHandle>, outbounds: Arc<OutboundRegistryHandle>, ) -> Result<Box<dyn sb_core::adapter::InboundService>> {`
- `crates/sb-adapters/src/inbound/redirect.rs:39` `pub async fn serve(cfg: RedirectConfig, mut stop_rx: mpsc::Receiver<()>) -> Result<()> {`
- `crates/sb-adapters/src/inbound/shadowsocks.rs:58` `pub fn from_method(m: &str) -> Option<Self> {`
- `crates/sb-adapters/src/inbound/shadowsocks.rs:441` `pub fn parse_ss_addr(buf: &[u8]) -> Result<(String, u16, usize)> {`
- `crates/sb-adapters/src/inbound/shadowsocks.rs:732` `pub async fn serve(cfg: ShadowsocksInboundConfig, stop_rx: mpsc::Receiver<()>) -> Result<()> {`
- `crates/sb-adapters/src/inbound/shadowsocks.rs:753` `pub async fn serve_with_ready( cfg: ShadowsocksInboundConfig, stop_rx: mpsc::Receiver<()>, ready_tx: oneshot::Sender<SocketAddr>, ) -> Result<()> {`
- `crates/sb-adapters/src/inbound/shadowsocks.rs:1217` `pub async fn accept_detour_stream<T>(&self, stream: T, peer: SocketAddr) -> Result<()> where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static, {`
- `crates/sb-adapters/src/inbound/shadowtls.rs:64` `pub fn parse(value: Option<&str>) -> Result<Self> {`
- `crates/sb-adapters/src/inbound/shadowtls.rs:93` `pub async fn serve(cfg: ShadowTlsInboundConfig, mut stop_rx: mpsc::Receiver<()>) -> Result<()> {`
- `crates/sb-adapters/src/inbound/socks/auth.rs:22` `pub async fn negotiate_userpass(stream: &mut TcpStream, policy: &SocksAuth) -> Result<()> {`
- `crates/sb-adapters/src/inbound/socks/handshake.rs:16` `pub async fn negotiate_method(stream: &mut TcpStream, policy: &SocksAuth) -> Result<u8> {`
- `crates/sb-adapters/src/inbound/socks/handshake.rs:38` `pub async fn read_request(stream: &mut TcpStream) -> Result<Request> {`
- `crates/sb-adapters/src/inbound/socks/handshake.rs:76` `pub async fn write_success_reply(stream: &mut TcpStream, bnd: Option<&std::net::SocketAddr>) -> Result<()> {`
- `crates/sb-adapters/src/inbound/socks/handshake.rs:107` `pub async fn write_fail_reply(stream: &mut TcpStream, code: u8) -> Result<()> {`
- `crates/sb-adapters/src/inbound/socks/mod.rs:98` `pub async fn serve_socks( cfg: SocksInboundConfig, stop_rx: mpsc::Receiver<()>, ready_tx: Option<oneshot::Sender<()>>, ) -> io::Result<()> {`
- `crates/sb-adapters/src/inbound/socks/mod.rs:165` `pub async fn run(cfg: SocksInboundConfig, stop_rx: mpsc::Receiver<()>) -> io::Result<()> {`
- `crates/sb-adapters/src/inbound/socks/mod.rs:204` `pub async fn serve(cfg: SocksInboundConfig, stop_rx: mpsc::Receiver<()>) -> io::Result<()> {`
- `crates/sb-adapters/src/inbound/socks/mod.rs:208` `pub async fn serve_conn<S>( cli: &mut S, peer: SocketAddr, cfg: &SocksInboundConfig, udp_addr: Option<SocketAddr>, ) -> io::Result<()> where S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send, {`
- `crates/sb-adapters/src/inbound/socks/mod.rs:1107` `pub async fn run(&self) -> anyhow::Result<()> {`
- `crates/sb-adapters/src/inbound/socks/tcp.rs:23` `pub async fn run_tcp(addr: &str) -> Result<()> {`
- `crates/sb-adapters/src/inbound/socks/udp.rs:181` `pub fn parse_udp_datagram(buf: &[u8]) -> Result<(UdpTargetAddr, usize), ParseError> {`
- `crates/sb-adapters/src/inbound/socks/udp.rs:269` `pub async fn serve_socks5_udp_service_real( bind: Vec<std::net::SocketAddr>, conn_tracker: Arc<sb_common::conntrack::ConnTracker>, ) -> Result<()> {`
- `crates/sb-adapters/src/inbound/socks/udp.rs:846` `pub async fn serve_socks5_udp_service( conn_tracker: Arc<sb_common::conntrack::ConnTracker>, ) -> Result<Result<(), anyhow::Error>> {`
- `crates/sb-adapters/src/inbound/socks/udp.rs:880` `pub async fn serve_socks5_udp( listen: Arc<UdpSocket>, conn_tracker: Arc<sb_common::conntrack::ConnTracker>, ) -> Result<()> {`
- `crates/sb-adapters/src/inbound/socks/udp.rs:979` `pub fn get_udp_bind_addr() -> Option<SocketAddr> {`
- `crates/sb-adapters/src/inbound/socks/udp.rs:987` `pub async fn bind_udp_any() -> Result<Arc<UdpSocket>> {`
- `crates/sb-adapters/src/inbound/socks/udp.rs:994` `pub async fn bind_udp_from_env_or_any() -> Result<Vec<Arc<UdpSocket>>> {`
- `crates/sb-adapters/src/inbound/socks/udp.rs:1047` `pub async fn serve_udp_datagrams( sock: Arc<UdpSocket>, timeout: Option<Duration>, inbound_tag: Option<String>, stats: Option<Arc<StatsManager>>, conn_tracker: Arc<sb_common::conntrack::ConnTracker>, ) -> Result<()> {`
- `crates/sb-adapters/src/inbound/socks/udp_enhanced.rs:189` `pub async fn serve_socks5_udp_enhanced(socket: Arc<UdpSocket>) -> Result<()> {`
- `crates/sb-adapters/src/inbound/ssh.rs:80` `pub fn new(config: SshInboundConfig) -> std::io::Result<Self> {`
- `crates/sb-adapters/src/inbound/ssh.rs:102` `pub fn create( param: &sb_core::adapter::InboundParam, ) -> std::io::Result<Box<dyn InboundService>> {`
- `crates/sb-adapters/src/inbound/ssh.rs:383` `pub async fn get_server_key(&self) -> Result<ssh_key::PrivateKey, anyhow::Error> {`
- `crates/sb-adapters/src/inbound/ssh.rs:410` `pub async fn run_ssh_server(&self) -> std::io::Result<()> {`
- `crates/sb-adapters/src/inbound/tproxy.rs:70` `pub async fn serve(cfg: TproxyConfig, mut stop_rx: mpsc::Receiver<()>) -> Result<()> {`
- `crates/sb-adapters/src/inbound/trojan.rs:148` `pub async fn serve(cfg: TrojanInboundConfig, mut stop_rx: mpsc::Receiver<()>) -> Result<()> {`
- `crates/sb-adapters/src/inbound/trojan.rs:590` `pub fn parse_trojan_request(buf: &[u8]) -> Result<()> {`
- `crates/sb-adapters/src/inbound/tuic.rs:143` `pub async fn serve(cfg: TuicInboundConfig, mut stop_rx: mpsc::Receiver<()>) -> Result<()> {`
- `crates/sb-adapters/src/inbound/tun/device.rs:17` `pub fn new( device: Box<dyn TunDevice>, rx_sender: mpsc::Sender<Vec<u8>>, tx_receiver: mpsc::Receiver<Vec<u8>>, mtu: usize, ) -> io::Result<Self> {`
- `crates/sb-adapters/src/inbound/tun/mod.rs:366` `pub fn new( cfg: TunInboundConfig, router: Arc<RouterHandle>, outbounds: Arc<OutboundRegistryHandle>, inbound_tag: Option<String>, stats: Option<Arc<StatsManager>>, sniff: bool, sniff_override_destination: bool, ) -> Self {`
- `crates/sb-adapters/src/inbound/tun/mod.rs:1082` `pub fn from_json(v: &Value, router: Arc<RouterHandle>) -> io::Result<Self> {`
- `crates/sb-adapters/src/inbound/tun/mod.rs:1341` `pub async fn open_and_pump_stub(_name: &str, _mtu: u32) -> io::Result<()> {`
- `crates/sb-adapters/src/inbound/tun/mod.rs:1345` `pub fn probe() -> io::Result<()> {`
- `crates/sb-adapters/src/inbound/tun/mod.rs:1353` `pub async fn open_async_fd(name_hint: &str, mtu: u32) -> io::Result<AsyncFd<std::fs::File>> {`
- `crates/sb-adapters/src/inbound/tun/mod.rs:1503` `pub fn parse_frame(buf: &[u8]) -> Option<Parsed> {`
- `crates/sb-adapters/src/inbound/tun/mod.rs:1650` `pub fn probe() -> io::Result<()> {`
- `crates/sb-adapters/src/inbound/tun/mod.rs:1662` `pub fn open_tun_device(name_hint: &str, mtu: u32) -> io::Result<tun::platform::Device> {`
- `crates/sb-adapters/src/inbound/tun/mod.rs:1682` `pub fn parse_tun_packet(pkt: &[u8]) -> Option<(crate::inbound::tun::L4, Option<IpAddr>, Option<u16>)> {`
- `crates/sb-adapters/src/inbound/tun/mod.rs:1766` `pub fn probe() -> io::Result<()> {`
- `crates/sb-adapters/src/inbound/tun/mod.rs:1788` `pub fn open_wintun_adapter(name_hint: &str, mtu: u32) -> io::Result<Arc<wintun::Adapter>> {`
- `crates/sb-adapters/src/inbound/tun/mod.rs:1820` `pub fn parse_wintun_packet(pkt: &[u8]) -> Option<(crate::inbound::tun::L4, Option<IpAddr>, Option<u16>)> {`
- `crates/sb-adapters/src/inbound/tun/stack.rs:178` `pub fn accept_tcp(&mut self) -> Option<SocketHandle> {`
- `crates/sb-adapters/src/inbound/tun/stack.rs:186` `pub fn connect_tcp( &mut self, local_addr: SocketAddr, remote_addr: SocketAddr, ) -> std::io::Result<SocketHandle> {`
- `crates/sb-adapters/src/inbound/tun/stack.rs:266` `pub fn tcp_send(&mut self, handle: SocketHandle, data: &[u8]) -> std::io::Result<usize> {`
- `crates/sb-adapters/src/inbound/tun/stack.rs:274` `pub fn tcp_recv(&mut self, handle: SocketHandle, buf: &mut [u8]) -> std::io::Result<usize> {`
- `crates/sb-adapters/src/inbound/tun_enhanced.rs:364` `pub fn from_tun_config( cfg: &TunInboundConfig, outbounds: Arc<OutboundRegistryHandle>, router: Option<Arc<RouterHandle>>, ) -> Self {`
- `crates/sb-adapters/src/inbound/tun_enhanced.rs:378` `pub async fn start(&self) -> io::Result<()> {`
- `crates/sb-adapters/src/inbound/tun_macos.rs:57` `pub async fn start( config: &ProcessAwareTunConfig, outbound: Arc<dyn OutboundConnector>, process_router: Option<Arc<ProcessRouter>>, process_matcher: Option<Arc<ProcessMatcher>>, stats: Arc<ProcessAwareTunStatistics>, v2ray_stats: Option<Arc<StatsManager>>, inbound_tag: Option<String>, conn_tracker: Arc<sb_common::conntrack::ConnTracker>, ) -> Result<Self, TunError> {`
- `crates/sb-adapters/src/inbound/tun_process_aware.rs:123` `pub fn new( config: ProcessAwareTunConfig, outbound: Arc<dyn OutboundConnector>, process_router: Option<ProcessRouter>, ) -> Result<Self, TunError> {`
- `crates/sb-adapters/src/inbound/tun_process_aware.rs:154` `pub async fn start(&self) -> Result<(), TunError> {`
- `crates/sb-adapters/src/inbound/tun_session.rs:76` `pub async fn send_to_outbound(&self, data: Bytes) -> Result<(), mpsc::error::SendError<Bytes>> {`
- `crates/sb-adapters/src/inbound/tun_session.rs:161` `pub fn get(&self, tuple: &FourTuple) -> Option<Arc<TcpSession>> {`
- `crates/sb-adapters/src/inbound/tun_session.rs:166` `pub fn create_session( &self, tuple: FourTuple, outbound: TcpStream, tun_writer: Arc<dyn TunWriter + Send + Sync>, traffic: Option<Arc<dyn TrafficRecorder>>, ) -> Arc<TcpSession> {`
- `crates/sb-adapters/src/inbound/tun_session.rs:176` `pub fn create_session_with_state( &self, tuple: FourTuple, outbound: TcpStream, tun_writer: Arc<dyn TunWriter + Send + Sync>, traffic: Option<Arc<dyn TrafficRecorder>>, client_next_seq: u32, server_next_seq: u32, ) -> Arc<TcpSession> {`
- `crates/sb-adapters/src/inbound/tun_session.rs:442` `pub fn build_tcp_response_packet( tuple: FourTuple, payload: &[u8], seq: u32, ack: u32, flags: u8, ) -> std::io::Result<Vec<u8>> {`
- `crates/sb-adapters/src/inbound/vless.rs:94` `pub async fn serve(cfg: VlessInboundConfig, mut stop_rx: mpsc::Receiver<()>) -> Result<()> {`
- `crates/sb-adapters/src/inbound/vmess.rs:99` `pub async fn serve(cfg: VmessInboundConfig, mut stop_rx: mpsc::Receiver<()>) -> Result<()> {`
- `crates/sb-adapters/src/inbound/vmess.rs:501` `pub fn parse_vmess_request(data: &[u8]) -> Result<(String, u16, u8)> {`
- `crates/sb-adapters/src/outbound/detour.rs:15` `pub async fn connect_tcp_stream( host: &str, port: u16, detour: Option<&str>, timeout: std::time::Duration, ) -> Result<BoxedStream> {`
- `crates/sb-adapters/src/outbound/quic_util.rs:55` `pub fn with_sni(mut self, sni: Option<String>) -> Self {`
- `crates/sb-adapters/src/outbound/quic_util.rs:82` `pub async fn quic_connect(cfg: &QuicConfig) -> anyhow::Result<quinn::Connection> {`
- `crates/sb-adapters/src/outbound/shadowsocks.rs:110` `pub fn new(config: ShadowsocksConfig) -> Result<Self> {`
- `crates/sb-adapters/src/outbound/shadowsocks.rs:160` `pub fn with_config( server: impl Into<String>, method: impl Into<String>, password: impl Into<String>, ) -> Result<Self> {`
- `crates/sb-adapters/src/outbound/shadowsocks.rs:179` `pub async fn udp_relay_dial(&self, target: Target) -> Result<Box<dyn OutboundDatagram>> {`
- `crates/sb-adapters/src/outbound/shadowsocks.rs:858` `pub fn new( socket: Arc<UdpSocket>, cipher_method: CipherMethod, master_key: Vec<u8>, ) -> Result<Self> {`
- `crates/sb-adapters/src/outbound/shadowsocksr/mod.rs:28` `pub fn new(config: ShadowsocksROutboundConfig) -> Result<Self> {`
- `crates/sb-adapters/src/outbound/shadowsocksr/obfs.rs:28` `pub fn create(name: &str, param: Option<&str>) -> Box<dyn SsrObfs> {`
- `crates/sb-adapters/src/outbound/shadowsocksr/obfs.rs:70` `pub fn new(param: Option<&str>) -> Self {`
- `crates/sb-adapters/src/outbound/shadowsocksr/obfs.rs:156` `pub fn new(param: Option<&str>) -> Self {`
- `crates/sb-adapters/src/outbound/shadowsocksr/protocol.rs:30` `pub fn create(name: &str, param: Option<&str>) -> Box<dyn SsrProtocol> {`
- `crates/sb-adapters/src/outbound/shadowsocksr/protocol.rs:75` `pub fn new(param: Option<&str>) -> Self {`
- `crates/sb-adapters/src/outbound/shadowsocksr/protocol.rs:178` `pub fn new(param: Option<&str>) -> Self {`
- `crates/sb-adapters/src/outbound/shadowtls.rs:1016` `pub async fn connect_detour_stream(&self, host: &str, port: u16) -> Result<BoxedStream> {`
- `crates/sb-adapters/src/outbound/socks5.rs:382` `pub async fn dial_udp( &self, target: Target, opts: DialOpts, ) -> Result<Arc<dyn OutboundDatagram>> {`
- `crates/sb-adapters/src/outbound/socks5.rs:468` `pub async fn dial_bind(&self, target: Target, opts: DialOpts) -> Result<BoxedStream> {`
- `crates/sb-adapters/src/outbound/tailscale.rs:329` `pub async fn init_wireguard(&mut self) -> Result<(), AdapterError> {`
- `crates/sb-adapters/src/outbound/tor.rs:64` `pub fn new(ir: &OutboundIR, _ctx: &Context) -> Result<Self> {`
- `crates/sb-adapters/src/outbound/trojan.rs:219` `pub async fn udp_relay_dial(&self, target: Target) -> Result<Box<dyn OutboundDatagram>> {`
- `crates/sb-adapters/src/outbound/trojan.rs:514` `pub fn new(socket: Arc<tokio::net::UdpSocket>) -> Result<Self> {`
- `crates/sb-adapters/src/outbound/tuic.rs:312` `pub fn decode_udp_packet(data: &[u8]) -> std::io::Result<(String, u16, Vec<u8>)> {`
- `crates/sb-adapters/src/outbound/vless.rs:233` `pub async fn udp_relay_dial(&self, target: Target) -> Result<Box<dyn OutboundDatagram>> {`
- `crates/sb-adapters/src/outbound/vless.rs:459` `pub fn new(socket: Arc<UdpSocket>, uuid: Uuid) -> Result<Self> {`
- `crates/sb-adapters/src/outbound/wireguard.rs:75` `pub async fn new(config: WireGuardOutboundConfig) -> Result<Self> {`
- `crates/sb-adapters/src/service/resolve1.rs:773` `pub async fn start_dbus_server( state: Arc<Resolve1ManagerState>, ) -> Result<Connection, Box<dyn std::error::Error + Send + Sync>> {`
- `crates/sb-adapters/src/service/resolve1.rs:813` `pub async fn start_dbus_server( _state: Arc<Resolve1ManagerState>, ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {`
- `crates/sb-adapters/src/service/resolved_impl.rs:49` `pub fn new( ir: &ServiceIR, ctx: &ServiceContext, ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {`
- `crates/sb-adapters/src/service/resolved_impl.rs:463` `pub fn build_resolved_service(ir: &ServiceIR, _ctx: &ServiceContext) -> Option<Arc<dyn Service>> {`
- `crates/sb-adapters/src/service_stubs.rs:50` `pub fn build_resolved_service(ir: &ServiceIR, ctx: &ServiceContext) -> Option<Arc<dyn Service>> {`
- `crates/sb-adapters/src/service_stubs.rs:69` `pub fn build_ssmapi_service(ir: &ServiceIR, ctx: &ServiceContext) -> Option<Arc<dyn Service>> {`
- `crates/sb-adapters/src/service_stubs.rs:74` `pub fn build_ssmapi_service(ir: &ServiceIR, ctx: &ServiceContext) -> Option<Arc<dyn Service>> {`
- `crates/sb-adapters/src/service_stubs.rs:96` `pub fn build_derp_service(ir: &ServiceIR, ctx: &ServiceContext) -> Option<Arc<dyn Service>> {`
- `crates/sb-adapters/src/testsupport/mod.rs:36` `pub async fn spawn_socks_udp_inbound() -> Result<SocketAddr> {`
- `crates/sb-adapters/src/traits.rs:633` `pub async fn with_retry<F, Fut, T>(retry_policy: &RetryPolicy, mut operation: F) -> Result<T> where F: FnMut() -> Fut, Fut: std::future::Future<Output = Result<T>>, {`
- `crates/sb-adapters/src/traits.rs:682` `pub async fn with_adapter_retry<F, Fut, T>( retry_policy: &RetryPolicy, adapter_name: &'static str, mut operation: F, ) -> Result<T> where F: FnMut() -> Fut, Fut: std::future::Future<Output = Result<T>>, {`
- `crates/sb-adapters/src/transport_config.rs:355` `pub async fn create_inbound_listener( &self, bind_addr: std::net::SocketAddr, ) -> Result<InboundListener, std::io::Error> {`
- `crates/sb-adapters/src/transport_config.rs:521` `pub async fn accept( &self, ) -> Result<(Box<dyn InboundStream>, std::net::SocketAddr), std::io::Error> {`
- `crates/sb-adapters/src/transport_config.rs:581` `pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {`
- `crates/sb-admin-contract/src/lib.rs:240` `pub fn as_result(self) -> Result<T, ErrorBody> {`
- `crates/sb-api/src/clash/auth.rs:21` `pub async fn auth_middleware(secret: Option<String>, request: Request, next: Next) -> Response {`
- `crates/sb-api/src/clash/handlers.rs:902` `pub async fn get_connections_or_ws( ws: Option<WebSocketUpgrade>, State(state): State<ApiState>, ) -> Response {`
- `crates/sb-api/src/clash/handlers.rs:1868` `pub async fn get_meta_memory( ws: Option<axum::extract::ws::WebSocketUpgrade>, State(state): State<ApiState>, ) -> impl IntoResponse {`
- `crates/sb-api/src/clash/server.rs:147` `pub fn new(config: ApiConfig) -> ApiResult<Self> {`
- `crates/sb-api/src/clash/server.rs:155` `pub fn with_monitoring( config: ApiConfig, monitoring: MonitoringSystemHandle, ) -> ApiResult<Self> {`
- `crates/sb-api/src/clash/server.rs:217` `pub async fn start(&self) -> ApiResult<()> {`
- `crates/sb-api/src/clash/server.rs:230` `pub async fn start_with_shutdown(&self, shutdown: oneshot::Receiver<()>) -> ApiResult<()> {`
- `crates/sb-api/src/clash/server.rs:244` `pub async fn serve_with_listener(&self, listener: tokio::net::TcpListener) -> ApiResult<()> {`
- `crates/sb-api/src/clash/server.rs:253` `pub async fn serve_with_listener_and_shutdown( &self, listener: tokio::net::TcpListener, shutdown: oneshot::Receiver<()>, ) -> ApiResult<()> {`
- `crates/sb-api/src/clash/server.rs:390` `pub fn broadcast_traffic(&self, stats: crate::types::TrafficStats) -> ApiResult<()> {`
- `crates/sb-api/src/clash/server.rs:398` `pub fn broadcast_log(&self, log: crate::types::LogEntry) -> ApiResult<()> {`
- `crates/sb-api/src/managers.rs:171` `pub async fn add_connection(&self, connection: Connection) -> ApiResult<()> {`
- `crates/sb-api/src/managers.rs:179` `pub async fn remove_connection(&self, id: &str) -> ApiResult<bool> {`
- `crates/sb-api/src/managers.rs:186` `pub async fn get_connections(&self) -> ApiResult<Vec<Connection>> {`
- `crates/sb-api/src/managers.rs:193` `pub async fn get_connection(&self, id: &str) -> ApiResult<Option<Connection>> {`
- `crates/sb-api/src/managers.rs:200` `pub async fn close_all_connections(&self) -> ApiResult<usize> {`
- `crates/sb-api/src/managers.rs:291` `pub async fn flush_dns_cache(&self) -> ApiResult<()> {`
- `crates/sb-api/src/managers.rs:301` `pub async fn flush_fake_ip_cache(&self) -> ApiResult<()> {`
- `crates/sb-api/src/managers.rs:318` `pub async fn add_fake_ip_mapping(&self, domain: String, fake_ip: String) -> ApiResult<()> {`
- `crates/sb-api/src/managers.rs:326` `pub async fn resolve_fake_ip(&self, fake_ip: &str) -> Option<String> {`
- `crates/sb-api/src/managers.rs:340` `pub async fn query_dns(&self, name: &str, query_type: &str) -> ApiResult<Vec<String>> {`
- `crates/sb-api/src/managers.rs:583` `pub async fn add_proxy_provider(&self, provider: Provider) -> ApiResult<()> {`
- `crates/sb-api/src/managers.rs:591` `pub async fn add_rule_provider(&self, provider: Provider) -> ApiResult<()> {`
- `crates/sb-api/src/managers.rs:599` `pub async fn get_proxy_providers(&self) -> ApiResult<HashMap<String, Provider>> {`
- `crates/sb-api/src/managers.rs:606` `pub async fn get_rule_providers(&self) -> ApiResult<HashMap<String, Provider>> {`
- `crates/sb-api/src/managers.rs:613` `pub async fn get_proxy_provider(&self, name: &str) -> ApiResult<Option<Provider>> {`
- `crates/sb-api/src/managers.rs:620` `pub async fn get_rule_provider(&self, name: &str) -> ApiResult<Option<Provider>> {`
- `crates/sb-api/src/managers.rs:628` `pub async fn update_provider(&self, name: &str, is_proxy_provider: bool) -> ApiResult<bool> {`
- `crates/sb-api/src/managers.rs:685` `pub async fn health_check_provider( &self, name: &str, is_proxy_provider: bool, ) -> ApiResult<bool> {`
- `crates/sb-api/src/monitoring/bridge.rs:265` `pub async fn collect_from_core(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {`
- `crates/sb-api/src/monitoring/collector.rs:64` `pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {`
- `crates/sb-api/src/monitoring/collector.rs:222` `pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {`
- `crates/sb-api/src/monitoring/collector.rs:323` `pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {`
- `crates/sb-api/src/monitoring/mod.rs:60` `pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {`
- `crates/sb-api/src/monitoring/reporter.rs:104` `pub async fn start( &self, traffic_rx: broadcast::Receiver<TrafficStats>, connection_rx: broadcast::Receiver<Connection>, performance_rx: broadcast::Receiver<serde_json::Value>, ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {`
- `crates/sb-api/src/v2ray/server.rs:36` `pub fn new(config: ApiConfig) -> ApiResult<Self> {`
- `crates/sb-api/src/v2ray/server.rs:52` `pub async fn start(&self) -> ApiResult<()> {`
- `crates/sb-api/src/v2ray/server.rs:89` `pub fn new(config: ApiConfig) -> ApiResult<Self> {`
- `crates/sb-api/src/v2ray/server.rs:95` `pub async fn start(&self) -> ApiResult<()> {`
- `crates/sb-api/src/v2ray/simple.rs:59` `pub fn new(config: ApiConfig) -> ApiResult<Self> {`
- `crates/sb-api/src/v2ray/simple.rs:79` `pub fn with_monitoring( config: ApiConfig, monitoring: MonitoringSystemHandle, ) -> ApiResult<Self> {`
- `crates/sb-api/src/v2ray/simple.rs:102` `pub async fn start(&self) -> ApiResult<()> {`
- `crates/sb-api/src/v2ray/simple.rs:154` `pub async fn start_with_shutdown(&self, mut shutdown: oneshot::Receiver<()>) -> ApiResult<()> {`
- `crates/sb-api/src/v2ray/simple.rs:198` `pub fn negotiate_version(&self, version: &str) -> ApiResult<()> {`
- `crates/sb-api/src/v2ray/simple.rs:208` `pub async fn get_stats(&self, request: SimpleStatsRequest) -> ApiResult<SimpleStatsResponse> {`
- `crates/sb-api/src/v2ray/simple.rs:235` `pub async fn query_stats( &self, request: SimpleQueryStatsRequest, ) -> ApiResult<SimpleQueryStatsResponse> {`
- `crates/sb-common/src/conntrack.rs:229` `pub fn unregister(&self, id: ConnId) -> Option<Arc<ConnMetadata>> {`
- `crates/sb-common/src/conntrack.rs:249` `pub fn get(&self, id: ConnId) -> Option<Arc<ConnMetadata>> {`
- `crates/sb-common/src/convertor.rs:153` `pub fn from_ss_uri(uri: &str) -> Option<Self> {`
- `crates/sb-common/src/convertor.rs:195` `pub fn from_vmess_uri(uri: &str) -> Option<Self> {`
- `crates/sb-common/src/convertor.rs:222` `pub fn from_vless_uri(uri: &str) -> Option<Self> {`
- `crates/sb-common/src/convertor.rs:274` `pub fn from_trojan_uri(uri: &str) -> Option<Self> {`
- `crates/sb-common/src/convertor.rs:331` `pub fn from_uri(uri: &str) -> Option<Self> {`
- `crates/sb-common/src/ja3.rs:86` `pub fn from_client_hello(data: &[u8]) -> Option<Self> {`
- `crates/sb-common/src/pipelistener.rs:41` `pub fn bind(path: impl AsRef<Path>) -> io::Result<Self> {`
- `crates/sb-common/src/pipelistener.rs:72` `pub async fn accept(&self) -> io::Result<PipeStream> {`
- `crates/sb-common/src/pipelistener.rs:105` `pub fn local_addr(&self) -> io::Result<tokio::net::unix::SocketAddr> {`
- `crates/sb-common/src/pipelistener.rs:187` `pub fn from_bytes(data: &[u8]) -> io::Result<Self> {`
- `crates/sb-common/src/tlsfrag.rs:157` `pub fn extract_sni(data: &[u8]) -> Option<String> {`
- `crates/sb-config/src/de.rs:5` `pub fn deserialize_string_or_list<'de, T, D>(deserializer: D) -> Result<Vec<T>, D::Error> where T: Deserialize<'de>, D: Deserializer<'de>, {`
- `crates/sb-config/src/de.rs:41` `pub fn deserialize<'de, D>(deserializer: D) -> Result<ListenAddr, D::Error> where D: Deserializer<'de>, {`
- `crates/sb-config/src/de.rs:73` `pub fn serialize<S>(value: &ListenAddr, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer, {`
- `crates/sb-config/src/ir/mod.rs:2496` `pub fn validate_reality(&self) -> Result<(), String> {`
- `crates/sb-config/src/ir/mod.rs:2577` `pub fn validate(&self) -> Result<(), Vec<String>> {`
- `crates/sb-config/src/json_norm.rs:59` `pub fn normalize_file_to_string(path: impl AsRef<Path>) -> anyhow::Result<String> {`
- `crates/sb-config/src/lib.rs:364` `pub fn from_value(doc: Value) -> Result<Self> {`
- `crates/sb-config/src/lib.rs:426` `pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {`
- `crates/sb-config/src/lib.rs:455` `pub fn validate(&self) -> Result<()> {`
- `crates/sb-config/src/lib.rs:519` `pub fn pick_outbound_for_host<'a>(&'a self, host: &str) -> Option<&'a str> {`
- `crates/sb-config/src/lib.rs:534` `pub fn build_registry_and_router(&self) -> Result<()> {`
- `crates/sb-config/src/lib.rs:574` `pub fn config_from_raw_value(raw: Value) -> Result<(Config, ir::ConfigIR)> {`
- `crates/sb-config/src/present.rs:9` `pub fn to_ir(cfg: &Config) -> Result<ConfigIR> {`
- `crates/sb-config/src/schema_v2.rs:10` `pub fn schema_v2() -> Result<Value> {`
- `crates/sb-config/src/subscribe.rs:26` `pub fn from_subscription(text: &str) -> Result<Config> {`
- `crates/sb-core/src/adapter/handler.rs:159` `pub fn get_connection_handler(&self, tag: &str) -> Option<Arc<dyn ConnectionHandlerEx>> {`
- `crates/sb-core/src/adapter/handler.rs:164` `pub fn get_packet_handler(&self, tag: &str) -> Option<Arc<dyn PacketHandlerEx>> {`
- `crates/sb-core/src/adapter/handler.rs:169` `pub fn get_upstream(&self, tag: &str) -> Option<Arc<dyn UpstreamHandler>> {`
- `crates/sb-core/src/adapter/mod.rs:501` `pub fn new_from_config(ir: &sb_config::ir::ConfigIR, context: Context) -> anyhow::Result<Self> {`
- `crates/sb-core/src/adapter/mod.rs:824` `pub fn find_outbound(&self, name: &str) -> Option<Arc<dyn OutboundConnector>> {`
- `crates/sb-core/src/adapter/mod.rs:831` `pub fn find_udp_factory(&self, name: &str) -> Option<Arc<dyn UdpOutboundFactory>> {`
- `crates/sb-core/src/adapter/mod.rs:854` `pub fn get_member(&self, name: &str) -> Option<Arc<dyn OutboundConnector>> {`
- `crates/sb-core/src/adapter/registry.rs:96` `pub fn get(&self, tag: &str) -> Option<Arc<dyn InboundService>> {`
- `crates/sb-core/src/adapter/registry.rs:125` `pub fn get_inbound(kind: &str) -> Option<InboundBuilder> {`
- `crates/sb-core/src/adapter/registry.rs:131` `pub fn get_outbound(kind: &str) -> Option<OutboundBuilder> {`
- `crates/sb-core/src/adapter/registry.rs:149` `pub fn runtime_inbounds() -> Option<Arc<InboundRegistryHandle>> {`
- `crates/sb-core/src/adapter/registry.rs:155` `pub fn runtime_outbounds() -> Option<Arc<OutboundRegistryHandle>> {`
- `crates/sb-core/src/admin/http.rs:876` `pub fn spawn_admin( listen: &str, #[cfg(feature = "router")] engine: Engine, #[cfg(not(feature = "router"))] _engine: (), bridge: Arc<Bridge>, admin_token: Option<String>, supervisor: Option<Arc<Supervisor>>, rt_handle: Option<Handle>, ) -> std::io::Result<thread::JoinHandle<()>> {`
- `crates/sb-core/src/config/mod.rs:9` `pub fn try_parse_str(s: &str) -> Result<(), ()> {`
- `crates/sb-core/src/conntrack/inbound_tcp.rs:139` `pub fn register_inbound_tcp( source: SocketAddr, destination_host: String, destination_port: u16, host_for_display: String, inbound_type: &'static str, inbound_tag: Option<String>, outbound_tag: Option<String>, chains: Vec<String>, rule: Option<String>, process_name: Option<String>, process_path: Option<String>, inner_traffic: Option<Arc<dyn TrafficRecorder>>, ) -> ConntrackWiring {`
- `crates/sb-core/src/conntrack/inbound_tcp.rs:172` `pub fn register_inbound_tcp_with_tracker( tracker: Arc<sb_common::conntrack::ConnTracker>, source: SocketAddr, destination_host: String, destination_port: u16, host_for_display: String, inbound_type: &'static str, inbound_tag: Option<String>, outbound_tag: Option<String>, chains: Vec<String>, rule: Option<String>, process_name: Option<String>, process_path: Option<String>, inner_traffic: Option<Arc<dyn TrafficRecorder>>, ) -> ConntrackWiring {`
- `crates/sb-core/src/conntrack/inbound_udp.rs:11` `pub fn register_inbound_udp( source: SocketAddr, destination_host: String, destination_port: u16, host_for_display: String, inbound_type: &'static str, inbound_tag: Option<String>, outbound_tag: Option<String>, chains: Vec<String>, rule: Option<String>, process_name: Option<String>, process_path: Option<String>, inner_traffic: Option<Arc<dyn TrafficRecorder>>, ) -> super::inbound_tcp::ConntrackWiring {`
- `crates/sb-core/src/conntrack/inbound_udp.rs:44` `pub fn register_inbound_udp_with_tracker( tracker: Arc<sb_common::conntrack::ConnTracker>, source: SocketAddr, destination_host: String, destination_port: u16, host_for_display: String, inbound_type: &'static str, inbound_tag: Option<String>, outbound_tag: Option<String>, chains: Vec<String>, rule: Option<String>, process_name: Option<String>, process_path: Option<String>, inner_traffic: Option<Arc<dyn TrafficRecorder>>, ) -> super::inbound_tcp::ConntrackWiring {`
- `crates/sb-core/src/context.rs:289` `pub async fn get_interface(&self, name: &str) -> Option<NetworkInterface> {`
- `crates/sb-core/src/context.rs:336` `pub fn wifi_ssid(&self) -> Option<String> {`
- `crates/sb-core/src/context.rs:346` `pub fn wifi_bssid(&self) -> Option<String> {`
- `crates/sb-core/src/context.rs:508` `pub fn get(&self, id: u64) -> Option<ConnectionInfo> {`
- `crates/sb-core/src/diagnostics/http_server.rs:29` `pub async fn start( options: &DebugOptions, ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {`
- `crates/sb-core/src/dns/cache.rs:230` `pub fn get(&self, key: &Key) -> Option<DnsAnswer> {`
- `crates/sb-core/src/dns/cache.rs:384` `pub fn peek_remaining(&self, key: &Key) -> Option<Duration> {`
- `crates/sb-core/src/dns/cache_v2.rs:59` `pub async fn get(&self, name: &str, q: QType, now: Instant) -> Option<CacheCell> {`
- `crates/sb-core/src/dns/client.rs:101` `pub async fn resolve(&self, host: &str, default_port: u16) -> anyhow::Result<Vec<SocketAddr>> {`
- `crates/sb-core/src/dns/config_builder.rs:22` `pub fn build_dns_components( ir: &sb_config::ir::ConfigIR, cache_file: Option<Arc<crate::services::cache_file::CacheFileService>>, ) -> Result<DnsComponents> {`
- `crates/sb-core/src/dns/config_builder.rs:210` `pub fn resolver_from_ir(ir: &sb_config::ir::ConfigIR) -> Result<Arc<dyn Resolver>> {`
- `crates/sb-core/src/dns/config_builder.rs:217` `pub fn build_upstream( addr: &str, _registry: &crate::dns::transport::TransportRegistry, ) -> Result<Option<Arc<dyn DnsUpstream>>> {`
- `crates/sb-core/src/dns/config_builder.rs:295` `pub fn build_upstream_from_server( srv: &sb_config::ir::DnsServerIR, _registry: &crate::dns::transport::TransportRegistry, ) -> Result<Option<Arc<dyn DnsUpstream>>> {`
- `crates/sb-core/src/dns/doh.rs:13` `pub async fn query_doh_once( url: &str, host: &str, qtype: u16, timeout_ms: u64, ) -> Result<(Vec<IpAddr>, Option<u32>)> {`
- `crates/sb-core/src/dns/doq.rs:14` `pub async fn query_doq_once( server: SocketAddr, server_name: &str, host: &str, qtype: u16, timeout_ms: u64, ) -> Result<(Vec<IpAddr>, Option<u32>)> {`
- `crates/sb-core/src/dns/dot.rs:8` `pub async fn query_dot_once( addr: SocketAddr, host: &str, qtype: u16, timeout_ms: u64, ) -> Result<(Vec<IpAddr>, Option<u32>)> {`
- `crates/sb-core/src/dns/enhanced_client.rs:363` `pub async fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>> {`
- `crates/sb-core/src/dns/fakeip.rs:361` `pub fn lookup_domain(ip: &IpAddr) -> Option<String> {`
- `crates/sb-core/src/dns/fakeip.rs:427` `pub fn to_domain(ip: &IpAddr) -> Option<String> {`
- `crates/sb-core/src/dns/global.rs:27` `pub fn get() -> Option<Arc<dyn Resolver>> {`
- `crates/sb-core/src/dns/hosts.rs:36` `pub fn new() -> Result<Self> {`
- `crates/sb-core/src/dns/hosts.rs:42` `pub fn with_path(file_path: PathBuf) -> Result<Self> {`
- `crates/sb-core/src/dns/hosts.rs:89` `pub fn load_hosts(&mut self) -> Result<()> {`
- `crates/sb-core/src/dns/hosts.rs:154` `pub fn reload(&mut self) -> Result<()> {`
- `crates/sb-core/src/dns/hosts.rs:159` `pub fn lookup(&self, hostname: &str) -> Option<Vec<IpAddr>> {`
- `crates/sb-core/src/dns/http_client.rs:46` `pub fn new(url: &str) -> Result<Self> {`
- `crates/sb-core/src/dns/http_client.rs:82` `pub async fn query(&self, name: &str, qtype: u16) -> Result<(Vec<IpAddr>, Option<u32>)> {`
- `crates/sb-core/src/dns/http_client.rs:94` `pub async fn exchange(&self, packet: &[u8]) -> Result<Vec<u8>> {`
- `crates/sb-core/src/dns/http_client.rs:194` `pub fn query(name: &str) -> std::io::Result<Vec<IpAddr>> {`
- `crates/sb-core/src/dns/message.rs:38` `pub fn as_ipv4(&self) -> Option<std::net::Ipv4Addr> {`
- `crates/sb-core/src/dns/message.rs:52` `pub fn as_ipv6(&self) -> Option<std::net::Ipv6Addr> {`
- `crates/sb-core/src/dns/message.rs:63` `pub fn as_ip(&self) -> Option<IpAddr> {`
- `crates/sb-core/src/dns/message.rs:71` `pub fn parse_question_key(pkt: &[u8]) -> Option<QuestionKey> {`
- `crates/sb-core/src/dns/message.rs:98` `pub fn parse_min_ttl(pkt: &[u8]) -> Option<u64> {`
- `crates/sb-core/src/dns/message.rs:144` `pub fn parse_answer_records(pkt: &[u8]) -> Option<Vec<Record>> {`
- `crates/sb-core/src/dns/message.rs:224` `pub fn pack_rr_uncompressed( name: &str, rtype: u16, class: u16, ttl: u32, rdata: &[u8], ) -> Option<Vec<u8>> {`
- `crates/sb-core/src/dns/message.rs:332` `pub fn build_dns_response(query: &[u8], ips: &[IpAddr], ttl: u32, rcode: u8) -> Option<Vec<u8>> {`
- `crates/sb-core/src/dns/message.rs:394` `pub fn extract_rcode(pkt: &[u8]) -> Option<u8> {`
- `crates/sb-core/src/dns/message.rs:463` `pub fn get_query_id(pkt: &[u8]) -> Option<u16> {`
- `crates/sb-core/src/dns/message.rs:504` `pub fn parse_subnet(subnet: &str) -> Option<(u16, u8, Vec<u8>)> {`
- `crates/sb-core/src/dns/message.rs:662` `pub fn parse_edns0_client_subnet(message: &[u8]) -> Option<String> {`
- `crates/sb-core/src/dns/mod.rs:463` `pub async fn resolve(&self, host: &str) -> Result<DnsAnswer> {`
- `crates/sb-core/src/dns/mod.rs:1402` `pub fn register( &self, tag: impl Into<String>, transport: Arc<dyn transport::DnsTransport>, ) -> Option<Arc<dyn transport::DnsTransport>> {`
- `crates/sb-core/src/dns/mod.rs:1421` `pub fn remove(&self, tag: &str) -> Option<Arc<dyn transport::DnsTransport>> {`
- `crates/sb-core/src/dns/mod.rs:1473` `pub async fn start_all(&self, stage: transport::DnsStartStage) -> Result<()> {`
- `crates/sb-core/src/dns/mod.rs:1488` `pub async fn close_all(&self) -> Result<()> {`
- `crates/sb-core/src/dns/resolve.rs:74` `pub async fn resolve_all(host: &str, port: u16) -> Result<Vec<SocketAddr>> {`
- `crates/sb-core/src/dns/resolve.rs:393` `pub async fn resolve_socketaddr(host: &str, port: u16) -> std::io::Result<SocketAddr> {`
- `crates/sb-core/src/dns/resolve.rs:404` `pub async fn resolve_all_compat(host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {`
- `crates/sb-core/src/dns/router.rs:85` `pub async fn lookup(&mut self, host: &str) -> Result<Vec<IpAddr>> {`
- `crates/sb-core/src/dns/router.rs:91` `pub fn resolve_cached_or_lookup(&self, host: &str) -> Option<Vec<IpAddr>> {`
- `crates/sb-core/src/dns/rule_engine.rs:145` `pub fn new( rules: Vec<DnsRoutingRule>, upstreams: HashMap<String, Arc<dyn DnsUpstream>>, default_upstream_tag: String, strategy: super::DnsStrategy, registry: Arc<crate::dns::transport::TransportRegistry>, geoip: Option<Arc<GeoIpDb>>, geosite: Option<Arc<GeoSiteDb>>, ) -> Self {`
- `crates/sb-core/src/dns/rule_engine.rs:187` `pub async fn resolve(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {`
- `crates/sb-core/src/dns/rule_engine.rs:204` `pub async fn resolve_with_context( &self, ctx: &DnsQueryContext, domain: &str, record_type: RecordType, ) -> Result<DnsAnswer> {`
- `crates/sb-core/src/dns/rule_engine.rs:366` `pub async fn explain(&self, domain: &str) -> Result<serde_json::Value> {`
- `crates/sb-core/src/dns/rule_engine.rs:542` `pub async fn start(&self, stage: crate::dns::transport::DnsStartStage) -> Result<()> {`
- `crates/sb-core/src/dns/rule_engine.rs:553` `pub async fn close(&self) -> Result<()> {`
- `crates/sb-core/src/dns/rule_engine.rs:564` `pub async fn resolve_dual_stack(&self, domain: &str) -> Result<DnsAnswer> {`
- `crates/sb-core/src/dns/rule_engine.rs:570` `pub async fn resolve_dual_stack_with_context( &self, ctx: &DnsQueryContext, domain: &str, ) -> Result<DnsAnswer> {`
- `crates/sb-core/src/dns/strategy.rs:112` `pub async fn query(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {`
- `crates/sb-core/src/dns/stub.rs:33` `pub fn resolve(&self, host: &str, port: u16) -> Option<Vec<SocketAddr>> {`
- `crates/sb-core/src/dns/stub.rs:81` `pub fn global() -> Option<&'static DnsCache> {`
- `crates/sb-core/src/dns/transport/dhcp.rs:68` `pub fn new(interface: Option<String>) -> Self {`
- `crates/sb-core/src/dns/transport/doh.rs:28` `pub fn new(url: String) -> Result<Self> {`
- `crates/sb-core/src/dns/transport/doh.rs:222` `pub fn build(self) -> Result<DohTransport> {`
- `crates/sb-core/src/dns/transport/doh3.rs:30` `pub fn new(server: SocketAddr, server_name: String, path: String) -> Result<Self> {`
- `crates/sb-core/src/dns/transport/doh3.rs:34` `pub fn new_with_tls( server: SocketAddr, server_name: String, path: String, extra_ca_paths: Vec<String>, extra_ca_pem: Vec<String>, skip_verify: bool, ) -> Result<Self> {`
- `crates/sb-core/src/dns/transport/doh3.rs:231` `pub fn new(_server: SocketAddr, _server_name: String, _path: String) -> Result<Self> {`
- `crates/sb-core/src/dns/transport/doq.rs:26` `pub fn new(server: SocketAddr, server_name: String) -> Result<Self> {`
- `crates/sb-core/src/dns/transport/doq.rs:30` `pub fn new_with_tls( server: SocketAddr, server_name: String, extra_ca_paths: Vec<String>, extra_ca_pem: Vec<String>, skip_verify: bool, ) -> Result<Self> {`
- `crates/sb-core/src/dns/transport/dot.rs:34` `pub fn new(server: SocketAddr, server_name: String) -> Result<Self> {`
- `crates/sb-core/src/dns/transport/dot.rs:39` `pub fn new_with_tls( server: SocketAddr, server_name: String, extra_ca_paths: Vec<String>, extra_ca_pem: Vec<String>, skip_verify: bool, ) -> Result<Self> {`
- `crates/sb-core/src/dns/transport/dot.rs:107` `pub fn with_bind_interface(mut self, iface: Option<String>) -> Self {`
- `crates/sb-core/src/dns/transport/registry.rs:45` `pub fn register_type<F>(&self, transport_type: &str, constructor: F) where F: Fn(&str, &serde_json::Value) -> Result<Arc<dyn DnsTransport>> + Send + Sync + 'static, {`
- `crates/sb-core/src/dns/transport/registry.rs:55` `pub fn create_transport( &self, tag: &str, transport_type: &str, options: &serde_json::Value, ) -> Result<Arc<dyn DnsTransport>> {`
- `crates/sb-core/src/dns/transport/registry.rs:92` `pub fn get(&self, tag: &str) -> Option<Arc<dyn DnsTransport>> {`
- `crates/sb-core/src/dns/transport/registry.rs:102` `pub fn get_startup_order(&self) -> Result<Vec<String>> {`
- `crates/sb-core/src/dns/transport/registry.rs:146` `pub async fn start_all(&self, stage: DnsStartStage) -> Result<()> {`
- `crates/sb-core/src/dns/transport/registry.rs:161` `pub async fn close_all(&self) -> Result<()> {`
- `crates/sb-core/src/dns/transport/registry.rs:177` `pub fn remove(&self, tag: &str) -> Option<Arc<dyn DnsTransport>> {`
- `crates/sb-core/src/dns/transport/resolved.rs:46` `pub fn to_ip_addr(&self) -> Option<IpAddr> {`
- `crates/sb-core/src/dns/transport/resolved.rs:71` `pub fn to_ip_addr(&self) -> Option<IpAddr> {`
- `crates/sb-core/src/dns/transport/resolved.rs:161` `pub fn update_link(&self, link: TransportLink) -> Result<(), String> {`
- `crates/sb-core/src/dns/udp.rs:6` `pub fn build_query(host: &str, qtype: u16) -> Result<Vec<u8>> {`
- `crates/sb-core/src/dns/udp.rs:96` `pub fn parse_answers(buf: &[u8], expect_qtype: u16) -> Result<(Vec<IpAddr>, Option<u32>)> {`
- `crates/sb-core/src/dns/upstream.rs:397` `pub fn with_client_subnet(mut self, client_subnet: Option<String>) -> Self {`
- `crates/sb-core/src/dns/upstream.rs:744` `pub fn from_spec(spec: &str, tag: Option<&str>) -> Result<Self> {`
- `crates/sb-core/src/dns/upstream.rs:861` `pub fn reload_servers(&self) -> Result<()> {`
- `crates/sb-core/src/dns/upstream.rs:1211` `pub fn from_spec(spec: &str, tag: Option<&str>) -> Result<Self> {`
- `crates/sb-core/src/dns/upstream.rs:1293` `pub fn reload_servers(&self) -> Result<()> {`
- `crates/sb-core/src/dns/upstream.rs:1554` `pub fn new_with_tls( server: SocketAddr, server_name: String, extra_ca_paths: Vec<String>, extra_ca_pem: Vec<String>, skip_verify: bool, transport: Option<Arc<dyn DnsTransport>>, ) -> Self {`
- `crates/sb-core/src/dns/upstream.rs:1582` `pub fn with_client_subnet(mut self, ecs: Option<String>) -> Self {`
- `crates/sb-core/src/dns/upstream.rs:1927` `pub fn new_with_tls( server: SocketAddr, server_name: String, extra_ca_paths: Vec<String>, extra_ca_pem: Vec<String>, skip_verify: bool, transport: Option<Arc<dyn DnsTransport>>, ) -> Self {`
- `crates/sb-core/src/dns/upstream.rs:2057` `pub fn with_client_subnet(mut self, ecs: Option<String>) -> Self {`
- `crates/sb-core/src/dns/upstream.rs:2075` `pub fn new(url: String) -> Result<Self> {`
- `crates/sb-core/src/dns/upstream.rs:2080` `pub fn new_with_tls( url: String, ca_paths: Vec<String>, ca_pem: Vec<String>, skip_verify: bool, ) -> Result<Self> {`
- `crates/sb-core/src/dns/upstream.rs:2253` `pub fn with_client_subnet(mut self, ecs: Option<String>) -> Self {`
- `crates/sb-core/src/dns/upstream.rs:2273` `pub fn new(server: std::net::SocketAddr, server_name: String, path: String) -> Result<Self> {`
- `crates/sb-core/src/dns/upstream.rs:2278` `pub fn new_with_tls( server: std::net::SocketAddr, server_name: String, path: String, _ca_paths: Vec<String>, _ca_pem: Vec<String>, _skip_verify: bool, ) -> Result<Self> {`
- `crates/sb-core/src/dns/upstream.rs:2320` `pub fn with_client_subnet(mut self, ecs: Option<String>) -> Self {`
- `crates/sb-core/src/dns/upstream.rs:2491` `pub fn new(tag: Option<&str>) -> Self {`
- `crates/sb-core/src/dns/upstream.rs:2574` `pub fn new(tag: Option<&str>) -> Self {`
- `crates/sb-core/src/dns/upstream.rs:2678` `pub fn new(tag: String, inet4_range: Option<String>, inet6_range: Option<String>) -> Self {`
- `crates/sb-core/src/dns/upstream.rs:2819` `pub fn from_json_predefined( tag: String, predefined: Option<&serde_json::Value>, hosts_paths: &[String], ) -> Self {`
- `crates/sb-core/src/endpoint/handler.rs:27` `pub fn new( router: Arc<RouterHandle>, outbounds: Arc<OutboundRegistryHandle>, udp_factories: Arc<HashMap<String, Arc<dyn UdpOutboundFactory>>>, stats: Option<Arc<StatsManager>>, ) -> Self {`
- `crates/sb-core/src/endpoint/mod.rs:72` `pub fn fqdn(&self) -> Option<&str> {`
- `crates/sb-core/src/endpoint/mod.rs:80` `pub fn addr(&self) -> Option<IpAddr> {`
- `crates/sb-core/src/endpoint/mod.rs:88` `pub fn to_socket_addr(&self) -> Option<SocketAddr> {`
- `crates/sb-core/src/endpoint/mod.rs:371` `pub fn get(&self, ty: EndpointType) -> Option<EndpointBuilder> {`
- `crates/sb-core/src/endpoint/mod.rs:377` `pub fn build(&self, ir: &EndpointIR, ctx: &EndpointContext) -> Option<Arc<dyn Endpoint>> {`
- `crates/sb-core/src/endpoint/mod.rs:456` `pub async fn get(&self, tag: &str) -> Option<Arc<dyn Endpoint>> {`
- `crates/sb-core/src/endpoint/mod.rs:462` `pub async fn remove(&self, tag: &str) -> Option<Arc<dyn Endpoint>> {`
- `crates/sb-core/src/endpoint/mod.rs:495` `pub fn run_stage( &self, stage: StartStage, ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {`
- `crates/sb-core/src/endpoint/mod.rs:533` `pub fn shutdown(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {`
- `crates/sb-core/src/endpoint/mod.rs:579` `pub async fn remove_with_check(&self, tag: &str) -> Result<Option<Arc<dyn Endpoint>>, String> {`
- `crates/sb-core/src/endpoint/mod.rs:588` `pub async fn as_outbound_connector( &self, tag: &str, ) -> Option<Arc<dyn crate::adapter::OutboundConnector>> {`
- `crates/sb-core/src/endpoint/tailscale.rs:545` `pub fn new( ir: &EndpointIR, #[cfg(feature = "router")] router: Option<Arc<crate::router::RouterHandle>>, ) -> Self {`
- `crates/sb-core/src/endpoint/tailscale.rs:560` `pub fn with_config( config: TailscaleEndpointConfig, #[cfg(feature = "router")] router: Option<Arc<crate::router::RouterHandle>>, ) -> Self {`
- `crates/sb-core/src/endpoint/tailscale.rs:585` `pub fn localapi_socket_path(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {`
- `crates/sb-core/src/endpoint/tailscale.rs:629` `pub fn last_error(&self) -> Option<String> {`
- `crates/sb-core/src/endpoint/tailscale.rs:1030` `pub fn build_tailscale_endpoint( ir: &EndpointIR, _ctx: &super::EndpointContext, ) -> Option<Arc<dyn Endpoint>> {`
- `crates/sb-core/src/endpoint/wireguard.rs:92` `pub fn new( ir: &EndpointIR, dns: Option<Arc<dyn crate::dns::Resolver>>, #[cfg(feature = "router")] router: Option<Arc<crate::router::RouterHandle>>, ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {`
- `crates/sb-core/src/endpoint/wireguard.rs:614` `pub fn build_wireguard_endpoint( ir: &EndpointIR, ctx: &super::EndpointContext, ) -> Option<Arc<dyn Endpoint>> {`
- `crates/sb-core/src/geo/loader.rs:9` `pub fn load_geoip() -> Option<Vec<u8>> {`
- `crates/sb-core/src/geo/loader.rs:17` `pub fn load_geosite() -> Option<HashSet<String>> {`
- `crates/sb-core/src/geoip/mmdb.rs:22` `pub fn new() -> anyhow::Result<Self> {`
- `crates/sb-core/src/geoip/mmdb.rs:36` `pub fn from_paths( country_path: Option<&Path>, city_path: Option<&Path>, asn_path: Option<&Path>, ) -> anyhow::Result<Self> {`
- `crates/sb-core/src/geoip/mmdb.rs:159` `pub fn new() -> anyhow::Result<Self> {`
- `crates/sb-core/src/geoip/mmdb.rs:168` `pub fn from_paths( country_path: Option<&Path>, city_path: Option<&Path>, asn_path: Option<&Path>, ) -> anyhow::Result<Self> {`
- `crates/sb-core/src/geoip/mmdb.rs:318` `pub fn new() -> anyhow::Result<Self> {`
- `crates/sb-core/src/geoip/mmdb.rs:325` `pub fn open( path: &std::path::Path, cache_capacity: usize, _ttl: std::time::Duration, ) -> anyhow::Result<Self> {`
- `crates/sb-core/src/geoip/mmdb.rs:389` `pub fn lookup(&self, ip: IpAddr) -> Option<GeoInfo> {`
- `crates/sb-core/src/geoip/mod.rs:60` `pub fn lookup(&self, ip: IpAddr) -> Option<GeoInfo> {`
- `crates/sb-core/src/geoip/mod.rs:75` `pub fn get_asn(&self, ip: IpAddr) -> Option<u32> {`
- `crates/sb-core/src/geoip/mod.rs:86` `pub fn init() -> anyhow::Result<()> {`
- `crates/sb-core/src/geoip/mod.rs:111` `pub fn service() -> Option<&'static GeoIpService> {`
- `crates/sb-core/src/geoip/mod.rs:154` `pub fn lookup_with_metrics_decision(ip: IpAddr) -> Option<&'static str> {`
- `crates/sb-core/src/geoip/multi.rs:52` `pub fn from_env() -> anyhow::Result<Self> {`
- `crates/sb-core/src/geoip/multi.rs:69` `pub fn lookup(&self, ip: std::net::IpAddr) -> Option<(String, String)> {`
- `crates/sb-core/src/http_client.rs:18` `pub fn install_http_client(client: Box<dyn HttpClient>) -> Result<(), Box<dyn HttpClient>> {`
- `crates/sb-core/src/http_client.rs:43` `pub fn global_http_client() -> Option<&'static dyn HttpClient> {`
- `crates/sb-core/src/http_client.rs:58` `pub async fn http_execute(req: HttpRequest) -> Result<HttpResponse, sb_types::CoreError> {`
- `crates/sb-core/src/inbound/direct.rs:95` `pub fn with_tag(mut self, tag: Option<String>) -> Self {`
- `crates/sb-core/src/inbound/direct.rs:100` `pub fn with_stats(mut self, stats: Option<Arc<StatsManager>>) -> Self {`
- `crates/sb-core/src/inbound/http_connect.rs:444` `pub fn with_basic_auth(mut self, user: Option<String>, pass: Option<String>) -> Self {`
- `crates/sb-core/src/inbound/manager.rs:62` `pub async fn get(&self, tag: &str) -> Option<InboundHandler> {`
- `crates/sb-core/src/inbound/manager.rs:69` `pub async fn remove(&self, tag: &str) -> Option<InboundHandler> {`
- `crates/sb-core/src/inbound/manager.rs:141` `pub async fn remove_with_check(&self, tag: &str) -> Result<Option<InboundHandler>, String> {`
- `crates/sb-core/src/inbound/mixed.rs:87` `pub fn with_basic_auth(mut self, user: Option<String>, pass: Option<String>) -> Self {`
- `crates/sb-core/src/inbound/socks5.rs:851` `pub async fn greet_noauth(stream: &mut AsyncTcpStream) -> anyhow::Result<()> {`
- `crates/sb-core/src/inbound/socks5.rs:865` `pub async fn udp_associate( stream: &mut AsyncTcpStream, bind_hint: Option<SocketAddr>, ) -> anyhow::Result<SocketAddr> {`
- `crates/sb-core/src/inbound/socks5.rs:950` `pub fn decode_udp_reply(packet: &[u8]) -> anyhow::Result<(SocketAddr, Vec<u8>)> {`
- `crates/sb-core/src/inbound/tun.rs:181` `pub fn get_or_create<F>(&self, key: FlowKey, create_fn: F) -> Option<Arc<RwLock<TunSession>>> where F: FnOnce(&FlowKey) -> Option<TunSession>, {`
- `crates/sb-core/src/inbound/tun.rs:223` `pub fn get(&self, key: &FlowKey) -> Option<Arc<RwLock<TunSession>>> {`
- `crates/sb-core/src/inbound/tun.rs:228` `pub fn remove(&self, key: &FlowKey) -> Option<Arc<RwLock<TunSession>>> {`
- `crates/sb-core/src/inbound/tun.rs:274` `pub fn flow_key(&self) -> Option<FlowKey> {`
- `crates/sb-core/src/inbound/tun.rs:291` `pub fn parse_ip_packet(packet: &[u8]) -> Option<ParsedPacket> {`
- `crates/sb-core/src/inbound/tun.rs:504` `pub fn with_tag(mut self, tag: Option<String>) -> Self {`
- `crates/sb-core/src/inbound/tun.rs:510` `pub fn with_stats(mut self, stats: Option<Arc<StatsManager>>) -> Self {`
- `crates/sb-core/src/inbound/unsupported.rs:14` `pub fn new(kind: impl Into<String>, reason: impl Into<String>, hint: Option<String>) -> Self {`
- `crates/sb-core/src/metrics/http_exporter.rs:48` `pub fn run_exporter(addr: &str) -> std::io::Result<()> {`
- `crates/sb-core/src/metrics/http_exporter.rs:52` `pub fn run_exporter_with_registry( addr: &str, registry: sb_metrics::MetricsRegistryHandle, ) -> std::io::Result<()> {`
- `crates/sb-core/src/metrics/registry_ext.rs:243` `pub fn get_or_register_histogram_vec( name: &str, help: &str, labels: &[&str], buckets: Option<Vec<f64>>, ) -> &'static HistogramVec {`
- `crates/sb-core/src/net/datagram.rs:66` `pub fn new<T>(_maybe_ttl: T) -> Self where T: Into<Option<Duration>>, {`
- `crates/sb-core/src/net/datagram.rs:75` `pub async fn get(&self, k: &UdpNatKey) -> Option<Arc<UdpSocket>> {`
- `crates/sb-core/src/net/datagram.rs:86` `pub async fn get_conntrack_meta( &self, k: &UdpNatKey, ) -> Option<(Arc<dyn TrafficRecorder>, CancellationToken)> {`
- `crates/sb-core/src/net/dial.rs:10` `pub async fn dial_hostport(host: &str, port: u16, per_attempt: Duration) -> io::Result<TcpStream> {`
- `crates/sb-core/src/net/dial.rs:19` `pub async fn dial_all(host: &str, port: u16, per_attempt: Duration) -> io::Result<TcpStream> {`
- `crates/sb-core/src/net/dial.rs:43` `pub async fn dial_socketaddrs<I>(iter: I, per_attempt: Duration) -> io::Result<TcpStream> where I: IntoIterator<Item = std::net::SocketAddr>, {`
- `crates/sb-core/src/net/dial.rs:74` `pub async fn dial_pref(host: &str, port: u16) -> io::Result<TcpStream> {`
- `crates/sb-core/src/net/metered.rs:88` `pub async fn copy_bidirectional_metered<A, B>( a: &mut A, b: &mut B, _label: &'static str, ) -> io::Result<()> where A: AsyncRead + AsyncWrite + Unpin + ?Sized, B: AsyncRead + AsyncWrite + Unpin + ?Sized, {`
- `crates/sb-core/src/net/metered.rs:104` `pub async fn copy_bidirectional_streaming<A, B>( a: &mut A, b: &mut B, _label: &'static str, interval_dur: Duration, ) -> io::Result<(u64, u64)> where A: AsyncRead + AsyncWrite + Unpin + ?Sized, B: AsyncRead + AsyncWrite + Unpin + ?Sized, {`
- `crates/sb-core/src/net/metered.rs:122` `pub async fn copy_bidirectional_streaming_ctl<A, B>( a: &mut A, b: &mut B, _label: &'static str, interval_dur: Duration, read_timeout: Option<Duration>, write_timeout: Option<Duration>, cancel: Option<CancellationToken>, traffic: Option<Arc<dyn TrafficRecorder>>, ) -> io::Result<(u64, u64)> where A: AsyncRead + AsyncWrite + Unpin + ?Sized, B: AsyncRead + AsyncWrite + Unpin + ?Sized, {`
- `crates/sb-core/src/net/rate_limit.rs:29` `pub fn from_env_udp() -> Option<Self> {`
- `crates/sb-core/src/net/rate_limit.rs:66` `pub fn allow(&self, sz: usize) -> Result<(), &'static str> {`
- `crates/sb-core/src/net/ratelimit.rs:99` `pub fn maybe_drop_udp(len: usize) -> Option<&'static str> {`
- `crates/sb-core/src/net/udp_nat.rs:98` `pub async fn get(&self, key: &NatKey) -> Option<Arc<UdpSocket>> {`
- `crates/sb-core/src/net/udp_nat.rs:120` `pub async fn get_conntrack_meta( &self, key: &NatKey, ) -> Option<(Arc<dyn TrafficRecorder>, CancellationToken)> {`
- `crates/sb-core/src/net/udp_nat.rs:147` `pub async fn insert_with_meta( &self, key: NatKey, upstream: Arc<UdpSocket>, conntrack: Option<UdpConntrackMeta>, ) -> bool {`
- `crates/sb-core/src/net/udp_nat_core.rs:131` `pub fn create_mapping(&mut self, src: SocketAddr, dst: SocketAddr) -> SbResult<SocketAddr> {`
- `crates/sb-core/src/net/udp_nat_core.rs:168` `pub fn lookup_session(&self, addr: &SocketAddr) -> Option<&UdpSession> {`
- `crates/sb-core/src/net/udp_nat_core.rs:174` `pub fn lookup_session_by_key(&self, flow_key: &UdpFlowKey) -> Option<&UdpSession> {`
- `crates/sb-core/src/net/udp_processor.rs:76` `pub async fn process_inbound(&self, packet: UdpPacket) -> SbResult<SocketAddr> {`
- `crates/sb-core/src/net/udp_processor.rs:98` `pub async fn process_outbound( &self, packet: UdpPacket, mapped_addr: SocketAddr, ) -> SbResult<Option<SocketAddr>> {`
- `crates/sb-core/src/net/udp_processor.rs:127` `pub async fn lookup_session(&self, mapped_addr: &SocketAddr) -> Option<UdpFlowKey> {`
- `crates/sb-core/src/net/udp_upstream_map.rs:39` `pub async fn get(&self, key: &Key) -> Option<Arc<UpSocksSession>> {`
- `crates/sb-core/src/net/udp_upstream_map.rs:77` `pub async fn remove(&self, key: &Key) -> Option<Arc<UpSocksSession>> {`
- `crates/sb-core/src/outbound/chain.rs:64` `pub fn compute_chain_for_decision( outbounds: Option<&OutboundRegistryHandle>, decision: &Decision, outbound_tag: Option<&str>, ) -> Vec<String> {`
- `crates/sb-core/src/outbound/direct_connector.rs:41` `pub fn with_options( connect_timeout: Option<Duration>, bind_interface: Option<String>, routing_mark: Option<u32>, reuse_addr: Option<bool>, tcp_fast_open: Option<bool>, tcp_multi_path: Option<bool>, ) -> Self {`
- `crates/sb-core/src/outbound/endpoint.rs:21` `pub fn parse(s: &str) -> Option<Self> {`
- `crates/sb-core/src/outbound/health.rs:80` `pub fn global_status() -> Option<&'static HealthStatus> {`
- `crates/sb-core/src/outbound/http_upstream.rs:17` `pub fn new(server: String, port: u16, user: Option<String>, pass: Option<String>) -> Self {`
- `crates/sb-core/src/outbound/hysteria/v1.rs:93` `pub fn new(config: HysteriaV1Config) -> anyhow::Result<Self> {`
- `crates/sb-core/src/outbound/hysteria/v1.rs:317` `pub async fn start(&self) -> io::Result<()> {`
- `crates/sb-core/src/outbound/hysteria/v1.rs:393` `pub async fn local_addr(&self) -> io::Result<SocketAddr> {`
- `crates/sb-core/src/outbound/hysteria/v1.rs:406` `pub async fn accept(&self) -> io::Result<(HysteriaV1Stream, SocketAddr)> {`
- `crates/sb-core/src/outbound/hysteria/v1.rs:610` `pub async fn get_session(&self, session_id: u32) -> Option<UdpSession> {`
- `crates/sb-core/src/outbound/hysteria2.rs:97` `pub fn new(up_mbps: Option<u32>, down_mbps: Option<u32>) -> Self {`
- `crates/sb-core/src/outbound/hysteria2.rs:156` `pub fn new(config: Hysteria2Config) -> anyhow::Result<Self> {`
- `crates/sb-core/src/outbound/hysteria2.rs:236` `pub async fn get_connection(&self) -> io::Result<Connection> {`
- `crates/sb-core/src/outbound/hysteria2.rs:525` `pub async fn create_udp_session( &self, connection: &Connection, ) -> io::Result<Hysteria2UdpSession> {`
- `crates/sb-core/src/outbound/hysteria2.rs:775` `pub async fn send_udp(&self, data: &[u8], target: &HostPort) -> io::Result<()> {`
- `crates/sb-core/src/outbound/hysteria2.rs:827` `pub async fn recv_udp(&self) -> io::Result<(Vec<u8>, SocketAddr)> {`
- `crates/sb-core/src/outbound/manager.rs:47` `pub fn validate_and_sort( all_tags: &[String], deps: &HashMap<String, Vec<String>>, ) -> Result<Vec<String>, String> {`
- `crates/sb-core/src/outbound/manager.rs:184` `pub async fn get(&self, tag: &str) -> Option<Arc<dyn OutboundConnector>> {`
- `crates/sb-core/src/outbound/manager.rs:199` `pub async fn get_adapter(&self, tag: &str) -> Option<OutboundHandler> {`
- `crates/sb-core/src/outbound/manager.rs:206` `pub async fn remove(&self, tag: &str) -> Option<Arc<dyn OutboundConnector>> {`
- `crates/sb-core/src/outbound/manager.rs:224` `pub async fn remove_with_check( &self, tag: &str, ) -> Result<Option<Arc<dyn OutboundConnector>>, String> {`
- `crates/sb-core/src/outbound/manager.rs:351` `pub async fn get_default(&self) -> Option<String> {`
- `crates/sb-core/src/outbound/manager.rs:404` `pub async fn get_startup_order(&self) -> Result<Vec<String>, String> {`
- `crates/sb-core/src/outbound/manager.rs:420` `pub async fn resolve_default(&self, config_tag: Option<&str>) -> Result<String, String> {`
- `crates/sb-core/src/outbound/mod.rs:121` `pub async fn connect(host: &str, port: u16) -> std::io::Result<TcpStream> {`
- `crates/sb-core/src/outbound/mod.rs:232` `pub fn get(&self, name: &str) -> Option<&OutboundImpl> {`
- `crates/sb-core/src/outbound/mod.rs:268` `pub async fn connect_tcp(&self, target: &RouteTarget, ep: Endpoint) -> io::Result<TcpStream> {`
- `crates/sb-core/src/outbound/mod.rs:312` `pub async fn connect_io( &self, target: &RouteTarget, ep: Endpoint, ) -> io::Result<sb_transport::IoStream> {`
- `crates/sb-core/src/outbound/mod.rs:401` `pub async fn connect_preferred( &self, target: &RouteTarget, ep: Endpoint, ) -> io::Result<sb_transport::IoStream> {`
- `crates/sb-core/src/outbound/mod.rs:428` `pub async fn connect_preferred( &self, target: &RouteTarget, ep: Endpoint, ) -> io::Result<TcpStream> {`
- `crates/sb-core/src/outbound/mod.rs:788` `pub async fn direct_connect_hostport( host: &str, port: u16, _opts: &ConnectOpts, ) -> io::Result<TcpStream> {`
- `crates/sb-core/src/outbound/mod.rs:797` `pub async fn http_proxy_connect_through_proxy( proxy_addr: &str, target_host: &str, target_port: u16, _opts: &ConnectOpts, ) -> io::Result<TcpStream> {`
- `crates/sb-core/src/outbound/mod.rs:815` `pub async fn socks5_connect_through_socks5( proxy_addr: &str, target_host: &str, target_port: u16, _opts: &ConnectOpts, ) -> io::Result<TcpStream> {`
- `crates/sb-core/src/outbound/naive_h2.rs:39` `pub fn new(config: NaiveH2Config) -> anyhow::Result<Self> {`
- `crates/sb-core/src/outbound/observe.rs:8` `pub async fn with_observation<T, E, F, Fut>( selector: &Selector, pool_name: &str, endpoint_index: usize, f: F, ) -> Result<T, E> where F: FnOnce() -> Fut, Fut: std::future::Future<Output = Result<T, E>>, {`
- `crates/sb-core/src/outbound/observe.rs:31` `pub async fn with_pool_observation<T, E, F, Fut>( _selector: &PoolSelector, pool_name: &str, endpoint_index: usize, f: F, ) -> Result<T, E> where F: FnOnce() -> Fut, Fut: std::future::Future<Output = Result<T, E>>, {`
- `crates/sb-core/src/outbound/optimizations.rs:225` `pub fn get<F>(&self, is_healthy: F) -> Option<Arc<T>> where F: Fn(&T) -> bool, {`
- `crates/sb-core/src/outbound/optimizations.rs:308` `pub fn get(&self, key: &K) -> Option<Arc<V>> {`
- `crates/sb-core/src/outbound/quic/common.rs:47` `pub fn with_sni(mut self, sni: Option<String>) -> Self {`
- `crates/sb-core/src/outbound/quic/common.rs:70` `pub async fn connect(cfg: &QuicConfig) -> anyhow::Result<Connection> {`
- `crates/sb-core/src/outbound/registry.rs:38` `pub fn global() -> Option<Arc<Registry>> {`
- `crates/sb-core/src/outbound/selector.rs:415` `pub fn get_pool(&self, pool_name: &str) -> Option<&HealthView> {`
- `crates/sb-core/src/outbound/selector.rs:419` `pub fn get_pool_mut(&mut self, pool_name: &str) -> Option<&mut HealthView> {`
- `crates/sb-core/src/outbound/selector.rs:423` `pub fn select_healthy_endpoint(&self, pool_name: &str) -> Option<&EndpointHealth> {`
- `crates/sb-core/src/outbound/selector.rs:454` `pub fn select( &self, pool_name: &str, _peer_addr: std::net::SocketAddr, _target: &str, _health: &(), ) -> Option<&ProxyEndpoint> {`
- `crates/sb-core/src/outbound/selector_group.rs:51` `pub fn new( tag: impl Into<String>, connector: Arc<dyn OutboundConnector>, udp_factory: Option<Arc<dyn UdpOutboundFactory>>, ) -> Self {`
- `crates/sb-core/src/outbound/selector_group.rs:183` `pub fn new_manual( name: String, members: Vec<ProxyMember>, default: Option<String>, cache_file: Option<Arc<dyn crate::context::CacheFile>>, urltest_history: Option<Arc<dyn crate::context::URLTestHistoryStorage>>, ) -> Self {`
- `crates/sb-core/src/outbound/selector_group.rs:236` `pub fn new_load_balancer( name: String, members: Vec<ProxyMember>, mode: SelectMode, cache_file: Option<Arc<dyn crate::context::CacheFile>>, urltest_history: Option<Arc<dyn crate::context::URLTestHistoryStorage>>, ) -> Self {`
- `crates/sb-core/src/outbound/selector_group.rs:260` `pub async fn select_by_name(&self, tag: &str) -> std::io::Result<()> {`
- `crates/sb-core/src/outbound/selector_group.rs:292` `pub async fn get_selected(&self) -> Option<String> {`
- `crates/sb-core/src/outbound/selector_group.rs:297` `pub async fn select_best(&self) -> Option<&ProxyMember> {`
- `crates/sb-core/src/outbound/selector_p3.rs:285` `pub fn get_current(&self) -> Option<&str> {`
- `crates/sb-core/src/outbound/socks5_udp.rs:33` `pub async fn create(ep: ProxyEndpoint, timeout_ms: u64) -> Result<Self> {`
- `crates/sb-core/src/outbound/socks5_udp.rs:133` `pub async fn send_to(&self, dst: SocketAddr, payload: &[u8]) -> Result<usize> {`
- `crates/sb-core/src/outbound/socks5_udp.rs:159` `pub async fn send_to_ip(&self, ip: IpAddr, port: u16, payload: &[u8]) -> Result<usize> {`
- `crates/sb-core/src/outbound/socks5_udp.rs:165` `pub async fn recv_once(&self, timeout_ms: u64) -> Result<Option<(SocketAddr, Vec<u8>)>> {`
- `crates/sb-core/src/outbound/socks5_udp.rs:229` `pub fn strip_udp_reply(pkt: &[u8]) -> Result<(SocketAddr, &[u8])> {`
- `crates/sb-core/src/outbound/socks_upstream.rs:17` `pub fn new(server: String, port: u16, user: Option<String>, pass: Option<String>) -> Self {`
- `crates/sb-core/src/outbound/tcp.rs:6` `pub async fn connect_direct(authority: &str) -> anyhow::Result<TcpStream> {`
- `crates/sb-core/src/outbound/tcp.rs:17` `pub async fn connect_via_http_proxy(authority: &str) -> anyhow::Result<TcpStream> {`
- `crates/sb-core/src/outbound/tcp.rs:54` `pub async fn connect_auto(authority: &str, decision: &str) -> anyhow::Result<TcpStream> {`
- `crates/sb-core/src/outbound/udp.rs:64` `pub async fn resolve_target_socketaddr( dst: &UdpTargetAddr, ) -> anyhow::Result<std::net::SocketAddr> {`
- `crates/sb-core/src/outbound/udp.rs:95` `pub async fn direct_udp_socket_for(dst: &UdpTargetAddr) -> Result<UdpSocket> {`
- `crates/sb-core/src/outbound/udp.rs:119` `pub async fn direct_sendto(sock: &UdpSocket, dst: &UdpTargetAddr, payload: &[u8]) -> Result<usize> {`
- `crates/sb-core/src/outbound/udp_balancer.rs:72` `pub async fn send_balanced( payload: &[u8], dst: &UdpTargetAddr, decision: &str, ) -> anyhow::Result<usize> {`
- `crates/sb-core/src/outbound/udp_direct.rs:6` `pub async fn connect_udp(dst: SocketAddr) -> Result<UdpSocket> {`
- `crates/sb-core/src/outbound/udp_proxy_glue.rs:44` `pub async fn ensure_client_assoc(listen: Arc<UdpSocket>, client: SocketAddr) -> anyhow::Result<()> {`
- `crates/sb-core/src/outbound/udp_proxy_glue.rs:101` `pub async fn send_via_proxy_for_client( client: SocketAddr, payload: &[u8], dst: SocketAddr, ) -> anyhow::Result<usize> {`
- `crates/sb-core/src/outbound/udp_socks5.rs:26` `pub async fn create_upstream_socket() -> anyhow::Result<UdpSocket> {`
- `crates/sb-core/src/outbound/udp_socks5.rs:35` `pub async fn ensure_udp_relay() -> anyhow::Result<SocketAddr> {`
- `crates/sb-core/src/outbound/udp_socks5.rs:58` `pub async fn ensure_udp_relay_at(proxy: SocketAddr) -> anyhow::Result<SocketAddr> {`
- `crates/sb-core/src/outbound/udp_socks5.rs:89` `pub async fn sendto_via_socks5( _listen_sock: &UdpSocket, buf: &[u8], dst: &UdpTargetAddr, ) -> anyhow::Result<usize> {`
- `crates/sb-core/src/outbound/udp_socks5.rs:110` `pub async fn sendto_via_socks5_addr( proxy: SocketAddr, payload: &[u8], dst: &SocketAddr, ) -> anyhow::Result<usize> {`
- `crates/sb-core/src/outbound/udp_socks5.rs:136` `pub async fn send_auto( _listen_sock: &UdpSocket, buf: &[u8], dst: &UdpTargetAddr, decision: &str, ) -> anyhow::Result<usize> {`
- `crates/sb-core/src/outbound/udp_socks5.rs:157` `pub async fn sendto_via_socks5_on( sock: &UdpSocket, payload: &[u8], dst: &SocketAddr, relay: SocketAddr, ) -> anyhow::Result<usize> {`
- `crates/sb-core/src/outbound/udp_socks5.rs:173` `pub async fn recv_from_via_socks5(sock: &UdpSocket) -> anyhow::Result<(SocketAddr, Vec<u8>)> {`
- `crates/sb-core/src/pipeline.rs:35` `pub async fn run(self) -> anyhow::Result<()> {`
- `crates/sb-core/src/pointer.rs:82` `pub fn last_segment(&self) -> Option<&str> {`
- `crates/sb-core/src/router/advanced.rs:192` `pub fn evaluate(&mut self, t: &Target) -> Option<&Action> {`
- `crates/sb-core/src/router/analyze_fix.rs:19` `pub fn build_portrange_merge_patch( report: &Report, _original_text: &str, file: Option<&str>, ) -> Option<CliPatch> {`
- `crates/sb-core/src/router/analyze_fix.rs:88` `pub fn build_suffix_shadow_cleanup_patch(report: &Report, file: Option<&str>) -> Option<CliPatch> {`
- `crates/sb-core/src/router/analyze_fix.rs:123` `pub fn build_port_aggregate_patch(original_text: &str, file: Option<&str>) -> Option<CliPatch> {`
- `crates/sb-core/src/router/analyze_fix.rs:180` `pub fn build_lint_autofix_patch( report: &Report, original_text: &str, file: Option<&str>, ) -> Option<CliPatch> {`
- `crates/sb-core/src/router/builder.rs:16` `pub fn build_index_from_ir(cfg: &ConfigIR) -> Result<Arc<RouterIndex>, String> {`
- `crates/sb-core/src/router/cache_hot.rs:20` `pub fn snapshot(limit: usize) -> Option<Vec<HotItem>> {`
- `crates/sb-core/src/router/cache_stats.rs:23` `pub fn snapshot() -> Option<CacheStats> {`
- `crates/sb-core/src/router/cache_wire.rs:95` `pub fn get(&self, k: &str) -> Option<u64> {`
- `crates/sb-core/src/router/conn.rs:61` `pub fn port_protocol(port: u16) -> Option<&'static str> {`
- `crates/sb-core/src/router/conn.rs:73` `pub fn protocol_timeout(protocol: &str) -> Option<Duration> {`
- `crates/sb-core/src/router/conn.rs:427` `pub fn with_stats(mut self, stats: Option<Arc<StatsManager>>) -> Self {`
- `crates/sb-core/src/router/dns.rs:41` `pub fn resolve_cached_or_lookup(&self, host: &str) -> Option<Vec<IpAddr>> {`
- `crates/sb-core/src/router/dns_integration.rs:124` `pub fn validate_dns_integration(router: &RouterHandle) -> Result<(), String> {`
- `crates/sb-core/src/router/dsl_derive.rs:105` `pub fn derive_targets(dsl_text: &str, limit: Option<usize>) -> Vec<String> {`
- `crates/sb-core/src/router/dsl_derive.rs:161` `pub fn derive_compare_targets( dsl_a: &str, dsl_b: &str, input_targets: Option<&str>, limit: Option<usize>, ) -> Vec<String> {`
- `crates/sb-core/src/router/dsl_plus.rs:17` `pub fn expand_dsl_plus(input: &str, cwd: Option<&Path>) -> Result<String, String> {`
- `crates/sb-core/src/router/engine.rs:452` `pub fn with_geoip_file<P: AsRef<std::path::Path>>( mut self, path: P, ) -> crate::error::SbResult<Self> {`
- `crates/sb-core/src/router/engine.rs:465` `pub fn geoip_db(&self) -> Option<&std::sync::Arc<crate::router::geo::GeoIpDb>> {`
- `crates/sb-core/src/router/engine.rs:491` `pub fn with_geosite_file<P: AsRef<std::path::Path>>( mut self, path: P, ) -> crate::error::SbResult<Self> {`
- `crates/sb-core/src/router/engine.rs:504` `pub fn geosite_db(&self) -> Option<&std::sync::Arc<crate::router::geo::GeoSiteDb>> {`
- `crates/sb-core/src/router/engine.rs:518` `pub fn rule_set_db(&self) -> Option<&std::sync::Arc<crate::router::rule_set::RuleSetDb>> {`
- `crates/sb-core/src/router/engine.rs:532` `pub fn enhanced_geoip_lookup( &self, ip: IpAddr, idx: &crate::router::RouterIndex, ) -> Option<&'static str> {`
- `crates/sb-core/src/router/engine.rs:581` `pub fn enhanced_geosite_lookup( &self, domain: &str, idx: &crate::router::RouterIndex, ) -> Option<&'static str> {`
- `crates/sb-core/src/router/engine.rs:755` `pub async fn replace_index(&self, new_index: Arc<RouterIndex>) -> Result<(), String> {`
- `crates/sb-core/src/router/engine.rs:1336` `pub fn select_ctx_and_record_with_meta(&self, ctx: RouteCtx) -> (RouteTarget, Option<String>) {`
- `crates/sb-core/src/router/engine.rs:1583` `pub fn export_rules_json(&self) -> Result<serde_json::Value, String> {`
- `crates/sb-core/src/router/engine.rs:1676` `pub fn export_and_rebuild(&self) -> Result<(), String> {`
- `crates/sb-core/src/router/engine.rs:1683` `pub fn geo_cc(&self, ip: std::net::IpAddr) -> Option<String> {`
- `crates/sb-core/src/router/engine.rs:1688` `pub fn rules_geo(&self) -> Option<Vec<GeoRuleView>> {`
- `crates/sb-core/src/router/engine.rs:1693` `pub fn rules_exact(&self) -> Option<Vec<ExactRuleView>> {`
- `crates/sb-core/src/router/engine.rs:2098` `pub fn get_geoip_db(&self) -> Option<&std::sync::Arc<crate::router::geo::GeoIpDb>> {`
- `crates/sb-core/src/router/explain_bridge.rs:76` `pub fn rebuild_index(rules_json: &serde_json::Value) -> Result<(), String> {`
- `crates/sb-core/src/router/explain_index.rs:199` `pub fn match_override_exact(&self, host: &str) -> Option<(&ExactRule, String)> {`
- `crates/sb-core/src/router/explain_index.rs:206` `pub fn match_override_suffix(&self, host: &str) -> Option<(&SuffixRule, String)> {`
- `crates/sb-core/src/router/explain_index.rs:213` `pub fn match_cidr(&self, ip: Option<IpAddr>) -> Option<(&CidrRule, String)> {`
- `crates/sb-core/src/router/explain_index.rs:223` `pub fn match_geo_cc(&self, cc: &str) -> Option<(&GeoRule, String)> {`
- `crates/sb-core/src/router/explain_index.rs:230` `pub fn match_suffix(&self, host: &str) -> Option<(&SuffixRule, String)> {`
- `crates/sb-core/src/router/explain_index.rs:237` `pub fn match_exact(&self, host: &str) -> Option<(&ExactRule, String)> {`
- `crates/sb-core/src/router/explain_util.rs:4` `pub fn try_override( _r: &RouterHandle, _q: &super::explain::ExplainQuery, ) -> Option<(String, String)> {`
- `crates/sb-core/src/router/explain_util.rs:32` `pub fn try_cidr(_r: &RouterHandle, ip: Option<IpAddr>) -> Option<(String, String)> {`
- `crates/sb-core/src/router/explain_util.rs:85` `pub fn try_geo(_r: &RouterHandle, ip: Option<IpAddr>) -> Option<(String, String)> {`
- `crates/sb-core/src/router/explain_util.rs:120` `pub fn try_suffix(_r: &RouterHandle, sni: &str) -> Option<(String, String)> {`
- `crates/sb-core/src/router/explain_util.rs:156` `pub fn try_exact(_r: &RouterHandle, sni: &str) -> Option<(String, String)> {`
- `crates/sb-core/src/router/geo.rs:30` `pub fn load_from_file(path: &Path) -> SbResult<Self> {`
- `crates/sb-core/src/router/geo.rs:52` `pub fn lookup_country(&self, ip: IpAddr) -> Option<String> {`
- `crates/sb-core/src/router/geo.rs:64` `pub fn export_country(&self, _country: &str) -> anyhow::Result<Vec<String>> {`
- `crates/sb-core/src/router/geo.rs:155` `pub fn lookup_country(&self, ip: IpAddr) -> Option<String> {`
- `crates/sb-core/src/router/geo.rs:277` `pub fn load_from_file(path: &Path) -> SbResult<Self> {`
- `crates/sb-core/src/router/geo.rs:376` `pub fn category_rules(&self, category: &str) -> anyhow::Result<CategoryRules> {`
- `crates/sb-core/src/router/hot_reload.rs:106` `pub async fn start(&mut self) -> Result<(), HotReloadError> {`
- `crates/sb-core/src/router/hot_reload.rs:430` `pub async fn validate_rule_set( content: &str, max_rules: usize, ) -> Result<Arc<RouterIndex>, HotReloadError> {`
- `crates/sb-core/src/router/hot_reload_cli.rs:37` `pub async fn start_hot_reload_cli( config: HotReloadCliConfig, ) -> Result<(), Box<dyn std::error::Error>> {`
- `crates/sb-core/src/router/hot_reload_cli.rs:125` `pub async fn validate_rule_files( rule_files: &[PathBuf], max_rules: usize, ) -> Result<(), Box<dyn std::error::Error>> {`
- `crates/sb-core/src/router/hot_reload_cli.rs:168` `pub async fn show_rule_stats(rule_files: &[PathBuf]) -> Result<(), Box<dyn std::error::Error>> {`
- `crates/sb-core/src/router/keyword.rs:14` `pub fn find(&self, haystack: &str) -> Option<aho_corasick::Match> {`
- `crates/sb-core/src/router/keyword.rs:65` `pub fn find_idx(&self, hay: &str) -> Option<usize> {`
- `crates/sb-core/src/router/matcher.rs:104` `pub fn match_kind(&self, host: &str) -> Option<&'static str> {`
- `crates/sb-core/src/router/matcher.rs:177` `pub fn load<I>(&mut self, cidrs: I) -> anyhow::Result<()> where I: IntoIterator<Item = String>, {`
- `crates/sb-core/src/router/matchers.rs:44` `pub fn match_with_rules(host: &str, exact: &[String], suffix: &[String], keyword: &[String]) -> Option<&'static str> {`
- `crates/sb-core/src/router/mod.rs:381` `pub fn trial_decide_by_suffix(&self, host: &str) -> Option<&'static str> {`
- `crates/sb-core/src/router/mod.rs:541` `pub fn router_build_index_from_str( rules: &str, max: usize, ) -> Result<Arc<RouterIndex>, BuildError> {`
- `crates/sb-core/src/router/mod.rs:1451` `pub fn router_index_decide_exact_suffix(idx: &RouterIndex, host: &str) -> Option<&'static str> {`
- `crates/sb-core/src/router/mod.rs:1492` `pub fn router_index_decide_transport_port( idx: &RouterIndex, port: Option<u16>, transport: Option<&str>, ) -> Option<&'static str> {`
- `crates/sb-core/src/router/mod.rs:1528` `pub fn router_index_decide_transport_port_with_kind( idx: &RouterIndex, port: Option<u16>, transport: Option<&str>, ) -> Option<(&'static str, &'static str)> {`
- `crates/sb-core/src/router/mod.rs:1563` `pub fn router_index_decide_ip(idx: &RouterIndex, ip: IpAddr) -> Option<&'static str> {`
- `crates/sb-core/src/router/mod.rs:1600` `pub fn router_index_decide_geosite( idx: &RouterIndex, domain: &str, geosite_db: &crate::router::geo::GeoSiteDb, ) -> Option<&'static str> {`
- `crates/sb-core/src/router/mod.rs:1615` `pub fn router_index_decide_wifi_ssid(idx: &RouterIndex, ssid: &str) -> Option<&'static str> {`
- `crates/sb-core/src/router/mod.rs:1625` `pub fn router_index_decide_wifi_bssid(idx: &RouterIndex, bssid: &str) -> Option<&'static str> {`
- `crates/sb-core/src/router/mod.rs:1635` `pub fn router_index_decide_rule_set(idx: &RouterIndex, input: &Input) -> Option<&'static str> {`
- `crates/sb-core/src/router/mod.rs:1649` `pub fn router_index_decide_process(idx: &RouterIndex, process: &str) -> Option<&'static str> {`
- `crates/sb-core/src/router/mod.rs:1659` `pub fn router_index_decide_process_path(idx: &RouterIndex, path: &str) -> Option<&'static str> {`
- `crates/sb-core/src/router/mod.rs:1669` `pub fn router_index_decide_protocol(idx: &RouterIndex, protocol: &str) -> Option<&'static str> {`
- `crates/sb-core/src/router/mod.rs:1679` `pub fn router_index_decide_network(idx: &RouterIndex, network: &str) -> Option<&'static str> {`
- `crates/sb-core/src/router/mod.rs:1689` `pub fn router_index_decide_source(idx: &RouterIndex, source: &str) -> Option<&'static str> {`
- `crates/sb-core/src/router/mod.rs:1699` `pub fn router_index_decide_dest(idx: &RouterIndex, dest: &str) -> Option<&'static str> {`
- `crates/sb-core/src/router/mod.rs:1709` `pub fn router_index_decide_user_agent(idx: &RouterIndex, ua: &str) -> Option<&'static str> {`
- `crates/sb-core/src/router/mod.rs:1927` `pub async fn spawn_rules_hot_reload( shared: Arc<RwLock<Arc<RouterIndex>>>, ) -> Result<tokio::task::JoinHandle<()>, BuildError> {`
- `crates/sb-core/src/router/mod.rs:2576` `pub fn runtime_override_http( host_norm: &str, port: Option<u16>, ) -> Option<(&'static str, &'static str)> {`
- `crates/sb-core/src/router/mod.rs:2632` `pub fn runtime_override_udp(host_norm: &str) -> Option<(&'static str, &'static str)> {`
- `crates/sb-core/src/router/mod.rs:2766` `pub fn router_captured_rules() -> Option<String> {`
- `crates/sb-core/src/router/mod.rs:2879` `pub fn router_index_decide_keyword(idx: &RouterIndex, host: &str) -> Option<&'static str> {`
- `crates/sb-core/src/router/mod.rs:2893` `pub fn router_index_decide_keyword_static( idx: &RouterIndex, host_norm: &str, ) -> Option<&'static str> {`
- `crates/sb-core/src/router/patch_apply.rs:15` `pub fn apply_cli_patch(original: &str, patch: &str) -> Result<String, ApplyError> {`
- `crates/sb-core/src/router/patch_plan.rs:40` `pub fn build_plan(text: &str, kinds: &[&str], file: Option<&str>) -> PlanResult {`
- `crates/sb-core/src/router/patch_plan.rs:81` `pub fn build_plan(_text: &str, _kinds: &[&str], _file: Option<&str>) -> PlanResult {`
- `crates/sb-core/src/router/preview.rs:12` `pub fn build_index_from_rules(text: &str) -> Result<Arc<RouterIndex>, String> {`
- `crates/sb-core/src/router/preview.rs:169` `pub fn build_index_from_rules_plus( dsl_text: &str, cwd: Option<&std::path::Path>, ) -> Result<Arc<RouterIndex>, String> {`
- `crates/sb-core/src/router/process_router.rs:22` `pub fn new(engine: Engine) -> Result<Self, ProcessMatchError> {`
- `crates/sb-core/src/router/process_router.rs:30` `pub async fn decide_with_process( &self, domain: Option<&str>, ip: Option<std::net::IpAddr>, transport_udp: bool, port: Option<u16>, local_addr: SocketAddr, remote_addr: SocketAddr, ) -> Decision {`
- `crates/sb-core/src/router/process_router.rs:65` `pub async fn decide_with_process_meta( &self, domain: Option<&str>, ip: Option<std::net::IpAddr>, transport_udp: bool, port: Option<u16>, local_addr: SocketAddr, remote_addr: SocketAddr, ) -> (Decision, Option<String>) {`
- `crates/sb-core/src/router/process_router.rs:98` `pub async fn decide_without_process( &self, domain: Option<&str>, ip: Option<std::net::IpAddr>, transport_udp: bool, port: Option<u16>, ) -> Decision {`
- `crates/sb-core/src/router/process_router.rs:120` `pub async fn decide_without_process_meta( &self, domain: Option<&str>, ip: Option<std::net::IpAddr>, transport_udp: bool, port: Option<u16>, ) -> (Decision, Option<String>) {`
- `crates/sb-core/src/router/rule_set.rs:47` `pub async fn start(&self, stage: RuleSetStage) -> Result<()> {`
- `crates/sb-core/src/router/rule_set.rs:159` `pub fn current_stage(&self) -> Option<RuleSetStage> {`
- `crates/sb-core/src/router/rule_set.rs:164` `pub fn add_rule_set(&self, tag: String, path: &str, format_str: &str) -> Result<(), String> {`
- `crates/sb-core/src/router/rules.rs:132` `pub fn new(pattern: String) -> Result<Self, regex::Error> {`
- `crates/sb-core/src/router/rules.rs:341` `pub fn new(pattern: String) -> Result<Self, regex::Error> {`
- `crates/sb-core/src/router/rules.rs:396` `pub fn parse(pattern: &str) -> Result<Self, String> {`
- `crates/sb-core/src/router/rules.rs:1800` `pub fn decide_with_meta(&self, ctx: &RouteCtx) -> (Decision, Option<String>) {`
- `crates/sb-core/src/router/rules.rs:2079` `pub fn parse_decision(s: &str) -> Option<Self> {`
- `crates/sb-core/src/router/rules.rs:2106` `pub fn global() -> Option<&'static Engine> {`
- `crates/sb-core/src/router/rules_capture.rs:17` `pub fn get() -> Option<String> {`
- `crates/sb-core/src/router/ruleset/adguard.rs:39` `pub fn parse_adguard_rules(input: &str) -> anyhow::Result<Vec<serde_json::Value>> {`
- `crates/sb-core/src/router/ruleset/binary.rs:37` `pub async fn load_from_file(path: &Path, format: RuleSetFormat) -> SbResult<RuleSet> {`
- `crates/sb-core/src/router/ruleset/binary.rs:52` `pub fn parse_binary(data: &[u8], source: RuleSetSource) -> SbResult<RuleSet> {`
- `crates/sb-core/src/router/ruleset/binary.rs:125` `pub fn parse_json(data: &[u8], source: RuleSetSource) -> SbResult<RuleSet> {`
- `crates/sb-core/src/router/ruleset/binary.rs:725` `pub async fn write_to_file(path: &Path, rules: &[Rule], version: u8) -> SbResult<()> {`
- `crates/sb-core/src/router/ruleset/mod.rs:169` `pub fn parse(s: &str) -> SbResult<Self> {`
- `crates/sb-core/src/router/ruleset/mod.rs:435` `pub async fn load( &self, tag: String, source: RuleSetSource, format: RuleSetFormat, ) -> SbResult<Arc<RuleSet>> {`
- `crates/sb-core/src/router/ruleset/mod.rs:469` `pub fn get(&self, tag: &str) -> Option<Arc<RuleSet>> {`
- `crates/sb-core/src/router/ruleset/remote.rs:19` `pub async fn load_from_url( url: &str, cache_dir: &Path, format: RuleSetFormat, ) -> SbResult<RuleSet> {`
- `crates/sb-core/src/router/ruleset/source.rs:4` `pub fn infer_format_from_path(path: &str) -> Option<super::RuleSetFormat> {`
- `crates/sb-core/src/router/ruleset/source.rs:15` `pub fn infer_format_from_url(url: &str) -> Option<super::RuleSetFormat> {`
- `crates/sb-core/src/router/sniff.rs:42` `pub fn sniff_tls_client_hello(buf: &[u8]) -> Option<TlsClientHelloInfo> {`
- `crates/sb-core/src/router/sniff.rs:184` `pub fn sniff_quic_initial(buf: &[u8]) -> Option<&'static str> {`
- `crates/sb-core/src/router/sniff.rs:208` `pub fn extract_sni_from_tls_client_hello(buf: &[u8]) -> Option<String> {`
- `crates/sb-core/src/router/sniff.rs:215` `pub fn extract_http_host_from_request(buf: &[u8]) -> Option<String> {`
- `crates/sb-core/src/router/sniff.rs:325` `pub fn sniff_datagram_multi(buf: &[u8]) -> (SniffOutcome, Option<QuicReassembly>) {`
- `crates/sb-core/src/router/sniff.rs:395` `pub fn sniff_datagram_continue( buf: &[u8], ctx: QuicReassembly, ) -> (Option<SniffOutcome>, Option<QuicReassembly>) {`
- `crates/sb-core/src/router/sniff.rs:537` `pub fn sniff_dns_query(buf: &[u8]) -> Option<DnsQueryInfo> {`
- `crates/sb-core/src/router/sniff_quic.rs:104` `pub fn sniff_quic_sni(buf: &[u8]) -> Option<SniffOutcome> {`
- `crates/sb-core/src/router/sniff_quic.rs:704` `pub fn sniff_quic_sni_multi(buf: &[u8], state: Option<QuicReassembly>) -> SniffQuicResult {`
- `crates/sb-core/src/router/suffix_trie.rs:50` `pub fn query(&self, host: &str) -> Option<&'static str> {`
- `crates/sb-core/src/routing/explain.rs:61` `pub fn from_config(cfg: &sb_config::Config) -> anyhow::Result<ExplainEngine> {`
- `crates/sb-core/src/routing/matcher.rs:116` `pub fn update(&mut self, route: &RouteIR) -> Result<()> {`
- `crates/sb-core/src/routing/matcher.rs:127` `pub fn decide( &self, host: Option<&str>, ip: Option<IpAddr>, port: Option<u16>, network: Option<&str>, ) -> Option<&str> {`
- `crates/sb-core/src/routing/router.rs:16` `pub fn new(_config: RouterConfig) -> Result<Self> {`
- `crates/sb-core/src/routing/router.rs:24` `pub async fn reload(&mut self, config_json: &Value) -> Result<()> {`
- `crates/sb-core/src/routing/router.rs:35` `pub async fn route(&self, _req: &str) -> Result<String> {`
- `crates/sb-core/src/runtime/mod.rs:58` `pub fn from_config_ir(ir: &ConfigIR) -> crate::error::SbResult<Self> {`
- `crates/sb-core/src/runtime/mod.rs:143` `pub fn engine(&self) -> Result<(), anyhow::Error> {`
- `crates/sb-core/src/runtime/mod.rs:175` `pub fn dummy_engine() -> Result<(), anyhow::Error> {`
- `crates/sb-core/src/runtime/supervisor.rs:148` `pub async fn start(ir: sb_config::ir::ConfigIR) -> Result<Self> {`
- `crates/sb-core/src/runtime/supervisor.rs:154` `pub async fn start_with_registry( ir: sb_config::ir::ConfigIR, adapter_registry: Option<crate::adapter::registry::RegistrySnapshot>, ) -> Result<Self> {`
- `crates/sb-core/src/runtime/supervisor.rs:328` `pub async fn start(ir: sb_config::ir::ConfigIR) -> Result<Self> {`
- `crates/sb-core/src/runtime/supervisor.rs:334` `pub async fn start_with_registry( ir: sb_config::ir::ConfigIR, adapter_registry: Option<crate::adapter::registry::RegistrySnapshot>, ) -> Result<Self> {`
- `crates/sb-core/src/runtime/supervisor.rs:494` `pub async fn reload(&self, new_ir: sb_config::ir::ConfigIR) -> Result<Diff> {`
- `crates/sb-core/src/runtime/supervisor.rs:528` `pub async fn shutdown_graceful(self, dur: Duration) -> Result<()> {`
- `crates/sb-core/src/runtime/supervisor.rs:988` `pub async fn shutdown_graceful(&self, dur: Duration) -> Result<()> {`
- `crates/sb-core/src/runtime/supervisor.rs:1001` `pub async fn reload(&self, new_ir: sb_config::ir::ConfigIR) -> Result<Diff> {`
- `crates/sb-core/src/runtime/supervisor.rs:1566` `pub fn from_ir(ir: &sb_config::ir::ConfigIR) -> Result<Engine> {`
- `crates/sb-core/src/runtime/supervisor.rs:1572` `pub fn engine_from_ir(_ir: &sb_config::ir::ConfigIR) -> Result<()> {`
- `crates/sb-core/src/runtime/supervisor.rs:1578` `pub fn from_ir(ir: &sb_config::ir::ConfigIR) -> Result<Self> {`
- `crates/sb-core/src/runtime/switchboard.rs:186` `pub fn register<C>(&mut self, name: String, connector: C) -> SbResult<()> where C: OutboundConnector + 'static, {`
- `crates/sb-core/src/runtime/switchboard.rs:227` `pub fn set_default<C>(&mut self, connector: C) -> SbResult<()> where C: OutboundConnector + 'static, {`
- `crates/sb-core/src/runtime/switchboard.rs:270` `pub fn get_connector(&self, name: &str) -> Option<Arc<dyn OutboundConnector>> {`
- `crates/sb-core/src/runtime/switchboard.rs:293` `pub fn register_udp_factory( &mut self, name: String, f: Arc<dyn crate::adapter::UdpOutboundFactory>, ) -> SbResult<()> {`
- `crates/sb-core/src/runtime/switchboard.rs:303` `pub fn get_udp_factory( &self, name: &str, ) -> Option<Arc<dyn crate::adapter::UdpOutboundFactory>> {`
- `crates/sb-core/src/runtime/switchboard.rs:355` `pub fn from_config_ir(ir: &sb_config::ir::ConfigIR) -> SbResult<OutboundSwitchboard> {`
- `crates/sb-core/src/runtime/transport.rs:393` `pub fn tls_override_from_ob(ob: &OutboundIR) -> Option<std::sync::Arc<rustls::ClientConfig>> {`
- `crates/sb-core/src/service.rs:140` `pub fn get(&self, ty: ServiceType) -> Option<ServiceBuilder> {`
- `crates/sb-core/src/service.rs:147` `pub fn build(&self, ir: &ServiceIR, ctx: &ServiceContext) -> Option<Arc<dyn Service>> {`
- `crates/sb-core/src/service.rs:222` `pub async fn get(&self, tag: &str) -> Option<Arc<dyn Service>> {`
- `crates/sb-core/src/service.rs:228` `pub async fn remove(&self, tag: &str) -> Option<Arc<dyn Service>> {`
- `crates/sb-core/src/services/cache_file.rs:325` `pub fn get_fakeip_by_domain(&self, domain: &str) -> Option<IpAddr> {`
- `crates/sb-core/src/services/cache_file.rs:342` `pub fn get_domain_by_fakeip(&self, ip: &IpAddr) -> Option<String> {`
- `crates/sb-core/src/services/cache_file.rs:465` `pub fn get_rdrc(&self, domain: &str) -> Option<Vec<IpAddr>> {`
- `crates/sb-core/src/services/cache_file.rs:573` `pub fn get_clash_mode(&self) -> Option<String> {`
- `crates/sb-core/src/services/cache_file.rs:611` `pub fn get_selected(&self, group: &str) -> Option<String> {`
- `crates/sb-core/src/services/cache_file.rs:654` `pub fn get_expand(&self, group: &str) -> Option<bool> {`
- `crates/sb-core/src/services/cache_file.rs:693` `pub fn get_rule_set(&self, tag: &str) -> Option<Vec<u8>> {`
- `crates/sb-core/src/services/derp/client_registry.rs:24` `pub fn send(&self, frame: DerpFrame) -> Result<(), String> {`
- `crates/sb-core/src/services/derp/client_registry.rs:124` `pub fn register_client( &self, public_key: PublicKey, addr: SocketAddr, tx: mpsc::UnboundedSender<DerpFrame>, ) -> Result<(), String> {`
- `crates/sb-core/src/services/derp/client_registry.rs:165` `pub fn unregister_client(&self, public_key: &PublicKey) -> Option<SocketAddr> {`
- `crates/sb-core/src/services/derp/client_registry.rs:186` `pub fn get_client(&self, public_key: &PublicKey) -> Option<ClientHandle> {`
- `crates/sb-core/src/services/derp/client_registry.rs:213` `pub fn send_to_client(&self, dst_key: &PublicKey, frame: DerpFrame) -> Result<(), String> {`
- `crates/sb-core/src/services/derp/client_registry.rs:224` `pub fn register_mesh_peer( &self, peer_key: PublicKey, tx: mpsc::UnboundedSender<DerpFrame>, ) -> Result<(), String> {`
- `crates/sb-core/src/services/derp/client_registry.rs:249` `pub fn register_mesh_forwarder( &self, peer_key: PublicKey, tx: mpsc::UnboundedSender<DerpFrame>, ) -> Result<(), String> {`
- `crates/sb-core/src/services/derp/client_registry.rs:288` `pub fn handle_forward_packet( &self, src_key: &PublicKey, dst_key: &PublicKey, packet: Vec<u8>, ) -> Result<(), String> {`
- `crates/sb-core/src/services/derp/client_registry.rs:312` `pub fn relay_packet( &self, src_key: &PublicKey, dst_key: &PublicKey, packet: Vec<u8>, ) -> Result<(), String> {`
- `crates/sb-core/src/services/derp/client_registry.rs:425` `pub fn register_mesh_watcher(&self, peer_key: PublicKey) -> Result<(), String> {`
- `crates/sb-core/src/services/derp/client_registry.rs:505` `pub fn send_existing_clients_to_mesh_watcher( &self, peer_key: &PublicKey, ) -> Result<(), String> {`
- `crates/sb-core/src/services/derp/server.rs:959` `pub fn from_ir( ir: &ServiceIR, ctx: &ServiceContext, ) -> Result<Arc<Self>, Box<dyn std::error::Error + Send + Sync>> {`
- `crates/sb-core/src/services/derp/server.rs:3483` `pub fn build_derp_service(ir: &ServiceIR, ctx: &ServiceContext) -> Option<Arc<dyn Service>> {`
- `crates/sb-core/src/services/dns_forwarder.rs:225` `pub fn build_dns_forwarder_service( ir: &ServiceIR, _ctx: &crate::service::ServiceContext, ) -> Option<Arc<dyn Service>> {`
- `crates/sb-core/src/services/ntp.rs:49` `pub fn spawn(self) -> Option<tokio::task::JoinHandle<()>> {`
- `crates/sb-core/src/services/ntp.rs:118` `pub fn ntp_offset_once(server: &str, timeout: Duration) -> Result<f64> {`
- `crates/sb-core/src/services/ssmapi/api.rs:112` `pub async fn add_user( State(state): State<ApiState>, body: Bytes, ) -> Result<StatusCode, (StatusCode, String)> {`
- `crates/sb-core/src/services/ssmapi/api.rs:126` `pub async fn get_user( State(state): State<ApiState>, Path(username): Path<String>, ) -> Result<Json<super::user::UserObject>, StatusCode> {`
- `crates/sb-core/src/services/ssmapi/registry.rs:26` `pub fn get_managed_ssm_server(tag: &str) -> Option<Arc<dyn ManagedSSMServer>> {`
- `crates/sb-core/src/services/ssmapi/server.rs:227` `pub fn from_ir( ir: &ServiceIR, _ctx: &ServiceContext, ) -> Result<Arc<Self>, Box<dyn std::error::Error + Send + Sync>> {`
- `crates/sb-core/src/services/ssmapi/server.rs:1069` `pub fn build_ssmapi_service(ir: &ServiceIR, ctx: &ServiceContext) -> Option<Arc<dyn Service>> {`
- `crates/sb-core/src/services/ssmapi/user.rs:34` `pub fn new(user_name: String, password: Option<String>) -> Self {`
- `crates/sb-core/src/services/ssmapi/user.rs:149` `pub fn get(&self, username: &str) -> Option<String> {`
- `crates/sb-core/src/services/ssmapi/user.rs:160` `pub fn add(&self, username: String, password: String) -> Result<(), UserError> {`
- `crates/sb-core/src/services/ssmapi/user.rs:177` `pub fn update(&self, username: &str, password: String) -> Result<(), UserError> {`
- `crates/sb-core/src/services/ssmapi/user.rs:194` `pub fn delete(&self, username: &str) -> Result<(), UserError> {`
- `crates/sb-core/src/services/ssmapi/user.rs:225` `pub fn set_users(&self, users_map: HashMap<String, String>) -> Result<(), UserError> {`
- `crates/sb-core/src/services/tailscale/coordinator.rs:148` `pub fn subscribe(&self) -> watch::Receiver<Option<NetworkMap>> {`
- `crates/sb-core/src/services/tailscale/coordinator.rs:159` `pub async fn start(&self) -> io::Result<()> {`
- `crates/sb-core/src/services/tailscale/crypto.rs:31` `pub fn new(local_private_key: &[u8], remote_public_key: &[u8]) -> Result<Self, CryptoError> {`
- `crates/sb-core/src/services/tailscale/crypto.rs:45` `pub fn new_responder( local_private_key: &[u8], remote_public_key: &[u8], ) -> Result<Self, CryptoError> {`
- `crates/sb-core/src/services/tailscale/crypto.rs:62` `pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {`
- `crates/sb-core/src/services/tailscale/crypto.rs:87` `pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {`
- `crates/sb-core/src/services/tailscale/crypto.rs:117` `pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {`
- `crates/sb-core/src/services/tailscale/crypto.rs:123` `pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {`
- `crates/sb-core/src/services/v2ray_api.rs:80` `pub fn new(cfg: Option<StatsIR>) -> Self {`
- `crates/sb-core/src/services/v2ray_api.rs:121` `pub fn get_stat(&self, name: &str) -> Option<u64> {`
- `crates/sb-core/src/services/v2ray_api.rs:197` `pub fn traffic_recorder( &self, inbound: Option<&str>, outbound: Option<&str>, user: Option<&str>, ) -> Option<Arc<dyn crate::net::metered::TrafficRecorder>> {`
- `crates/sb-core/src/socks5/mod.rs:8` `pub async fn greet_noauth(stream: &mut TcpStream) -> anyhow::Result<()> {`
- `crates/sb-core/src/socks5/mod.rs:20` `pub async fn udp_associate(stream: &mut TcpStream, bind: SocketAddr) -> anyhow::Result<SocketAddr> {`
- `crates/sb-core/src/socks5/mod.rs:117` `pub fn decode_udp_reply(buf: &[u8]) -> anyhow::Result<(SocketAddr, &[u8])> {`
- `crates/sb-core/src/tls/trust.rs:49` `pub fn mk_client(opts: &TlsOpts) -> Result<Arc<ClientConfig>, crate::error::SbError> {`
- `crates/sb-core/src/tls/trust.rs:104` `pub fn mk_client(_opts: &TlsOpts) -> Result<Arc<()>, crate::error::SbError> {`
- `crates/sb-core/src/transport/dialer.rs:54` `pub fn keepalive(mut self, d: Option<Duration>) -> Self {`
- `crates/sb-core/src/transport/dialer.rs:62` `pub fn recv_buffer_size(mut self, v: Option<u32>) -> Self {`
- `crates/sb-core/src/transport/dialer.rs:66` `pub fn send_buffer_size(mut self, v: Option<u32>) -> Self {`
- `crates/sb-core/src/transport/tls.rs:34` `pub async fn connect( &self, server_name: String, tcp_stream: TcpStream, ) -> anyhow::Result<tokio_rustls::client::TlsStream<TcpStream>> {`
- `crates/sb-core/src/transport/tls.rs:66` `pub async fn connect( &self, _server_name: String, _tcp_stream: TcpStream, ) -> anyhow::Result<()> {`
- `crates/sb-core/src/types.rs:78` `pub fn as_domain(&self) -> Option<&str> {`
- `crates/sb-core/src/types.rs:146` `pub fn to_socket_addr(&self) -> Option<SocketAddr> {`
- `crates/sb-core/src/util/fs_atomic.rs:7` `pub fn write_atomic<P: AsRef<Path>>(path: P, data: &[u8]) -> io::Result<()> {`
- `crates/sb-core/src/util/mod.rs:11` `pub fn secs_opt_to_duration(v: Option<u64>, default: u64) -> Duration {`
- `crates/sb-core/src/utils/timing.rs:5` `pub async fn race_timeout<F, T>(d: Duration, fut: F) -> Result<T, Elapsed> where F: std::future::Future<Output = T>, {`
- `crates/sb-metrics/src/lib.rs:203` `pub fn register_cloned<C>(&self, metric: &str, collector: &C) -> Result<(), prometheus::Error> where C: Collector + Clone + 'static, {`
- `crates/sb-metrics/src/lib.rs:230` `pub fn encode_text(&self) -> Result<Vec<u8>, prometheus::Error> {`
- `crates/sb-metrics/src/lib.rs:1060` `pub fn spawn_http_exporter_from_env(registry: MetricsRegistryHandle) -> Option<JoinHandle<()>> {`
- `crates/sb-platform/src/android_protect.rs:65` `pub fn protect_socket(fd: i32) -> io::Result<()> {`
- `crates/sb-platform/src/android_protect.rs:92` `pub fn protect_socket(_fd: i32) -> io::Result<()> {`
- `crates/sb-platform/src/android_protect.rs:98` `pub fn protect_tcp_socket(socket: &tokio::net::TcpSocket) -> io::Result<()> {`
- `crates/sb-platform/src/android_protect.rs:105` `pub fn protect_udp_socket(socket: &tokio::net::UdpSocket) -> io::Result<()> {`
- `crates/sb-platform/src/android_protect.rs:112` `pub fn protect_tcp_socket(_socket: &tokio::net::TcpSocket) -> io::Result<()> {`
- `crates/sb-platform/src/android_protect.rs:118` `pub fn protect_udp_socket(_socket: &tokio::net::UdpSocket) -> io::Result<()> {`
- `crates/sb-platform/src/monitor.rs:140` `pub fn start( &self, ) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error + Send + Sync>> {`
- `crates/sb-platform/src/monitor.rs:163` `pub fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {`
- `crates/sb-platform/src/network.rs:22` `pub fn get_interface_mac(iface: &str) -> Result<MacAddress, String> {`
- `crates/sb-platform/src/network.rs:197` `pub fn parse_mac_string(raw: &str) -> Option<MacAddress> {`
- `crates/sb-platform/src/process/android.rs:30` `pub fn new() -> Result<Self, ProcessMatchError> {`
- `crates/sb-platform/src/process/android.rs:50` `pub async fn find_process_id(&self, conn: &ConnectionInfo) -> Result<u32, ProcessMatchError> {`
- `crates/sb-platform/src/process/android.rs:58` `pub async fn get_process_info(&self, pid: u32) -> Result<ProcessInfo, ProcessMatchError> {`
- `crates/sb-platform/src/process/linux.rs:26` `pub fn new() -> Result<Self, ProcessMatchError> {`
- `crates/sb-platform/src/process/linux.rs:34` `pub async fn find_process_id(&self, conn: &ConnectionInfo) -> Result<u32, ProcessMatchError> {`
- `crates/sb-platform/src/process/linux.rs:46` `pub async fn get_process_info(&self, pid: u32) -> Result<ProcessInfo, ProcessMatchError> {`
- `crates/sb-platform/src/process/macos.rs:25` `pub fn new() -> Result<Self, ProcessMatchError> {`
- `crates/sb-platform/src/process/macos.rs:36` `pub async fn find_process_id(&self, conn: &ConnectionInfo) -> Result<u32, ProcessMatchError> {`
- `crates/sb-platform/src/process/macos.rs:48` `pub async fn get_process_info(&self, pid: u32) -> Result<ProcessInfo, ProcessMatchError> {`
- `crates/sb-platform/src/process/macos_common.rs:9` `pub async fn find_process_with_lsof(conn: &ConnectionInfo) -> Result<u32, ProcessMatchError> {`
- `crates/sb-platform/src/process/mod.rs:156` `pub fn new() -> Result<Self, ProcessMatchError> {`
- `crates/sb-platform/src/process/mod.rs:188` `pub async fn match_connection( &self, conn: &ConnectionInfo, ) -> Result<ProcessInfo, ProcessMatchError> {`
- `crates/sb-platform/src/process/native_macos.rs:44` `pub async fn find_process_id(&self, conn: &ConnectionInfo) -> Result<u32, ProcessMatchError> {`
- `crates/sb-platform/src/process/native_macos.rs:54` `pub async fn get_process_info(&self, pid: u32) -> Result<ProcessInfo, ProcessMatchError> {`
- `crates/sb-platform/src/process/native_windows.rs:83` `pub fn new() -> Result<Self, ProcessMatchError> {`
- `crates/sb-platform/src/process/native_windows.rs:88` `pub async fn find_process_id(&self, conn: &ConnectionInfo) -> Result<u32, ProcessMatchError> {`
- `crates/sb-platform/src/process/native_windows.rs:96` `pub async fn get_process_info(&self, pid: u32) -> Result<ProcessInfo, ProcessMatchError> {`
- `crates/sb-platform/src/process/windows.rs:24` `pub fn new() -> Result<Self, ProcessMatchError> {`
- `crates/sb-platform/src/process/windows.rs:35` `pub async fn find_process_id(&self, conn: &ConnectionInfo) -> Result<u32, ProcessMatchError> {`
- `crates/sb-platform/src/process/windows.rs:46` `pub async fn get_process_info(&self, pid: u32) -> Result<ProcessInfo, ProcessMatchError> {`
- `crates/sb-platform/src/system_proxy.rs:243` `pub fn enable(&self) -> io::Result<()> {`
- `crates/sb-platform/src/system_proxy.rs:305` `pub fn disable(&self) -> io::Result<()> {`
- `crates/sb-platform/src/tun/mod.rs:200` `pub fn new(config: &TunConfig) -> Result<Self, TunError> {`
- `crates/sb-platform/src/tun/mod.rs:214` `pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, TunError> {`
- `crates/sb-platform/src/tun/mod.rs:222` `pub fn write(&mut self, buf: &[u8]) -> Result<usize, TunError> {`
- `crates/sb-platform/src/tun/mod.rs:230` `pub fn close(&mut self) -> Result<(), TunError> {`
- `crates/sb-platform/src/tun/mod.rs:264` `pub fn create_platform_device(config: &TunConfig) -> Result<Box<dyn TunDevice>, TunError> {`
- `crates/sb-platform/src/tun/mod.rs:305` `pub fn create_device(&mut self, config: &TunConfig) -> Result<(), TunError> {`
- `crates/sb-platform/src/tun/mod.rs:316` `pub fn remove_device(&mut self, name: &str) -> Result<(), TunError> {`
- `crates/sb-platform/src/tun/mod.rs:324` `pub fn get_device(&mut self, name: &str) -> Option<&mut AsyncTunDevice> {`
- `crates/sb-platform/src/tun/mod.rs:341` `pub fn close_all(&mut self) -> Result<(), TunError> {`
- `crates/sb-platform/src/tun/windows.rs:305` `pub fn get_wintun_version() -> Result<String, TunError> {`
- `crates/sb-platform/src/tun/windows.rs:313` `pub fn list_adapters() -> Result<Vec<String>, TunError> {`
- `crates/sb-platform/src/wifi.rs:21` `pub fn get_wifi_info() -> Option<WifiInfo> {`
- `crates/sb-platform/src/wininet.rs:75` `pub fn detect_system_proxy() -> Option<ProxyConfig> {`
- `crates/sb-platform/src/wininet.rs:87` `pub fn detect_env_proxy() -> Option<ProxyConfig> {`
- `crates/sb-platform/src/wininet.rs:125` `pub fn detect_windows_proxy() -> Option<ProxyConfig> {`
- `crates/sb-platform/src/wininet.rs:208` `pub fn detect_windows_proxy() -> Option<ProxyConfig> {`
- `crates/sb-platform/src/wininet.rs:214` `pub fn set_system_proxy(config: &ProxyConfig) -> std::io::Result<()> {`
- `crates/sb-platform/src/wininet.rs:245` `pub fn set_system_proxy(_config: &ProxyConfig) -> std::io::Result<()> {`
- `crates/sb-proto/src/outbound_registry.rs:132` `pub fn ss2022_hello_bytes( name: &str, reg: &Registry, host: &str, port: u16, ) -> Result<Vec<u8>, RegistryError> {`
- `crates/sb-runtime/src/jsonl.rs:43` `pub fn stream_frames<P: AsRef<Path>>(p: P) -> Result<impl Iterator<Item = Result<Frame>>> {`
- `crates/sb-runtime/src/jsonl.rs:111` `pub fn basic_verify<P: AsRef<Path>>(p: P) -> Result<serde_json::Value> {`
- `crates/sb-runtime/src/jsonl.rs:205` `pub fn replay_decode<P: AsRef<Path>>( proto: &dyn crate::handshake::Handshake, p: P, strict: bool, ) -> Result<(usize, usize)> {`
- `crates/sb-runtime/src/loopback.rs:246` `pub fn log_frame(&self, frame: &Frame) -> Result<()> {`
- `crates/sb-runtime/src/loopback.rs:269` `pub fn stream_frames(&self) -> Result<impl Iterator<Item = Result<Frame>> + '_> {`
- `crates/sb-runtime/src/loopback.rs:311` `pub fn run_once<P: AsRef<Path>>( proto: &dyn Handshake, seed: u64, log_path: Option<P>, ) -> Result<SessionMetrics> {`
- `crates/sb-runtime/src/loopback.rs:401` `pub fn replay_decode( proto: &dyn Handshake, jsonl_path: &Path, strict: bool, ) -> Result<(usize, usize)> {`
- `crates/sb-runtime/src/scenario.rs:206` `pub fn run_file<P: AsRef<Path>>(p: P) -> Result<ScenarioSummary> {`
- `crates/sb-runtime/src/scenario.rs:295` `pub fn run(sc: ScenarioFile) -> Result<ScenarioSummary> {`
- `crates/sb-runtime/src/tcp_local.rs:59` `pub async fn io_local_once( proto: &dyn Handshake, target: SocketAddr, seed: u64, log_path: &std::path::Path, read_max: usize, to_ms: u64, chaos: Option<ChaosSpec>, ) -> Result<(usize, usize)> {`
- `crates/sb-runtime/src/tcp_local.rs:125` `pub async fn spawn_echo_once(bind: SocketAddr, xor_key: Option<u8>) -> Result<SocketAddr> {`
- `crates/sb-runtime/src/tcp_local.rs:150` `pub async fn io_local_with_optional_echo( proto: &dyn Handshake, config: IoLocalConfig<'_>, ) -> Result<(SocketAddr, usize, usize)> {`
- `crates/sb-security/src/key_loading.rs:177` `pub fn validate<F>(&self, validator: F) -> Result<(), KeyLoadingError> where F: FnOnce(&str) -> Result<(), String>, {`
- `crates/sb-security/src/key_loading.rs:228` `pub fn load(&mut self, source: &KeySource) -> Result<LoadedSecret, KeyLoadingError> {`
- `crates/sb-security/src/key_loading.rs:381` `pub fn min_length(min_len: usize) -> impl Fn(&str) -> Result<(), String> {`
- `crates/sb-security/src/key_loading.rs:396` `pub fn base64() -> impl Fn(&str) -> Result<(), String> {`
- `crates/sb-security/src/key_loading.rs:407` `pub fn hex() -> impl Fn(&str) -> Result<(), String> {`
- `crates/sb-security/src/key_loading.rs:418` `pub fn pattern(regex: &'static str) -> impl Fn(&str) -> Result<(), String> {`
- `crates/sb-security/src/key_loading.rs:431` `pub fn ascii_printable() -> impl Fn(&str) -> Result<(), String> {`
- `crates/sb-subscribe/src/bindings.rs:76` `pub async fn dry_connect_test(p: &Profile, target: Option<&str>) -> String {`
- `crates/sb-subscribe/src/bindings.rs:153` `pub async fn bindings_enhanced_minijson( p: &Profile, test_connect: bool, target: Option<&str>, ) -> String {`
- `crates/sb-subscribe/src/convert_full.rs:147` `pub fn convert_full_minijson( input: &str, format: &str, use_keyword: bool, normalize: bool, ) -> Result<String, String> {`
- `crates/sb-subscribe/src/diff_full.rs:129` `pub fn diff_full_minijson( lhs: &str, rhs: &str, format: &str, use_keyword: bool, normalize: bool, ) -> Result<DiffOutput, String> {`
- `crates/sb-subscribe/src/http.rs:37` `pub async fn fetch_text(url: &str) -> Result<String, SubsError> {`
- `crates/sb-subscribe/src/http.rs:57` `pub async fn fetch_with_retry( url: &str, cache_meta: Option<&FetchMeta>, ) -> Result<FetchResult, SubsError> {`
- `crates/sb-subscribe/src/lint.rs:73` `pub fn lint_minijson( input: &str, format: &str, use_keyword: bool, normalize: bool, ) -> Result<LintResult, String> {`
- `crates/sb-subscribe/src/parse_clash.rs:73` `pub fn parse_with_mode(yaml: &str, use_keyword: bool) -> Result<Profile, SubsError> {`
- `crates/sb-subscribe/src/parse_clash.rs:97` `pub fn parse(yaml: &str) -> Result<Profile, SubsError> {`
- `crates/sb-subscribe/src/parse_clash.rs:106` `pub fn parse_with_providers( yaml: &str, use_keyword: bool, providers: &HashMap<String, String>, ) -> Result<Profile, SubsError> {`
- `crates/sb-subscribe/src/parse_singbox.rs:81` `pub fn parse_with_mode(json: &str, use_keyword: bool) -> Result<Profile, SubsError> {`
- `crates/sb-subscribe/src/parse_singbox.rs:108` `pub fn parse(json: &str) -> Result<Profile, SubsError> {`
- `crates/sb-subscribe/src/preview_plan.rs:78` `pub fn field(&self, key: &str) -> Option<String> {`
- `crates/sb-subscribe/src/preview_plan.rs:110` `pub fn preview_plan_minijson( input: &str, format: &str, use_keyword: bool, normalize: bool, kinds: Option<&str>, apply: bool, ) -> Result<PlanOutput, String> {`
- `crates/sb-subscribe/src/provider_parse.rs:25` `pub fn parse_proxy_content(content: &str) -> Result<Vec<OutboundIR>, SubsError> {`
- `crates/sb-subscribe/src/provider_parse.rs:251` `pub fn parse_rule_content(content: &str) -> Result<Vec<String>, SubsError> {`
- `crates/sb-subscribe/src/providers.rs:24` `pub fn get(&mut self, name: &str) -> Option<&str> {`
- `crates/sb-test-utils/src/socks5.rs:89` `pub async fn start_mock_socks5() -> anyhow::Result<(SocketAddr, SocketAddr)> {`
- `crates/sb-tls/src/acme.rs:173` `pub async fn get_token(&self, token: &str) -> Option<String> {`
- `crates/sb-tls/src/acme.rs:205` `pub fn new(config: AcmeConfig) -> Result<Self, AcmeError> {`
- `crates/sb-tls/src/acme.rs:227` `pub fn with_dns_challenger( config: AcmeConfig, challenger: Arc<dyn DnsChallenger>, ) -> Result<Self, AcmeError> {`
- `crates/sb-tls/src/acme.rs:244` `pub async fn init(&self) -> Result<(), AcmeError> {`
- `crates/sb-tls/src/acme.rs:268` `pub async fn init(&self) -> Result<(), AcmeError> {`
- `crates/sb-tls/src/acme.rs:309` `pub async fn obtain_certificate(&self) -> Result<CertificateInfo, AcmeError> {`
- `crates/sb-tls/src/acme.rs:567` `pub async fn obtain_certificate(&self) -> Result<CertificateInfo, AcmeError> {`
- `crates/sb-tls/src/acme.rs:642` `pub async fn start_auto_renewal(self: Arc<Self>) -> Result<(), AcmeError> {`
- `crates/sb-tls/src/ech/config.rs:36` `pub fn from_base64(private_b64: &str, public_b64: &str) -> Result<Self, super::EchError> {`
- `crates/sb-tls/src/ech/config.rs:121` `pub fn new(config_base64: String) -> Result<Self, super::EchError> {`
- `crates/sb-tls/src/ech/config.rs:158` `pub fn validate(&self) -> Result<(), super::EchError> {`
- `crates/sb-tls/src/ech/config.rs:173` `pub fn to_rustls_ech_mode(&self) -> Result<rustls::client::EchMode, super::EchError> {`
- `crates/sb-tls/src/ech/config.rs:223` `pub fn validate(&self) -> Result<(), super::EchError> {`
- `crates/sb-tls/src/ech/hpke.rs:38` `pub fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> EchResult<Vec<u8>> {`
- `crates/sb-tls/src/ech/hpke.rs:100` `pub fn setup( &self, recipient_public_key: &[u8], info: &[u8], ) -> EchResult<(Vec<u8>, HpkeContext)> {`
- `crates/sb-tls/src/ech/mod.rs:143` `pub fn new(config: EchClientConfig) -> EchResult<Self> {`
- `crates/sb-tls/src/ech/mod.rs:183` `pub fn wrap_tls(&self, server_name: &str) -> EchResult<EchClientHello> {`
- `crates/sb-tls/src/ech/mod.rs:279` `pub fn verify_ech_acceptance(&self, server_hello: &[u8]) -> EchResult<bool> {`
- `crates/sb-tls/src/ech/mod.rs:337` `pub fn from_u16(value: u16) -> Option<Self> {`
- `crates/sb-tls/src/ech/mod.rs:359` `pub fn from_u16(value: u16) -> Option<Self> {`
- `crates/sb-tls/src/ech/mod.rs:385` `pub fn from_u16(value: u16) -> Option<Self> {`
- `crates/sb-tls/src/ech/mod.rs:409` `pub fn from_u16(value: u16) -> Option<Self> {`
- `crates/sb-tls/src/ech/parser.rs:120` `pub fn first(&self) -> Option<&EchConfig> {`
- `crates/sb-tls/src/ech/parser.rs:137` `pub fn parse_ech_config_list(data: &[u8]) -> EchResult<EchConfigList> {`
- `crates/sb-tls/src/global.rs:235` `pub fn start( ca_paths: &[String], ca_pems: &[String], cert_dirs: &[String], shutdown: tokio_util::sync::CancellationToken, ) -> Result<Self, notify::Error> {`
- `crates/sb-tls/src/reality/client.rs:53` `pub fn new(config: RealityClientConfig) -> RealityResult<Self> {`
- `crates/sb-tls/src/reality/config.rs:50` `pub fn validate(&self) -> Result<(), String> {`
- `crates/sb-tls/src/reality/config.rs:97` `pub fn public_key_bytes(&self) -> Result<[u8; 32], String> {`
- `crates/sb-tls/src/reality/config.rs:149` `pub fn validate(&self) -> Result<(), String> {`
- `crates/sb-tls/src/reality/config.rs:184` `pub fn private_key_bytes(&self) -> Result<[u8; 32], String> {`
- `crates/sb-tls/src/reality/server.rs:62` `pub fn new(config: RealityServerConfig) -> RealityResult<Self> {`
- `crates/sb-tls/src/reality/server.rs:106` `pub async fn accept<S>(&self, stream: S) -> RealityResult<RealityConnection> where S: AsyncRead + AsyncWrite + Unpin + Send + 'static, {`
- `crates/sb-tls/src/reality/server.rs:718` `pub async fn handle(self) -> io::Result<Option<crate::TlsIoStream>> {`
- `crates/sb-tls/src/reality/tls_record.rs:125` `pub async fn read_from<R: AsyncRead + Unpin>(stream: &mut R) -> io::Result<Self> {`
- `crates/sb-tls/src/reality/tls_record.rs:144` `pub async fn write_to<W: AsyncWrite + Unpin>(&self, stream: &mut W) -> io::Result<()> {`
- `crates/sb-tls/src/reality/tls_record.rs:172` `pub fn parse(data: &[u8]) -> io::Result<Self> {`
- `crates/sb-tls/src/reality/tls_record.rs:259` `pub fn serialize(&self) -> io::Result<Vec<u8>> {`
- `crates/sb-tls/src/reality/tls_record.rs:432` `pub fn parse_reality_auth(&self) -> io::Result<([u8; 32], Vec<u8>, [u8; 32])> {`
- `crates/sb-tls/src/standard.rs:55` `pub fn new() -> TlsResult<Self> {`
- `crates/sb-transport/src/derp/client.rs:66` `pub async fn connect(&self) -> io::Result<()> {`
- `crates/sb-transport/src/derp/client.rs:202` `pub async fn send_packet(&self, dst_key: PublicKey, packet: &[u8]) -> io::Result<()> {`
- `crates/sb-transport/src/derp/client.rs:225` `pub async fn recv_packet(&self) -> io::Result<(PublicKey, Vec<u8>)> {`
- `crates/sb-transport/src/derp/protocol.rs:86` `pub fn from_json(data: &[u8]) -> Result<Self, ProtocolError> {`
- `crates/sb-transport/src/derp/protocol.rs:199` `pub fn decode_node_private_key(s: &str) -> Result<PrivateKey, ProtocolError> {`
- `crates/sb-transport/src/derp/protocol.rs:243` `pub fn seal_to( sender_private: &PrivateKey, recipient_public: &PublicKey, cleartext: &[u8], ) -> Result<Vec<u8>, ProtocolError> {`
- `crates/sb-transport/src/derp/protocol.rs:264` `pub fn open_from( recipient_private: &PrivateKey, sender_public: &PublicKey, msgbox: &[u8], ) -> Result<Vec<u8>, ProtocolError> {`
- `crates/sb-transport/src/derp/protocol.rs:346` `pub fn from_u8(byte: u8) -> Result<Self, ProtocolError> {`
- `crates/sb-transport/src/derp/protocol.rs:518` `pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), ProtocolError> {`
- `crates/sb-transport/src/derp/protocol.rs:663` `pub fn read_from<R: Read>(reader: &mut R) -> Result<Self, ProtocolError> {`
- `crates/sb-transport/src/derp/protocol.rs:983` `pub fn to_bytes(&self) -> Result<Vec<u8>, ProtocolError> {`
- `crates/sb-transport/src/derp/protocol.rs:990` `pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {`
- `crates/sb-transport/src/derp/protocol.rs:996` `pub async fn write_to_async<W>(&self, writer: &mut W) -> Result<(), ProtocolError> where W: AsyncWriteExt + Unpin, {`
- `crates/sb-transport/src/derp/protocol.rs:1010` `pub async fn read_from_async<R>(reader: &mut R) -> Result<Self, ProtocolError> where R: AsyncReadExt + Unpin, {`
- `crates/sb-transport/src/grpc.rs:221` `pub async fn new(channel: Channel, _config: &GrpcConfig) -> Result<Self, DialError> {`
- `crates/sb-transport/src/grpc.rs:500` `pub async fn bind( bind_addr: std::net::SocketAddr, config: GrpcServerConfig, ) -> std::io::Result<Self> {`
- `crates/sb-transport/src/grpc.rs:567` `pub async fn accept(&self) -> Result<IoStream, DialError> {`
- `crates/sb-transport/src/grpc.rs:577` `pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {`
- `crates/sb-transport/src/grpc_lite.rs:125` `pub fn decode(buf: &mut BytesMut) -> io::Result<Option<Self>> {`
- `crates/sb-transport/src/http2.rs:483` `pub async fn accept(&self) -> Result<IoStream, DialError> {`
- `crates/sb-transport/src/http2.rs:572` `pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {`
- `crates/sb-transport/src/httpupgrade.rs:321` `pub async fn accept(&self) -> Result<IoStream, DialError> {`
- `crates/sb-transport/src/httpupgrade.rs:415` `pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {`
- `crates/sb-transport/src/multiplex.rs:665` `pub async fn accept(&self) -> Result<(IoStream, std::net::SocketAddr), DialError> {`
- `crates/sb-transport/src/multiplex.rs:674` `pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {`
- `crates/sb-transport/src/quic.rs:128` `pub fn new(config: QuicConfig) -> Result<Self, DialError> {`
- `crates/sb-transport/src/quic.rs:197` `pub fn with_default_config(server_name: &str) -> Result<Self, DialError> {`
- `crates/sb-transport/src/resource_pressure.rs:293` `pub async fn analyze_dial_error(error: &DialError) -> Option<ResourceType> {`
- `crates/sb-transport/src/retry.rs:162` `pub async fn execute<T, E, F, Fut>( &self, operation_kind: &str, operation: F, should_retry: impl Fn(&E) -> bool, ) -> Result<T, E> where F: Fn() -> Fut, Fut: std::future::Future<Output = Result<T, E>>, E: std::fmt::Display, {`
- `crates/sb-transport/src/sip003.rs:138` `pub async fn start(&mut self) -> io::Result<SocketAddr> {`
- `crates/sb-transport/src/sip003.rs:183` `pub async fn stop(&mut self) -> io::Result<()> {`
- `crates/sb-transport/src/sip003.rs:205` `pub fn local_addr(&self) -> Option<SocketAddr> {`
- `crates/sb-transport/src/sip003.rs:210` `pub async fn connect(&self) -> io::Result<TcpStream> {`
- `crates/sb-transport/src/sip003.rs:237` `pub async fn connect(config: Sip003Config) -> io::Result<Self> {`
- `crates/sb-transport/src/tailscale_dns.rs:112` `pub fn with_socket_factory<F, Fut>(mut self, factory: F) -> Self where F: Fn() -> Fut + Send + Sync + 'static, Fut: Future<Output = io::Result<UdpSocket>> + Send + 'static, {`
- `crates/sb-transport/src/tailscale_dns.rs:152` `pub async fn resolve(&self, hostname: &str) -> io::Result<Vec<IpAddr>> {`
- `crates/sb-transport/src/tailscale_dns.rs:441` `pub async fn probe(&self) -> io::Result<()> {`
- `crates/sb-transport/src/tailscale_dns.rs:449` `pub async fn send(&self, _peer_key: &[u8; 32], _data: &[u8]) -> io::Result<()> {`
- `crates/sb-transport/src/tailscale_dns.rs:456` `pub async fn recv(&self) -> io::Result<(Vec<u8>, [u8; 32])> {`
- `crates/sb-transport/src/tailscale_dns.rs:493` `pub async fn register(&self, _public_key: &[u8; 32]) -> io::Result<()> {`
- `crates/sb-transport/src/tailscale_dns.rs:501` `pub async fn get_peers(&self) -> io::Result<Vec<TailscalePeer>> {`
- `crates/sb-transport/src/tls.rs:436` `pub fn new(inner: D, config: sb_tls::RealityClientConfig) -> Result<Self, DialError> {`
- `crates/sb-transport/src/tls.rs:494` `pub fn from_env(inner: D) -> Result<Self, DialError> {`
- `crates/sb-transport/src/tls.rs:820` `pub fn new( inner: D, config: Arc<rustls::ClientConfig>, ech_config: sb_tls::EchClientConfig, ) -> Result<Self, DialError> {`
- `crates/sb-transport/src/tls.rs:902` `pub fn from_env(inner: D, config: Arc<rustls::ClientConfig>) -> Result<Self, DialError> {`
- `crates/sb-transport/src/tls.rs:1121` `pub fn serialize<S>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer, {`
- `crates/sb-transport/src/tls.rs:1131` `pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error> where D: Deserializer<'de>, {`
- `crates/sb-transport/src/tls.rs:1174` `pub async fn wrap_client<S>(&self, stream: S, server_name: &str) -> Result<IoStream, DialError> where S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static, {`
- `crates/sb-transport/src/tls.rs:1205` `pub async fn wrap_server<S>(&self, stream: S) -> Result<IoStream, DialError> where S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static, {`
- `crates/sb-transport/src/tls_secure.rs:97` `pub fn build_client_config( &self, ) -> Result<Arc<ClientConfig>, Box<dyn std::error::Error + Send + Sync>> {`
- `crates/sb-transport/src/tls_secure.rs:125` `pub fn from_env(inner: D) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {`
- `crates/sb-transport/src/trojan.rs:320` `pub fn decode(buf: &mut BytesMut) -> io::Result<Option<Self>> {`
- `crates/sb-transport/src/uot.rs:123` `pub fn encode_packet_v1(data: &[u8]) -> io::Result<Bytes> {`
- `crates/sb-transport/src/uot.rs:138` `pub fn encode_packet_v2(packet: &UdpPacket) -> io::Result<Bytes> {`
- `crates/sb-transport/src/uot.rs:170` `pub fn decode_packet_v1(buf: &mut BytesMut) -> io::Result<Option<Bytes>> {`
- `crates/sb-transport/src/uot.rs:192` `pub fn decode_packet_v2(buf: &mut BytesMut) -> io::Result<Option<UdpPacket>> {`
- `crates/sb-transport/src/util.rs:103` `pub async fn dial_with_timeout<D: Dialer + Send + Sync>( d: &D, host: &str, port: u16, ms: u64, ) -> Result<IoStream, DialError> {`
- `crates/sb-transport/src/util.rs:190` `pub async fn connect_with_timeout<D: Dialer + Send + Sync>( d: &D, addr: (&str, u16), ms: u64, ) -> Result<IoStream, DialError> {`
- `crates/sb-transport/src/util.rs:279` `pub async fn dial_with_timeout_future<F, T, E>(fut: F, ms: u64) -> Result<T, DialError> where F: std::future::Future<Output = Result<T, E>>, E: Into<DialError>, {`
- `crates/sb-transport/src/websocket.rs:473` `pub async fn accept(&self) -> Result<IoStream, DialError> {`
- `crates/sb-transport/src/websocket.rs:506` `pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {`
- `crates/sb-transport/src/wireguard.rs:107` `pub async fn new(config: WireGuardConfig) -> Result<Self, WireGuardError> {`
- `crates/sb-transport/src/wireguard.rs:208` `pub async fn send(&self, data: &[u8]) -> io::Result<()> {`
- `crates/sb-transport/src/wireguard.rs:227` `pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {`
- `crates/sb-transport/src/wireguard.rs:258` `pub async fn handshake(&self) -> io::Result<()> {`
- `crates/sb-types/src/errors.rs:174` `pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer, {`
- `crates/sb-types/src/errors.rs:181` `pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error> where D: Deserializer<'de>, {`
- `crates/sb-types/src/ports/http.rs:66` `pub fn header(&self, key: &str) -> Option<&str> {`

### serde_without_deny_unknown_fields (261)
- 判定：边界卫生命中
- 对应层：Layer 4

- `app/src/admin_debug/audit.rs:9` `struct AuditEntry`
- `app/src/admin_debug/auth/jwt.rs:85` `struct JsonWebKey`
- `app/src/admin_debug/auth/jwt.rs:106` `struct JwksResponse`
- `app/src/admin_debug/auth/mod.rs:39` `enum AuthConfig`
- `app/src/bootstrap.rs:1115` `struct Ep`
- `app/src/bootstrap.rs:1125` `struct Pool`
- `app/src/capability_probe.rs:13` `struct CapabilityProbeReport`
- `app/src/capability_probe.rs:21` `struct CapabilityProbeEntry`
- `app/src/cli/bench.rs:133` `struct Hist`
- `app/src/cli/bench.rs:143` `struct IoStats`
- `app/src/cli/check/types.rs:6` `enum IssueKind`
- `app/src/cli/check/types.rs:15` `struct CheckIssue`
- `app/src/cli/check/types.rs:39` `struct CheckReport`
- `app/src/cli/geoip.rs:105` `struct CountryRecord`
- `app/src/cli/geoip.rs:110` `struct CountryInfo`
- `app/src/cli/health.rs:9` `struct HealthSnapshot`
- `crates/sb-adapters/src/inbound/shadowtls.rs:43` `struct ShadowTlsUser`
- `crates/sb-adapters/src/inbound/shadowtls.rs:50` `struct ShadowTlsHandshakeConfig`
- `crates/sb-adapters/src/inbound/tun/mod.rs:250` `struct TunInboundConfig`
- `crates/sb-adapters/src/inbound/tun_enhanced.rs:35` `struct EnhancedTunConfig`
- `crates/sb-adapters/src/inbound/tun_process_aware.rs:29` `struct ProcessAwareTunConfig`
- `crates/sb-adapters/src/outbound/shadowsocks.rs:31` `struct ShadowsocksConfig`
- `crates/sb-adapters/src/outbound/trojan.rs:74` `struct TrojanConfig`
- `crates/sb-adapters/src/transport_config.rs:75` `struct WebSocketTransportConfig`
- `crates/sb-adapters/src/transport_config.rs:116` `struct GrpcTransportConfig`
- `crates/sb-adapters/src/transport_config.rs:139` `struct HttpUpgradeTransportConfig`
- `crates/sb-adapters/src/transport_config.rs:160` `enum TransportConfig`
- `crates/sb-admin-contract/src/lib.rs:300` `struct ErrorBody`
- `crates/sb-admin-contract/src/lib.rs:326` `enum ErrorKind`
- `crates/sb-api/src/clash/handlers.rs:59` `struct CapabilitiesReport`
- `crates/sb-api/src/clash/handlers.rs:69` `struct CapabilitiesReportEntry`
- `crates/sb-api/src/clash/handlers.rs:82` `struct CapabilitiesReportRuntimeProbe`
- `crates/sb-api/src/clash/handlers.rs:88` `struct CapabilitiesReportProbeMeta`
- `crates/sb-api/src/types.rs:22` `struct Connection`
- `crates/sb-api/src/types.rs:53` `struct ConnectionMetadata`
- `crates/sb-api/src/types.rs:133` `struct Proxy`
- `crates/sb-api/src/types.rs:161` `struct DelayHistory`
- `crates/sb-api/src/types.rs:170` `struct SelectProxyRequest`
- `crates/sb-api/src/types.rs:182` `struct TrafficStats`
- `crates/sb-api/src/types.rs:217` `struct LogEntry`
- `crates/sb-api/src/types.rs:238` `struct Rule`
- `crates/sb-api/src/types.rs:257` `struct Config`
- `crates/sb-api/src/types.rs:295` `struct Provider`
- `crates/sb-api/src/types.rs:328` `struct SubscriptionInfo`
- `crates/sb-api/src/types.rs:346` `enum WebSocketMessage`
- `crates/sb-api/src/v2ray/mod.rs:32` `struct InboundHandlerConfig`
- `crates/sb-api/src/v2ray/mod.rs:40` `struct GetStatsRequest`
- `crates/sb-api/src/v2ray/mod.rs:46` `struct GetStatsResponse`
- `crates/sb-api/src/v2ray/mod.rs:51` `struct QueryStatsRequest`
- `crates/sb-api/src/v2ray/mod.rs:57` `struct QueryStatsResponse`
- `crates/sb-api/src/v2ray/mod.rs:62` `struct SysStatsRequest`
- `crates/sb-api/src/v2ray/mod.rs:65` `struct SysStatsResponse`
- `crates/sb-api/src/v2ray/mod.rs:79` `struct Stat`
- `crates/sb-api/src/v2ray/mod.rs:86` `struct AddInboundRequest`
- `crates/sb-api/src/v2ray/mod.rs:91` `struct AddInboundResponse`
- `crates/sb-api/src/v2ray/mod.rs:94` `struct RemoveInboundRequest`
- `crates/sb-api/src/v2ray/mod.rs:99` `struct RemoveInboundResponse`
- `crates/sb-api/src/v2ray/mod.rs:102` `struct AlterInboundRequest`
- `crates/sb-api/src/v2ray/mod.rs:108` `struct AlterInboundResponse`
- `crates/sb-api/src/v2ray/mod.rs:111` `struct AddOutboundRequest`
- `crates/sb-api/src/v2ray/mod.rs:116` `struct AddOutboundResponse`
- `crates/sb-api/src/v2ray/mod.rs:119` `struct RemoveOutboundRequest`
- `crates/sb-api/src/v2ray/mod.rs:124` `struct RemoveOutboundResponse`
- `crates/sb-api/src/v2ray/mod.rs:127` `struct AlterOutboundRequest`
- `crates/sb-api/src/v2ray/mod.rs:133` `struct AlterOutboundResponse`
- `crates/sb-api/src/v2ray/mod.rs:137` `struct SubscribeRoutingStatsRequest`
- `crates/sb-api/src/v2ray/mod.rs:140` `struct TestRouteRequest`
- `crates/sb-api/src/v2ray/mod.rs:146` `struct RoutingContext`
- `crates/sb-api/src/v2ray/mod.rs:158` `struct RestartLoggerRequest`
- `crates/sb-api/src/v2ray/mod.rs:161` `struct RestartLoggerResponse`
- `crates/sb-api/src/v2ray/mod.rs:164` `struct FollowLogRequest`
- `crates/sb-api/src/v2ray/mod.rs:167` `struct LogEntry`
- `crates/sb-api/src/v2ray/simple.rs:10` `struct SimpleStat`
- `crates/sb-api/src/v2ray/simple.rs:19` `struct SimpleStatsRequest`
- `crates/sb-api/src/v2ray/simple.rs:28` `struct SimpleStatsResponse`
- `crates/sb-api/src/v2ray/simple.rs:35` `struct SimpleQueryStatsRequest`
- `crates/sb-api/src/v2ray/simple.rs:44` `struct SimpleQueryStatsResponse`
- `crates/sb-config/src/acme_config.rs:7` `struct AcmeConfig`
- `crates/sb-config/src/de.rs:12` `enum StringOrList`
- `crates/sb-config/src/de.rs:47` `enum Raw`
- `crates/sb-config/src/de.rs:53` `struct Obj`
- `crates/sb-config/src/deprecation.rs:10` `enum DeprecationSeverity`
- `crates/sb-config/src/deprecation.rs:21` `enum DeprecationCategory`
- `crates/sb-config/src/deprecation.rs:34` `struct DeprecatedField`
- `crates/sb-config/src/inbound.rs:29` `enum InboundDef`
- `crates/sb-config/src/ir/diff.rs:16` `struct Change`
- `crates/sb-config/src/ir/diff.rs:27` `struct Diff`
- `crates/sb-config/src/ir/experimental.rs:4` `struct ExperimentalIR`
- `crates/sb-config/src/ir/experimental.rs:22` `struct CacheFileIR`
- `crates/sb-config/src/ir/experimental.rs:43` `struct ClashApiIR`
- `crates/sb-config/src/ir/experimental.rs:60` `struct V2RayApiIR`
- `crates/sb-config/src/ir/experimental.rs:69` `struct DebugIR`
- `crates/sb-config/src/ir/experimental.rs:98` `struct StatsIR`
- `crates/sb-config/src/ir/mod.rs:17` `struct Credentials`
- `crates/sb-config/src/ir/mod.rs:36` `enum InboundType`
- `crates/sb-config/src/ir/mod.rs:129` `enum OutboundType`
- `crates/sb-config/src/ir/mod.rs:227` `struct ShadowsocksUserIR`
- `crates/sb-config/src/ir/mod.rs:236` `struct VmessUserIR`
- `crates/sb-config/src/ir/mod.rs:248` `struct VlessUserIR`
- `crates/sb-config/src/ir/mod.rs:269` `struct TrojanUserIR`
- `crates/sb-config/src/ir/mod.rs:278` `struct ShadowTlsUserIR`
- `crates/sb-config/src/ir/mod.rs:288` `struct ShadowTlsHandshakeIR`
- `crates/sb-config/src/ir/mod.rs:298` `struct AnyTlsUserIR`
- `crates/sb-config/src/ir/mod.rs:308` `struct Hysteria2UserIR`
- `crates/sb-config/src/ir/mod.rs:317` `struct TuicUserIR`
- `crates/sb-config/src/ir/mod.rs:326` `struct HysteriaUserIR`
- `crates/sb-config/src/ir/mod.rs:335` `struct MultiplexOptionsIR`
- `crates/sb-config/src/ir/mod.rs:373` `struct BrutalIR`
- `crates/sb-config/src/ir/mod.rs:382` `struct MasqueradeIR`
- `crates/sb-config/src/ir/mod.rs:394` `struct MasqueradeFileIR`
- `crates/sb-config/src/ir/mod.rs:399` `struct MasqueradeProxyIR`
- `crates/sb-config/src/ir/mod.rs:406` `struct MasqueradeStringIR`
- `crates/sb-config/src/ir/mod.rs:421` `struct InboundIR`
- `crates/sb-config/src/ir/mod.rs:711` `struct TunOptionsIR`
- `crates/sb-config/src/ir/mod.rs:762` `struct OutboundIR`
- `crates/sb-config/src/ir/mod.rs:1192` `struct HeaderEntry`
- `crates/sb-config/src/ir/mod.rs:1203` `enum RuleAction`
- `crates/sb-config/src/ir/mod.rs:1272` `struct RuleIR`
- `crates/sb-config/src/ir/mod.rs:1631` `struct DomainResolveOptionsIR`
- `crates/sb-config/src/ir/mod.rs:1650` `struct RouteIR`
- `crates/sb-config/src/ir/mod.rs:1755` `struct RuleSetIR`
- `crates/sb-config/src/ir/mod.rs:1791` `enum EndpointType`
- `crates/sb-config/src/ir/mod.rs:1800` `struct EndpointIR`
- `crates/sb-config/src/ir/mod.rs:1878` `struct WireGuardPeerIR`
- `crates/sb-config/src/ir/mod.rs:1909` `enum ServiceType`
- `crates/sb-config/src/ir/mod.rs:1924` `struct InboundTlsOptionsIR`
- `crates/sb-config/src/ir/mod.rs:2008` `struct DerpStunOptionsObj`
- `crates/sb-config/src/ir/mod.rs:2046` `enum Repr`
- `crates/sb-config/src/ir/mod.rs:2092` `enum Repr`
- `crates/sb-config/src/ir/mod.rs:2146` `enum Repr`
- `crates/sb-config/src/ir/mod.rs:2159` `struct DerpDomainResolverIR`
- `crates/sb-config/src/ir/mod.rs:2182` `struct DerpDialOptionsIR`
- `crates/sb-config/src/ir/mod.rs:2214` `struct DerpVerifyClientUrlIR`
- `crates/sb-config/src/ir/mod.rs:2232` `struct DerpOutboundTlsOptionsIR`
- `crates/sb-config/src/ir/mod.rs:2249` `struct DerpMeshPeerIR`
- `crates/sb-config/src/ir/mod.rs:2306` `struct ServiceIR`
- `crates/sb-config/src/ir/mod.rs:2406` `struct ConfigIR`
- `crates/sb-config/src/ir/mod.rs:2447` `struct CertificateIR`
- `crates/sb-config/src/ir/mod.rs:3111` `struct LogIR`
- `crates/sb-config/src/ir/mod.rs:3133` `struct NtpIR`
- `crates/sb-config/src/ir/mod.rs:3153` `struct DnsServerIR`
- `crates/sb-config/src/ir/mod.rs:3226` `struct DnsRuleIR`
- `crates/sb-config/src/ir/mod.rs:3324` `struct DnsIR`
- `crates/sb-config/src/ir/mod.rs:3405` `struct DnsHostIR`
- `crates/sb-config/src/lib.rs:57` `struct Config`
- `crates/sb-config/src/lib.rs:240` `struct Auth`
- `crates/sb-config/src/lib.rs:246` `struct Rule`
- `crates/sb-config/src/model.rs:20` `struct ListenAddr`
- `crates/sb-config/src/model.rs:37` `struct User`
- `crates/sb-config/src/model.rs:47` `enum SocksAuth`
- `crates/sb-config/src/model.rs:58` `struct Inbound`
- `crates/sb-config/src/model.rs:70` `enum InboundDef`
- `crates/sb-config/src/model.rs:101` `struct Outbound`
- `crates/sb-config/src/model.rs:112` `enum OutboundDef`
- `crates/sb-config/src/model.rs:122` `enum Rule`
- `crates/sb-config/src/model.rs:137` `struct Config`
- `crates/sb-config/src/outbound.rs:9` `enum Outbound`
- `crates/sb-config/src/outbound.rs:44` `struct DirectConfig`
- `crates/sb-config/src/outbound.rs:50` `struct HttpProxyConfig`
- `crates/sb-config/src/outbound.rs:69` `struct Socks5Config`
- `crates/sb-config/src/outbound.rs:85` `struct Socks4Config`
- `crates/sb-config/src/outbound.rs:99` `struct VmessConfig`
- `crates/sb-config/src/outbound.rs:143` `struct VlessConfig`
- `crates/sb-config/src/outbound.rs:178` `struct TuicConfig`
- `crates/sb-config/src/outbound.rs:225` `struct SelectorConfig`
- `crates/sb-config/src/outbound.rs:239` `struct UrlTestConfig`
- `crates/sb-config/src/outbound.rs:280` `struct TlsConfig`
- `crates/sb-config/src/outbound.rs:304` `struct RealityConfig`
- `crates/sb-config/src/outbound.rs:320` `struct EchConfig`
- `crates/sb-config/src/outbound.rs:340` `enum TransportConfig`
- `crates/sb-config/src/outbound.rs:408` `struct MultiplexConfig`
- `crates/sb-config/src/outbound.rs:465` `struct BrutalConfig`
- `crates/sb-config/src/rule/negation.rs:14` `struct RuleLite`
- `crates/sb-config/src/rule/negation.rs:53` `struct RouteLite`
- `crates/sb-config/src/rule/negation.rs:59` `struct ConfigLite`
- `crates/sb-config/src/subscribe.rs:48` `struct ClashSub`
- `crates/sb-config/src/subscribe.rs:60` `struct ClashProxy`
- `crates/sb-config/src/subscribe.rs:98` `struct WsOpts`
- `crates/sb-config/src/subscribe.rs:107` `struct GrpcOpts`
- `crates/sb-config/src/subscribe.rs:114` `struct ClashGroup`
- `crates/sb-core/src/adapter/clash.rs:10` `enum ClashMode`
- `crates/sb-core/src/diagnostics/options.rs:12` `struct DebugOptions`
- `crates/sb-core/src/endpoint/tailscale.rs:232` `struct TailscaleStatus`
- `crates/sb-core/src/endpoint/tailscale.rs:250` `struct SelfNode`
- `crates/sb-core/src/geoip/mmdb.rs:254` `struct CountryRecord`
- `crates/sb-core/src/geoip/mmdb.rs:262` `struct CityRecord`
- `crates/sb-core/src/geoip/mmdb.rs:272` `struct AsnRecord`
- `crates/sb-core/src/geoip/mmdb.rs:279` `struct ContinentInfo`
- `crates/sb-core/src/geoip/mmdb.rs:286` `struct CountryInfo`
- `crates/sb-core/src/geoip/mmdb.rs:293` `struct SubdivisionInfo`
- `crates/sb-core/src/geoip/mmdb.rs:300` `struct CityInfo`
- `crates/sb-core/src/geoip/mmdb.rs:306` `struct LocationInfo`
- `crates/sb-core/src/router/json_bridge.rs:10` `struct JsonRule`
- `crates/sb-core/src/router/json_bridge.rs:25` `struct JsonDoc`
- `crates/sb-core/src/router/ruleset/remote.rs:93` `struct CacheMeta`
- `crates/sb-core/src/routing/ir.rs:6` `enum InboundType`
- `crates/sb-core/src/routing/ir.rs:14` `enum OutboundType`
- `crates/sb-core/src/routing/ir.rs:22` `struct InboundIR`
- `crates/sb-core/src/routing/ir.rs:35` `struct OutboundIR`
- `crates/sb-core/src/routing/ir.rs:48` `struct RuleIR`
- `crates/sb-core/src/routing/ir.rs:95` `struct RouteIR`
- `crates/sb-core/src/routing/ir.rs:103` `struct ConfigIR`
- `crates/sb-core/src/services/cache_file.rs:29` `struct RdrcEntry`
- `crates/sb-core/src/services/derp/server.rs:3272` `struct DerpConfigFile`
- `crates/sb-core/src/services/ssmapi/api.rs:31` `struct AddUserRequest`
- `crates/sb-core/src/services/ssmapi/api.rs:39` `struct UpdateUserRequest`
- `crates/sb-core/src/services/ssmapi/api.rs:52` `struct StatsQuery`
- `crates/sb-core/src/services/ssmapi/server.rs:20` `struct Cache`
- `crates/sb-core/src/services/ssmapi/server.rs:28` `struct EndpointCache`
- `crates/sb-core/src/services/ssmapi/server.rs:64` `struct LegacyCache`
- `crates/sb-core/src/services/ssmapi/server.rs:70` `struct LegacyEndpointCache`
- `crates/sb-core/src/services/tailscale/coordinator.rs:38` `struct State`
- `crates/sb-core/src/services/tailscale/coordinator.rs:45` `struct NetworkMap`
- `crates/sb-core/src/services/tailscale/coordinator.rs:58` `struct NodeInfo`
- `crates/sb-core/src/services/tailscale/coordinator.rs:75` `struct DerpMap`
- `crates/sb-core/src/services/tailscale/coordinator.rs:82` `struct DerpRegion`
- `crates/sb-core/src/services/tailscale/coordinator.rs:89` `struct DerpNode`
- `crates/sb-runtime/src/handshake.rs:85` `struct ProtoCtx`
- `crates/sb-runtime/src/loopback.rs:150` `enum FrameDir`
- `crates/sb-runtime/src/loopback.rs:172` `struct Frame`
- `crates/sb-runtime/src/loopback.rs:292` `struct SessionMetrics`
- `crates/sb-runtime/src/protocols/trojan.rs:17` `struct Trojan`
- `crates/sb-runtime/src/protocols/vmess.rs:17` `struct Vmess`
- `crates/sb-runtime/src/scenario.rs:24` `enum ProtoLite`
- `crates/sb-runtime/src/scenario.rs:39` `struct ChaosFile`
- `crates/sb-runtime/src/scenario.rs:66` `struct Expect`
- `crates/sb-runtime/src/scenario.rs:74` `struct Defaults`
- `crates/sb-runtime/src/scenario.rs:84` `enum Step`
- `crates/sb-runtime/src/scenario.rs:118` `struct ScenarioFile`
- `crates/sb-runtime/src/scenario.rs:147` `struct StepResult`
- `crates/sb-runtime/src/scenario.rs:154` `struct ScenarioSummary`
- `crates/sb-security/src/key_loading.rs:51` `enum KeySource`
- `crates/sb-subscribe/src/diff_full.rs:109` `struct DiffOutput`
- `crates/sb-subscribe/src/parse_clash.rs:7` `struct ClashDoc`
- `crates/sb-subscribe/src/parse_singbox.rs:5` `struct SBoxDoc`
- `crates/sb-subscribe/src/parse_singbox.rs:13` `struct Route`
- `crates/sb-subscribe/src/preview_plan.rs:52` `struct PlanOutput`
- `crates/sb-tls/src/ech/config.rs:10` `struct EchKeypair`
- `crates/sb-tls/src/ech/config.rs:87` `struct EchClientConfig`
- `crates/sb-tls/src/ech/config.rs:201` `struct EchServerConfig`
- `crates/sb-tls/src/reality/config.rs:10` `struct RealityClientConfig`
- `crates/sb-tls/src/reality/config.rs:110` `struct RealityServerConfig`
- `crates/sb-transport/src/tls.rs:982` `enum TlsConfig`
- `crates/sb-transport/src/tls.rs:1000` `struct StandardTlsConfig`
- `crates/sb-transport/src/tls.rs:1042` `struct RealityTlsConfig`
- `crates/sb-transport/src/tls.rs:1079` `struct EchTlsConfig`
- `crates/sb-types/src/errors.rs:14` `enum ErrorClass`
- `crates/sb-types/src/errors.rs:54` `enum CoreError`
- `crates/sb-types/src/errors.rs:192` `enum DnsError`
- `crates/sb-types/src/errors.rs:214` `enum TransportError`
- `crates/sb-types/src/lib.rs:65` `enum IssueCode`
- `crates/sb-types/src/lib.rs:260` `struct IssuePayload`
- `crates/sb-types/src/ports/admin.rs:9` `enum LogLevel`
- `crates/sb-types/src/ports/admin.rs:33` `struct ConnSnapshot`
- `crates/sb-types/src/ports/admin.rs:45` `struct TrafficSnapshot`
- `crates/sb-types/src/session.rs:16` `struct InboundTag`
- `crates/sb-types/src/session.rs:38` `struct OutboundTag`
- `crates/sb-types/src/session.rs:61` `enum TargetAddr`
- `crates/sb-types/src/session.rs:141` `struct UserId`
- `crates/sb-types/src/session.rs:145` `struct SessionMeta`
- `crates/sb-types/src/session.rs:164` `struct Session`

### unsafe_missing_safety_comment (40)
- 判定：确定命中
- 对应层：Layer 4

- `crates/sb-adapters/src/inbound/tproxy.rs:37` `unsafe {`
- `crates/sb-adapters/src/inbound/tun/device.rs:120` `unsafe {`
- `crates/sb-adapters/src/inbound/tun/mod.rs:884` `let writer_file = unsafe {`
- `crates/sb-adapters/src/inbound/tun/mod.rs:1358` `let fd = unsafe { open_utun(name_hint)? };`
- `crates/sb-adapters/src/inbound/tun/mod.rs:1366` `unsafe { AsyncFd::with_interest(std::fs::File::from_raw_fd(fd), Interest::READABLE) }`
- `crates/sb-adapters/src/inbound/tun/mod.rs:1455` `let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };`
- `crates/sb-adapters/src/inbound/tun/mod.rs:1463` `let r = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };`
- `crates/sb-adapters/src/inbound/tun_enhanced.rs:660` `unsafe {`
- `crates/sb-adapters/src/inbound/tun_macos.rs:484` `unsafe {`
- `crates/sb-adapters/src/service/resolve1.rs:762` `unsafe { libc::if_indextoname(if_index as u32, buf.as_mut_ptr() as *mut i8) };`
- `crates/sb-adapters/src/service/resolve1.rs:764` `if let Ok(name) = unsafe { CStr::from_ptr(result) }.to_str() {`
- `crates/sb-api/src/clash/websocket.rs:403` `unsafe {`
- `crates/sb-core/src/diagnostics/memory.rs:116` `unsafe {`
- `crates/sb-core/src/router/conn.rs:1240` `let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };`
- `crates/sb-core/src/router/conn.rs:1242` `let ret = unsafe {`
- `crates/sb-core/src/router/conn.rs:1270` `let ret = unsafe {`
- `crates/sb-core/src/router/context_pop.rs:96` `unsafe {`
- `crates/sb-core/src/router/context_pop.rs:132` `unsafe {`
- `crates/sb-core/src/router/context_pop.rs:151` `unsafe {`
- `crates/sb-core/src/util/fs_atomic.rs:39` `let _ = unsafe { libc::fsync(f.as_raw_fd()) };`
- `crates/sb-platform/src/monitor.rs:234` `unsafe {`
- `crates/sb-platform/src/monitor.rs:290` `let result = unsafe {`
- `crates/sb-platform/src/monitor.rs:311` `unsafe {`
- `crates/sb-platform/src/network.rs:69` `unsafe {`
- `crates/sb-platform/src/network.rs:124` `let result = unsafe {`
- `crates/sb-platform/src/network.rs:146` `unsafe {`
- `crates/sb-platform/src/process/native_windows.rs:26` `unsafe fn tcp_rows<'a>(buffer: &'a [u8]) -> Result<&'a [MIB_TCPROW_OWNER_PID], ProcessMatchError> {`
- `crates/sb-platform/src/process/native_windows.rs:49` `unsafe fn udp_rows<'a>(buffer: &'a [u8]) -> Result<&'a [MIB_UDPROW_OWNER_PID], ProcessMatchError> {`
- `crates/sb-platform/src/system_proxy.rs:554` `unsafe {`
- `crates/sb-platform/src/tun/linux.rs:41` `unsafe {`
- `crates/sb-platform/src/tun/linux.rs:355` `let name_bytes = unsafe {`
- `crates/sb-platform/src/tun/macos.rs:25` `let fd = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };`
- `crates/sb-platform/src/tun/macos.rs:65` `let result = unsafe { libc::ioctl(fd, CTLIOCGINFO, &mut ctl_info) };`
- `crates/sb-platform/src/tun/macos.rs:72` `unsafe {`
- `crates/sb-platform/src/tun/macos.rs:94` `let result = unsafe {`
- `crates/sb-platform/src/tun/macos.rs:107` `unsafe {`
- `crates/sb-platform/src/tun/macos.rs:124` `let file = unsafe { File::from_raw_fd(fd) };`
- `crates/sb-platform/src/tun/macos.rs:161` `let result = unsafe {`
- `crates/sb-transport/src/dialer.rs:570` `unsafe {`
- `crates/sb-transport/src/dialer.rs:582` `unsafe {`

### undocumented_public_items (1555)
- 判定：确定命中
- 对应层：Layer 4

- `app/src/admin_debug/audit.rs:9` `pub struct AuditEntry {`
- `app/src/admin_debug/audit.rs:26` `pub fn log(entry: &AuditEntry) {`
- `app/src/admin_debug/audit.rs:44` `pub fn recent(n: usize) -> Vec<AuditEntry> {`
- `app/src/admin_debug/audit.rs:53` `pub fn latest_ts() -> Option<u64> {`
- `app/src/admin_debug/audit.rs:59` `pub fn create_entry(`
- `app/src/admin_debug/audit.rs:84` `pub const fn with_changed(mut self, changed: bool) -> Self {`
- `app/src/admin_debug/breaker.rs:119` `pub struct HostBreaker {`
- `app/src/admin_debug/breaker.rs:131` `pub fn new(window_ms: u64, open_ms: u64, threshold: u32, ratio: f32) -> Self {`
- `app/src/admin_debug/breaker.rs:143` `pub fn check(&mut self, host: &str) -> bool {`
- `app/src/admin_debug/breaker.rs:189` `pub fn mark_success(&mut self, host: &str) {`
- `app/src/admin_debug/breaker.rs:213` `pub fn mark_failure(&mut self, host: &str) {`
- `app/src/admin_debug/breaker.rs:218` `pub fn mark_failure_with_metrics(&mut self, host: &str, metrics: &SecurityMetricsState) {`
- `app/src/admin_debug/breaker.rs:300` `pub fn reset(&mut self) {`
- `app/src/admin_debug/breaker.rs:328` `pub fn stats(&self) -> Vec<(String, u32, u32, bool)> {`
- `app/src/admin_debug/breaker.rs:343` `pub fn state_stats(&self) -> Vec<(String, String, u32)> {`
- `app/src/admin_debug/breaker.rs:361` `pub fn mark_fail(&mut self, host: &str) {`
- `app/src/admin_debug/breaker.rs:364` `pub fn mark_ok(&mut self, host: &str) {`
- `app/src/admin_debug/breaker.rs:377` `pub fn global() -> &'static Mutex<HostBreaker> {`
- `app/src/admin_debug/cache.rs:11` `pub struct CacheEntry {`
- `app/src/admin_debug/cache.rs:28` `pub enum TierEntry {`
- `app/src/admin_debug/cache.rs:41` `pub const fn body_len(&self) -> usize {`
- `app/src/admin_debug/cache.rs:49` `pub const fn etag(&self) -> Option<&String> {`
- `app/src/admin_debug/cache.rs:57` `pub const fn content_type(&self) -> Option<&String> {`
- `app/src/admin_debug/cache.rs:65` `pub const fn timestamp(&self) -> Instant {`
- `app/src/admin_debug/cache.rs:82` `pub struct Lru {`
- `app/src/admin_debug/cache.rs:96` `pub fn new(cap_items: usize, ttl_ms: u64) -> Self {`
- `app/src/admin_debug/cache.rs:100` `pub fn with_byte_limit(cap_items: usize, ttl_ms: u64, cap_bytes: usize) -> Self {`
- `app/src/admin_debug/cache.rs:131` `pub fn get(&mut self, key: &str) -> Option<TierEntry> {`
- `app/src/admin_debug/cache.rs:142` `pub fn put(&mut self, key: String, value: CacheEntry) {`
- `app/src/admin_debug/cache.rs:300` `pub fn size(&self) -> usize {`
- `app/src/admin_debug/cache.rs:305` `pub fn byte_usage(&self) -> (usize, usize) {`
- `app/src/admin_debug/cache.rs:324` `pub const fn metrics(&self) -> (u64, u64, u64) {`
- `app/src/admin_debug/cache.rs:328` `pub const fn inc_head_count(&mut self) {`
- `app/src/admin_debug/cache.rs:332` `pub fn clear(&mut self) {`
- `app/src/admin_debug/cache.rs:343` `pub fn global() -> &'static Mutex<Lru> {`
- `app/src/admin_debug/endpoints/analyze.rs:46` `pub async fn handle(`
- `app/src/admin_debug/endpoints/config.rs:11` `pub struct ConfigView {`
- `app/src/admin_debug/endpoints/config.rs:17` `pub struct ConfigDelta {`
- `app/src/admin_debug/endpoints/route_dryrun.rs:5` `pub async fn handle(path_q: &str, sock: &mut (impl AsyncWriteExt + Unpin)) -> std::io::Result<()> {`
- `app/src/admin_debug/endpoints/subs.rs:109` `pub fn resize_limiters(new_conc: usize, new_rps: u64) {`
- `app/src/admin_debug/endpoints/subs.rs:132` `pub fn resize_rps(cap: u64) {`
- `app/src/admin_debug/endpoints/subs.rs:138` `pub fn get_current_concurrency() -> u64 {`
- `app/src/admin_debug/endpoints/subs.rs:150` `pub fn get_current_concurrency() -> u64 {`
- `app/src/admin_debug/endpoints/subs.rs:870` `pub async fn fetch_with_limits_to_cache(`
- `app/src/admin_debug/endpoints/subs.rs:879` `pub async fn fetch_with_limits_to_cache_with_metrics(`
- `app/src/admin_debug/endpoints/subs.rs:1355` `pub async fn handle_with_metrics(`
- `app/src/admin_debug/endpoints/subs.rs:1363` `pub async fn handle(path_q: &str, sock: &mut (impl AsyncWriteExt + Unpin)) -> std::io::Result<()> {`
- `app/src/admin_debug/http/redirect.rs:6` `pub struct SafeRedirect {`
- `app/src/admin_debug/http/redirect.rs:13` `pub const fn new(allow_host_suffix: Vec<String>) -> Self {`
- `app/src/admin_debug/http/redirect.rs:33` `pub fn policy(self) -> impl Fn(Attempt) -> Action + Clone + Send + Sync + 'static {`
- `app/src/admin_debug/http_server.rs:27` `pub struct TlsConf {`
- `app/src/admin_debug/http_server.rs:37` `pub const fn disabled() -> Self {`
- `app/src/admin_debug/http_server.rs:47` `pub fn from_env() -> Self {`
- `app/src/admin_debug/http_server.rs:68` `pub enum AuthConf {`
- `app/src/admin_debug/http_server.rs:78` `pub fn from_env() -> Self {`
- `app/src/admin_debug/http_server.rs:102` `pub const fn mode(&self) -> &'static str {`
- `app/src/admin_debug/http_server.rs:139` `pub fn check_auth(headers: &HashMap<String, String>, path: &str) -> bool {`
- `app/src/admin_debug/http_server.rs:293` `pub fn get_auth_mode() -> &'static str {`
- `app/src/admin_debug/http_server.rs:618` `pub async fn serve(`
- `app/src/admin_debug/http_server.rs:986` `pub async fn serve_plain(`
- `app/src/admin_debug/http_util.rs:8` `pub fn generate_request_id() -> String {`
- `app/src/admin_debug/http_util.rs:22` `pub fn get_or_generate_request_id(headers: &HashMap<String, String>) -> String {`
- `app/src/admin_debug/http_util.rs:37` `pub fn parse_query(q: &str) -> HashMap<String, String> {`
- `app/src/admin_debug/http_util.rs:48` `pub fn url_decode(s: &str) -> String {`
- `app/src/admin_debug/http_util.rs:52` `pub async fn respond(`
- `app/src/admin_debug/http_util.rs:76` `pub async fn respond_json_ok(`
- `app/src/admin_debug/http_util.rs:92` `pub type AdminResponse<T> = ResponseEnvelope<T>;`
- `app/src/admin_debug/http_util.rs:93` `pub type AdminError = ErrorBody;`
- `app/src/admin_debug/http_util.rs:96` `pub fn admin_error_io(msg: impl Into<String>) -> AdminError {`
- `app/src/admin_debug/http_util.rs:105` `pub fn admin_error_parse(msg: impl Into<String>) -> AdminError {`
- `app/src/admin_debug/http_util.rs:114` `pub fn admin_error_not_found(msg: impl Into<String>) -> AdminError {`
- `app/src/admin_debug/http_util.rs:123` `pub fn admin_error_conflict(msg: impl Into<String>) -> AdminError {`
- `app/src/admin_debug/http_util.rs:132` `pub fn admin_error_state(msg: impl Into<String>) -> AdminError {`
- `app/src/admin_debug/http_util.rs:141` `pub fn admin_error_with_ptr(mut error: AdminError, ptr: impl Into<String>) -> AdminError {`
- `app/src/admin_debug/http_util.rs:146` `pub fn admin_error_with_hint(mut error: AdminError, hint: impl Into<String>) -> AdminError {`
- `app/src/admin_debug/http_util.rs:152` `pub async fn respond_json_error(`
- `app/src/admin_debug/http_util.rs:166` `pub async fn respond_admin_success<T: Serialize>(`
- `app/src/admin_debug/http_util.rs:173` `pub async fn respond_admin_success_with_request_id<T: Serialize>(`
- `app/src/admin_debug/http_util.rs:185` `pub async fn respond_admin_error(`
- `app/src/admin_debug/http_util.rs:193` `pub async fn respond_admin_error_with_request_id(`
- `app/src/admin_debug/http_util.rs:208` `pub async fn respond_admin_parse_error(`
- `app/src/admin_debug/http_util.rs:224` `pub async fn respond_admin_not_found(`
- `app/src/admin_debug/http_util.rs:236` `pub async fn respond_admin_conflict(`
- `app/src/admin_debug/middleware/auth.rs:131` `pub fn new(auth_middleware: AuthMiddleware) -> Self {`
- `app/src/admin_debug/middleware/auth.rs:142` `pub fn with_exempt_paths(mut self, paths: Vec<String>) -> Self {`
- `app/src/admin_debug/middleware/mod.rs:31` `pub fn new(method: String, path: String, headers: HashMap<String, String>) -> Self {`
- `app/src/admin_debug/middleware/mod.rs:43` `pub fn with_body(mut self, body: bytes::Bytes) -> Self {`
- `app/src/admin_debug/middleware/mod.rs:62` `pub fn new() -> Self {`
- `app/src/admin_debug/middleware/mod.rs:69` `pub fn add<M: Middleware + 'static>(mut self, middleware: M) -> Self {`
- `app/src/admin_debug/middleware/rate_limit.rs:98` `pub const fn new(max_requests: u32, window_secs: u64) -> Self {`
- `app/src/admin_debug/middleware/rate_limit.rs:108` `pub const fn with_strategy(mut self, strategy: RateLimitStrategy) -> Self {`
- `app/src/admin_debug/middleware/rate_limit.rs:114` `pub const fn with_burst(mut self, burst_capacity: u32) -> Self {`
- `app/src/admin_debug/middleware/rate_limit.rs:137` `pub fn new(config: RateLimitConfig) -> Self {`
- `app/src/admin_debug/middleware/request_id.rs:35` `pub const fn new() -> Self {`
- `app/src/admin_debug/mod.rs:73` `pub struct AdminDebugState {`
- `app/src/admin_debug/prefetch.rs:18` `pub struct PrefetchJob {`
- `app/src/admin_debug/prefetch.rs:26` `pub struct Prefetcher {`
- `app/src/admin_debug/prefetch.rs:82` `pub fn from_env() -> Self {`
- `app/src/admin_debug/prefetch.rs:111` `pub fn global() -> &'static Self {`
- `app/src/admin_debug/prefetch.rs:115` `pub fn enqueue(&self, job: PrefetchJob) -> bool {`
- `app/src/admin_debug/prefetch.rs:134` `pub fn shutdown(self) {`
- `app/src/admin_debug/prefetch.rs:245` `pub fn enqueue_prefetch(url: &str, etag: Option<String>) -> bool {`
- `app/src/admin_debug/prefetch.rs:268` `pub fn enqueue_prefetch_with_metrics(`
- `app/src/admin_debug/reloadable.rs:68` `pub struct EnvConfig {`
- `app/src/admin_debug/reloadable.rs:86` `pub fn from_env() -> Self {`
- `app/src/admin_debug/reloadable.rs:173` `pub fn get() -> EnvConfig {`
- `app/src/admin_debug/reloadable.rs:180` `pub fn get_arc() -> Arc<EnvConfig> {`
- `app/src/admin_debug/reloadable.rs:187` `pub fn apply(delta: &crate::admin_debug::endpoints::config::ConfigDelta) -> Result<String, String> {`
- `app/src/admin_debug/reloadable.rs:304` `pub fn version() -> u64 {`
- `app/src/admin_debug/reloadable.rs:311` `pub struct ApplyResult {`
- `app/src/admin_debug/reloadable.rs:416` `pub fn apply_with_dryrun(`
- `app/src/admin_debug/reloadable.rs:473` `pub fn reload() {`
- `app/src/admin_debug/reloadable.rs:489` `pub fn init_signal_handler() {`
- `app/src/admin_debug/security.rs:74` `pub fn is_private_ip(ip: IpAddr) -> bool {`
- `app/src/admin_debug/security.rs:81` `pub fn forbid_private_host(url: &Url) -> Result<()> {`
- `app/src/admin_debug/security.rs:99` `pub fn forbid_private_host_or_resolved(url: &Url) -> Result<()> {`
- `app/src/admin_debug/security_async.rs:95` `pub async fn resolve_host_checked(host: &str) -> Result<Vec<IpAddr>> {`
- `app/src/admin_debug/security_async.rs:130` `pub async fn forbid_private_host_or_resolved_async_with_metrics(`
- `app/src/admin_debug/security_metrics.rs:13` `pub enum SecurityErrorKind {`
- `app/src/admin_debug/security_metrics.rs:28` `pub const fn as_str(&self) -> &'static str {`
- `app/src/admin_debug/security_metrics.rs:45` `pub struct ErrorEntry {`
- `app/src/admin_debug/security_metrics.rs:53` `pub struct SecuritySnapshot {`
- `app/src/admin_debug/security_metrics.rs:109` `pub struct SecurityMetricsState {`
- `app/src/admin_debug/security_metrics.rs:155` `pub fn new() -> Self {`
- `app/src/admin_debug/security_metrics.rs:164` `pub fn inc_block_private_ip(&self) {`
- `app/src/admin_debug/security_metrics.rs:167` `pub fn inc_exceed_size(&self) {`
- `app/src/admin_debug/security_metrics.rs:170` `pub fn inc_timeout(&self) {`
- `app/src/admin_debug/security_metrics.rs:173` `pub fn inc_redirects(&self) {`
- `app/src/admin_debug/security_metrics.rs:176` `pub fn inc_connect_timeout(&self) {`
- `app/src/admin_debug/security_metrics.rs:179` `pub fn inc_upstream_4xx(&self) {`
- `app/src/admin_debug/security_metrics.rs:182` `pub fn inc_upstream_5xx(&self) {`
- `app/src/admin_debug/security_metrics.rs:185` `pub fn inc_rate_limited(&self) {`
- `app/src/admin_debug/security_metrics.rs:188` `pub fn inc_cache_hit(&self) {`
- `app/src/admin_debug/security_metrics.rs:191` `pub fn inc_cache_miss(&self) {`
- `app/src/admin_debug/security_metrics.rs:194` `pub fn inc_cache_evict_mem(&self) {`
- `app/src/admin_debug/security_metrics.rs:197` `pub fn inc_cache_evict_disk(&self) {`
- `app/src/admin_debug/security_metrics.rs:200` `pub fn inc_head_total(&self) {`
- `app/src/admin_debug/security_metrics.rs:203` `pub fn inc_breaker_block(&self) {`
- `app/src/admin_debug/security_metrics.rs:206` `pub fn inc_breaker_reopen(&self) {`
- `app/src/admin_debug/security_metrics.rs:209` `pub fn inc_total_requests(&self) {`
- `app/src/admin_debug/security_metrics.rs:212` `pub fn inc_dns_cache_hit(&self) {`
- `app/src/admin_debug/security_metrics.rs:215` `pub fn inc_dns_cache_miss(&self) {`
- `app/src/admin_debug/security_metrics.rs:219` `pub const fn init_prefetch_metrics(&self) {`
- `app/src/admin_debug/security_metrics.rs:223` `pub fn prefetch_inc(&self, event: &str) {`
- `app/src/admin_debug/security_metrics.rs:244` `pub fn record_prefetch_run_ms(&self, ms: u64) {`
- `app/src/admin_debug/security_metrics.rs:254` `pub fn set_prefetch_queue_depth(&self, depth: u64) {`
- `app/src/admin_debug/security_metrics.rs:259` `pub fn get_prefetch_queue_depth(&self) -> u64 {`
- `app/src/admin_debug/security_metrics.rs:263` `pub fn set_prefetch_queue_high_watermark(&self, watermark: u64) {`
- `app/src/admin_debug/security_metrics.rs:269` `pub fn get_prefetch_queue_high_watermark(&self) -> u64 {`
- `app/src/admin_debug/security_metrics.rs:274` `pub fn get_prefetch_counters(&self) -> (u64, u64, u64, u64, u64) {`
- `app/src/admin_debug/security_metrics.rs:284` `pub fn add_prefetch_bytes(&self, bytes: u64) {`
- `app/src/admin_debug/security_metrics.rs:290` `pub fn get_prefetch_total_bytes(&self) -> u64 {`
- `app/src/admin_debug/security_metrics.rs:294` `pub fn start_prefetch_session(&self) {`
- `app/src/admin_debug/security_metrics.rs:299` `pub fn get_prefetch_session_duration_ms(&self) -> u64 {`
- `app/src/admin_debug/security_metrics.rs:306` `pub fn record_dns_latency_ms(&self, ms: u64) {`
- `app/src/admin_debug/security_metrics.rs:318` `pub fn set_last_error(&self, kind: SecurityErrorKind, msg: impl Into<String>) {`
- `app/src/admin_debug/security_metrics.rs:322` `pub fn set_last_error_with_host(`
- `app/src/admin_debug/security_metrics.rs:341` `pub fn set_last_error_with_url(`
- `app/src/admin_debug/security_metrics.rs:350` `pub fn mark_last_ok(&self) {`
- `app/src/admin_debug/security_metrics.rs:354` `pub fn record_latency_ms(&self, ms: u64) {`
- `app/src/admin_debug/security_metrics.rs:532` `pub fn install_default(state: Arc<SecurityMetricsState>) -> Arc<SecurityMetricsState> {`
- `app/src/admin_debug/security_metrics.rs:604` `pub fn inc_block_private_ip() { with_current(SecurityMetricsState::inc_block_private_ip); }`
- `app/src/admin_debug/security_metrics.rs:605` `pub fn inc_exceed_size() { with_current(SecurityMetricsState::inc_exceed_size); }`
- `app/src/admin_debug/security_metrics.rs:606` `pub fn inc_timeout() { with_current(SecurityMetricsState::inc_timeout); }`
- `app/src/admin_debug/security_metrics.rs:607` `pub fn inc_redirects() { with_current(SecurityMetricsState::inc_redirects); }`
- `app/src/admin_debug/security_metrics.rs:608` `pub fn inc_connect_timeout() { with_current(SecurityMetricsState::inc_connect_timeout); }`
- `app/src/admin_debug/security_metrics.rs:609` `pub fn inc_upstream_4xx() { with_current(SecurityMetricsState::inc_upstream_4xx); }`
- `app/src/admin_debug/security_metrics.rs:610` `pub fn inc_upstream_5xx() { with_current(SecurityMetricsState::inc_upstream_5xx); }`
- `app/src/admin_debug/security_metrics.rs:611` `pub fn inc_rate_limited() { with_current(SecurityMetricsState::inc_rate_limited); }`
- `app/src/admin_debug/security_metrics.rs:612` `pub fn inc_cache_hit() { with_current(SecurityMetricsState::inc_cache_hit); }`
- `app/src/admin_debug/security_metrics.rs:613` `pub fn inc_cache_miss() { with_current(SecurityMetricsState::inc_cache_miss); }`
- `app/src/admin_debug/security_metrics.rs:614` `pub fn inc_cache_evict_mem() { with_current(SecurityMetricsState::inc_cache_evict_mem); }`
- `app/src/admin_debug/security_metrics.rs:615` `pub fn inc_cache_evict_disk() { with_current(SecurityMetricsState::inc_cache_evict_disk); }`
- `app/src/admin_debug/security_metrics.rs:616` `pub fn inc_head_total() { with_current(SecurityMetricsState::inc_head_total); }`
- `app/src/admin_debug/security_metrics.rs:617` `pub fn inc_breaker_block() { with_current(SecurityMetricsState::inc_breaker_block); }`
- `app/src/admin_debug/security_metrics.rs:618` `pub fn inc_breaker_reopen() { with_current(SecurityMetricsState::inc_breaker_reopen); }`
- `app/src/admin_debug/security_metrics.rs:619` `pub fn init_prefetch_metrics() { with_current(SecurityMetricsState::init_prefetch_metrics); }`
- `app/src/admin_debug/security_metrics.rs:620` `pub fn prefetch_inc(event: &str) { with_current(|s| s.prefetch_inc(event)); }`
- `app/src/admin_debug/security_metrics.rs:621` `pub fn record_prefetch_run_ms(ms: u64) { with_current(|s| s.record_prefetch_run_ms(ms)); }`
- `app/src/admin_debug/security_metrics.rs:622` `pub fn set_prefetch_queue_depth(depth: u64) { with_current(|s| s.set_prefetch_queue_depth(depth)); }`
- `app/src/admin_debug/security_metrics.rs:624` `pub fn get_prefetch_queue_depth() -> u64 { map_current(SecurityMetricsState::get_prefetch_queue_depth, 0) }`
- `app/src/admin_debug/security_metrics.rs:625` `pub fn set_prefetch_queue_high_watermark(watermark: u64) { with_current(|s| s.set_prefetch_queue_high_watermark(watermark)); }`
- `app/src/admin_debug/security_metrics.rs:627` `pub fn get_prefetch_queue_high_watermark() -> u64 { map_current(SecurityMetricsState::get_prefetch_queue_high_watermark, 0) }`
- `app/src/admin_debug/security_metrics.rs:629` `pub fn get_prefetch_counters() -> (u64, u64, u64, u64, u64) { map_current(SecurityMetricsState::get_prefetch_counters, (0, 0, 0, 0, 0)) }`
- `app/src/admin_debug/security_metrics.rs:630` `pub fn add_prefetch_bytes(bytes: u64) { with_current(|s| s.add_prefetch_bytes(bytes)); }`
- `app/src/admin_debug/security_metrics.rs:632` `pub fn get_prefetch_session_duration_ms() -> u64 { map_current(SecurityMetricsState::get_prefetch_session_duration_ms, 0) }`
- `app/src/admin_debug/security_metrics.rs:634` `pub fn get_prefetch_total_bytes() -> u64 { map_current(SecurityMetricsState::get_prefetch_total_bytes, 0) }`
- `app/src/admin_debug/security_metrics.rs:635` `pub fn start_prefetch_session() { with_current(SecurityMetricsState::start_prefetch_session); }`
- `app/src/admin_debug/security_metrics.rs:636` `pub fn inc_dns_cache_hit() { with_current(SecurityMetricsState::inc_dns_cache_hit); }`
- `app/src/admin_debug/security_metrics.rs:637` `pub fn inc_dns_cache_miss() { with_current(SecurityMetricsState::inc_dns_cache_miss); }`
- `app/src/admin_debug/security_metrics.rs:638` `pub fn record_dns_latency_ms(ms: u64) { with_current(|s| s.record_dns_latency_ms(ms)); }`
- `app/src/admin_debug/security_metrics.rs:639` `pub fn set_last_error(kind: SecurityErrorKind, msg: impl Into<String>) { with_current(|s| s.set_last_error(kind, msg)); }`
- `app/src/admin_debug/security_metrics.rs:640` `pub fn set_last_error_with_host(kind: SecurityErrorKind, host: &str, msg: impl Into<String>) { with_current(|s| s.set_last_error_with_host(kind, host, msg)); }`
- `app/src/admin_debug/security_metrics.rs:641` `pub fn set_last_error_with_url(kind: SecurityErrorKind, url: &str, msg: impl Into<String>) { with_current(|s| s.set_last_error_with_url(kind, url, msg)); }`
- `app/src/admin_debug/security_metrics.rs:642` `pub fn inc_total_requests() { with_current(SecurityMetricsState::inc_total_requests); }`
- `app/src/admin_debug/security_metrics.rs:643` `pub fn record_latency_ms(ms: u64) { with_current(|s| s.record_latency_ms(ms)); }`
- `app/src/admin_debug/security_metrics.rs:644` `pub fn mark_last_ok() { with_current(SecurityMetricsState::mark_last_ok); }`
- `app/src/admin_debug/security_metrics.rs:645` `pub fn snapshot() -> Result<SecuritySnapshot> { current()?.snapshot() }`
- `app/src/analyze/builders/core_adapters.rs:69` `pub fn register_core_adapters(registry: &AnalyzeRegistry) {`
- `app/src/analyze/registry.rs:14` `pub type AsyncBuilderFn = fn(&Value) -> Pin<Box<dyn Future<Output = Result<Value>> + Send>>;`
- `app/src/analyze/registry.rs:16` `pub struct AnalyzeRegistry {`
- `app/src/analyze/registry.rs:23` `pub fn new() -> Self {`
- `app/src/analyze/registry.rs:32` `pub fn register(&self, kind: &'static str, f: BuilderFn) {`
- `app/src/analyze/registry.rs:37` `pub fn supported_kinds(&self) -> Vec<&'static str> {`
- `app/src/analyze/registry.rs:56` `pub fn register_async(&self, kind: &'static str, f: AsyncBuilderFn) {`
- `app/src/analyze/registry.rs:61` `pub fn supported_async_kinds(&self) -> Vec<&'static str> {`
- `app/src/bin/handshake.rs:460` `pub fn main() -> Result<()> {`
- `app/src/capability_probe.rs:13` `pub struct CapabilityProbeReport {`
- `app/src/capability_probe.rs:21` `pub struct CapabilityProbeEntry {`
- `app/src/capability_probe.rs:32` `pub fn collect_report(raw: &Value, ir: &ConfigIR) -> CapabilityProbeReport {`
- `app/src/capability_probe.rs:52` `pub fn log_report(report: &CapabilityProbeReport) {`
- `app/src/capability_probe.rs:93` `pub fn probe_only_enabled() -> bool {`
- `app/src/capability_probe.rs:98` `pub fn probe_output_path_from_env() -> Option<String> {`
- `app/src/capability_probe.rs:110` `pub const fn default_probe_output_path() -> &'static str {`
- `app/src/cli/auth.rs:24` `pub struct AuthArgs {`
- `app/src/cli/auth.rs:30` `pub enum Algo {`
- `app/src/cli/auth.rs:38` `pub enum AuthCmd {`
- `app/src/cli/auth.rs:107` `pub fn main(a: AuthArgs) -> Result<()> {`
- `app/src/cli/bench.rs:24` `pub struct BenchArgs {`
- `app/src/cli/bench.rs:30` `pub enum BenchCmd {`
- `app/src/cli/bench.rs:74` `pub async fn main(a: BenchArgs) -> Result<()> {`
- `app/src/cli/buildinfo.rs:4` `pub struct BuildInfo {`
- `app/src/cli/buildinfo.rs:12` `pub const fn current() -> BuildInfo {`
- `app/src/cli/check/args.rs:5` `pub struct CheckArgs {`
- `app/src/cli/check/types.rs:6` `pub enum IssueKind {`
- `app/src/cli/check/types.rs:15` `pub struct CheckIssue {`
- `app/src/cli/check/types.rs:39` `pub struct CheckReport {`
- `app/src/cli/completion.rs:19` `pub enum Shell {`
- `app/src/cli/completion.rs:28` `pub struct CompletionArgs {`
- `app/src/cli/completion.rs:40` `pub fn main(a: CompletionArgs) -> Result<()> {`
- `app/src/cli/dns_cli.rs:7` `pub struct DnsArgs {`
- `app/src/cli/dns_cli.rs:13` `pub enum DnsCommands {`
- `app/src/cli/dns_cli.rs:23` `pub struct QueryArgs {`
- `app/src/cli/dns_cli.rs:35` `pub struct CacheArgs {`
- `app/src/cli/dns_cli.rs:42` `pub struct UpstreamArgs {`
- `app/src/cli/dns_cli.rs:48` `pub fn run(global: &GlobalArgs, args: DnsArgs) -> Result<()> {`
- `app/src/cli/format.rs:18` `pub struct FormatArgs {`
- `app/src/cli/format.rs:27` `pub fn run(global: &GlobalArgs, args: FormatArgs) -> Result<()> {`
- `app/src/cli/fs_scan.rs:14` `pub struct ScanSummary {`
- `app/src/cli/fs_scan.rs:20` `pub struct Occur {`
- `app/src/cli/fs_scan.rs:26` `pub struct ErrorJsonCoverage {`
- `app/src/cli/fs_scan.rs:36` `pub struct AnalyzeDispatch {`
- `app/src/cli/fs_scan.rs:45` `pub struct BinGates {`
- `app/src/cli/fs_scan.rs:51` `pub struct SubsLimits {`
- `app/src/cli/fs_scan.rs:58` `pub struct SecurityFlags {`
- `app/src/cli/fs_scan.rs:65` `pub struct ReportMetrics {`
- `app/src/cli/fs_scan.rs:75` `pub struct FsReport {`
- `app/src/cli/fs_scan.rs:82` `pub struct Scanner {`
- `app/src/cli/fs_scan.rs:88` `pub fn new(root: impl AsRef<Path>) -> Self {`
- `app/src/cli/fs_scan.rs:94` `pub fn run(&self) -> anyhow::Result<FsReport> {`
- `app/src/cli/generate.rs:16` `pub struct GenerateArgs {`
- `app/src/cli/generate.rs:22` `pub enum GenerateCommands {`
- `app/src/cli/generate.rs:59` `pub fn run(args: GenerateArgs) -> Result<()> {`
- `app/src/cli/geoip.rs:29` `pub struct GeoipArgs {`
- `app/src/cli/geoip.rs:39` `pub enum GeoipCmd {`
- `app/src/cli/geoip.rs:54` `pub async fn run(args: GeoipArgs) -> Result<()> {`
- `app/src/cli/geosite.rs:27` `pub struct GeositeArgs {`
- `app/src/cli/geosite.rs:37` `pub enum GeositeCmd {`
- `app/src/cli/geosite.rs:66` `pub async fn run(args: GeositeArgs) -> Result<()> {`
- `app/src/cli/health.rs:9` `pub struct HealthSnapshot {`
- `app/src/cli/health.rs:22` `pub struct HealthReport {`
- `app/src/cli/health.rs:32` `pub fn probe_from_portfile(portfile: Option<&Path>, timeout_ms: u64) -> HealthReport {`
- `app/src/cli/json.rs:34` `pub fn ok<T: Serialize>(payload: &T) {`
- `app/src/cli/json.rs:43` `pub fn err(_code: u16, error: &str, hint: &str) -> ! {`
- `app/src/cli/man.rs:7` `pub struct ManArgs {`
- `app/src/cli/man.rs:16` `pub fn main(a: ManArgs) -> Result<()> {`
- `app/src/cli/merge.rs:14` `pub struct MergeArgs {`
- `app/src/cli/merge.rs:23` `pub fn run(global: &GlobalArgs, args: MergeArgs) -> Result<()> {`
- `app/src/cli/mod.rs:131` `pub struct GlobalArgs {`
- `app/src/cli/mod.rs:149` `pub struct Args {`
- `app/src/cli/mod.rs:156` `pub fn apply_global_options(global: &GlobalArgs) -> Result<()> {`
- `app/src/cli/mod.rs:174` `pub enum Commands {`
- `app/src/cli/mod.rs:229` `pub struct VersionArgs {`
- `app/src/cli/prefetch/mod.rs:16` `pub struct PrefetchArgs {`
- `app/src/cli/prefetch/mod.rs:22` `pub enum PrefetchCmd {`
- `app/src/cli/prefetch/mod.rs:113` `pub fn main(a: PrefetchArgs) -> anyhow::Result<()> {`
- `app/src/cli/prefetch/mod.rs:148` `pub fn main(_a: PrefetchArgs) -> anyhow::Result<()> {`
- `app/src/cli/prefetch/types.rs:14` `pub struct PrefStats {`
- `app/src/cli/prefetch/types.rs:33` `pub struct SampleOut {`
- `app/src/cli/probe.rs:20` `pub struct ProbeArgs {`
- `app/src/cli/probe.rs:26` `pub enum ProbeCmd {`
- `app/src/cli/probe.rs:148` `pub async fn main(args: ProbeArgs) -> Result<()> {`
- `app/src/cli/prom.rs:21` `pub struct PromArgs {`
- `app/src/cli/prom.rs:27` `pub enum PromCmd {`
- `app/src/cli/prom.rs:67` `pub enum HistFormat {`
- `app/src/cli/prom.rs:80` `pub fn main(a: PromArgs) -> Result<()> {`
- `app/src/cli/report.rs:10` `pub struct Args {`
- `app/src/cli/report.rs:20` `pub struct Receipt<'a> {`
- `app/src/cli/report.rs:40` `pub fn main(args: Args) -> anyhow::Result<()> {`
- `app/src/cli/route.rs:8` `pub struct RouteArgs {`
- `app/src/cli/route.rs:26` `pub fn run(global: &GlobalArgs, args: RouteArgs) -> Result<()> {`
- `app/src/cli/ruleset.rs:26` `pub struct RulesetArgs {`
- `app/src/cli/ruleset.rs:42` `pub enum RulesetCmd {`
- `app/src/cli/ruleset.rs:164` `pub async fn run(args: RulesetArgs) -> Result<()> {`
- `app/src/cli/run.rs:28` `pub struct RunArgs {`
- `app/src/cli/run.rs:63` `pub async fn run(global: &GlobalArgs, args: RunArgs) -> Result<()> {`
- `app/src/cli/tools.rs:13` `pub enum Net {`
- `app/src/cli/tools.rs:21` `pub struct ToolsArgs {`
- `app/src/cli/tools.rs:27` `pub enum ToolsCmd {`
- `app/src/cli/tools.rs:105` `pub async fn run(global: &GlobalArgs, args: ToolsArgs) -> Result<()> {`
- `app/src/cli/version.rs:8` `pub struct VersionInfo {`
- `app/src/cli/version.rs:17` `pub fn run(args: VersionArgs) -> Result<()> {`
- `app/src/config_loader.rs:30` `pub enum ConfigSource {`
- `app/src/config_loader.rs:36` `pub struct ConfigEntry {`
- `app/src/config_loader.rs:41` `pub fn collect_config_entries(`
- `app/src/config_loader.rs:92` `pub fn load_merged_value(entries: &[ConfigEntry]) -> Result<Value> {`
- `app/src/config_loader.rs:107` `pub fn load_config(entries: &[ConfigEntry]) -> Result<sb_config::Config> {`
- `app/src/config_loader.rs:116` `pub fn entry_files(entries: &[ConfigEntry]) -> Vec<PathBuf> {`
- `app/src/config_loader.rs:138` `pub fn check_only(`
- `app/src/env_dump.rs:7` `pub fn print_once_if_enabled() {`
- `app/src/hardening.rs:19` `pub fn apply() {`
- `app/src/hardening.rs:40` `pub const fn apply() {}`
- `app/src/inbound_starter.rs:46` `pub enum InboundStop {`
- `app/src/inbound_starter.rs:53` `pub struct InboundHandle {`
- `app/src/inbound_starter.rs:61` `pub async fn shutdown(self) {`
- `app/src/inbound_starter.rs:201` `pub fn start_inbounds_from_ir(`
- `app/src/logging.rs:32` `pub struct LoggingOwner {`
- `app/src/logging.rs:45` `pub async fn flush(&self) {`
- `app/src/panic.rs:23` `pub fn install() {`
- `app/src/redact.rs:11` `pub struct Redactor {`
- `app/src/router/mod.rs:21` `pub const fn reset() {`
- `app/src/router/mod.rs:26` `pub fn snapshot() -> serde_json::Value {`
- `app/src/router/mod.rs:35` `pub fn supported_patch_kinds_json() -> String {`
- `app/src/router/mod.rs:70` `pub const fn derive_compare_targets(_a: &str, _b: &str, _limit: Option<usize>) -> Vec<String> {`
- `app/src/router/mod.rs:75` `pub const fn derive_targets(_dsl: &str, _limit: Option<usize>) -> Vec<String> {`
- `app/src/router/mod.rs:80` `pub fn analyze_dsl(_dsl: &str) -> AnalysisResult {`
- `app/src/router/mod.rs:85` `pub fn analysis_to_json(_analysis: &AnalysisResult) -> String {`
- `app/src/router/mod.rs:90` `pub struct PreviewResult {`
- `app/src/router/mod.rs:97` `pub struct AnalysisResult {`
- `app/src/router/mod.rs:105` `pub enum Val {`
- `app/src/router/mod.rs:111` `pub fn obj(_items: &[(&str, Val)]) -> String {`
- `app/src/router/mod.rs:141` `pub struct ExplainQuery {`
- `app/src/router/mod.rs:148` `pub struct ExplainResult {`
- `app/src/router/mod.rs:161` `pub struct RouterHandle;`
- `app/src/router/mod.rs:166` `pub const fn from_env() -> Self {`
- `app/src/router/mod.rs:176` `pub struct Report {`
- `app/src/router/mod.rs:182` `pub fn analyze(_text: &str) -> Report {`
- `app/src/router/mod.rs:190` `pub const fn rebuild_periodic(`
- `app/src/router/mod.rs:199` `pub fn snapshot_digest(_idx: &()) -> String {`
- `app/src/router/mod.rs:219` `pub fn rules_normalize(rules: &str) -> String {`
- `app/src/router/mod.rs:226` `pub const fn router_captured_rules() -> Option<Vec<String>> {`
- `app/src/router/mod.rs:232` `pub const fn get_index() {}`
- `app/src/router/mod.rs:236` `pub struct Router;`
- `app/src/router/mod.rs:240` `pub struct RouterHandle;`
- `app/src/router/mod.rs:254` `pub struct ExplainEngine;`
- `app/src/router/mod.rs:266` `pub fn explain(&self, _dest: &str, _with_trace: bool) -> ExplainResult {`
- `app/src/router/mod.rs:273` `pub struct ExplainResult {`
- `app/src/router/mod.rs:285` `pub struct Trace {`
- `app/src/run_go.rs:17` `pub async fn run_go1124(ir: &ConfigIr) -> Result<()> {`
- `app/src/runtime_deps.rs:16` `pub struct AppRuntimeDeps {`
- `app/src/runtime_deps.rs:74` `pub fn metrics_registry(&self) -> sb_metrics::MetricsRegistryHandle {`
- `app/src/runtime_deps.rs:80` `pub fn admin_state(&self) -> Arc<crate::admin_debug::AdminDebugState> {`
- `app/src/telemetry.rs:22` `pub fn next_trace_id() -> String {`
- `app/src/telemetry.rs:60` `pub fn init_and_listen(deps: &crate::runtime_deps::AppRuntimeDeps) {`
- `app/src/telemetry.rs:72` `pub const fn next_trace_id() -> String {`
- `app/src/telemetry.rs:76` `pub const fn init_tracing(_deps: &crate::runtime_deps::AppRuntimeDeps) -> Result<()> {`
- `app/src/telemetry.rs:87` `pub fn init_and_listen(_deps: &crate::runtime_deps::AppRuntimeDeps) {`
- `app/src/tls_provider.rs:5` `pub enum TlsProviderKind {`
- `app/src/tls_provider.rs:12` `pub const fn as_str(self) -> &'static str {`
- `app/src/tls_provider.rs:21` `pub struct TlsProviderDecision {`
- `app/src/tls_provider.rs:83` `pub const fn aws_lc_compiled() -> bool {`
- `crates/sb-adapters/src/endpoint/tailscale.rs:12` `pub fn build_tailscale_endpoint(`
- `crates/sb-adapters/src/endpoint/wireguard.rs:11` `pub fn build_wireguard_endpoint(`
- `crates/sb-adapters/src/inbound/anytls.rs:63` `pub struct AnyTlsInboundAdapter {`
- `crates/sb-adapters/src/inbound/anytls.rs:78` `pub fn new(`
- `crates/sb-adapters/src/inbound/http.rs:401` `pub async fn serve_conn<S>(mut cli: S, peer: SocketAddr, cfg: &HttpProxyConfig) -> Result<()>`
- `crates/sb-adapters/src/inbound/http.rs:868` `pub fn parse_request_line(line: &[u8]) -> Result<(String, String, String)> {`
- `crates/sb-adapters/src/inbound/hysteria.rs:58` `pub fn new(config: HysteriaInboundConfig) -> Result<Self> {`
- `crates/sb-adapters/src/inbound/hysteria.rs:81` `pub async fn start_server(&self) -> Result<()> {`
- `crates/sb-adapters/src/inbound/hysteria.rs:127` `pub async fn start(&self) -> Result<()> {`
- `crates/sb-adapters/src/inbound/hysteria.rs:137` `pub async fn accept(&self) -> Result<(BoxedStream, SocketAddr)> {`
- `crates/sb-adapters/src/inbound/hysteria2.rs:101` `pub fn new(config: Hysteria2InboundConfig) -> Result<Self> {`
- `crates/sb-adapters/src/inbound/hysteria2.rs:126` `pub async fn start_server(&self) -> Result<()> {`
- `crates/sb-adapters/src/inbound/hysteria2.rs:413` `pub async fn start(&self) -> Result<()> {`
- `crates/sb-adapters/src/inbound/hysteria2.rs:423` `pub async fn accept(&self) -> Result<(BoxedStream, SocketAddr)> {`
- `crates/sb-adapters/src/inbound/mixed.rs:33` `pub struct MixedInboundConfig {`
- `crates/sb-adapters/src/inbound/mixed.rs:53` `pub async fn serve_mixed(`
- `crates/sb-adapters/src/inbound/redirect.rs:32` `pub struct RedirectConfig {`
- `crates/sb-adapters/src/inbound/redirect.rs:39` `pub async fn serve(cfg: RedirectConfig, mut stop_rx: mpsc::Receiver<()>) -> Result<()> {`
- `crates/sb-adapters/src/inbound/shadowsocks.rs:48` `pub enum AeadCipherKind {`
- `crates/sb-adapters/src/inbound/shadowsocks.rs:58` `pub fn from_method(m: &str) -> Option<Self> {`
- `crates/sb-adapters/src/inbound/shadowsocks.rs:68` `pub fn key_len(&self) -> usize {`
- `crates/sb-adapters/src/inbound/shadowsocks.rs:74` `pub fn salt_len(&self) -> usize {`
- `crates/sb-adapters/src/inbound/shadowsocks.rs:80` `pub fn tag_len(&self) -> usize {`
- `crates/sb-adapters/src/inbound/shadowsocks.rs:83` `pub fn is_aead2022(&self) -> bool {`
- `crates/sb-adapters/src/inbound/shadowsocks.rs:98` `pub fn new(name: String, password: String) -> Self {`
- `crates/sb-adapters/src/inbound/shadowsocks.rs:104` `pub struct ShadowsocksInboundConfig {`
- `crates/sb-adapters/src/inbound/shadowsocks.rs:732` `pub async fn serve(cfg: ShadowsocksInboundConfig, stop_rx: mpsc::Receiver<()>) -> Result<()> {`
- `crates/sb-adapters/src/inbound/shadowsocks.rs:1118` `pub struct ShadowsocksInboundAdapter {`
- `crates/sb-adapters/src/inbound/shadowsocks.rs:1146` `pub fn new(config: ShadowsocksInboundConfig) -> Self {`
- `crates/sb-adapters/src/inbound/shadowsocks.rs:1150` `pub fn with_tag(config: ShadowsocksInboundConfig, tag: String) -> Self {`
- `crates/sb-adapters/src/inbound/shadowsocks.rs:1217` `pub async fn accept_detour_stream<T>(&self, stream: T, peer: SocketAddr) -> Result<()>`
- `crates/sb-adapters/src/inbound/shadowtls.rs:43` `pub struct ShadowTlsUser {`
- `crates/sb-adapters/src/inbound/shadowtls.rs:50` `pub struct ShadowTlsHandshakeConfig {`
- `crates/sb-adapters/src/inbound/shadowtls.rs:57` `pub enum ShadowTlsWildcardSniMode {`
- `crates/sb-adapters/src/inbound/shadowtls.rs:64` `pub fn parse(value: Option<&str>) -> Result<Self> {`
- `crates/sb-adapters/src/inbound/shadowtls.rs:75` `pub struct ShadowTlsInboundConfig {`
- `crates/sb-adapters/src/inbound/shadowtls.rs:93` `pub async fn serve(cfg: ShadowTlsInboundConfig, mut stop_rx: mpsc::Receiver<()>) -> Result<()> {`
- `crates/sb-adapters/src/inbound/shadowtls.rs:1122` `pub struct ShadowTlsInboundAdapter {`
- `crates/sb-adapters/src/inbound/shadowtls.rs:1128` `pub fn new(cfg: ShadowTlsInboundConfig) -> Self {`
- `crates/sb-adapters/src/inbound/socks/error.rs:5` `pub enum SocksError {`
- `crates/sb-adapters/src/inbound/socks/error.rs:25` `pub fn reply_code(&self) -> u8 {`
- `crates/sb-adapters/src/inbound/socks/error.rs:39` `pub fn map_connect_error(e: &io::Error) -> SocksError {`
- `crates/sb-adapters/src/inbound/socks/handshake.rs:9` `pub struct Request {`
- `crates/sb-adapters/src/inbound/socks/mod.rs:89` `pub enum DomainStrategy {`
- `crates/sb-adapters/src/inbound/socks/mod.rs:208` `pub async fn serve_conn<S>(`
- `crates/sb-adapters/src/inbound/socks/mod.rs:1102` `pub struct SocksInbound {`
- `crates/sb-adapters/src/inbound/socks/mod.rs:1107` `pub async fn run(&self) -> anyhow::Result<()> {`
- `crates/sb-adapters/src/inbound/socks/mod.rs:1199` `pub struct SocksInboundAdapter {`
- `crates/sb-adapters/src/inbound/socks/mod.rs:1205` `pub fn new(cfg: SocksInboundConfig) -> Self {`
- `crates/sb-adapters/src/inbound/socks/tcp.rs:23` `pub async fn run_tcp(addr: &str) -> Result<()> {`
- `crates/sb-adapters/src/inbound/socks/udp.rs:1047` `pub async fn serve_udp_datagrams(`
- `crates/sb-adapters/src/inbound/tproxy.rs:63` `pub struct TproxyConfig {`
- `crates/sb-adapters/src/inbound/tproxy.rs:70` `pub async fn serve(cfg: TproxyConfig, mut stop_rx: mpsc::Receiver<()>) -> Result<()> {`
- `crates/sb-adapters/src/inbound/trojan.rs:85` `pub fn new(name: String, password: String) -> Self {`
- `crates/sb-adapters/src/inbound/trojan.rs:97` `pub struct TrojanInboundConfig {`
- `crates/sb-adapters/src/inbound/trojan.rs:148` `pub async fn serve(cfg: TrojanInboundConfig, mut stop_rx: mpsc::Receiver<()>) -> Result<()> {`
- `crates/sb-adapters/src/inbound/trojan.rs:910` `pub struct TrojanInboundAdapter {`
- `crates/sb-adapters/src/inbound/trojan.rs:916` `pub fn new(cfg: TrojanInboundConfig) -> Self {`
- `crates/sb-adapters/src/inbound/tuic.rs:891` `pub struct TuicInboundAdapter {`
- `crates/sb-adapters/src/inbound/tuic.rs:897` `pub fn new(cfg: TuicInboundConfig) -> Self {`
- `crates/sb-adapters/src/inbound/tun/device.rs:9` `pub struct TunDeviceDriver {`
- `crates/sb-adapters/src/inbound/tun/device.rs:17` `pub fn new(`
- `crates/sb-adapters/src/inbound/tun/device.rs:37` `pub async fn run(mut self) {`
- `crates/sb-adapters/src/inbound/tun/mod.rs:197` `pub fn tun_metrics_snapshot() -> (u64, u64, u64) {`
- `crates/sb-adapters/src/inbound/tun/mod.rs:366` `pub fn new(`
- `crates/sb-adapters/src/inbound/tun/mod.rs:1341` `pub async fn open_and_pump_stub(_name: &str, _mtu: u32) -> io::Result<()> {`
- `crates/sb-adapters/src/inbound/tun/mod.rs:1345` `pub fn probe() -> io::Result<()> {`
- `crates/sb-adapters/src/inbound/tun/mod.rs:1492` `pub fn dst_socket(&self) -> (IpAddr, u16) {`
- `crates/sb-adapters/src/inbound/tun/mod.rs:1496` `pub fn src_socket(&self) -> (IpAddr, u16) {`
- `crates/sb-adapters/src/inbound/tun/mod.rs:1650` `pub fn probe() -> io::Result<()> {`
- `crates/sb-adapters/src/inbound/tun/mod.rs:1766` `pub fn probe() -> io::Result<()> {`
- `crates/sb-adapters/src/inbound/tun/stack.rs:33` `pub fn new(rx: mpsc::Receiver<Vec<u8>>, tx: mpsc::Sender<Vec<u8>>, mtu: usize) -> Self {`
- `crates/sb-adapters/src/inbound/tun/stack.rs:82` `pub struct VecRxToken {`
- `crates/sb-adapters/src/inbound/tun/stack.rs:95` `pub struct ChannelTxToken {`
- `crates/sb-adapters/src/inbound/tun/stack.rs:120` `pub fn new(mtu: usize, tx: mpsc::Sender<Vec<u8>>) -> Self {`
- `crates/sb-adapters/src/inbound/tun/stack.rs:281` `pub fn get_socket_mut<T: smoltcp::socket::AnySocket<'static>>(`
- `crates/sb-adapters/src/inbound/tun/stack.rs:288` `pub fn remove_socket(&mut self, handle: SocketHandle) {`
- `crates/sb-adapters/src/inbound/tun_enhanced.rs:90` `pub fn from_legacy_config(cfg: &TunInboundConfig) -> Self {`
- `crates/sb-adapters/src/inbound/tun_enhanced.rs:282` `pub struct EnhancedTunInbound {`
- `crates/sb-adapters/src/inbound/tun_enhanced.rs:342` `pub fn new(config: EnhancedTunConfig, outbounds: Arc<OutboundRegistryHandle>) -> Self {`
- `crates/sb-adapters/src/inbound/tun_enhanced.rs:351` `pub fn with_router(`
- `crates/sb-adapters/src/inbound/tun_enhanced.rs:364` `pub fn from_tun_config(`
- `crates/sb-adapters/src/inbound/tun_enhanced.rs:378` `pub async fn start(&self) -> io::Result<()> {`
- `crates/sb-adapters/src/inbound/tun_enhanced.rs:400` `pub fn config(&self) -> &EnhancedTunConfig {`
- `crates/sb-adapters/src/inbound/tun_macos.rs:137` `pub fn socks_addr(&self) -> SocketAddr {`
- `crates/sb-adapters/src/inbound/tun_macos.rs:141` `pub async fn shutdown(mut self) {`
- `crates/sb-adapters/src/inbound/tun_process_aware.rs:92` `pub fn snapshot(&self) -> TunStatsSnapshot {`
- `crates/sb-adapters/src/inbound/tun_process_aware.rs:123` `pub fn new(`
- `crates/sb-adapters/src/inbound/tun_process_aware.rs:141` `pub fn stats(&self) -> Arc<ProcessAwareTunStatistics> {`
- `crates/sb-adapters/src/inbound/tun_process_aware.rs:145` `pub fn set_v2ray_stats(`
- `crates/sb-adapters/src/inbound/tun_process_aware.rs:154` `pub async fn start(&self) -> Result<(), TunError> {`
- `crates/sb-adapters/src/inbound/tun_process_aware.rs:173` `pub async fn stop(&self) {`
- `crates/sb-adapters/src/inbound/tun_session.rs:33` `pub fn new(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Self {`
- `crates/sb-adapters/src/inbound/tun_session.rs:80` `pub fn observe_client_segment(&self, next_seq: u32) {`
- `crates/sb-adapters/src/inbound/tun_session.rs:95` `pub fn client_next_seq(&self) -> u32 {`
- `crates/sb-adapters/src/inbound/tun_session.rs:99` `pub fn server_next_seq(&self) -> u32 {`
- `crates/sb-adapters/src/inbound/tun_session.rs:103` `pub fn observe_server_ack(&self, ack: u32) {`
- `crates/sb-adapters/src/inbound/tun_session.rs:123` `pub fn server_acked_seq(&self) -> u32 {`
- `crates/sb-adapters/src/inbound/tun_session.rs:127` `pub fn reserve_server_seq(&self, consumed: u32) -> u32 {`
- `crates/sb-adapters/src/inbound/tun_session.rs:135` `pub fn initiate_close(&self) {`
- `crates/sb-adapters/src/inbound/tun_session.rs:154` `pub fn new() -> Self {`
- `crates/sb-adapters/src/inbound/tun_session.rs:176` `pub fn create_session_with_state(`
- `crates/sb-adapters/src/inbound/vless.rs:59` `pub struct VlessInboundConfig {`
- `crates/sb-adapters/src/inbound/vless.rs:94` `pub async fn serve(cfg: VlessInboundConfig, mut stop_rx: mpsc::Receiver<()>) -> Result<()> {`
- `crates/sb-adapters/src/inbound/vless.rs:618` `pub struct VlessInboundAdapter {`
- `crates/sb-adapters/src/inbound/vless.rs:624` `pub fn new(config: VlessInboundConfig) -> Self {`
- `crates/sb-adapters/src/inbound/vmess.rs:56` `pub struct VmessInboundConfig {`
- `crates/sb-adapters/src/inbound/vmess.rs:99` `pub async fn serve(cfg: VmessInboundConfig, mut stop_rx: mpsc::Receiver<()>) -> Result<()> {`
- `crates/sb-adapters/src/inbound/vmess.rs:501` `pub fn parse_vmess_request(data: &[u8]) -> Result<(String, u16, u8)> {`
- `crates/sb-adapters/src/inbound/vmess.rs:602` `pub struct VmessInboundAdapter {`
- `crates/sb-adapters/src/inbound/vmess.rs:608` `pub fn new(config: VmessInboundConfig) -> Self {`
- `crates/sb-adapters/src/outbound/anytls.rs:41` `pub fn new(config: AnyTlsConfig) -> Self {`
- `crates/sb-adapters/src/outbound/detour.rs:15` `pub async fn connect_tcp_stream(`
- `crates/sb-adapters/src/outbound/http.rs:37` `pub fn new(config: HttpProxyConfig) -> Self {`
- `crates/sb-adapters/src/outbound/hysteria.rs:47` `pub fn new(cfg: HysteriaAdapterConfig) -> Self {`
- `crates/sb-adapters/src/outbound/hysteria2.rs:52` `pub fn new(cfg: Hysteria2AdapterConfig) -> Self {`
- `crates/sb-adapters/src/outbound/quic_util.rs:29` `pub fn new(server: String, port: u16) -> Self {`
- `crates/sb-adapters/src/outbound/quic_util.rs:43` `pub fn with_alpn(mut self, alpn: Vec<Vec<u8>>) -> Self {`
- `crates/sb-adapters/src/outbound/quic_util.rs:49` `pub fn with_allow_insecure(mut self, allow: bool) -> Self {`
- `crates/sb-adapters/src/outbound/quic_util.rs:55` `pub fn with_sni(mut self, sni: Option<String>) -> Self {`
- `crates/sb-adapters/src/outbound/quic_util.rs:61` `pub fn with_extra_ca_paths(mut self, paths: Vec<String>) -> Self {`
- `crates/sb-adapters/src/outbound/quic_util.rs:67` `pub fn with_extra_ca_pem(mut self, pems: Vec<String>) -> Self {`
- `crates/sb-adapters/src/outbound/quic_util.rs:73` `pub fn with_enable_0rtt(mut self, enable: bool) -> Self {`
- `crates/sb-adapters/src/outbound/selector.rs:12` `pub fn build_selector_outbound(`
- `crates/sb-adapters/src/outbound/shadowsocks.rs:110` `pub fn new(config: ShadowsocksConfig) -> Result<Self> {`
- `crates/sb-adapters/src/outbound/shadowsocks.rs:858` `pub fn new(`
- `crates/sb-adapters/src/outbound/shadowsocksr/mod.rs:11` `pub struct ShadowsocksROutboundConfig {`
- `crates/sb-adapters/src/outbound/shadowsocksr/mod.rs:23` `pub struct ShadowsocksROutbound {`
- `crates/sb-adapters/src/outbound/shadowsocksr/mod.rs:28` `pub fn new(config: ShadowsocksROutboundConfig) -> Result<Self> {`
- `crates/sb-adapters/src/outbound/shadowsocksr/obfs.rs:70` `pub fn new(param: Option<&str>) -> Self {`
- `crates/sb-adapters/src/outbound/shadowsocksr/obfs.rs:156` `pub fn new(param: Option<&str>) -> Self {`
- `crates/sb-adapters/src/outbound/shadowsocksr/protocol.rs:75` `pub fn new(param: Option<&str>) -> Self {`
- `crates/sb-adapters/src/outbound/shadowsocksr/protocol.rs:178` `pub fn new(param: Option<&str>) -> Self {`
- `crates/sb-adapters/src/outbound/shadowsocksr/stream.rs:22` `pub fn new(`
- `crates/sb-adapters/src/outbound/shadowtls.rs:900` `pub fn new(cfg: ShadowTlsAdapterConfig) -> Self {`
- `crates/sb-adapters/src/outbound/shadowtls.rs:1016` `pub async fn connect_detour_stream(&self, host: &str, port: u16) -> Result<BoxedStream> {`
- `crates/sb-adapters/src/outbound/socks4.rs:34` `pub fn new(config: Socks4Config) -> Self {`
- `crates/sb-adapters/src/outbound/socks5.rs:46` `pub fn new(config: Socks5Config) -> Self {`
- `crates/sb-adapters/src/outbound/ssh.rs:68` `pub fn new(config: SshAdapterConfig) -> Self {`
- `crates/sb-adapters/src/outbound/tailscale.rs:493` `pub type MagicDnsSocketFactory = Arc<`
- `crates/sb-adapters/src/outbound/trojan.rs:128` `pub fn new(config: TrojanConfig) -> Self {`
- `crates/sb-adapters/src/outbound/trojan.rs:514` `pub fn new(socket: Arc<tokio::net::UdpSocket>) -> Result<Self> {`
- `crates/sb-adapters/src/outbound/tuic.rs:65` `pub struct TuicConnector {`
- `crates/sb-adapters/src/outbound/tuic.rs:422` `pub fn new(cfg: TuicAdapterConfig) -> Self {`
- `crates/sb-adapters/src/outbound/urltest.rs:14` `pub fn build_urltest_outbound(`
- `crates/sb-adapters/src/outbound/vless.rs:459` `pub fn new(socket: Arc<UdpSocket>, uuid: Uuid) -> Result<Self> {`
- `crates/sb-adapters/src/service/resolved_impl.rs:49` `pub fn new(`
- `crates/sb-adapters/src/service_stubs.rs:17` `pub fn new(ty_str: &'static str, tag: String) -> Self {`
- `crates/sb-adapters/src/service_stubs.rs:74` `pub fn build_ssmapi_service(ir: &ServiceIR, ctx: &ServiceContext) -> Option<Arc<dyn Service>> {`
- `crates/sb-admin-contract/src/lib.rs:134` `pub struct ResponseEnvelope<T> {`
- `crates/sb-api/src/v2ray/mod.rs:32` `pub struct InboundHandlerConfig {`
- `crates/sb-api/src/v2ray/mod.rs:40` `pub struct GetStatsRequest {`
- `crates/sb-api/src/v2ray/mod.rs:46` `pub struct GetStatsResponse {`
- `crates/sb-api/src/v2ray/mod.rs:51` `pub struct QueryStatsRequest {`
- `crates/sb-api/src/v2ray/mod.rs:57` `pub struct QueryStatsResponse {`
- `crates/sb-api/src/v2ray/mod.rs:62` `pub struct SysStatsRequest {}`
- `crates/sb-api/src/v2ray/mod.rs:65` `pub struct SysStatsResponse {`
- `crates/sb-api/src/v2ray/mod.rs:79` `pub struct Stat {`
- `crates/sb-api/src/v2ray/mod.rs:86` `pub struct AddInboundRequest {`
- `crates/sb-api/src/v2ray/mod.rs:91` `pub struct AddInboundResponse {}`
- `crates/sb-api/src/v2ray/mod.rs:94` `pub struct RemoveInboundRequest {`
- `crates/sb-api/src/v2ray/mod.rs:99` `pub struct RemoveInboundResponse {}`
- `crates/sb-api/src/v2ray/mod.rs:102` `pub struct AlterInboundRequest {`
- `crates/sb-api/src/v2ray/mod.rs:108` `pub struct AlterInboundResponse {}`
- `crates/sb-api/src/v2ray/mod.rs:111` `pub struct AddOutboundRequest {`
- `crates/sb-api/src/v2ray/mod.rs:116` `pub struct AddOutboundResponse {}`
- `crates/sb-api/src/v2ray/mod.rs:119` `pub struct RemoveOutboundRequest {`
- `crates/sb-api/src/v2ray/mod.rs:124` `pub struct RemoveOutboundResponse {}`
- `crates/sb-api/src/v2ray/mod.rs:127` `pub struct AlterOutboundRequest {`
- `crates/sb-api/src/v2ray/mod.rs:133` `pub struct AlterOutboundResponse {}`
- `crates/sb-api/src/v2ray/mod.rs:137` `pub struct SubscribeRoutingStatsRequest {}`
- `crates/sb-api/src/v2ray/mod.rs:140` `pub struct TestRouteRequest {`
- `crates/sb-api/src/v2ray/mod.rs:146` `pub struct RoutingContext {`
- `crates/sb-api/src/v2ray/mod.rs:158` `pub struct RestartLoggerRequest {}`
- `crates/sb-api/src/v2ray/mod.rs:161` `pub struct RestartLoggerResponse {}`
- `crates/sb-api/src/v2ray/mod.rs:164` `pub struct FollowLogRequest {}`
- `crates/sb-api/src/v2ray/mod.rs:167` `pub struct LogEntry {`
- `crates/sb-api/src/v2ray/mod.rs:182` `pub trait StatsService: Send + Sync + 'static {`
- `crates/sb-api/src/v2ray/mod.rs:200` `pub struct StatsServiceServer<T> {`
- `crates/sb-api/src/v2ray/mod.rs:206` `pub fn new(inner: T) -> Self {`
- `crates/sb-api/src/v2ray/mod.rs:264` `pub trait HandlerService: Send + Sync + 'static {`
- `crates/sb-api/src/v2ray/mod.rs:297` `pub struct HandlerServiceServer<T> {`
- `crates/sb-api/src/v2ray/mod.rs:303` `pub fn new(inner: T) -> Self {`
- `crates/sb-api/src/v2ray/mod.rs:362` `pub trait RoutingService: Send + Sync + 'static {`
- `crates/sb-api/src/v2ray/mod.rs:379` `pub struct RoutingServiceServer<T> {`
- `crates/sb-api/src/v2ray/mod.rs:385` `pub fn new(inner: T) -> Self {`
- `crates/sb-api/src/v2ray/mod.rs:444` `pub trait LoggerService: Send + Sync + 'static {`
- `crates/sb-api/src/v2ray/mod.rs:459` `pub struct LoggerServiceServer<T> {`
- `crates/sb-api/src/v2ray/mod.rs:465` `pub fn new(inner: T) -> Self {`
- `crates/sb-api/src/v2ray/services.rs:37` `pub fn new(stream: BroadcastStream<T>) -> Self {`
- `crates/sb-api/src/v2ray/services.rs:81` `pub fn new() -> Self {`
- `crates/sb-api/src/v2ray/services.rs:244` `pub fn new() -> Self {`
- `crates/sb-api/src/v2ray/services.rs:418` `pub fn new() -> Self {`
- `crates/sb-api/src/v2ray/services.rs:486` `pub fn new() -> Self {`
- `crates/sb-common/src/minijson.rs:30` `pub fn obj<const N: usize>(kvs: [(&str, Val); N]) -> String {`
- `crates/sb-common/src/minijson.rs:66` `pub fn arr_str(list: &[&str]) -> String {`
- `crates/sb-config/src/ir/mod.rs:394` `pub struct MasqueradeFileIR {`
- `crates/sb-config/src/ir/mod.rs:399` `pub struct MasqueradeProxyIR {`
- `crates/sb-config/src/ir/mod.rs:406` `pub struct MasqueradeStringIR {`
- `crates/sb-config/src/ir/mod.rs:2077` `pub fn into_vec(self) -> Vec<T> {`
- `crates/sb-config/src/ir/mod.rs:2131` `pub fn into_inner(self) -> T {`
- `crates/sb-config/src/lib.rs:57` `pub struct Config {`
- `crates/sb-config/src/lib.rs:240` `pub struct Auth {`
- `crates/sb-config/src/lib.rs:246` `pub struct Rule {`
- `crates/sb-config/src/lib.rs:364` `pub fn from_value(doc: Value) -> Result<Self> {`
- `crates/sb-config/src/lib.rs:387` `pub fn raw(&self) -> &Value {`
- `crates/sb-config/src/lib.rs:391` `pub fn ir(&self) -> &crate::ir::ConfigIR {`
- `crates/sb-config/src/lib.rs:395` `pub fn stats(&self) -> (usize, usize, usize) {`
- `crates/sb-config/src/lib.rs:426` `pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {`
- `crates/sb-config/src/lib.rs:455` `pub fn validate(&self) -> Result<()> {`
- `crates/sb-config/src/minimize.rs:172` `pub enum MinimizeAction {`
- `crates/sb-config/src/minimize.rs:177` `pub fn minimize_config(cfg: &mut ConfigIR) -> MinimizeAction {`
- `crates/sb-config/src/model.rs:137` `pub struct Config {`
- `crates/sb-config/src/model.rs:152` `pub fn normalize(mut self) -> Self {`
- `crates/sb-config/src/normalize.rs:80` `pub fn normalize_rule(r: &mut RuleIR) {`
- `crates/sb-config/src/normalize.rs:108` `pub fn normalize_config(cfg: &mut ConfigIR) {`
- `crates/sb-config/src/outbound.rs:41` `pub type OutboundKind = Outbound;`
- `crates/sb-config/src/outbound.rs:44` `pub struct DirectConfig {`
- `crates/sb-config/src/outbound.rs:50` `pub struct HttpProxyConfig {`
- `crates/sb-config/src/outbound.rs:69` `pub struct Socks5Config {`
- `crates/sb-config/src/outbound.rs:85` `pub struct Socks4Config {`
- `crates/sb-config/src/outbound.rs:99` `pub struct VmessConfig {`
- `crates/sb-config/src/outbound.rs:143` `pub struct VlessConfig {`
- `crates/sb-config/src/outbound.rs:178` `pub struct TuicConfig {`
- `crates/sb-config/src/outbound.rs:225` `pub struct SelectorConfig {`
- `crates/sb-config/src/outbound.rs:239` `pub struct UrlTestConfig {`
- `crates/sb-config/src/rule/negation.rs:59` `pub struct ConfigLite {`
- `crates/sb-core/src/adapter/bridge.rs:747` `pub fn build_bridge(`
- `crates/sb-core/src/adapter/clash.rs:86` `pub fn new() -> Self {`
- `crates/sb-core/src/adapter/clash.rs:90` `pub fn with_cache_file(mut self, cache_file: Arc<dyn crate::context::CacheFile>) -> Self {`
- `crates/sb-core/src/adapter/handler.rs:101` `pub fn new(tag: String, connector: Arc<dyn super::OutboundConnector>) -> Self {`
- `crates/sb-core/src/adapter/handler.rs:135` `pub fn new() -> Self {`
- `crates/sb-core/src/adapter/handler.rs:178` `pub fn list_packet_tags(&self) -> Vec<String> {`
- `crates/sb-core/src/adapter/handler.rs:182` `pub fn list_upstream_tags(&self) -> Vec<String> {`
- `crates/sb-core/src/adapter/registry.rs:45` `pub type InboundBuilder =`
- `crates/sb-core/src/adapter/registry.rs:47` `pub type OutboundBuilder = fn(`
- `crates/sb-core/src/adapter/registry.rs:57` `pub struct RegistrySnapshot {`
- `crates/sb-core/src/adapter/registry.rs:64` `pub fn new() -> Self {`
- `crates/sb-core/src/adapter/registry.rs:68` `pub fn register_inbound(&mut self, kind: &'static str, builder: InboundBuilder) -> bool {`
- `crates/sb-core/src/adapter/registry.rs:72` `pub fn register_outbound(&mut self, kind: &'static str, builder: OutboundBuilder) -> bool {`
- `crates/sb-core/src/adapter/registry.rs:87` `pub struct InboundRegistryHandle {`
- `crates/sb-core/src/adapter/registry.rs:92` `pub fn new(inner: HashMap<String, Arc<dyn InboundService>>) -> Self {`
- `crates/sb-core/src/adapter/registry.rs:96` `pub fn get(&self, tag: &str) -> Option<Arc<dyn InboundService>> {`
- `crates/sb-core/src/admin/http.rs:876` `pub fn spawn_admin(`
- `crates/sb-core/src/config/mod.rs:9` `pub fn try_parse_str(s: &str) -> Result<(), ()> {`
- `crates/sb-core/src/config/schema_v2.rs:21` `pub type Config = ConfigV2;`
- `crates/sb-core/src/config/schema_v2.rs:22` `pub type Route = RouteV2;`
- `crates/sb-core/src/config/schema_v2.rs:23` `pub type RouteRule = RouteRuleV2;`
- `crates/sb-core/src/config/schema_v2.rs:24` `pub type Inbound = InboundV2;`
- `crates/sb-core/src/config/schema_v2.rs:25` `pub type Outbound = OutboundV2;`
- `crates/sb-core/src/config/schema_v2.rs:28` `pub fn dump_v2_schema() -> serde_json::Value {`
- `crates/sb-core/src/conntrack/inbound_tcp.rs:20` `pub fn id(&self) -> sb_common::conntrack::ConnId {`
- `crates/sb-core/src/context.rs:144` `pub fn new() -> Self {`
- `crates/sb-core/src/context.rs:174` `pub fn with_cache_file(mut self, cache_file: Arc<dyn CacheFile>) -> Self {`
- `crates/sb-core/src/context.rs:179` `pub fn with_urltest_history(mut self, history: Arc<dyn URLTestHistoryStorage>) -> Self {`
- `crates/sb-core/src/context.rs:184` `pub fn with_v2ray_server(mut self, v2ray_server: Arc<dyn V2RayServer>) -> Self {`
- `crates/sb-core/src/context.rs:189` `pub fn with_ntp_service(mut self, ntp_service: Arc<dyn NtpService>) -> Self {`
- `crates/sb-core/src/context.rs:194` `pub fn with_time_service(mut self, time_service: Arc<dyn TimeService>) -> Self {`
- `crates/sb-core/src/context.rs:199` `pub fn with_certificate_store(mut self, certificate_store: Arc<dyn CertificateStore>) -> Self {`
- `crates/sb-core/src/context.rs:221` `pub struct RouteOptions {`
- `crates/sb-core/src/context.rs:259` `pub fn new() -> Self {`
- `crates/sb-core/src/context.rs:329` `pub fn route_options(&self) -> RouteOptions {`
- `crates/sb-core/src/context.rs:474` `pub fn new() -> Self {`
- `crates/sb-core/src/context.rs:566` `pub fn new() -> Self {`
- `crates/sb-core/src/context.rs:664` `pub fn new() -> Self {`
- `crates/sb-core/src/context.rs:759` `pub trait CacheFile: Send + Sync + std::fmt::Debug {`
- `crates/sb-core/src/context.rs:768` `pub trait V2RayServer: Send + Sync + std::fmt::Debug {`
- `crates/sb-core/src/context.rs:775` `pub trait NtpService: Send + Sync + std::fmt::Debug {}`
- `crates/sb-core/src/dns/cache.rs:43` `pub const fn as_str(&self) -> &'static str {`
- `crates/sb-core/src/dns/cache.rs:79` `pub const fn from_u16(value: u16) -> Self {`
- `crates/sb-core/src/dns/cache.rs:88` `pub const fn to_u16(&self) -> u16 {`
- `crates/sb-core/src/dns/cache_v2.rs:8` `pub enum QType {`
- `crates/sb-core/src/dns/cache_v2.rs:14` `pub struct PosEntry {`
- `crates/sb-core/src/dns/cache_v2.rs:20` `pub struct NegEntry {`
- `crates/sb-core/src/dns/cache_v2.rs:24` `pub enum CacheCell {`
- `crates/sb-core/src/dns/cache_v2.rs:29` `pub struct DnsCache {`
- `crates/sb-core/src/dns/cache_v2.rs:38` `pub fn new(min_ttl: Duration, max_ttl: Duration) -> Self {`
- `crates/sb-core/src/dns/cache_v2.rs:59` `pub async fn get(&self, name: &str, q: QType, now: Instant) -> Option<CacheCell> {`
- `crates/sb-core/src/dns/cache_v2.rs:82` `pub async fn put_pos(`
- `crates/sb-core/src/dns/cache_v2.rs:112` `pub async fn put_neg(&self, name: &str, q: QType, ttl: Duration, now: Instant) {`
- `crates/sb-core/src/dns/client.rs:13` `pub struct DnsClient {`
- `crates/sb-core/src/dns/client.rs:37` `pub fn new(ttl: Duration) -> Self {`
- `crates/sb-core/src/dns/client.rs:256` `pub struct Timer {`
- `crates/sb-core/src/dns/client.rs:261` `pub fn new(name: &'static str) -> Self {`
- `crates/sb-core/src/dns/client.rs:267` `pub fn observe_duration_ms(&self) -> u128 {`
- `crates/sb-core/src/dns/dot.rs:8` `pub async fn query_dot_once(`
- `crates/sb-core/src/dns/fakeip.rs:245` `pub fn enabled() -> bool {`
- `crates/sb-core/src/dns/fakeip.rs:251` `pub fn set_storage(storage: Arc<dyn FakeIpStorage>) {`
- `crates/sb-core/src/dns/fakeip.rs:276` `pub fn allocate_v4(domain: &str) -> IpAddr {`
- `crates/sb-core/src/dns/fakeip.rs:319` `pub fn allocate_v6(domain: &str) -> IpAddr {`
- `crates/sb-core/src/dns/fakeip.rs:361` `pub fn lookup_domain(ip: &IpAddr) -> Option<String> {`
- `crates/sb-core/src/dns/fakeip.rs:367` `pub fn mapping_count() -> usize {`
- `crates/sb-core/src/dns/fakeip.rs:373` `pub fn reset() -> usize {`
- `crates/sb-core/src/dns/fakeip.rs:418` `pub fn is_fake_ip(ip: &IpAddr) -> bool {`
- `crates/sb-core/src/dns/fakeip.rs:427` `pub fn to_domain(ip: &IpAddr) -> Option<String> {`
- `crates/sb-core/src/dns/handle.rs:8` `pub struct DnsHandle(pub Arc<RwLock<Arc<DnsRouter>>>);`
- `crates/sb-core/src/dns/handle.rs:11` `pub fn new(router: DnsRouter) -> Self {`
- `crates/sb-core/src/dns/message.rs:9` `pub struct QuestionKey {`
- `crates/sb-core/src/dns/message.rs:27` `pub const fn new(name: String, rtype: u16, class: u16, ttl: u32, data: Vec<u8>) -> Self {`
- `crates/sb-core/src/dns/metrics.rs:3` `pub fn inc_timeout(kind: &'static str) {`
- `crates/sb-core/src/dns/metrics.rs:9` `pub fn inc_blackhole() {`
- `crates/sb-core/src/dns/metrics.rs:15` `pub fn inc_resolve_err(code: &'static str) {`
- `crates/sb-core/src/dns/metrics.rs:21` `pub fn obs_inflight(scope: &'static str, v: i64) {`
- `crates/sb-core/src/dns/mod.rs:189` `pub const fn as_u16(self) -> u16 {`
- `crates/sb-core/src/dns/mod.rs:193` `pub const fn from_u16(value: u16) -> Option<Self> {`
- `crates/sb-core/src/dns/mod.rs:230` `pub trait DnsResolver: Send + Sync {`
- `crates/sb-core/src/dns/mod.rs:318` `pub fn from_env_or_default() -> Self {`
- `crates/sb-core/src/dns/mod.rs:463` `pub async fn resolve(&self, host: &str) -> Result<DnsAnswer> {`
- `crates/sb-core/src/dns/resolve.rs:8` `pub enum DnsBackend {`
- `crates/sb-core/src/dns/stub.rs:17` `pub struct DnsCache {`
- `crates/sb-core/src/dns/stub.rs:23` `pub fn new(ttl_secs: u64) -> Self {`
- `crates/sb-core/src/dns/stub.rs:33` `pub fn resolve(&self, host: &str, port: u16) -> Option<Vec<SocketAddr>> {`
- `crates/sb-core/src/dns/stub.rs:66` `pub fn purge_expired(&self) {`
- `crates/sb-core/src/dns/stub.rs:72` `pub fn size(&self) -> usize {`
- `crates/sb-core/src/dns/stub.rs:78` `pub fn init_global(ttl_secs: u64) {`
- `crates/sb-core/src/dns/stub.rs:81` `pub fn global() -> Option<&'static DnsCache> {`
- `crates/sb-core/src/dns/system.rs:12` `pub struct SystemResolver {`
- `crates/sb-core/src/dns/system.rs:17` `pub const fn new(default_ttl: Duration) -> Self {`
- `crates/sb-core/src/dns/transport/dhcp.rs:54` `pub struct DhcpTransport {`
- `crates/sb-core/src/dns/transport/dhcp.rs:68` `pub fn new(interface: Option<String>) -> Self {`
- `crates/sb-core/src/dns/transport/doh3.rs:19` `pub struct Doh3Transport {`
- `crates/sb-core/src/dns/transport/doh3.rs:30` `pub fn new(server: SocketAddr, server_name: String, path: String) -> Result<Self> {`
- `crates/sb-core/src/dns/transport/doh3.rs:34` `pub fn new_with_tls(`
- `crates/sb-core/src/dns/transport/doh3.rs:227` `pub struct Doh3Transport;`
- `crates/sb-core/src/dns/transport/doh3.rs:231` `pub fn new(_server: SocketAddr, _server_name: String, _path: String) -> Result<Self> {`
- `crates/sb-core/src/dns/transport/doq.rs:17` `pub struct DoqTransport {`
- `crates/sb-core/src/dns/transport/doq.rs:26` `pub fn new(server: SocketAddr, server_name: String) -> Result<Self> {`
- `crates/sb-core/src/dns/transport/doq.rs:30` `pub fn new_with_tls(`
- `crates/sb-core/src/dns/transport/local.rs:8` `pub struct LocalTransport;`
- `crates/sb-core/src/dns/transport/local.rs:11` `pub fn new() -> Self {`
- `crates/sb-core/src/dns/transport/mod.rs:83` `pub trait DnsTransport: Send + Sync {`
- `crates/sb-core/src/dns/transport/mod.rs:154` `pub type DohClient = DohTransport;`
- `crates/sb-core/src/dns/transport/mod.rs:156` `pub type DotClient = DotTransport;`
- `crates/sb-core/src/dns/transport/mod.rs:160` `pub struct DhcpResolver {`
- `crates/sb-core/src/dns/transport/mod.rs:165` `pub fn new() -> Self {`
- `crates/sb-core/src/dns/transport/resolved.rs:46` `pub fn to_ip_addr(&self) -> Option<IpAddr> {`
- `crates/sb-core/src/dns/transport/resolved.rs:71` `pub fn to_ip_addr(&self) -> Option<IpAddr> {`
- `crates/sb-core/src/dns/transport/resolved.rs:118` `pub fn new() -> Self {`
- `crates/sb-core/src/dns/transport/resolved.rs:134` `pub fn set_service_tag(&self, tag: String) {`
- `crates/sb-core/src/dns/transport/resolved.rs:138` `pub fn get_service_tag(&self) -> String {`
- `crates/sb-core/src/dns/transport/resolved.rs:149` `pub fn get_or_create_link(&self, if_index: i32, if_name: &str) -> TransportLink {`
- `crates/sb-core/src/dns/transport/resolved.rs:161` `pub fn update_link(&self, link: TransportLink) -> Result<(), String> {`
- `crates/sb-core/src/dns/transport/resolved.rs:173` `pub fn delete_link(&self, if_index: i32) {`
- `crates/sb-core/src/dns/udp.rs:6` `pub fn build_query(host: &str, qtype: u16) -> Result<Vec<u8>> {`
- `crates/sb-core/src/dns/udp.rs:96` `pub fn parse_answers(buf: &[u8], expect_qtype: u16) -> Result<(Vec<IpAddr>, Option<u32>)> {`
- `crates/sb-core/src/dns/upstream.rs:1056` `pub fn new(name: String, addrs: Vec<SocketAddr>) -> Self {`
- `crates/sb-core/src/dns/upstream.rs:1211` `pub fn from_spec(spec: &str, tag: Option<&str>) -> Result<Self> {`
- `crates/sb-core/src/dns/upstream.rs:1479` `pub fn new(tag: String, config: ResolvedTransportConfig) -> Self {`
- `crates/sb-core/src/dns/upstream.rs:1554` `pub fn new_with_tls(`
- `crates/sb-core/src/dns/upstream.rs:1582` `pub fn with_client_subnet(mut self, ecs: Option<String>) -> Self {`
- `crates/sb-core/src/dns/upstream.rs:1923` `pub fn new(server: SocketAddr, server_name: String) -> Self {`
- `crates/sb-core/src/dns/upstream.rs:1927` `pub fn new_with_tls(`
- `crates/sb-core/src/dns/upstream.rs:2491` `pub fn new(tag: Option<&str>) -> Self {`
- `crates/sb-core/src/dns/upstream.rs:2574` `pub fn new(tag: Option<&str>) -> Self {`
- `crates/sb-core/src/endpoint/handler.rs:19` `pub struct EndpointConnectionHandler {`
- `crates/sb-core/src/endpoint/handler.rs:27` `pub fn new(`
- `crates/sb-core/src/endpoint/mod.rs:332` `pub struct EndpointContext {`
- `crates/sb-core/src/endpoint/mod.rs:605` `pub fn new(tag: String, endpoint: Arc<dyn Endpoint>) -> Self {`
- `crates/sb-core/src/endpoint/mod.rs:609` `pub fn tag(&self) -> &str {`
- `crates/sb-core/src/endpoint/tailscale.rs:169` `pub fn new(config: TailscaleEndpointConfig) -> Self {`
- `crates/sb-core/src/endpoint/wireguard.rs:92` `pub fn new(`
- `crates/sb-core/src/endpoint/wireguard.rs:614` `pub fn build_wireguard_endpoint(`
- `crates/sb-core/src/error.rs:17` `pub type Result<T, E = Error> = std::result::Result<T, E>;`
- `crates/sb-core/src/error.rs:18` `pub type SbResult<T> = std::result::Result<T, SbError>;`
- `crates/sb-core/src/error_map.rs:8` `pub fn from_io_error(e: &io::Error) -> IssueCode {`
- `crates/sb-core/src/errors/classify.rs:5` `pub struct NetClass {`
- `crates/sb-core/src/errors/classify.rs:10` `pub fn classify_io(e: &std::io::Error) -> NetClass {`
- `crates/sb-core/src/errors/classify.rs:30` `pub const fn classify_tls(err: &rustls::Error) -> NetClass {`
- `crates/sb-core/src/geo/loader.rs:9` `pub fn load_geoip() -> Option<Vec<u8>> {`
- `crates/sb-core/src/geo/loader.rs:17` `pub fn load_geosite() -> Option<HashSet<String>> {`
- `crates/sb-core/src/geoip/mmdb.rs:159` `pub fn new() -> anyhow::Result<Self> {`
- `crates/sb-core/src/geoip/mmdb.rs:168` `pub fn from_paths(`
- `crates/sb-core/src/geoip/mmdb.rs:318` `pub fn new() -> anyhow::Result<Self> {`
- `crates/sb-core/src/geoip/mmdb.rs:389` `pub fn lookup(&self, ip: IpAddr) -> Option<GeoInfo> {`
- `crates/sb-core/src/geoip/mmdb.rs:393` `pub fn is_country(&self, ip: IpAddr, country_code: &str) -> bool {`
- `crates/sb-core/src/geoip/mod.rs:55` `pub fn new(provider: Box<dyn GeoIpProvider>) -> Self {`
- `crates/sb-core/src/geoip/mod.rs:124` `pub fn lookup_country_code(ip: IpAddr) -> Option<String> {`
- `crates/sb-core/src/geoip/multi.rs:380` `pub fn new(strategy: LookupStrategy) -> Self {`
- `crates/sb-core/src/geoip/multi.rs:387` `pub fn add_provider(`
- `crates/sb-core/src/geoip/multi.rs:398` `pub fn build(self) -> GeoMux {`
- `crates/sb-core/src/health/mod.rs:37` `pub fn spawn_health_task(bridge: Arc<Bridge>) -> tokio::task::JoinHandle<()> {`
- `crates/sb-core/src/inbound/direct.rs:27` `pub struct DirectConfig {`
- `crates/sb-core/src/inbound/direct.rs:52` `pub struct DirectForward {`
- `crates/sb-core/src/inbound/direct.rs:68` `pub fn new(listen: SocketAddr, dst_host: String, dst_port: u16, udp_enabled: bool) -> Self {`
- `crates/sb-core/src/inbound/direct.rs:90` `pub fn with_config(mut self, cfg: DirectConfig) -> Self {`
- `crates/sb-core/src/inbound/direct.rs:95` `pub fn with_tag(mut self, tag: Option<String>) -> Self {`
- `crates/sb-core/src/inbound/direct.rs:100` `pub fn with_stats(mut self, stats: Option<Arc<StatsManager>>) -> Self {`
- `crates/sb-core/src/inbound/direct.rs:105` `pub fn with_conn_tracker(mut self, conn_tracker: Arc<ConnTracker>) -> Self {`
- `crates/sb-core/src/inbound/http_connect.rs:392` `pub struct HttpConnect {`
- `crates/sb-core/src/inbound/http_connect.rs:407` `pub fn new(listen: String, port: u16) -> Self {`
- `crates/sb-core/src/inbound/http_connect.rs:421` `pub fn with_engine(mut self, eng: EngineX) -> Self {`
- `crates/sb-core/src/inbound/http_connect.rs:433` `pub fn with_bridge(mut self, br: Arc<Bridge>) -> Self {`
- `crates/sb-core/src/inbound/http_connect.rs:444` `pub fn with_basic_auth(mut self, user: Option<String>, pass: Option<String>) -> Self {`
- `crates/sb-core/src/inbound/mixed.rs:33` `pub struct MixedInbound {`
- `crates/sb-core/src/inbound/mixed.rs:49` `pub fn new(listen: String, port: u16) -> Self {`
- `crates/sb-core/src/inbound/mixed.rs:67` `pub fn with_engine(mut self, eng: EngineX) -> Self {`
- `crates/sb-core/src/inbound/mixed.rs:72` `pub fn with_engine(mut self, eng: Engine) -> Self {`
- `crates/sb-core/src/inbound/mixed.rs:77` `pub fn with_bridge(mut self, br: Arc<Bridge>) -> Self {`
- `crates/sb-core/src/inbound/mixed.rs:82` `pub fn with_sniff(mut self, enabled: bool) -> Self {`
- `crates/sb-core/src/inbound/mixed.rs:87` `pub fn with_basic_auth(mut self, user: Option<String>, pass: Option<String>) -> Self {`
- `crates/sb-core/src/inbound/socks5.rs:690` `pub struct Socks5 {`
- `crates/sb-core/src/inbound/socks5.rs:706` `pub fn new(listen: String, port: u16) -> Self {`
- `crates/sb-core/src/inbound/socks5.rs:724` `pub fn with_engine(mut self, eng: EngineX) -> Self {`
- `crates/sb-core/src/inbound/socks5.rs:736` `pub fn with_bridge(mut self, br: Arc<Bridge>) -> Self {`
- `crates/sb-core/src/inbound/tun.rs:135` `pub fn new(key: FlowKey, outbound: String) -> Self {`
- `crates/sb-core/src/inbound/tun.rs:172` `pub fn new(max_sessions: usize, timeout_secs: u64) -> Self {`
- `crates/sb-core/src/inbound/unsupported.rs:7` `pub struct UnsupportedInbound {`
- `crates/sb-core/src/inbound/unsupported.rs:14` `pub fn new(kind: impl Into<String>, reason: impl Into<String>, hint: Option<String>) -> Self {`
- `crates/sb-core/src/log/mod.rs:8` `pub enum Level {`
- `crates/sb-core/src/log/mod.rs:64` `pub fn configure(ir: &sb_config::ir::LogIR) {`
- `crates/sb-core/src/log/mod.rs:123` `pub fn init(target: &str) {`
- `crates/sb-core/src/log/mod.rs:127` `pub fn log(level: Level, msg: &str, kv: &[(&str, &str)]) {`
- `crates/sb-core/src/metrics/dns.rs:16` `pub enum DnsQueryType {`
- `crates/sb-core/src/metrics/dns.rs:22` `pub const fn from_u16(v: u16) -> Self {`
- `crates/sb-core/src/metrics/dns.rs:29` `pub const fn as_str(&self) -> &'static str {`
- `crates/sb-core/src/metrics/dns.rs:39` `pub enum DnsErrorClass {`
- `crates/sb-core/src/metrics/dns.rs:46` `pub const fn as_str(&self) -> &'static str {`
- `crates/sb-core/src/metrics/dns.rs:54` `pub fn from_error_str(s: &str) -> Self {`
- `crates/sb-core/src/metrics/dns.rs:68` `pub fn record_query(_q: DnsQueryType) {`
- `crates/sb-core/src/metrics/dns.rs:75` `pub fn record_rtt(_rtt_ms: f64) {`
- `crates/sb-core/src/metrics/dns.rs:82` `pub fn record_error(_c: DnsErrorClass) {`
- `crates/sb-core/src/metrics/dns.rs:90` `pub fn record_cache_hit() {`
- `crates/sb-core/src/metrics/dns.rs:94` `pub fn record_cache_miss() {`
- `crates/sb-core/src/metrics/dns.rs:98` `pub fn set_cache_size(_size: usize) {`
- `crates/sb-core/src/metrics/dns.rs:105` `pub fn record_successful_query(_q: DnsQueryType, _rtt_ms: f64, _from_cache: bool) {`
- `crates/sb-core/src/metrics/dns.rs:119` `pub fn record_failed_query(_q: DnsQueryType, _class: DnsErrorClass) {`
- `crates/sb-core/src/metrics/dns.rs:131` `pub fn register_metrics() {`
- `crates/sb-core/src/metrics/dns.rs:153` `pub fn dns_query_total() -> &'static prometheus::IntCounterVec {`
- `crates/sb-core/src/metrics/dns.rs:158` `pub fn dns_error_total() -> &'static prometheus::IntCounterVec {`
- `crates/sb-core/src/metrics/dns.rs:163` `pub fn dns_cache_hit_total() -> &'static prometheus::IntCounterVec {`
- `crates/sb-core/src/metrics/dns.rs:172` `pub fn dns_cache_store_total() -> &'static prometheus::IntCounterVec {`
- `crates/sb-core/src/metrics/dns.rs:181` `pub fn dns_cache_ttl_clamped_total() -> &'static prometheus::IntCounterVec {`
- `crates/sb-core/src/metrics/dns.rs:190` `pub struct DnsCacheMetrics {`
- `crates/sb-core/src/metrics/dns.rs:197` `pub fn register_dns_cache_metrics() -> DnsCacheMetrics {`
- `crates/sb-core/src/metrics/dns.rs:206` `pub struct DnsCacheMetrics {}`
- `crates/sb-core/src/metrics/dns.rs:208` `pub fn register_dns_cache_metrics() -> DnsCacheMetrics {`
- `crates/sb-core/src/metrics/dns_v2.rs:5` `pub struct DnsCacheMetrics {`
- `crates/sb-core/src/metrics/dns_v2.rs:12` `pub fn register_dns_cache_metrics() -> DnsCacheMetrics {`
- `crates/sb-core/src/metrics/dns_v2.rs:37` `pub struct DnsCacheMetrics {}`
- `crates/sb-core/src/metrics/dns_v2.rs:39` `pub fn register_dns_cache_metrics() -> DnsCacheMetrics {`
- `crates/sb-core/src/metrics/geoip.rs:85` `pub fn geoip_lookup_duration(_duration: f64) {}`
- `crates/sb-core/src/metrics/geoip.rs:88` `pub fn geoip_lookup_total(_result: &str) {}`
- `crates/sb-core/src/metrics/geoip.rs:91` `pub fn geoip_country_lookup_total(_country: &str) {}`
- `crates/sb-core/src/metrics/geoip.rs:94` `pub fn geoip_provider_success(_provider: &str, _duration: f64) {}`
- `crates/sb-core/src/metrics/geoip.rs:97` `pub fn geoip_provider_failure(_provider: &str, _duration: f64) {}`
- `crates/sb-core/src/metrics/geoip.rs:100` `pub fn geoip_fastest_provider(_provider: &str, _duration: f64) {}`
- `crates/sb-core/src/metrics/geoip.rs:103` `pub fn geoip_cache_hit() {}`
- `crates/sb-core/src/metrics/geoip.rs:106` `pub fn geoip_cache_miss() {}`
- `crates/sb-core/src/metrics/geoip.rs:109` `pub fn geoip_cache_size(_size: usize) {}`
- `crates/sb-core/src/metrics/geoip.rs:112` `pub fn geoip_database_loaded(_db_type: &str, _file_size: u64) {}`
- `crates/sb-core/src/metrics/geoip.rs:115` `pub fn geoip_database_load_error(_db_type: &str, _error: &str) {}`
- `crates/sb-core/src/metrics/geoip.rs:129` `pub fn init_geoip_metrics() {}`
- `crates/sb-core/src/metrics/http.rs:130` `pub const fn as_str(&self) -> &'static str {`
- `crates/sb-core/src/metrics/http_exporter.rs:48` `pub fn run_exporter(addr: &str) -> std::io::Result<()> {`
- `crates/sb-core/src/metrics/http_exporter.rs:52` `pub fn run_exporter_with_registry(`
- `crates/sb-core/src/metrics/labels.rs:6` `pub enum Proto {`
- `crates/sb-core/src/metrics/labels.rs:18` `pub enum ResultTag {`
- `crates/sb-core/src/metrics/labels.rs:32` `pub enum CipherType {`
- `crates/sb-core/src/metrics/labels.rs:39` `pub const fn as_str(&self) -> &'static str {`
- `crates/sb-core/src/metrics/labels.rs:54` `pub const fn as_str(&self) -> &'static str {`
- `crates/sb-core/src/metrics/labels.rs:71` `pub const fn as_str(&self) -> &'static str {`
- `crates/sb-core/src/metrics/labels.rs:81` `pub fn record_connect_total(_proto: Proto, _result: ResultTag) {`
- `crates/sb-core/src/metrics/labels.rs:90` `pub fn record_handshake_duration(_proto: Proto, _duration_ms: f64) {`
- `crates/sb-core/src/metrics/labels.rs:99` `pub fn record_tls_verify(_proto: Proto, _result: &'static str) {`
- `crates/sb-core/src/metrics/mod.rs:23` `pub fn registry() -> &'static prometheus::Registry {`
- `crates/sb-core/src/metrics/outbound.rs:22` `pub enum OutboundErrorClass {`
- `crates/sb-core/src/metrics/outbound.rs:57` `pub fn register_metrics() {`
- `crates/sb-core/src/metrics/outbound.rs:61` `pub fn record_connect_attempt(_kind: OutboundKind) {`
- `crates/sb-core/src/metrics/outbound.rs:75` `pub fn record_connect_success(_kind: OutboundKind) {`
- `crates/sb-core/src/metrics/outbound.rs:89` `pub fn record_connect_failure(_kind: OutboundKind) {`
- `crates/sb-core/src/metrics/outbound.rs:103` `pub fn record_connect_error(_kind: OutboundKind, _class: OutboundErrorClass) {`
- `crates/sb-core/src/metrics/outbound.rs:119` `pub fn record_connect_duration(_duration_ms: f64) {`
- `crates/sb-core/src/metrics/outbound.rs:151` `pub struct SelectorMetrics {`
- `crates/sb-core/src/metrics/outbound.rs:160` `pub fn params_gauge() -> &'static prometheus::IntGaugeVec {`
- `crates/sb-core/src/metrics/outbound.rs:178` `pub fn proxy_select_score() -> &'static prometheus::GaugeVec {`
- `crates/sb-core/src/metrics/outbound.rs:188` `pub fn proxy_select_switch_total() -> &'static prometheus::IntCounterVec {`
- `crates/sb-core/src/metrics/outbound.rs:197` `pub fn proxy_select_explore_total() -> &'static prometheus::IntCounterVec {`
- `crates/sb-core/src/metrics/outbound.rs:206` `pub fn rate_limited_total() -> &'static prometheus::IntCounterVec {`
- `crates/sb-core/src/metrics/outbound.rs:215` `pub fn register_selector_metrics() -> SelectorMetrics {`
- `crates/sb-core/src/metrics/outbound.rs:224` `pub struct SelectorMetrics {}`
- `crates/sb-core/src/metrics/outbound.rs:227` `pub fn register_selector_metrics() -> SelectorMetrics {`
- `crates/sb-core/src/metrics/outbound.rs:233` `pub fn handshake_duration_histogram() -> &'static prometheus::HistogramVec {`
- `crates/sb-core/src/metrics/outbound.rs:246` `pub fn handshake_duration_histogram() -> DummyHistogramVec {`
- `crates/sb-core/src/metrics/outbound.rs:251` `pub struct DummyHistogramVec;`
- `crates/sb-core/src/metrics/outbound.rs:255` `pub const fn with_label_values(&self, _labels: &[&str]) -> DummyHistogram {`
- `crates/sb-core/src/metrics/outbound.rs:261` `pub struct DummyHistogram;`
- `crates/sb-core/src/metrics/outbound.rs:265` `pub const fn observe(&self, _value: f64) {}`
- `crates/sb-core/src/metrics/outbound.rs:269` `pub fn record_trojan_connect_success() {`
- `crates/sb-core/src/metrics/outbound.rs:275` `pub fn record_trojan_connect_error() {`
- `crates/sb-core/src/metrics/outbound.rs:281` `pub fn record_trojan_handshake_duration(duration_ms: f64) {`
- `crates/sb-core/src/metrics/outbound.rs:287` `pub fn record_shadowsocks_connect_success() {`
- `crates/sb-core/src/metrics/outbound.rs:293` `pub fn record_shadowsocks_connect_error() {`
- `crates/sb-core/src/metrics/outbound.rs:299` `pub fn record_shadowsocks_encrypt_bytes(bytes: u64) {`
- `crates/sb-core/src/metrics/outbound.rs:307` `pub fn register_comprehensive_metrics() {`
- `crates/sb-core/src/metrics/outbound.rs:386` `pub fn register_comprehensive_metrics() {`
- `crates/sb-core/src/metrics/outbound.rs:392` `pub fn record_trojan_connect_attempt(cipher: &str) {`
- `crates/sb-core/src/metrics/outbound.rs:399` `pub fn record_trojan_connect_success_with_cipher(cipher: &str) {`
- `crates/sb-core/src/metrics/outbound.rs:405` `pub fn record_trojan_connect_error_with_cipher(cipher: &str) {`
- `crates/sb-core/src/metrics/outbound.rs:413` `pub fn record_ss_connect_attempt(cipher: &str) {`
- `crates/sb-core/src/metrics/outbound.rs:420` `pub fn record_ss_connect_success_with_cipher(cipher: &str) {`
- `crates/sb-core/src/metrics/outbound.rs:426` `pub fn record_ss_connect_error_with_cipher(cipher: &str) {`
- `crates/sb-core/src/metrics/outbound.rs:432` `pub fn record_ss_encrypt_bytes_with_cipher(bytes: u64, cipher: &str) {`
- `crates/sb-core/src/metrics/outbound.rs:438` `pub fn record_ss_udp_send_with_cipher(cipher: &str) {`
- `crates/sb-core/src/metrics/outbound.rs:444` `pub fn record_ss_udp_recv_with_cipher(cipher: &str) {`
- `crates/sb-core/src/metrics/outbound.rs:450` `pub fn record_ss_aead_op_duration(duration_ms: f64, cipher: &str, operation: &str) {`
- `crates/sb-core/src/metrics/outbound.rs:457` `pub fn record_aead_encrypt_duration(`
- `crates/sb-core/src/metrics/outbound.rs:471` `pub fn record_aead_decrypt_duration(`
- `crates/sb-core/src/metrics/outbound.rs:485` `pub fn record_aead_encrypt_total(`
- `crates/sb-core/src/metrics/outbound.rs:502` `pub fn record_ss_stream_error_with_cipher(reason: &str, cipher: &str) {`
- `crates/sb-core/src/metrics/outbound.rs:513` `pub fn record_ss_decrypt_bytes_with_cipher(bytes: u64, cipher: &str) {`
- `crates/sb-core/src/metrics/outbound.rs:518` `pub fn record_aead_decrypt_total(`
- `crates/sb-core/src/metrics/registry_ext.rs:86` `pub fn get_or_register_gauge_vec(name: &str, help: &str, labels: &[&str]) -> &'static IntGaugeVec {`
- `crates/sb-core/src/metrics/registry_ext.rs:150` `pub fn get_or_register_counter_vec(`
- `crates/sb-core/src/metrics/registry_ext.rs:243` `pub fn get_or_register_histogram_vec(`
- `crates/sb-core/src/metrics/udp.rs:20` `pub struct UdpNatMetrics {`
- `crates/sb-core/src/metrics/udp.rs:31` `pub fn register_udp_nat_metrics() -> UdpNatMetrics {`
- `crates/sb-core/src/metrics/udp.rs:86` `pub struct UdpNatMetrics {}`
- `crates/sb-core/src/metrics/udp.rs:88` `pub fn register_udp_nat_metrics() -> UdpNatMetrics {`
- `crates/sb-core/src/metrics/udp.rs:93` `pub fn set_nat_size(_size: usize) {`
- `crates/sb-core/src/metrics/udp.rs:107` `pub enum EvictionReason {`
- `crates/sb-core/src/metrics/udp.rs:113` `pub fn record_nat_eviction(_reason: EvictionReason) {`
- `crates/sb-core/src/metrics/udp.rs:125` `pub fn inc_packets_in() {`
- `crates/sb-core/src/metrics/udp.rs:129` `pub fn inc_packets_out() {`
- `crates/sb-core/src/metrics/udp.rs:134` `pub enum UdpErrorClass {`
- `crates/sb-core/src/metrics/udp.rs:142` `pub fn record_upstream_failure(_class: UdpErrorClass) {`
- `crates/sb-core/src/metrics/udp.rs:164` `pub fn record_flow_bytes(_dir: &str, _n: usize) {`
- `crates/sb-core/src/metrics/udp.rs:172` `pub fn record_session_ttl(_ttl_seconds: f64) {`
- `crates/sb-core/src/metrics/udp.rs:178` `pub fn record_timeout_failure() {`
- `crates/sb-core/src/metrics/udp.rs:182` `pub fn record_io_failure() {`
- `crates/sb-core/src/metrics/udp.rs:186` `pub fn record_decode_failure() {`
- `crates/sb-core/src/metrics/udp.rs:190` `pub fn record_no_route_failure() {`
- `crates/sb-core/src/metrics/udp.rs:194` `pub fn record_canceled_failure() {`
- `crates/sb-core/src/metrics/udp.rs:198` `pub fn record_other_failure() {`
- `crates/sb-core/src/metrics/udp.rs:204` `pub fn udp_nat_size_gauge() -> &'static prometheus::IntGaugeVec {`
- `crates/sb-core/src/metrics/udp.rs:209` `pub fn udp_nat_evicted_total() -> &'static prometheus::IntCounterVec {`
- `crates/sb-core/src/metrics/udp.rs:213` `pub fn register_metrics() {`
- `crates/sb-core/src/metrics/udp_v2.rs:5` `pub struct UdpNatMetrics {`
- `crates/sb-core/src/metrics/udp_v2.rs:15` `pub fn register_udp_nat_metrics() -> UdpNatMetrics {`
- `crates/sb-core/src/metrics/udp_v2.rs:53` `pub struct UdpNatMetrics {}`
- `crates/sb-core/src/metrics/udp_v2.rs:55` `pub fn register_udp_nat_metrics() -> UdpNatMetrics {`
- `crates/sb-core/src/net/datagram.rs:66` `pub fn new<T>(_maybe_ttl: T) -> Self`
- `crates/sb-core/src/net/datagram.rs:75` `pub async fn get(&self, k: &UdpNatKey) -> Option<Arc<UdpSocket>> {`
- `crates/sb-core/src/net/datagram.rs:100` `pub async fn upsert(&self, k: UdpNatKey, upstream: Arc<UdpSocket>) {`
- `crates/sb-core/src/net/datagram.rs:173` `pub async fn len(&self) -> usize {`
- `crates/sb-core/src/net/datagram.rs:177` `pub async fn is_empty(&self) -> bool {`
- `crates/sb-core/src/net/datagram.rs:204` `pub async fn map(&self) -> &Mutex<HashMap<UdpNatKey, UdpNatEntry>> {`
- `crates/sb-core/src/net/metered.rs:122` `pub async fn copy_bidirectional_streaming_ctl<A, B>(`
- `crates/sb-core/src/net/metered.rs:353` `pub fn new(inner: T, label: &'static str) -> Self {`
- `crates/sb-core/src/net/metered.rs:363` `pub fn into_inner(self) -> T {`
- `crates/sb-core/src/net/rate_limit.rs:19` `pub struct RateLimiter {`
- `crates/sb-core/src/net/rate_limit.rs:29` `pub fn from_env_udp() -> Option<Self> {`
- `crates/sb-core/src/net/tcp_rate_limit.rs:42` `pub fn from_env() -> Self {`
- `crates/sb-core/src/net/tcp_rate_limit.rs:85` `pub fn new(config: TcpRateLimitConfig) -> Self {`
- `crates/sb-core/src/net/udp_nat.rs:17` `pub enum TargetAddr {`
- `crates/sb-core/src/net/udp_nat.rs:23` `pub struct NatKey {`
- `crates/sb-core/src/net/udp_nat.rs:29` `pub struct NatEntry {`
- `crates/sb-core/src/net/udp_nat.rs:67` `pub struct NatMap {`
- `crates/sb-core/src/net/udp_nat.rs:77` `pub fn new(ttl: Duration, cap: usize) -> Arc<Self> {`
- `crates/sb-core/src/net/udp_nat.rs:93` `pub fn is_empty(&self) -> bool {`
- `crates/sb-core/src/net/udp_nat.rs:336` `pub fn add_out_bytes(&self, key: &NatKey, n: usize) {`
- `crates/sb-core/src/net/udp_nat_v2.rs:13` `pub enum TargetAddr {`
- `crates/sb-core/src/net/udp_nat_v2.rs:19` `pub struct NatKey {`
- `crates/sb-core/src/net/udp_nat_v2.rs:25` `pub struct NatEntry {`
- `crates/sb-core/src/net/udp_nat_v2.rs:62` `pub struct NatMap {`
- `crates/sb-core/src/net/udp_nat_v2.rs:72` `pub fn new(ttl: Duration, cap: usize) -> Arc<Self> {`
- `crates/sb-core/src/net/udp_nat_v2.rs:147` `pub fn add_out_bytes(&self, key: &NatKey, n: usize) {`
- `crates/sb-core/src/net/udp_upstream_map.rs:11` `pub struct Key {`
- `crates/sb-core/src/net/udp_upstream_map.rs:21` `pub struct UdpUpstreamMap {`
- `crates/sb-core/src/net/udp_upstream_map.rs:28` `pub fn new(ttl: Duration) -> Self {`
- `crates/sb-core/src/net/udp_upstream_map.rs:39` `pub async fn get(&self, key: &Key) -> Option<Arc<UpSocksSession>> {`
- `crates/sb-core/src/net/udp_upstream_map.rs:49` `pub async fn insert(&self, key: Key, sess: Arc<UpSocksSession>) -> bool {`
- `crates/sb-core/src/net/udp_upstream_map.rs:77` `pub async fn remove(&self, key: &Key) -> Option<Arc<UpSocksSession>> {`
- `crates/sb-core/src/net/udp_upstream_map.rs:90` `pub async fn evict_expired(&self) -> usize {`
- `crates/sb-core/src/net/util/mod.rs:2` `pub enum Address {`
- `crates/sb-core/src/obs/access.rs:20` `pub fn log(event: &str, kv: &[(&str, String)]) {`
- `crates/sb-core/src/outbound/address.rs:13` `pub fn from_target_addr(target: &TargetAddr) -> Self {`
- `crates/sb-core/src/outbound/block.rs:10` `pub struct BlockOutbound;`
- `crates/sb-core/src/outbound/block_connector.rs:11` `pub fn new() -> Self {`
- `crates/sb-core/src/outbound/crypto_types.rs:13` `pub const fn new(host: String, port: u16) -> Self {`
- `crates/sb-core/src/outbound/crypto_types.rs:17` `pub fn from_domain(domain: &str, port: u16) -> Self {`
- `crates/sb-core/src/outbound/direct.rs:12` `pub struct DirectOutbound<D = SystemDialer> {`
- `crates/sb-core/src/outbound/direct.rs:23` `pub fn with_ctx(ctx: OutboundContext<D>) -> Self {`
- `crates/sb-core/src/outbound/direct.rs:89` `pub fn new() -> Self {`
- `crates/sb-core/src/outbound/direct_connector.rs:41` `pub fn with_options(`
- `crates/sb-core/src/outbound/direct_simple.rs:6` `pub struct Direct;`
- `crates/sb-core/src/outbound/endpoint.rs:4` `pub enum ProxyKind {`
- `crates/sb-core/src/outbound/endpoint.rs:10` `pub struct ProxyEndpoint {`
- `crates/sb-core/src/outbound/endpoint.rs:21` `pub fn parse(s: &str) -> Option<Self> {`
- `crates/sb-core/src/outbound/feedback.rs:9` `pub trait SelectorFeedback {`
- `crates/sb-core/src/outbound/feedback.rs:16` `pub struct FeedbackHandle {`
- `crates/sb-core/src/outbound/feedback.rs:21` `pub fn new(inner: Arc<Mutex<dyn SelectorFeedback + Send + Sync>>) -> Self {`
- `crates/sb-core/src/outbound/feedback.rs:24` `pub fn success(&self, id: &str, started: Instant) {`
- `crates/sb-core/src/outbound/feedback.rs:28` `pub fn error(&self, id: &str) {`
- `crates/sb-core/src/outbound/feedback.rs:31` `pub fn open_fail(&self, id: &str) {`
- `crates/sb-core/src/outbound/feedback.rs:44` `pub fn new(inner: Arc<Mutex<crate::outbound::selector_p3::ScoreSelector>>) -> Self {`
- `crates/sb-core/src/outbound/health.rs:15` `pub struct HealthStatus {`
- `crates/sb-core/src/outbound/health.rs:23` `pub fn new() -> Self {`
- `crates/sb-core/src/outbound/health.rs:32` `pub fn is_up(&self) -> bool {`
- `crates/sb-core/src/outbound/health.rs:43` `pub struct EpState {`
- `crates/sb-core/src/outbound/health.rs:54` `pub struct MultiHealthView;`
- `crates/sb-core/src/outbound/health.rs:80` `pub fn global_status() -> Option<&'static HealthStatus> {`
- `crates/sb-core/src/outbound/health.rs:84` `pub async fn spawn_if_enabled() {`
- `crates/sb-core/src/outbound/http_proxy.rs:15` `pub struct HttpProxyOptions {`
- `crates/sb-core/src/outbound/http_proxy.rs:22` `pub struct HttpProxyOutbound<D = SystemDialer> {`
- `crates/sb-core/src/outbound/http_proxy.rs:32` `pub fn with_ctx(ctx: OutboundContext<D>, opts: HttpProxyOptions) -> Self {`
- `crates/sb-core/src/outbound/http_upstream.rs:9` `pub struct HttpUp {`
- `crates/sb-core/src/outbound/http_upstream.rs:17` `pub fn new(server: String, port: u16, user: Option<String>, pass: Option<String>) -> Self {`
- `crates/sb-core/src/outbound/hysteria/v1.rs:93` `pub fn new(config: HysteriaV1Config) -> anyhow::Result<Self> {`
- `crates/sb-core/src/outbound/hysteria/v1.rs:309` `pub fn new(config: HysteriaV1ServerConfig) -> Self {`
- `crates/sb-core/src/outbound/hysteria/v1.rs:585` `pub fn new(timeout: Duration) -> Self {`
- `crates/sb-core/src/outbound/hysteria/v1.rs:592` `pub async fn create_session(`
- `crates/sb-core/src/outbound/hysteria/v1.rs:610` `pub async fn get_session(&self, session_id: u32) -> Option<UdpSession> {`
- `crates/sb-core/src/outbound/hysteria/v1.rs:615` `pub async fn cleanup_expired(&self) {`
- `crates/sb-core/src/outbound/hysteria2.rs:38` `pub struct Hysteria2Config {`
- `crates/sb-core/src/outbound/hysteria2.rs:60` `pub struct BrutalConfig {`
- `crates/sb-core/src/outbound/hysteria2.rs:67` `pub enum CongestionControl {`
- `crates/sb-core/src/outbound/hysteria2.rs:76` `pub struct Hysteria2Outbound {`
- `crates/sb-core/src/outbound/hysteria2.rs:87` `pub struct BandwidthLimiter {`
- `crates/sb-core/src/outbound/hysteria2.rs:97` `pub fn new(up_mbps: Option<u32>, down_mbps: Option<u32>) -> Self {`
- `crates/sb-core/src/outbound/hysteria2.rs:107` `pub async fn consume_up(&self, bytes: u32) -> bool {`
- `crates/sb-core/src/outbound/hysteria2.rs:121` `pub async fn consume_down(&self, bytes: u32) -> bool {`
- `crates/sb-core/src/outbound/hysteria2.rs:135` `pub async fn refill_tokens(&self) {`
- `crates/sb-core/src/outbound/hysteria2.rs:156` `pub fn new(config: Hysteria2Config) -> anyhow::Result<Self> {`
- `crates/sb-core/src/outbound/hysteria2.rs:209` `pub fn generate_auth_hash(&self) -> [u8; 32] {`
- `crates/sb-core/src/outbound/hysteria2.rs:767` `pub struct Hysteria2UdpSession {`
- `crates/sb-core/src/outbound/hysteria2.rs:775` `pub async fn send_udp(&self, data: &[u8], target: &HostPort) -> io::Result<()> {`
- `crates/sb-core/src/outbound/hysteria2.rs:827` `pub async fn recv_udp(&self) -> io::Result<(Vec<u8>, SocketAddr)> {`
- `crates/sb-core/src/outbound/hysteria2.rs:1043` `pub struct Hysteria2Stream {`
- `crates/sb-core/src/outbound/hysteria2.rs:1182` `pub struct Hysteria2Config;`
- `crates/sb-core/src/outbound/hysteria2.rs:1186` `pub fn new() -> Self {`
- `crates/sb-core/src/outbound/hysteria2.rs:1262` `pub fn new(config: Hysteria2ServerConfig) -> Self {`
- `crates/sb-core/src/outbound/mod.rs:177` `pub enum OutboundKind {`
- `crates/sb-core/src/outbound/mod.rs:190` `pub enum RouteTarget {`
- `crates/sb-core/src/outbound/mod.rs:196` `pub const fn direct() -> Self {`
- `crates/sb-core/src/outbound/mod.rs:199` `pub const fn block() -> Self {`
- `crates/sb-core/src/outbound/mod.rs:205` `pub enum Endpoint {`
- `crates/sb-core/src/outbound/mod.rs:211` `pub enum OutboundImpl {`
- `crates/sb-core/src/outbound/mod.rs:225` `pub struct OutboundRegistry {`
- `crates/sb-core/src/outbound/mod.rs:229` `pub const fn new(map: HashMap<String, OutboundImpl>) -> Self {`
- `crates/sb-core/src/outbound/mod.rs:232` `pub fn get(&self, name: &str) -> Option<&OutboundImpl> {`
- `crates/sb-core/src/outbound/mod.rs:235` `pub fn insert(&mut self, name: String, v: OutboundImpl) {`
- `crates/sb-core/src/outbound/mod.rs:238` `pub fn keys(&self) -> impl Iterator<Item = &String> {`
- `crates/sb-core/src/outbound/mod.rs:244` `pub struct OutboundRegistryHandle {`
- `crates/sb-core/src/outbound/mod.rs:255` `pub fn new(reg: OutboundRegistry) -> Self {`
- `crates/sb-core/src/outbound/mod.rs:260` `pub fn replace(&self, reg: OutboundRegistry) {`
- `crates/sb-core/src/outbound/mod.rs:265` `pub fn read(&self) -> std::sync::RwLockReadGuard<'_, OutboundRegistry> {`
- `crates/sb-core/src/outbound/mod.rs:268` `pub async fn connect_tcp(&self, target: &RouteTarget, ep: Endpoint) -> io::Result<TcpStream> {`
- `crates/sb-core/src/outbound/mod.rs:530` `pub struct Socks5Config {`
- `crates/sb-core/src/outbound/mod.rs:684` `pub struct HttpProxyConfig {`
- `crates/sb-core/src/outbound/mod.rs:783` `pub struct ConnectOpts {`
- `crates/sb-core/src/outbound/naive_h2.rs:24` `pub struct NaiveH2Config {`
- `crates/sb-core/src/outbound/naive_h2.rs:32` `pub struct NaiveH2Outbound {`
- `crates/sb-core/src/outbound/naive_h2.rs:39` `pub fn new(config: NaiveH2Config) -> anyhow::Result<Self> {`
- `crates/sb-core/src/outbound/naive_h2.rs:194` `pub struct NaiveH2Config;`
- `crates/sb-core/src/outbound/naive_h2.rs:198` `pub fn new() -> Self {`
- `crates/sb-core/src/outbound/p3_selector.rs:10` `pub struct PickerConfig {`
- `crates/sb-core/src/outbound/p3_selector.rs:83` `pub struct P3Selector {`
- `crates/sb-core/src/outbound/p3_selector.rs:91` `pub fn new(outbounds: Vec<String>, cfg: PickerConfig) -> Self {`
- `crates/sb-core/src/outbound/p3_selector.rs:104` `pub fn record_rtt(&mut self, ob: &str, ms: f64) {`
- `crates/sb-core/src/outbound/p3_selector.rs:109` `pub fn record_result(&mut self, ob: &str, ok: bool) {`
- `crates/sb-core/src/outbound/quic/common.rs:11` `pub struct QuicConfig {`
- `crates/sb-core/src/outbound/quic/common.rs:24` `pub fn new(server: String, port: u16) -> Self {`
- `crates/sb-core/src/outbound/quic/common.rs:37` `pub fn with_alpn(mut self, alpn: Vec<Vec<u8>>) -> Self {`
- `crates/sb-core/src/outbound/quic/common.rs:42` `pub fn with_allow_insecure(mut self, allow: bool) -> Self {`
- `crates/sb-core/src/outbound/quic/common.rs:47` `pub fn with_sni(mut self, sni: Option<String>) -> Self {`
- `crates/sb-core/src/outbound/quic/common.rs:52` `pub fn with_extra_ca_paths(mut self, paths: Vec<String>) -> Self {`
- `crates/sb-core/src/outbound/quic/common.rs:57` `pub fn with_extra_ca_pem(mut self, pems: Vec<String>) -> Self {`
- `crates/sb-core/src/outbound/quic/common.rs:62` `pub fn with_enable_0rtt(mut self, enable: bool) -> Self {`
- `crates/sb-core/src/outbound/quic/common.rs:188` `pub struct QuicConfig;`
- `crates/sb-core/src/outbound/quic/common.rs:192` `pub fn new(_server: String, _port: u16) -> Self {`
- `crates/sb-core/src/outbound/quic/io.rs:18` `pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {`
- `crates/sb-core/src/outbound/registry.rs:7` `pub struct Registry {`
- `crates/sb-core/src/outbound/registry.rs:13` `pub struct ProxyPool {`
- `crates/sb-core/src/outbound/registry.rs:21` `pub enum PoolPolicy {`
- `crates/sb-core/src/outbound/registry.rs:27` `pub struct StickyCfg {`
- `crates/sb-core/src/outbound/registry.rs:34` `pub fn install_global(r: Registry) {`
- `crates/sb-core/src/outbound/registry.rs:38` `pub fn global() -> Option<Arc<Registry>> {`
- `crates/sb-core/src/outbound/selector.rs:13` `pub struct Member {`
- `crates/sb-core/src/outbound/selector.rs:38` `pub struct Selector {`
- `crates/sb-core/src/outbound/selector.rs:49` `pub fn new(name: String, members: Vec<Member>) -> Self {`
- `crates/sb-core/src/outbound/selector.rs:337` `pub struct EndpointHealth {`
- `crates/sb-core/src/outbound/selector.rs:347` `pub const fn new(pool_name: String) -> Self {`
- `crates/sb-core/src/outbound/selector.rs:354` `pub fn add_endpoint(&mut self, proxy_endpoint: ProxyEndpoint) {`
- `crates/sb-core/src/outbound/selector.rs:366` `pub fn add_endpoint_from_string(&mut self, address: String) {`
- `crates/sb-core/src/outbound/selector.rs:372` `pub fn update_endpoint_health(&mut self, index: usize, is_healthy: bool, rtt_ms: Option<f64>) {`
- `crates/sb-core/src/outbound/selector.rs:390` `pub fn new(name: String, default_pool: String) -> Self {`
- `crates/sb-core/src/outbound/selector.rs:399` `pub fn new_with_capacity(capacity: usize, _ttl: Duration) -> Self {`
- `crates/sb-core/src/outbound/selector.rs:407` `pub fn add_pool(&mut self, pool_name: String, endpoints: Vec<String>) {`
- `crates/sb-core/src/outbound/selector.rs:415` `pub fn get_pool(&self, pool_name: &str) -> Option<&HealthView> {`
- `crates/sb-core/src/outbound/selector.rs:419` `pub fn get_pool_mut(&mut self, pool_name: &str) -> Option<&mut HealthView> {`
- `crates/sb-core/src/outbound/selector.rs:423` `pub fn select_healthy_endpoint(&self, pool_name: &str) -> Option<&EndpointHealth> {`
- `crates/sb-core/src/outbound/selector.rs:437` `pub fn record_observation(`
- `crates/sb-core/src/outbound/selector_group.rs:51` `pub fn new(`
- `crates/sb-core/src/outbound/selector_group.rs:102` `pub fn record_success(&self, rtt_ms: u64) {`
- `crates/sb-core/src/outbound/selector_group.rs:144` `pub fn is_healthy(&self) -> bool {`
- `crates/sb-core/src/outbound/selector_group.rs:151` `pub fn get_rtt_ms(&self) -> u64 {`
- `crates/sb-core/src/outbound/selector_group.rs:155` `pub fn is_permanently_failed(&self) -> bool {`
- `crates/sb-core/src/outbound/selector_p3.rs:5` `pub struct Candidate {`
- `crates/sb-core/src/outbound/selector_p3.rs:11` `pub struct Stats {`
- `crates/sb-core/src/outbound/selector_p3.rs:32` `pub enum ExploreMode {`
- `crates/sb-core/src/outbound/selector_p3.rs:68` `pub struct ScoreSelector {`
- `crates/sb-core/src/outbound/selector_p3.rs:87` `pub fn new(config: SelectorConfig) -> Self {`
- `crates/sb-core/src/outbound/selector_p3.rs:121` `pub fn choose(&mut self, cs: &[Candidate], now: Instant) -> String {`
- `crates/sb-core/src/outbound/selector_p3.rs:258` `pub fn record_success(&mut self, id: &str, rtt_ms: u64) {`
- `crates/sb-core/src/outbound/selector_p3.rs:272` `pub fn record_error(&mut self, id: &str) {`
- `crates/sb-core/src/outbound/selector_p3.rs:279` `pub fn record_open_fail(&mut self, id: &str) {`
- `crates/sb-core/src/outbound/selector_p3.rs:285` `pub fn get_current(&self) -> Option<&str> {`
- `crates/sb-core/src/outbound/selector_p3.rs:289` `pub fn get_stats(&self) -> &HashMap<String, Stats> {`
- `crates/sb-core/src/outbound/socks5.rs:15` `pub struct Socks5Opts {`
- `crates/sb-core/src/outbound/socks5.rs:23` `pub struct Socks5Outbound<D = SystemDialer> {`
- `crates/sb-core/src/outbound/socks5.rs:29` `pub fn new(ctx: OutboundContext<D>, opts: Socks5Opts) -> Self {`
- `crates/sb-core/src/outbound/socks_upstream.rs:9` `pub struct SocksUp {`
- `crates/sb-core/src/outbound/socks_upstream.rs:17` `pub fn new(server: String, port: u16, user: Option<String>, pass: Option<String>) -> Self {`
- `crates/sb-core/src/outbound/ss/hkdf.rs:30` `pub const fn derive_subkey(_master_key: &[u8], _salt: &[u8], _hash_alg: HashAlgorithm) -> [u8; 32] {`
- `crates/sb-core/src/outbound/ss/hkdf.rs:61` `pub const fn generate_salt(_size: usize) -> Vec<u8> {`
- `crates/sb-core/src/outbound/types.rs:20` `pub const fn new(host: String, port: u16) -> Self {`
- `crates/sb-core/src/outbound/types.rs:118` `pub const fn new(target: TargetAddr) -> Self {`
- `crates/sb-core/src/outbound/types.rs:125` `pub const fn with_timeout(mut self, timeout_ms: u64) -> Self {`
- `crates/sb-core/src/outbound/types.rs:139` `pub const fn new(bind: SocketAddr) -> Self {`
- `crates/sb-core/src/outbound/types.rs:143` `pub fn with_target(mut self, target: TargetAddr) -> Self {`
- `crates/sb-core/src/outbound/udp.rs:119` `pub async fn direct_sendto(sock: &UdpSocket, dst: &UdpTargetAddr, payload: &[u8]) -> Result<usize> {`
- `crates/sb-core/src/outbound/udp_socks5.rs:35` `pub async fn ensure_udp_relay() -> anyhow::Result<SocketAddr> {`
- `crates/sb-core/src/pipeline.rs:9` `pub trait Inbound: Send + Sync {`
- `crates/sb-core/src/pipeline.rs:14` `pub trait Outbound: Send + Sync {`
- `crates/sb-core/src/pipeline.rs:25` `pub type DynOutbound = Arc<dyn Outbound>;`
- `crates/sb-core/src/pipeline.rs:27` `pub struct Pipeline<I: Inbound> {`
- `crates/sb-core/src/pipeline.rs:32` `pub const fn new(inbound: I) -> Self {`
- `crates/sb-core/src/pipeline.rs:35` `pub async fn run(self) -> anyhow::Result<()> {`
- `crates/sb-core/src/router/advanced.rs:36` `pub enum Proto {`
- `crates/sb-core/src/router/advanced.rs:109` `pub fn atom(c: AtomCond) -> Self { Cond::Atom(c) }`
- `crates/sb-core/src/router/advanced.rs:110` `pub fn and<I: IntoIterator<Item = Cond>>(it: I) -> Self { Cond::And(it.into_iter().collect()) }`
- `crates/sb-core/src/router/advanced.rs:111` `pub fn or<I: IntoIterator<Item = Cond>>(it: I) -> Self { Cond::Or(it.into_iter().collect()) }`
- `crates/sb-core/src/router/advanced.rs:112` `pub fn not(c: Cond) -> Self { Cond::Not(Box::new(c)) }`
- `crates/sb-core/src/router/advanced.rs:114` `pub fn hit(&self, t: &Target) -> bool {`
- `crates/sb-core/src/router/advanced.rs:144` `pub fn builder(name: impl Into<String>) -> AdvRuleBuilder {`
- `crates/sb-core/src/router/advanced.rs:163` `pub fn when(mut self, cond: Cond) -> Self { self.cond = cond; self }`
- `crates/sb-core/src/router/advanced.rs:164` `pub fn to(mut self, action: Action) -> Self { self.action = action; self }`
- `crates/sb-core/src/router/advanced.rs:165` `pub fn priority(mut self, p: i32) -> Self { self.priority = p; self }`
- `crates/sb-core/src/router/advanced.rs:166` `pub fn build(self) -> AdvRule {`
- `crates/sb-core/src/router/advanced.rs:180` `pub fn new() -> Self { Self::default() }`
- `crates/sb-core/src/router/advanced.rs:182` `pub fn with_rules<I: IntoIterator<Item = AdvRule>>(mut self, it: I) -> Self {`
- `crates/sb-core/src/router/advanced.rs:187` `pub fn add_rules<I: IntoIterator<Item = AdvRule>>(&mut self, it: I) {`
- `crates/sb-core/src/router/advanced.rs:192` `pub fn evaluate(&mut self, t: &Target) -> Option<&Action> {`
- `crates/sb-core/src/router/advanced.rs:202` `pub fn stats(&self) -> BTreeMap<String, u64> {`
- `crates/sb-core/src/router/advanced.rs:232` `pub fn rule_domain_suffix(name: impl Into<String>, suf: impl Into<String>, outbound: impl Into<String>, prio: i32) -> AdvRule {`
- `crates/sb-core/src/router/advanced.rs:240` `pub fn rule_domain_keyword(name: impl Into<String>, kw: impl Into<String>, outbound: impl Into<String>, prio: i32) -> AdvRule {`
- `crates/sb-core/src/router/advanced.rs:248` `pub fn rule_ip_cidr(name: impl Into<String>, cidr: IpNet, outbound: impl Into<String>, prio: i32) -> AdvRule {`
- `crates/sb-core/src/router/advanced.rs:256` `pub fn rule_port(name: impl Into<String>, port: u16, outbound: impl Into<String>, prio: i32) -> AdvRule {`
- `crates/sb-core/src/router/advanced.rs:264` `pub fn rule_port_range(name: impl Into<String>, a: u16, b: u16, outbound: impl Into<String>, prio: i32) -> AdvRule {`
- `crates/sb-core/src/router/advanced.rs:272` `pub fn rule_proto(name: impl Into<String>, p: Proto, outbound: impl Into<String>, prio: i32) -> AdvRule {`
- `crates/sb-core/src/router/advanced.rs:284` `pub fn rule_or(name: impl Into<String>, conds: Vec<Cond>, action: Action, prio: i32) -> AdvRule {`
- `crates/sb-core/src/router/advanced.rs:287` `pub fn rule_not(name: impl Into<String>, cond: Cond, action: Action, prio: i32) -> AdvRule {`
- `crates/sb-core/src/router/advanced.rs:308` `pub struct AdvStats {`
- `crates/sb-core/src/router/analyze.rs:13` `pub struct Report {`
- `crates/sb-core/src/router/analyze.rs:33` `pub struct Shadow {`
- `crates/sb-core/src/router/analyze.rs:44` `pub struct Conflict {`
- `crates/sb-core/src/router/analyze.rs:52` `pub fn to_json(&self) -> String {`
- `crates/sb-core/src/router/analyze.rs:99` `pub fn analyze(text: &str) -> Report {`
- `crates/sb-core/src/router/analyze.rs:255` `pub struct AnalyzeIssue {`
- `crates/sb-core/src/router/cache_hot.rs:6` `pub struct HotItem {`
- `crates/sb-core/src/router/cache_hot.rs:25` `pub trait CacheHotSource: Send + Sync + 'static {`
- `crates/sb-core/src/router/cache_hot.rs:89` `pub fn register_router_hot_adapter(src: &'static dyn CacheHotSource) {`
- `crates/sb-core/src/router/cache_stats.rs:5` `pub struct CacheStats {`
- `crates/sb-core/src/router/cache_wire.rs:8` `pub fn clear_cache_metrics() {`
- `crates/sb-core/src/router/cache_wire.rs:16` `pub trait DecisionCacheSource: Send + Sync + 'static {`
- `crates/sb-core/src/router/cache_wire.rs:27` `pub fn register_router_decision_cache_adapter(src: &'static dyn DecisionCacheSource) {`
- `crates/sb-core/src/router/cache_wire.rs:46` `pub fn register_router_hot_adapter(_src: &'static dyn DecisionCacheSource) {`
- `crates/sb-core/src/router/cache_wire.rs:73` `pub struct LruDecision {`
- `crates/sb-core/src/router/cache_wire.rs:80` `pub fn new(cap: usize) -> Self {`
- `crates/sb-core/src/router/cache_wire.rs:95` `pub fn get(&self, k: &str) -> Option<u64> {`
- `crates/sb-core/src/router/cache_wire.rs:106` `pub fn put(&self, k: &str, v: u64) {`
- `crates/sb-core/src/router/conn.rs:54` `pub const PROTOCOL_NTP: &str = "ntp";`
- `crates/sb-core/src/router/conn.rs:55` `pub const PROTOCOL_STUN: &str = "stun";`
- `crates/sb-core/src/router/conn.rs:56` `pub const PROTOCOL_QUIC: &str = "quic";`
- `crates/sb-core/src/router/conn.rs:57` `pub const PROTOCOL_DTLS: &str = "dtls";`
- `crates/sb-core/src/router/conn.rs:427` `pub fn with_stats(mut self, stats: Option<Arc<StatsManager>>) -> Self {`
- `crates/sb-core/src/router/conn.rs:432` `pub fn with_conn_tracker(mut self, conn_tracker: Arc<ConnTracker>) -> Self {`
- `crates/sb-core/src/router/coverage.rs:36` `pub fn enable_if_env() {`
- `crates/sb-core/src/router/coverage.rs:42` `pub fn bump(rule_id: &str) {`
- `crates/sb-core/src/router/coverage.rs:52` `pub struct SnapshotEntry {`
- `crates/sb-core/src/router/coverage.rs:57` `pub fn snapshot() -> Vec<SnapshotEntry> {`
- `crates/sb-core/src/router/coverage.rs:66` `pub fn reset() {`
- `crates/sb-core/src/router/dns.rs:23` `pub struct DnsCache {`
- `crates/sb-core/src/router/dns.rs:32` `pub fn new(ttl: Duration) -> Self {`
- `crates/sb-core/src/router/dns_bridge.rs:55` `pub fn new(resolver: Arc<dyn Resolver>, name: String) -> Self {`
- `crates/sb-core/src/router/dsl_derive.rs:161` `pub fn derive_compare_targets(`
- `crates/sb-core/src/router/dsl_inspect.rs:30` `pub struct Analysis {`
- `crates/sb-core/src/router/dsl_inspect.rs:88` `pub fn analyze_dsl(dsl_text: &str) -> Analysis {`
- `crates/sb-core/src/router/engine.rs:389` `pub fn with_geoip_provider_for_tests(`
- `crates/sb-core/src/router/engine.rs:1676` `pub fn export_and_rebuild(&self) -> Result<(), String> {`
- `crates/sb-core/src/router/engine.rs:1700` `pub struct GeoRuleView {`
- `crates/sb-core/src/router/engine.rs:1707` `pub struct ExactRuleView {`
- `crates/sb-core/src/router/engine.rs:1738` `pub fn as_str(&self) -> &'static str {`
- `crates/sb-core/src/router/engine.rs:1799` `pub trait IntoRouterDefault {`
- `crates/sb-core/src/router/engine.rs:1887` `pub fn decide_http_explain(target: &str) -> DecisionExplain {`
- `crates/sb-core/src/router/engine.rs:1971` `pub async fn decide_udp_async_explain(handle: &RouterHandle, host: &str) -> DecisionExplain {`
- `crates/sb-core/src/router/explain.rs:6` `pub struct ExplainQuery {`
- `crates/sb-core/src/router/explain.rs:20` `pub struct ExplainStep {`
- `crates/sb-core/src/router/explain.rs:28` `pub struct ExplainTrace {`
- `crates/sb-core/src/router/explain.rs:33` `pub struct ExplainResult {`
- `crates/sb-core/src/router/explain.rs:127` `pub fn push(`
- `crates/sb-core/src/router/explain.rs:142` `pub fn into_steps(self) -> Vec<ExplainStep> {`
- `crates/sb-core/src/router/explain.rs:148` `pub fn new(`
- `crates/sb-core/src/router/explain.rs:164` `pub fn envelope_from_parts(`
- `crates/sb-core/src/router/explain.rs:175` `pub fn envelope_from_result(`
- `crates/sb-core/src/router/explain_index.rs:18` `pub fn get_index() -> ExplainIndex {`
- `crates/sb-core/src/router/explain_index.rs:22` `pub fn set_index(idx: ExplainIndex) {`
- `crates/sb-core/src/router/explain_index.rs:29` `pub struct CidrRule {`
- `crates/sb-core/src/router/explain_index.rs:36` `pub struct SuffixRule {`
- `crates/sb-core/src/router/explain_index.rs:43` `pub struct ExactRule {`
- `crates/sb-core/src/router/explain_index.rs:50` `pub struct GeoRule {`
- `crates/sb-core/src/router/explain_index.rs:57` `pub struct ExplainIndex {`
- `crates/sb-core/src/router/explain_index.rs:68` `pub fn from_rules_json(view: &serde_json::Value) -> Self {`
- `crates/sb-core/src/router/explain_index.rs:189` `pub fn is_empty(&self) -> bool {`
- `crates/sb-core/src/router/explain_index.rs:199` `pub fn match_override_exact(&self, host: &str) -> Option<(&ExactRule, String)> {`
- `crates/sb-core/src/router/explain_index.rs:206` `pub fn match_override_suffix(&self, host: &str) -> Option<(&SuffixRule, String)> {`
- `crates/sb-core/src/router/explain_index.rs:213` `pub fn match_cidr(&self, ip: Option<IpAddr>) -> Option<(&CidrRule, String)> {`
- `crates/sb-core/src/router/explain_index.rs:223` `pub fn match_geo_cc(&self, cc: &str) -> Option<(&GeoRule, String)> {`
- `crates/sb-core/src/router/explain_index.rs:230` `pub fn match_suffix(&self, host: &str) -> Option<(&SuffixRule, String)> {`
- `crates/sb-core/src/router/explain_index.rs:237` `pub fn match_exact(&self, host: &str) -> Option<(&ExactRule, String)> {`
- `crates/sb-core/src/router/explain_index.rs:245` `pub fn snapshot_digest(idx: &ExplainIndex) -> String {`
- `crates/sb-core/src/router/explain_index.rs:358` `pub fn rebuild_periodic(handle: crate::router::RouterHandle) {`
- `crates/sb-core/src/router/explain_util.rs:4` `pub fn try_override(`
- `crates/sb-core/src/router/explain_util.rs:32` `pub fn try_cidr(_r: &RouterHandle, ip: Option<IpAddr>) -> Option<(String, String)> {`
- `crates/sb-core/src/router/explain_util.rs:85` `pub fn try_geo(_r: &RouterHandle, ip: Option<IpAddr>) -> Option<(String, String)> {`
- `crates/sb-core/src/router/explain_util.rs:120` `pub fn try_suffix(_r: &RouterHandle, sni: &str) -> Option<(String, String)> {`
- `crates/sb-core/src/router/explain_util.rs:156` `pub fn try_exact(_r: &RouterHandle, sni: &str) -> Option<(String, String)> {`
- `crates/sb-core/src/router/geo.rs:59` `pub fn available_countries(&self) -> Vec<String> {`
- `crates/sb-core/src/router/geo.rs:64` `pub fn export_country(&self, _country: &str) -> anyhow::Result<Vec<String>> {`
- `crates/sb-core/src/router/geo.rs:68` `pub fn stats(&self) -> GeoIpStats {`
- `crates/sb-core/src/router/geo.rs:245` `pub struct GeoSiteList {`
- `crates/sb-core/src/router/geo.rs:251` `pub struct GeoSite {`
- `crates/sb-core/src/router/geo.rs:259` `pub struct Domain {`
- `crates/sb-core/src/router/geo.rs:268` `pub enum Type {`
- `crates/sb-core/src/router/json_bridge.rs:10` `pub struct JsonRule {`
- `crates/sb-core/src/router/json_bridge.rs:25` `pub struct JsonDoc {`
- `crates/sb-core/src/router/json_bridge.rs:252` `pub fn to_rules_for_test(doc: JsonDoc) -> Vec<Rule> {`
- `crates/sb-core/src/router/keyword.rs:9` `pub struct AcMatcher(pub(crate) aho_corasick::AhoCorasick);`
- `crates/sb-core/src/router/keyword.rs:14` `pub fn find(&self, haystack: &str) -> Option<aho_corasick::Match> {`
- `crates/sb-core/src/router/keyword.rs:20` `pub struct Index {`
- `crates/sb-core/src/router/keyword.rs:59` `pub fn is_empty(&self) -> bool {`
- `crates/sb-core/src/router/keyword.rs:62` `pub fn len(&self) -> usize {`
- `crates/sb-core/src/router/keyword.rs:65` `pub fn find_idx(&self, hay: &str) -> Option<usize> {`
- `crates/sb-core/src/router/matcher.rs:54` `pub fn from_tagged_rules<I>(rules: I) -> Self`
- `crates/sb-core/src/router/matcher.rs:169` `pub fn new() -> Self {`
- `crates/sb-core/src/router/matcher.rs:197` `pub fn matches_ip(&self, ip: IpAddr) -> bool {`
- `crates/sb-core/src/router/minijson.rs:2` `pub enum Val<'a> {`
- `crates/sb-core/src/router/minijson.rs:27` `pub fn obj<const N: usize>(kvs: [(&str, Val); N]) -> String {`
- `crates/sb-core/src/router/minijson.rs:63` `pub fn arr_str(list: &[&str]) -> String {`
- `crates/sb-core/src/router/mod.rs:128` `pub fn as_str(&self) -> &str {`
- `crates/sb-core/src/router/mod.rs:242` `pub struct RouterIndex {`
- `crates/sb-core/src/router/mod.rs:324` `pub struct RuleSizes {`
- `crates/sb-core/src/router/mod.rs:422` `pub fn decide_http_explain(&self, host_norm: &str) -> crate::router::engine::DecisionExplain {`
- `crates/sb-core/src/router/mod.rs:458` `pub enum InvalidReason {`
- `crates/sb-core/src/router/mod.rs:484` `pub enum BuildError {`
- `crates/sb-core/src/router/mod.rs:502` `pub struct Ipv6Net {`
- `crates/sb-core/src/router/mod.rs:1424` `pub fn normalize_host_ascii<'a>(host: &'a str) -> std::borrow::Cow<'a, str> {`
- `crates/sb-core/src/router/mod.rs:1435` `pub fn normalize_host(host: &str) -> String {`
- `crates/sb-core/src/router/mod.rs:1446` `pub fn normalize_host(host: &str) -> String {`
- `crates/sb-core/src/router/mod.rs:1563` `pub fn router_index_decide_ip(idx: &RouterIndex, ip: IpAddr) -> Option<&'static str> {`
- `crates/sb-core/src/router/mod.rs:1794` `pub struct HotReloader {`
- `crates/sb-core/src/router/mod.rs:1805` `pub fn spawn(path: PathBuf, router_handle: RouterHandle) {`
- `crates/sb-core/src/router/mod.rs:2576` `pub fn runtime_override_http(`
- `crates/sb-core/src/router/mod.rs:2632` `pub fn runtime_override_udp(host_norm: &str) -> Option<(&'static str, &'static str)> {`
- `crates/sb-core/src/router/mod.rs:2947` `pub fn decide_udp_with_rules(host_or_ip: &str, _use_geoip: bool, rules: &str) -> &'static str {`
- `crates/sb-core/src/router/mod.rs:2994` `pub fn decide_udp_with_rules_and_handle(`
- `crates/sb-core/src/router/mod.rs:3058` `pub fn decide_udp_with_rules_and_ips_v46(`
- `crates/sb-core/src/router/mod.rs:3130` `pub fn decide_udp_with_rules_and_ips(`
- `crates/sb-core/src/router/normalize.rs:73` `pub fn normalize(input: &str) -> String {`
- `crates/sb-core/src/router/patch_apply.rs:10` `pub enum ApplyError {`
- `crates/sb-core/src/router/patch_apply.rs:15` `pub fn apply_cli_patch(original: &str, patch: &str) -> Result<String, ApplyError> {`
- `crates/sb-core/src/router/patch_plan.rs:9` `pub struct PlanSummary {`
- `crates/sb-core/src/router/patch_plan.rs:17` `pub fn to_json(&self) -> String {`
- `crates/sb-core/src/router/patch_plan.rs:33` `pub struct PlanResult {`
- `crates/sb-core/src/router/patch_plan.rs:81` `pub fn build_plan(_text: &str, _kinds: &[&str], _file: Option<&str>) -> PlanResult {`
- `crates/sb-core/src/router/patch_plan.rs:120` `pub fn apply_plan(text: &str, _kinds: &[&str]) -> String {`
- `crates/sb-core/src/router/rule_id.rs:4` `pub struct CanonRule<'a> {`
- `crates/sb-core/src/router/rule_set.rs:37` `pub fn new() -> Self {`
- `crates/sb-core/src/router/rules.rs:64` `pub fn as_str(&self) -> &str {`
- `crates/sb-core/src/router/rules.rs:132` `pub fn new(pattern: String) -> Result<Self, regex::Error> {`
- `crates/sb-core/src/router/rules.rs:137` `pub fn is_match(&self, text: &str) -> bool {`
- `crates/sb-core/src/router/rules.rs:141` `pub fn pattern(&self) -> &str {`
- `crates/sb-core/src/router/rules.rs:341` `pub fn new(pattern: String) -> Result<Self, regex::Error> {`
- `crates/sb-core/src/router/rules.rs:347` `pub fn is_match(&self, text: &str) -> bool {`
- `crates/sb-core/src/router/rules.rs:351` `pub fn pattern(&self) -> &str {`
- `crates/sb-core/src/router/rules.rs:485` `pub enum RuleKind {`
- `crates/sb-core/src/router/rules.rs:511` `pub struct Rule {`
- `crates/sb-core/src/router/rules.rs:640` `pub struct RouteCtx<'a> {`
- `crates/sb-core/src/router/rules.rs:687` `pub fn matches(&self, ctx: &RouteCtx) -> bool {`
- `crates/sb-core/src/router/rules.rs:1483` `pub struct Engine {`
- `crates/sb-core/src/router/rules.rs:1504` `pub fn new() -> Self {`
- `crates/sb-core/src/router/rules.rs:1508` `pub fn build(rules: Vec<Rule>) -> Self {`
- `crates/sb-core/src/router/rules.rs:1936` `pub fn parse_rules(lines: &str) -> Vec<Rule> {`
- `crates/sb-core/src/router/rules.rs:2079` `pub fn parse_decision(s: &str) -> Option<Self> {`
- `crates/sb-core/src/router/rules.rs:2116` `pub fn init_from_env() {`
- `crates/sb-core/src/router/ruleset/mod.rs:27` `pub const RULESET_VERSION_2: u8 = 2;`
- `crates/sb-core/src/router/ruleset/mod.rs:28` `pub const RULESET_VERSION_3: u8 = 3;`
- `crates/sb-core/src/router/ruleset/mod.rs:29` `pub const RULESET_VERSION_CURRENT: u8 = RULESET_VERSION_3;`
- `crates/sb-core/src/router/ruleset/mod.rs:291` `pub fn new() -> Self {`
- `crates/sb-core/src/router/ruleset/mod.rs:426` `pub fn new(cache_dir: PathBuf, update_interval: Duration) -> Self {`
- `crates/sb-core/src/router/runtime.rs:2` `pub enum ProxyChoice {`
- `crates/sb-core/src/router/runtime.rs:9` `pub fn label(&self) -> &'static str {`
- `crates/sb-core/src/router/suffix_trie.rs:2` `pub struct SuffixTrie {`
- `crates/sb-core/src/router/suffix_trie.rs:14` `pub fn new() -> Self {`
- `crates/sb-core/src/router/suffix_trie.rs:34` `pub fn insert_suffix(&mut self, dom: &str, dec: &'static str) {`
- `crates/sb-core/src/router/suffix_trie.rs:50` `pub fn query(&self, host: &str) -> Option<&'static str> {`
- `crates/sb-core/src/routing/engine.rs:11` `pub type ClassifyIpFn = dyn Fn(IpAddr) -> Option<&'static str> + Send + Sync;`
- `crates/sb-core/src/routing/engine.rs:12` `pub type MatchHostFn = dyn for<'a> Fn(&'a str) -> bool + Send + Sync;`
- `crates/sb-core/src/routing/engine.rs:15` `pub struct Decide {`
- `crates/sb-core/src/routing/engine.rs:23` `pub struct Input<'a> {`
- `crates/sb-core/src/routing/engine.rs:70` `pub struct Engine {`
- `crates/sb-core/src/routing/engine.rs:97` `pub fn new(cfg: Arc<ConfigIR>) -> Self {`
- `crates/sb-core/src/routing/engine.rs:769` `pub fn decide(&self, inp: &Input, want_trace: bool) -> Decide {`
- `crates/sb-core/src/routing/explain.rs:7` `pub struct ExplainResult {`
- `crates/sb-core/src/routing/ir.rs:6` `pub enum InboundType {`
- `crates/sb-core/src/routing/ir.rs:14` `pub enum OutboundType {`
- `crates/sb-core/src/routing/ir.rs:22` `pub struct InboundIR {`
- `crates/sb-core/src/routing/ir.rs:35` `pub struct OutboundIR {`
- `crates/sb-core/src/routing/ir.rs:48` `pub struct RuleIR {`
- `crates/sb-core/src/routing/ir.rs:95` `pub struct RouteIR {`
- `crates/sb-core/src/routing/ir.rs:103` `pub struct ConfigIR {`
- `crates/sb-core/src/routing/ir.rs:113` `pub fn has_any_negation(&self) -> bool {`
- `crates/sb-core/src/routing/matcher.rs:105` `pub struct Matcher {`
- `crates/sb-core/src/routing/matcher.rs:111` `pub fn new() -> Self {`
- `crates/sb-core/src/routing/router.rs:8` `pub struct RouterConfig;`
- `crates/sb-core/src/routing/router.rs:10` `pub struct Router {`
- `crates/sb-core/src/routing/router.rs:16` `pub fn new(_config: RouterConfig) -> Result<Self> {`
- `crates/sb-core/src/routing/router.rs:24` `pub async fn reload(&mut self, config_json: &Value) -> Result<()> {`
- `crates/sb-core/src/routing/router.rs:35` `pub async fn route(&self, _req: &str) -> Result<String> {`
- `crates/sb-core/src/routing/router.rs:41` `pub async fn get_rules(&self) -> Vec<sb_config::ir::RuleIR> {`
- `crates/sb-core/src/routing/trace.rs:6` `pub struct Step {`
- `crates/sb-core/src/routing/trace.rs:13` `pub struct Trace {`
- `crates/sb-core/src/routing/trace.rs:19` `pub fn sha8(s: &str) -> String {`
- `crates/sb-core/src/runtime/mod.rs:21` `pub struct Runtime {`
- `crates/sb-core/src/runtime/mod.rs:31` `pub struct Runtime {`
- `crates/sb-core/src/runtime/mod.rs:41` `pub fn new(`
- `crates/sb-core/src/runtime/mod.rs:74` `pub fn new(_engine: (), bridge: Bridge, switchboard: switchboard::OutboundSwitchboard) -> Self {`
- `crates/sb-core/src/runtime/mod.rs:143` `pub fn engine(&self) -> Result<(), anyhow::Error> {`
- `crates/sb-core/src/runtime/mod.rs:146` `pub const fn bridge(&self) -> &Arc<Bridge> {`
- `crates/sb-core/src/runtime/mod.rs:175` `pub fn dummy_engine() -> Result<(), anyhow::Error> {`
- `crates/sb-core/src/runtime/supervisor.rs:79` `pub struct State {`
- `crates/sb-core/src/runtime/supervisor.rs:109` `pub fn new(`
- `crates/sb-core/src/runtime/supervisor.rs:131` `pub fn new(_engine: (), bridge: Bridge, context: Context, ir: sb_config::ir::ConfigIR) -> Self {`
- `crates/sb-core/src/runtime/supervisor.rs:983` `pub fn reload_sender(&self) -> mpsc::Sender<ReloadMsg> {`
- `crates/sb-core/src/runtime/supervisor.rs:1572` `pub fn engine_from_ir(_ir: &sb_config::ir::ConfigIR) -> Result<()> {`
- `crates/sb-core/src/runtime/switchboard.rs:30` `pub fn new(host: impl Into<String>, port: u16, kind: TransportKind) -> Self {`
- `crates/sb-core/src/runtime/switchboard.rs:38` `pub fn tcp(host: impl Into<String>, port: u16) -> Self {`
- `crates/sb-core/src/runtime/switchboard.rs:42` `pub fn udp(host: impl Into<String>, port: u16) -> Self {`
- `crates/sb-core/src/runtime/switchboard.rs:64` `pub fn new() -> Self {`
- `crates/sb-core/src/runtime/switchboard.rs:68` `pub const fn with_connect_timeout(mut self, timeout: Duration) -> Self {`
- `crates/sb-core/src/runtime/switchboard.rs:73` `pub const fn with_read_timeout(mut self, timeout: Duration) -> Self {`
- `crates/sb-core/src/runtime/switchboard.rs:145` `pub type AdapterResult<T> = Result<T, AdapterError>;`
- `crates/sb-core/src/services/cache_file.rs:261` `pub fn enabled(&self) -> bool {`
- `crates/sb-core/src/services/cache_file.rs:265` `pub fn store_fakeip(&self) -> bool {`
- `crates/sb-core/src/services/cache_file.rs:269` `pub fn store_rdrc(&self) -> bool {`
- `crates/sb-core/src/services/cache_file.rs:555` `pub fn set_clash_mode(&self, mode: String) {`
- `crates/sb-core/src/services/cache_file.rs:573` `pub fn get_clash_mode(&self) -> Option<String> {`
- `crates/sb-core/src/services/cache_file.rs:591` `pub fn set_selected(&self, group: &str, selected: &str) {`
- `crates/sb-core/src/services/cache_file.rs:611` `pub fn get_selected(&self, group: &str) -> Option<String> {`
- `crates/sb-core/src/services/cache_file.rs:634` `pub fn set_expand(&self, group: &str, expand: bool) {`
- `crates/sb-core/src/services/cache_file.rs:654` `pub fn get_expand(&self, group: &str) -> Option<bool> {`
- `crates/sb-core/src/services/cache_file.rs:677` `pub fn store_rule_set(&self, tag: &str, content: Vec<u8>) {`
- `crates/sb-core/src/services/cache_file.rs:693` `pub fn get_rule_set(&self, tag: &str) -> Option<Vec<u8>> {`
- `crates/sb-core/src/services/derp/client_registry.rs:61` `pub fn new(tag: Arc<str>) -> Self {`
- `crates/sb-core/src/services/derp/client_registry.rs:70` `pub fn connect_failed(&self, reason: &str) {`
- `crates/sb-core/src/services/derp/client_registry.rs:74` `pub fn client_connected(&self, active: usize) {`
- `crates/sb-core/src/services/derp/client_registry.rs:80` `pub fn client_disconnected(&self, active: usize, lifetime: Duration) {`
- `crates/sb-core/src/services/derp/client_registry.rs:86` `pub fn packet_relayed(&self, size_bytes: usize) {`
- `crates/sb-core/src/services/derp/client_registry.rs:92` `pub fn relay_failed(&self, reason: &str) {`
- `crates/sb-core/src/services/derp/client_registry.rs:96` `pub fn set_active_clients(&self, active: usize) {`
- `crates/sb-core/src/services/derp/client_registry.rs:101` `pub fn get_stats(&self) -> (usize, u64, u64) {`
- `crates/sb-core/src/services/derp/server.rs:908` `pub struct DerpService {`
- `crates/sb-core/src/services/dns_forwarder.rs:24` `pub fn new(ir: &ServiceIR) -> Self {`
- `crates/sb-core/src/services/dns_forwarder.rs:225` `pub fn build_dns_forwarder_service(`
- `crates/sb-core/src/services/ntp.rs:10` `pub struct NtpConfig {`
- `crates/sb-core/src/services/ntp.rs:39` `pub struct NtpService {`
- `crates/sb-core/src/services/ntp.rs:44` `pub fn new(cfg: NtpConfig) -> Self {`
- `crates/sb-core/src/services/ntp.rs:82` `pub struct NtpMarker {`
- `crates/sb-core/src/services/tailscale/coordinator.rs:58` `pub struct NodeInfo {`
- `crates/sb-core/src/services/tailscale/coordinator.rs:75` `pub struct DerpMap {`
- `crates/sb-core/src/services/tailscale/coordinator.rs:82` `pub struct DerpRegion {`
- `crates/sb-core/src/services/tailscale/coordinator.rs:89` `pub struct DerpNode {`
- `crates/sb-core/src/services/time.rs:12` `pub fn new() -> Self {`
- `crates/sb-core/src/services/urltest_history.rs:5` `pub struct URLTestHistoryService {`
- `crates/sb-core/src/services/urltest_history.rs:10` `pub fn new() -> Self {`
- `crates/sb-core/src/services/v2ray_api.rs:100` `pub fn enabled(&self) -> bool {`
- `crates/sb-core/src/services/v2ray_api.rs:104` `pub fn created_at(&self) -> Instant {`
- `crates/sb-core/src/services/v2ray_api.rs:197` `pub fn traffic_recorder(`
- `crates/sb-core/src/services/v2ray_api.rs:282` `pub struct TrafficCounters {`
- `crates/sb-core/src/services/v2ray_api.rs:469` `pub struct StatsServiceImpl {`
- `crates/sb-core/src/session.rs:16` `pub enum Transport {`
- `crates/sb-core/src/socks.rs:6` `pub enum Rep {`
- `crates/sb-core/src/socks.rs:18` `pub fn map_error_to_rep(e: &Error) -> Rep {`
- `crates/sb-core/src/subscribe/mod.rs:6` `pub struct MergeResult {`
- `crates/sb-core/src/subscribe/mod.rs:33` `pub fn merge(base: Value, others: &[Value]) -> (Value, MergeResult) {`
- `crates/sb-core/src/subscribe/mod.rs:94` `pub struct Diff {`
- `crates/sb-core/src/subscribe/mod.rs:99` `pub fn diff(old: &Value, new: &Value) -> Diff {`
- `crates/sb-core/src/telemetry.rs:8` `pub fn err_kind(e: &io::Error) -> &'static str {`
- `crates/sb-core/src/telemetry.rs:111` `pub fn outbound_connect(kind: &'static str, result: &'static str, err: Option<&'static str>) {`
- `crates/sb-core/src/telemetry.rs:127` `pub fn outbound_handshake(kind: &'static str, result: &'static str, err: Option<&'static str>) {`
- `crates/sb-core/src/telemetry.rs:143` `pub fn inbound_parse(kind: &'static str, result: &'static str, reason: &'static str) {`
- `crates/sb-core/src/telemetry.rs:153` `pub fn inbound_forward(label: &'static str, result: &'static str, err: Option<&'static str>) {`
- `crates/sb-core/src/telemetry.rs:169` `pub fn router_select(mode: &'static str, target: &RouteTarget) {`
- `crates/sb-core/src/telemetry/dial.rs:7` `pub enum Phase {`
- `crates/sb-core/src/telemetry/dial.rs:14` `pub const fn as_str(&self) -> &'static str {`
- `crates/sb-core/src/telemetry/dial.rs:24` `pub fn start() -> Instant {`
- `crates/sb-core/src/telemetry/dial.rs:29` `pub fn record_ok(kind: &'static str, phase: Phase, t0: Instant) {`
- `crates/sb-core/src/telemetry/dial.rs:44` `pub fn record_err(kind: &'static str, phase: Phase, t0: Instant, class: &'static str) {`
- `crates/sb-core/src/telemetry/error_class.rs:44` `pub fn error_class(err: &Error) -> &'static str {`
- `crates/sb-core/src/tls/trust.rs:12` `pub struct TlsOpts {`
- `crates/sb-core/src/tls/trust.rs:24` `pub fn new(sni: String) -> Self {`
- `crates/sb-core/src/tls/trust.rs:31` `pub const fn with_allow_insecure(mut self, allow: bool) -> Self {`
- `crates/sb-core/src/tls/trust.rs:36` `pub fn with_pins(mut self, pins: Vec<[u8; 32]>) -> Self {`
- `crates/sb-core/src/tls/trust.rs:41` `pub fn with_alpn(mut self, alpn: Vec<Vec<u8>>) -> Self {`
- `crates/sb-core/src/tls/trust.rs:104` `pub fn mk_client(_opts: &TlsOpts) -> Result<Arc<()>, crate::error::SbError> {`
- `crates/sb-core/src/transport/dialer.rs:46` `pub fn timeout(mut self, d: Duration) -> Self {`
- `crates/sb-core/src/transport/dialer.rs:50` `pub fn nodelay(mut self, on: bool) -> Self {`
- `crates/sb-core/src/transport/dialer.rs:54` `pub fn keepalive(mut self, d: Option<Duration>) -> Self {`
- `crates/sb-core/src/transport/dialer.rs:58` `pub fn bind(mut self, addr: SocketAddr) -> Self {`
- `crates/sb-core/src/transport/dialer.rs:62` `pub fn recv_buffer_size(mut self, v: Option<u32>) -> Self {`
- `crates/sb-core/src/transport/dialer.rs:66` `pub fn send_buffer_size(mut self, v: Option<u32>) -> Self {`
- `crates/sb-core/src/transport/mod.rs:7` `pub type TlsStream<T> = tokio_rustls::TlsStream<T>;`
- `crates/sb-core/src/transport/mod.rs:10` `pub type TlsStream<T> = T; // Fallback when TLS not enabled`
- `crates/sb-core/src/transport/tcp.rs:7` `pub struct TcpDialer {`
- `crates/sb-core/src/transport/tcp.rs:21` `pub struct DialResult {`
- `crates/sb-core/src/transport/tcp.rs:28` `pub fn dial(&self, addr: &str) -> DialResult {`
- `crates/sb-core/src/transport/tls.rs:11` `pub struct TlsClient {`
- `crates/sb-core/src/transport/tls.rs:16` `pub struct TlsResult {`
- `crates/sb-core/src/transport/tls.rs:29` `pub fn from_env() -> Self {`
- `crates/sb-core/src/transport/tls.rs:34` `pub async fn connect(`
- `crates/sb-core/src/transport/tls.rs:66` `pub async fn connect(`
- `crates/sb-core/src/transport/tls.rs:74` `pub fn handshake(&self, server_name: &str, addr: &str) -> TlsResult {`
- `crates/sb-core/src/types.rs:10` `pub type HostPort = Endpoint;`
- `crates/sb-core/src/types.rs:11` `pub type DnsRecord = crate::dns::message::Record;`
- `crates/sb-core/src/types.rs:22` `pub const fn new(addr: SocketAddr) -> Self {`
- `crates/sb-core/src/types.rs:30` `pub const fn with_reuse_addr(mut self, reuse: bool) -> Self {`
- `crates/sb-core/src/types.rs:35` `pub const fn with_reuse_port(mut self, reuse: bool) -> Self {`
- `crates/sb-core/src/types.rs:214` `pub const fn new(name: String, path: String, pid: u32) -> Self {`
- `crates/sb-core/src/udp_nat_instrument.rs:8` `pub enum EvictReason {`
- `crates/sb-core/src/udp_nat_instrument.rs:25` `pub enum UpstreamFail {`
- `crates/sb-core/src/udp_nat_instrument.rs:56` `pub fn new(max_entries: usize) -> Self {`
- `crates/sb-core/src/udp_nat_instrument.rs:62` `pub fn insert(&self, src: SocketAddr, upstream: SocketAddr, ttl: Duration) {`
- `crates/sb-core/src/udp_nat_instrument.rs:87` `pub fn hit(&self, src: SocketAddr, upstream: SocketAddr) {`
- `crates/sb-core/src/udp_nat_instrument.rs:96` `pub fn evict_expired(&self) {`
- `crates/sb-core/src/udp_nat_instrument.rs:117` `pub fn upstream_fail(&self, class: UpstreamFail) {`
- `crates/sb-core/src/util/failpoint.rs:5` `pub enum Action {`
- `crates/sb-core/src/util/mod.rs:11` `pub fn secs_opt_to_duration(v: Option<u64>, default: u64) -> Duration {`
- `crates/sb-core/src/util/token_bucket.rs:1` `pub struct Bucket {`
- `crates/sb-core/src/util/token_bucket.rs:8` `pub fn new(cap: u64, rate_per_s: f64) -> Self {`
- `crates/sb-core/src/util/token_bucket.rs:16` `pub fn allow(&mut self, cost: u64) -> bool {`
- `crates/sb-core/src/utils/correlation.rs:11` `pub fn new() -> Self {`
- `crates/sb-core/src/utils/metered.rs:22` `pub struct Counters {`
- `crates/sb-core/src/utils/metered.rs:34` `pub fn add_in(&self, n: u64) { self.in_bytes.fetch_add(n, Ordering::Relaxed); }`
- `crates/sb-core/src/utils/metered.rs:35` `pub fn add_out(&self, n: u64) { self.out_bytes.fetch_add(n, Ordering::Relaxed); }`
- `crates/sb-core/src/utils/metered.rs:36` `pub fn snapshot(&self) -> (u64, u64) {`
- `crates/sb-core/src/utils/metered.rs:50` `pub fn new(inner: S, kind: &'static str) -> Self {`
- `crates/sb-core/src/utils/metered.rs:53` `pub fn into_inner(self) -> S { self.inner }`
- `crates/sb-core/src/utils/metered.rs:54` `pub fn counters(&self) -> Arc<Counters> { self.ctr.clone() }`
- `crates/sb-core/src/utils/metered.rs:55` `pub fn kind(&self) -> &'static str { self.kind }`
- `crates/sb-core/src/utils/metered.rs:56` `pub fn snapshot(&self) -> (u64, u64) { self.ctr.snapshot() }`
- `crates/sb-metrics/src/http.rs:214` `pub struct HttpReqTimer {`
- `crates/sb-metrics/src/http.rs:229` `pub fn on_connect_ok() {`
- `crates/sb-metrics/src/http.rs:232` `pub fn on_connect_fail() {`
- `crates/sb-metrics/src/http.rs:268` `pub fn record_timeout_error() {`
- `crates/sb-metrics/src/http.rs:272` `pub fn record_busy_error() {`
- `crates/sb-metrics/src/http.rs:276` `pub fn record_net_error() {`
- `crates/sb-metrics/src/http.rs:280` `pub fn record_other_export_error() {`
- `crates/sb-metrics/src/lib.rs:185` `pub struct MetricsRegistryOwner {`
- `crates/sb-metrics/src/lib.rs:251` `pub fn handle(&self) -> MetricsRegistryHandle {`
- `crates/sb-metrics/src/lib.rs:257` `pub fn install_default_registry(registry: Arc<Registry>) -> MetricsRegistryOwner {`
- `crates/sb-metrics/src/lib.rs:272` `pub fn install_default_registry_owner() -> MetricsRegistryOwner {`
- `crates/sb-metrics/src/lib.rs:680` `pub static CONNECTION_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {`
- `crates/sb-metrics/src/lib.rs:690` `pub static ACTIVE_CLIENTS: LazyLock<IntGaugeVec> = LazyLock::new(|| {`
- `crates/sb-metrics/src/lib.rs:701` `pub static RELAY_PACKETS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {`
- `crates/sb-metrics/src/lib.rs:711` `pub static RELAY_BYTES_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {`
- `crates/sb-metrics/src/lib.rs:717` `pub static HTTP_REQUEST_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {`
- `crates/sb-metrics/src/lib.rs:727` `pub static STUN_REQUEST_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {`
- `crates/sb-metrics/src/lib.rs:737` `pub static CLIENT_LIFETIME_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {`
- `crates/sb-metrics/src/lib.rs:865` `pub static UDP_MAP_SIZE: LazyLock<IntGauge> =`
- `crates/sb-metrics/src/lib.rs:868` `pub static UDP_EVICT_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {`
- `crates/sb-metrics/src/lib.rs:872` `pub static UDP_FAIL_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {`
- `crates/sb-metrics/src/lib.rs:876` `pub static ROUTE_EXPLAIN_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {`
- `crates/sb-metrics/src/lib.rs:880` `pub static TCP_CONNECT_DURATION: LazyLock<Histogram> = LazyLock::new(|| {`
- `crates/sb-metrics/src/lib.rs:888` `pub static PROXY_SELECT_SCORE: LazyLock<GaugeVec> = LazyLock::new(|| {`
- `crates/sb-metrics/src/lib.rs:901` `pub static OUTBOUND_UP: LazyLock<GaugeVec> = LazyLock::new(|| {`
- `crates/sb-metrics/src/lib.rs:914` `pub static PROM_HTTP_FAIL: LazyLock<IntCounterVec> = LazyLock::new(|| {`
- `crates/sb-metrics/src/lib.rs:922` `pub static UDP_TTL_SECONDS: LazyLock<Histogram> = LazyLock::new(|| {`
- `crates/sb-metrics/src/lib.rs:930` `pub static PROXY_SELECT_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {`
- `crates/sb-metrics/src/lib.rs:1060` `pub fn spawn_http_exporter_from_env(registry: MetricsRegistryHandle) -> Option<JoinHandle<()>> {`
- `crates/sb-metrics/src/lib.rs:1073` `pub fn maybe_spawn_http_exporter_from_env_with(`
- `crates/sb-metrics/src/lib.rs:1080` `pub fn maybe_spawn_http_exporter_from_env() -> Option<JoinHandle<()>> {`
- `crates/sb-metrics/src/lib.rs:1108` `pub fn export_prometheus() -> String {`
- `crates/sb-platform/src/process/android.rs:30` `pub fn new() -> Result<Self, ProcessMatchError> {`
- `crates/sb-platform/src/process/android.rs:50` `pub async fn find_process_id(&self, conn: &ConnectionInfo) -> Result<u32, ProcessMatchError> {`
- `crates/sb-platform/src/process/android.rs:58` `pub async fn get_process_info(&self, pid: u32) -> Result<ProcessInfo, ProcessMatchError> {`
- `crates/sb-platform/src/tun/mod.rs:163` `pub trait TunDevice: Send + Sync {`
- `crates/sb-runtime/src/scenario.rs:30` `pub fn make(&self, host: String, port: u16) -> Box<dyn Handshake> {`
- `crates/sb-runtime/src/scenario.rs:39` `pub struct ChaosFile {`
- `crates/sb-runtime/src/scenario.rs:50` `pub fn to_spec(&self) -> ChaosSpec {`
- `crates/sb-runtime/src/scenario.rs:66` `pub struct Expect {`
- `crates/sb-runtime/src/scenario.rs:74` `pub struct Defaults {`
- `crates/sb-runtime/src/scenario.rs:84` `pub enum Step {`
- `crates/sb-runtime/src/scenario.rs:118` `pub struct ScenarioFile {`
- `crates/sb-runtime/src/scenario.rs:147` `pub struct StepResult {`
- `crates/sb-runtime/src/scenario.rs:154` `pub struct ScenarioSummary {`
- `crates/sb-runtime/src/scenario.rs:295` `pub fn run(sc: ScenarioFile) -> Result<ScenarioSummary> {`
- `crates/sb-subscribe/src/bindings.rs:30` `pub fn bindings_minijson(p: &Profile) -> String {`
- `crates/sb-subscribe/src/diff_full.rs:109` `pub struct DiffOutput {`
- `crates/sb-subscribe/src/diff_full.rs:114` `pub fn to_json_string(&self) -> String {`
- `crates/sb-subscribe/src/diff_full.rs:117` `pub fn to_json_pretty(&self) -> String {`
- `crates/sb-subscribe/src/diff_full.rs:129` `pub fn diff_full_minijson(`
- `crates/sb-subscribe/src/lint.rs:67` `pub struct LintResult {`
- `crates/sb-subscribe/src/lint.rs:73` `pub fn lint_minijson(`
- `crates/sb-subscribe/src/lint_fix.rs:9` `pub fn make_autofix_patch(dsl: &str) -> String {`
- `crates/sb-subscribe/src/model.rs:4` `pub enum SubsError {`
- `crates/sb-subscribe/src/model.rs:24` `pub type JsonValue = serde_json::Value;`
- `crates/sb-subscribe/src/model.rs:26` `pub type JsonValue = ();`
- `crates/sb-subscribe/src/model.rs:55` `pub fn rules_len(&self) -> usize {`
- `crates/sb-subscribe/src/model.rs:58` `pub fn outbounds_kinds(&self) -> Vec<String> {`
- `crates/sb-subscribe/src/parse_clash.rs:97` `pub fn parse(yaml: &str) -> Result<Profile, SubsError> {`
- `crates/sb-subscribe/src/parse_singbox.rs:108` `pub fn parse(json: &str) -> Result<Profile, SubsError> {`
- `crates/sb-subscribe/src/providers.rs:9` `pub struct MemoryProvider {`
- `crates/sb-subscribe/src/providers.rs:16` `pub fn new() -> Self {`
- `crates/sb-subscribe/src/providers.rs:20` `pub fn put_b64(&mut self, name: &str, b64: &str) {`
- `crates/sb-subscribe/src/providers.rs:24` `pub fn get(&mut self, name: &str) -> Option<&str> {`
- `crates/sb-subscribe/src/providers.rs:34` `pub fn stats(&self) -> (u64, u64) {`
- `crates/sb-tls/src/acme.rs:268` `pub async fn init(&self) -> Result<(), AcmeError> {`
- `crates/sb-tls/src/acme.rs:567` `pub async fn obtain_certificate(&self) -> Result<CertificateInfo, AcmeError> {`
- `crates/sb-tls/src/danger.rs:24` `pub const fn new() -> Self {`
- `crates/sb-tls/src/danger.rs:85` `pub const fn new(pins: Vec<[u8; 32]>) -> Self {`
- `crates/sb-tls/src/ech/hpke.rs:38` `pub fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> EchResult<Vec<u8>> {`
- `crates/sb-tls/src/ech/hpke.rs:96` `pub fn new(kem: HpkeKem, kdf: HpkeKdf, aead: HpkeAead) -> Self {`
- `crates/sb-tls/src/ech/hpke.rs:100` `pub fn setup(`
- `crates/sb-tls/src/ech/mod.rs:127` `pub type EchResult<T> = Result<T, EchError>;`
- `crates/sb-tls/src/lib.rs:162` `pub type TlsResult<T> = Result<T, TlsError>;`
- `crates/sb-tls/src/reality/mod.rs:68` `pub enum RealityError {`
- `crates/sb-tls/src/reality/mod.rs:85` `pub type RealityResult<T> = Result<T, RealityError>;`
- `crates/sb-transport/src/circuit_breaker.rs:46` `pub fn as_str(&self) -> &'static str {`
- `crates/sb-transport/src/derp/protocol.rs:155` `pub fn new(version: u32) -> Self {`
- `crates/sb-transport/src/derp/protocol.rs:163` `pub fn to_json(&self) -> Vec<u8> {`
- `crates/sb-transport/src/derp/protocol.rs:190` `pub fn encode_node_private_key(priv_key: &PrivateKey) -> String {`
- `crates/sb-transport/src/derp/protocol.rs:199` `pub fn decode_node_private_key(s: &str) -> Result<PrivateKey, ProtocolError> {`
- `crates/sb-transport/src/derp/protocol.rs:229` `pub fn clamp_private_key(key: &mut PrivateKey) {`
- `crates/sb-transport/src/derp/protocol.rs:236` `pub fn derive_public_key(private_key: &PrivateKey) -> PublicKey {`
- `crates/sb-transport/src/derp/protocol.rs:243` `pub fn seal_to(`
- `crates/sb-transport/src/derp/protocol.rs:264` `pub fn open_from(`
- `crates/sb-transport/src/derp/protocol.rs:305` `pub type PublicKey = [u8; KEY_LEN];`
- `crates/sb-transport/src/derp/protocol.rs:346` `pub fn from_u8(byte: u8) -> Result<Self, ProtocolError> {`
- `crates/sb-transport/src/derp/protocol.rs:381` `pub fn from_u8(byte: u8) -> Self {`
- `crates/sb-transport/src/derp/protocol.rs:392` `pub const IS_REGULAR: u8 = 1 << 0;`
- `crates/sb-transport/src/derp/protocol.rs:393` `pub const IS_MESH_PEER: u8 = 1 << 1;`
- `crates/sb-transport/src/derp/protocol.rs:394` `pub const IS_PROBER: u8 = 1 << 2;`
- `crates/sb-transport/src/derp/protocol.rs:395` `pub const NOT_IDEAL: u8 = 1 << 3;`
- `crates/sb-transport/src/dialer.rs:86` `pub trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}`
- `crates/sb-transport/src/dialer.rs:193` `pub struct TcpDialer {`
- `crates/sb-transport/src/dialer.rs:738` `pub struct ResourceAwareDialer<D: Dialer> {`
- `crates/sb-transport/src/dialer.rs:872` `pub fn new(f: F) -> Self {`
- `crates/sb-transport/src/httpupgrade.rs:67` `pub struct HttpUpgradeConfig {`
- `crates/sb-transport/src/multiplex.rs:62` `pub fn new(up_mbps: u64, down_mbps: u64) -> Self {`
- `crates/sb-transport/src/multiplex.rs:66` `pub fn up_bytes_per_sec(&self) -> u64 {`
- `crates/sb-transport/src/multiplex.rs:70` `pub fn down_bytes_per_sec(&self) -> u64 {`
- `crates/sb-transport/src/multiplex.rs:213` `pub fn new(config: MultiplexConfig, dialer: Box<dyn Dialer>) -> Self {`
- `crates/sb-transport/src/multiplex.rs:225` `pub fn with_default_config(inner: Box<dyn Dialer>) -> Self {`
- `crates/sb-transport/src/multiplex.rs:537` `pub struct MultiplexListener {`
- `crates/sb-transport/src/multiplex.rs:546` `pub fn new(tcp_listener: tokio::net::TcpListener, config: MultiplexServerConfig) -> Self {`
- `crates/sb-transport/src/multiplex.rs:562` `pub fn with_default_config(tcp_listener: tokio::net::TcpListener) -> Self {`
- `crates/sb-transport/src/multiplex.rs:566` `pub fn config(&self) -> &MultiplexServerConfig {`
- `crates/sb-transport/src/multiplex.rs:665` `pub async fn accept(&self) -> Result<(IoStream, std::net::SocketAddr), DialError> {`
- `crates/sb-transport/src/multiplex.rs:674` `pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {`
- `crates/sb-transport/src/multiplex/padding.rs:9` `pub struct PaddingStream<S> {`
- `crates/sb-transport/src/multiplex/padding.rs:39` `pub fn new(inner: S, is_client: bool) -> Self {`
- `crates/sb-transport/src/resource_pressure.rs:46` `pub fn as_str(&self) -> &'static str {`
- `crates/sb-transport/src/sip003.rs:287` `pub const MODE_WEBSOCKET: &str = "websocket";`
- `crates/sb-transport/src/sip003.rs:288` `pub const MODE_QUIC: &str = "quic";`
- `crates/sb-transport/src/sip003.rs:308` `pub const MODE_HTTP: &str = "http";`
- `crates/sb-transport/src/sip003.rs:309` `pub const MODE_TLS: &str = "tls";`
- `crates/sb-transport/src/tls.rs:59` `pub struct TlsDialer<D: Dialer> {`
- `crates/sb-transport/src/tls.rs:576` `pub fn from_env(inner: D, config: Arc<rustls::ClientConfig>) -> Self {`
- `crates/sb-transport/src/tls.rs:1121` `pub fn serialize<S>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>`
- `crates/sb-transport/src/tls.rs:1131` `pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>`
- `crates/sb-types/src/errors.rs:111` `pub fn io(message: impl Into<String>) -> Self {`
- `crates/sb-types/src/errors.rs:119` `pub fn timeout(operation: impl Into<String>, duration: Duration) -> Self {`
- `crates/sb-types/src/errors.rs:127` `pub fn dns(message: impl Into<String>) -> Self {`
- `crates/sb-types/src/errors.rs:134` `pub fn auth(message: impl Into<String>) -> Self {`
- `crates/sb-types/src/errors.rs:141` `pub fn protocol(message: impl Into<String>) -> Self {`
- `crates/sb-types/src/errors.rs:148` `pub fn policy(reason: impl Into<String>) -> Self {`
- `crates/sb-types/src/errors.rs:155` `pub fn resource_exhausted(resource: impl Into<String>) -> Self {`
- `crates/sb-types/src/errors.rs:162` `pub fn internal(message: impl Into<String>) -> Self {`
- `crates/sb-types/src/errors.rs:174` `pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>`
- `crates/sb-types/src/errors.rs:181` `pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>`
- `crates/sb-types/src/session.rs:20` `pub fn new(tag: impl Into<String>) -> Self {`
- `crates/sb-types/src/session.rs:25` `pub fn as_str(&self) -> &str {`
- `crates/sb-types/src/session.rs:42` `pub fn new(tag: impl Into<String>) -> Self {`
- `crates/sb-types/src/session.rs:47` `pub fn as_str(&self) -> &str {`

### allow_clippy_escapes (28)
- 判定：治理命中
- 对应层：Layer 4

- `app/src/admin_debug/auth/mod.rs:13` `#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]`
- `app/src/admin_debug/endpoints/subs.rs:157` `#[allow(clippy::expect_used)] // Safe: limiter_init() just called above`
- `app/src/http_util.rs:23` `#![allow(clippy::expect_used, clippy::needless_pass_by_value)]`
- `crates/sb-adapters/src/outbound/tuic.rs:7` `#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]`
- `crates/sb-core/src/router/mod.rs:1920` `#[allow(clippy::expect_used)]`
- `crates/sb-metrics/src/lib.rs:84` `#[allow(clippy::unwrap_used)]`
- `crates/sb-metrics/src/lib.rs:91` `#[allow(clippy::unwrap_used)]`
- `crates/sb-metrics/src/lib.rs:98` `#[allow(clippy::unwrap_used)]`
- `crates/sb-metrics/src/lib.rs:111` `#[allow(clippy::unwrap_used)]`
- `crates/sb-metrics/src/lib.rs:117` `#[allow(clippy::unwrap_used)]`
- `crates/sb-metrics/src/lib.rs:583` `#[allow(clippy::unwrap_used)]`
- `crates/sb-metrics/src/lib.rs:694` `#[allow(clippy::unwrap_used)]`
- `crates/sb-metrics/src/lib.rs:894` `#[allow(clippy::unwrap_used)]`
- `crates/sb-metrics/src/lib.rs:907` `#[allow(clippy::unwrap_used)]`
- `crates/sb-metrics/src/lib.rs:1097` `#[allow(clippy::expect_used)] // Test utility function, panic is acceptable`
- `crates/sb-metrics/src/lib.rs:1106` `#[allow(clippy::expect_used)] // Test utility function, panic is acceptable`
- `crates/sb-platform/src/tun/validation.rs:447` `#[allow(clippy::unwrap_used, clippy::expect_used)]`
- `crates/sb-platform/src/wifi.rs:91` `#[allow(clippy::expect_used)]`
- `crates/sb-tls/src/ech/hpke.rs:173` `#[allow(clippy::unwrap_used, clippy::panic)]`
- `crates/sb-tls/src/ech/mod.rs:423` `#[allow(clippy::unwrap_used, clippy::panic)]`
- `crates/sb-tls/src/ech/parser.rs:326` `#[allow(clippy::unwrap_used, clippy::panic)]`
- `crates/sb-tls/src/reality/client.rs:556` `#[allow(clippy::unwrap_used, clippy::manual_string_new)]`
- `crates/sb-tls/src/reality/config.rs:240` `#[allow(clippy::unwrap_used, clippy::manual_string_new)]`
- `crates/sb-tls/src/reality/server.rs:836` `#[allow(clippy::unwrap_used, clippy::manual_string_new)]`
- `crates/sb-tls/src/reality/tls_record.rs:497` `#[allow(clippy::unwrap_used, clippy::identity_op)]`
- `crates/sb-tls/src/standard.rs:121` `#[allow(clippy::unwrap_used)]`
- `crates/sb-transport/src/metrics_ext.rs:52` `#[allow(clippy::unwrap_used)]`
- `crates/sb-transport/src/metrics_ext.rs:79` `#[allow(clippy::unwrap_used)]`

---

## 附录 B：本轮静态审计记录到的全部“需复核 / 需声明意图”命中

说明：这一组并不等于全部都是 bug，但它们与规则集存在明显张力，至少需要**改造或写明豁免意图**。

### super_path (302)
- 判定：需复核，绝大多数应改为 crate::
- 对应层：Layer 1

- `app/src/admin_debug/auth/apikey.rs:6` `use super::{AuthError, AuthProvider};`
- `app/src/admin_debug/auth/jwt.rs:11` `use super::{AuthError, AuthProvider};`
- `app/src/admin_debug/auth/none.rs:6` `use super::{AuthError, AuthProvider};`
- `app/src/admin_debug/middleware/auth.rs:7` `use super::{Middleware, MiddlewareResult, RequestContext};`
- `app/src/admin_debug/middleware/rate_limit.rs:9` `use super::{Middleware, MiddlewareResult, RequestContext};`
- `app/src/admin_debug/middleware/request_id.rs:7` `use super::{Middleware, MiddlewareResult, RequestContext};`
- `app/src/cli/check/run.rs:25` `use super::args::CheckArgs;`
- `app/src/cli/check/run.rs:26` `use super::types::{push_err, push_warn, CheckIssue, CheckReport, IssueCode, IssueKind};`
- `crates/sb-adapters/src/inbound/anytls.rs:10` `use super::tls;`
- `crates/sb-adapters/src/inbound/socks/handshake.rs:6` `use super::auth::select_method;`
- `crates/sb-adapters/src/inbound/ssh.rs:128` `use super::*;`
- `crates/sb-adapters/src/inbound/tproxy.rs:103` `let orig = super::redirect::get_original_dst(&cli)?;`
- `crates/sb-adapters/src/inbound/trojan.rs:10` `use super::tls;`
- `crates/sb-adapters/src/inbound/tun/platform/linux.rs:16` `use super::{TunPlatformConfig, TunPlatformHook};`
- `crates/sb-adapters/src/inbound/tun/platform/macos.rs:14` `use super::{TunPlatformConfig, TunPlatformHook};`
- `crates/sb-adapters/src/inbound/tun/platform/windows.rs:14` `use super::{TunPlatformConfig, TunPlatformHook};`
- `crates/sb-adapters/src/inbound/tun_process_aware.rs:25` `use super::tun_macos::TunMacosRuntime;`
- `crates/sb-adapters/src/inbound/tun_session.rs:454` `Ok(super::tun_packet::build_ipv4_tcp_packet(`
- `crates/sb-adapters/src/outbound/hysteria.rs:82` `let quic_cfg = super::quic_util::QuicConfig::new(self.cfg.server.clone(), self.cfg.port)`
- `crates/sb-adapters/src/outbound/hysteria.rs:93` `let connection = super::quic_util::quic_connect(&quic_cfg)`
- `crates/sb-adapters/src/outbound/hysteria.rs:113` `Ok(Box::new(super::quic_util::QuicBidiStream::new(send, recv)) as BoxedStream)`
- `crates/sb-adapters/src/outbound/hysteria2.rs:107` `use super::Hysteria2AdapterConfig;`
- `crates/sb-adapters/src/outbound/shadowsocksr/stream.rs:7` `use super::crypto::SsrCipher;`
- `crates/sb-adapters/src/outbound/shadowsocksr/stream.rs:8` `use super::obfs::SsrObfs;`
- `crates/sb-adapters/src/outbound/shadowsocksr/stream.rs:9` `use super::protocol::SsrProtocol;`
- `crates/sb-adapters/src/outbound/ssh.rs:95` `use super::*;`
- `crates/sb-adapters/src/outbound/tuic.rs:59` `quic_config: super::quic_util::QuicConfig,`
- `crates/sb-adapters/src/outbound/tuic.rs:87` `let quic_config = super::quic_util::QuicConfig::new(cfg.server.clone(), cfg.port)`
- `crates/sb-adapters/src/outbound/tuic.rs:122` `match super::quic_util::quic_connect(&self.quic_config).await {`
- `crates/sb-adapters/src/outbound/tuic.rs:220` `stream: &mut super::quic_util::QuicBidiStream,`
- `crates/sb-adapters/src/outbound/tuic.rs:474` `let mut quic_stream = super::quic_util::QuicBidiStream::new(send_stream, recv_stream);`
- `crates/sb-adapters/src/service/resolve1.rs:19` `use super::*;`
- `crates/sb-adapters/src/service/resolve1.rs:810` `use super::*;`
- `crates/sb-adapters/src/service/resolved_impl.rs:12` `use super::*;`
- `crates/sb-api/src/v2ray/mod.rs:176` `use super::*;`
- `crates/sb-api/src/v2ray/mod.rs:258` `use super::*;`
- `crates/sb-api/src/v2ray/mod.rs:355` `use super::*;`
- `crates/sb-api/src/v2ray/mod.rs:437` `use super::*;`
- `crates/sb-api/src/v2ray/server.rs:16` `use super::*;`
- `crates/sb-api/src/v2ray/server.rs:79` `use super::*;`
- `crates/sb-config/src/de.rs:32` `use super::*;`
- `crates/sb-config/src/ir/diff.rs:6` `use super::{ConfigIR, InboundIR, OutboundIR, RuleIR};`
- `crates/sb-core/src/adapter/handler.rs:97` `connector: Arc<dyn super::OutboundConnector>,`
- `crates/sb-core/src/adapter/handler.rs:101` `pub fn new(tag: String, connector: Arc<dyn super::OutboundConnector>) -> Self {`
- `crates/sb-core/src/adapter/registry.rs:7` `use super::{`
- `crates/sb-core/src/config/schema_v2.rs:16` `pub use super::types_route::{`
- `crates/sb-core/src/conntrack/inbound_udp.rs:24` `) -> super::inbound_tcp::ConntrackWiring {`
- `crates/sb-core/src/conntrack/inbound_udp.rs:58` `) -> super::inbound_tcp::ConntrackWiring {`
- `crates/sb-core/src/conntrack/inbound_udp.rs:59` `super::inbound_tcp::register_inbound(`
- `crates/sb-core/src/diagnostics/http_server.rs:10` `use super::memory::MemoryStats;`
- `crates/sb-core/src/diagnostics/http_server.rs:11` `use super::options::DebugOptions;`
- `crates/sb-core/src/dns/cache.rs:17` `use super::DnsAnswer;`
- `crates/sb-core/src/dns/client.rs:281` `pub use super::timer::Timer;`
- `crates/sb-core/src/dns/dns_router.rs:13` `use super::DnsAnswer;`
- `crates/sb-core/src/dns/global.rs:3` `use super::Resolver;`
- `crates/sb-core/src/dns/handle.rs:5` `use super::DnsRouter;`
- `crates/sb-core/src/dns/hosts.rs:20` `use super::{DnsAnswer, Resolver};`
- `crates/sb-core/src/dns/hosts.rs:209` `super::cache::Source::Static, // Hosts entries are treated as static`
- `crates/sb-core/src/dns/hosts.rs:210` `super::cache::Rcode::NoError,`
- `crates/sb-core/src/dns/resolve.rs:2` `use super::cache::{DnsCache, QType};`
- `crates/sb-core/src/dns/resolve.rs:560` `let answer = super::DnsAnswer::new(`
- `crates/sb-core/src/dns/resolve.rs:563` `super::cache::Source::System,`
- `crates/sb-core/src/dns/resolve.rs:564` `super::cache::Rcode::NoError,`
- `crates/sb-core/src/dns/resolve.rs:654` `let answer = super::DnsAnswer::new(`
- `crates/sb-core/src/dns/resolve.rs:657` `super::cache::Source::System,`
- `crates/sb-core/src/dns/resolve.rs:658` `super::cache::Rcode::NoError,`
- `crates/sb-core/src/dns/resolve.rs:669` `ck: super::cache::Key,`
- `crates/sb-core/src/dns/resolve.rs:702` `let answer = super::DnsAnswer::new(`
- `crates/sb-core/src/dns/resolve.rs:705` `super::cache::Source::System,`
- `crates/sb-core/src/dns/resolve.rs:706` `super::cache::Rcode::NoError,`
- `crates/sb-core/src/dns/resolve.rs:717` `ck: super::cache::Key,`
- `crates/sb-core/src/dns/resolve.rs:747` `let answer = super::DnsAnswer::new(`
- `crates/sb-core/src/dns/resolve.rs:750` `super::cache::Source::System,`
- `crates/sb-core/src/dns/resolve.rs:751` `super::cache::Rcode::NoError,`
- `crates/sb-core/src/dns/resolver.rs:13` `use super::{DnsAnswer, DnsUpstream, RecordType, Resolver};`
- `crates/sb-core/src/dns/resolver.rs:28` `strategy: super::DnsStrategy,`
- `crates/sb-core/src/dns/resolver.rs:59` `strategy: super::DnsStrategy::default(),`
- `crates/sb-core/src/dns/resolver.rs:64` `pub fn with_strategy(mut self, strategy: super::DnsStrategy) -> Self {`
- `crates/sb-core/src/dns/resolver.rs:81` `use super::DnsStrategy;`
- `crates/sb-core/src/dns/router.rs:3` `use super::{DnsTransport, Record, SystemResolverTransport, TtlCache};`
- `crates/sb-core/src/dns/rule_engine.rs:14` `use super::{DnsAnswer, DnsUpstream, RecordType};`
- `crates/sb-core/src/dns/rule_engine.rs:129` `strategy: super::DnsStrategy,`
- `crates/sb-core/src/dns/rule_engine.rs:149` `strategy: super::DnsStrategy,`
- `crates/sb-core/src/dns/rule_engine.rs:578` `use super::DnsStrategy;`
- `crates/sb-core/src/dns/strategy.rs:13` `use super::{DnsAnswer, DnsUpstream, RecordType};`
- `crates/sb-core/src/dns/system.rs:6` `use super::{DnsAnswer, DnsResolver};`
- `crates/sb-core/src/dns/system.rs:34` `super::cache::Source::System,`
- `crates/sb-core/src/dns/system.rs:35` `super::cache::Rcode::NoError,`
- `crates/sb-core/src/dns/transport/dhcp.rs:22` `use super::{DnsStartStage, DnsTransport};`
- `crates/sb-core/src/dns/transport/doh.rs:14` `use super::DnsTransport;`
- `crates/sb-core/src/dns/transport/doh3.rs:16` `use super::DnsTransport;`
- `crates/sb-core/src/dns/transport/doq.rs:15` `use super::DnsTransport;`
- `crates/sb-core/src/dns/transport/dot.rs:15` `use super::DnsTransport;`
- `crates/sb-core/src/dns/transport/local.rs:6` `use super::DnsTransport;`
- `crates/sb-core/src/dns/transport/mod.rs:11` `use super::resolver::DnsResolver;`
- `crates/sb-core/src/dns/transport/mod.rs:198` `impl super::Resolver for DhcpResolver {`
- `crates/sb-core/src/dns/transport/mod.rs:199` `async fn resolve(&self, domain: &str) -> Result<super::DnsAnswer> {`
- `crates/sb-core/src/dns/transport/registry.rs:1` `use super::{DnsStartStage, DnsTransport};`
- `crates/sb-core/src/dns/transport/resolved.rs:8` `use super::{DnsStartStage, DnsTransport};`
- `crates/sb-core/src/dns/transport/resolved.rs:559` `use super::dot::DotTransport;`
- `crates/sb-core/src/dns/transport/tcp.rs:15` `use super::DnsTransport;`
- `crates/sb-core/src/dns/transport/udp.rs:29` `use super::{tcp::TcpTransport, DnsStartStage, DnsTransport, DnsTransportError};`
- `crates/sb-core/src/dns/upstream.rs:24` `use super::metrics;`
- `crates/sb-core/src/dns/upstream.rs:25` `use super::{DnsAnswer, DnsUpstream, RecordType};`
- `crates/sb-core/src/dns/upstream.rs:515` `super::cache::Source::Upstream,`
- `crates/sb-core/src/dns/upstream.rs:516` `super::cache::Rcode::NoError,`
- `crates/sb-core/src/dns/upstream.rs:1502` `super::cache::Source::Upstream,`
- `crates/sb-core/src/dns/upstream.rs:1503` `super::cache::Rcode::NoError,`
- `crates/sb-core/src/dns/upstream.rs:1989` `super::cache::Source::Upstream,`
- `crates/sb-core/src/dns/upstream.rs:1990` `super::cache::Rcode::NoError,`
- `crates/sb-core/src/dns/upstream.rs:2465` `super::cache::Source::Upstream,`
- `crates/sb-core/src/dns/upstream.rs:2466` `super::cache::Rcode::NoError,`
- `crates/sb-core/src/dns/upstream.rs:2726` `super::cache::Source::Static,`
- `crates/sb-core/src/dns/upstream.rs:2727` `super::cache::Rcode::NoError,`
- `crates/sb-core/src/dns/upstream.rs:2735` `super::cache::Source::Static,`
- `crates/sb-core/src/dns/upstream.rs:2736` `super::cache::Rcode::NoError,`
- `crates/sb-core/src/dns/upstream.rs:2746` `super::cache::Source::Static,`
- `crates/sb-core/src/dns/upstream.rs:2747` `super::cache::Rcode::NoError,`
- `crates/sb-core/src/dns/upstream.rs:2874` `super::cache::Source::Static,`
- `crates/sb-core/src/dns/upstream.rs:2875` `super::cache::Rcode::NoError,`
- `crates/sb-core/src/dns/upstream.rs:2881` `super::cache::Source::Static,`
- `crates/sb-core/src/dns/upstream.rs:2882` `super::cache::Rcode::NoError,`
- `crates/sb-core/src/dns/upstream.rs:2889` `super::cache::Source::Static,`
- `crates/sb-core/src/dns/upstream.rs:2890` `super::cache::Rcode::NxDomain,`
- `crates/sb-core/src/endpoint/tailscale.rs:21` `use super::{`
- `crates/sb-core/src/endpoint/tailscale.rs:1032` `_ctx: &super::EndpointContext,`
- `crates/sb-core/src/endpoint/wireguard.rs:1` `use super::{`
- `crates/sb-core/src/endpoint/wireguard.rs:616` `ctx: &super::EndpointContext,`
- `crates/sb-core/src/geoip/mmdb.rs:6` `use super::{GeoInfo, GeoIpProvider};`
- `crates/sb-core/src/geoip/multi.rs:6` `use super::{GeoInfo, GeoIpProvider};`
- `crates/sb-core/src/geoip/multi.rs:56` `if let Ok(mmdb_provider) = super::mmdb::MmdbProvider::new() {`
- `crates/sb-core/src/metrics/error_class.rs:94` `pub fn record_outbound_error(kind: super::outbound::OutboundKind, err: &dyn Display) {`
- `crates/sb-core/src/metrics/error_class.rs:97` `ErrorClass::Timeout => super::outbound::OutboundErrorClass::Timeout,`
- `crates/sb-core/src/metrics/error_class.rs:98` `ErrorClass::Io => super::outbound::OutboundErrorClass::Io,`
- `crates/sb-core/src/metrics/error_class.rs:99` `ErrorClass::Tls => super::outbound::OutboundErrorClass::Handshake,`
- `crates/sb-core/src/metrics/error_class.rs:101` `super::outbound::OutboundErrorClass::Protocol`
- `crates/sb-core/src/metrics/error_class.rs:104` `super::outbound::record_connect_error(kind, mapped);`
- `crates/sb-core/src/metrics/registry_ext.rs:339` `use super::get_or_register_counter_vec;`
- `crates/sb-core/src/outbound/block.rs:6` `use super::{Outbound, TcpConnectRequest, UdpBindRequest};`
- `crates/sb-core/src/outbound/direct.rs:8` `use super::{Outbound, OutboundContext, TargetAddr, TcpConnectRequest, UdpBindRequest};`
- `crates/sb-core/src/outbound/direct_connector.rs:76` `Host::Name(domain) => super::resolve_host_for_direct(domain, endpoint.port)`
- `crates/sb-core/src/outbound/direct_connector.rs:448` `Host::Name(domain) => super::resolve_host_for_direct(domain, dst.port)`
- `crates/sb-core/src/outbound/http_proxy.rs:10` `use super::{Outbound, OutboundContext, TargetAddr, TcpConnectRequest, UdpBindRequest};`
- `crates/sb-core/src/outbound/hysteria/v1.rs:16` `use super::super::quic::common::{connect as quic_connect, QuicConfig};`
- `crates/sb-core/src/outbound/hysteria/v1.rs:17` `use super::super::types::{HostPort, OutboundTcp};`
- `crates/sb-core/src/outbound/hysteria2.rs:31` `use super::quic::common::{connect as quic_connect, QuicConfig};`
- `crates/sb-core/src/outbound/hysteria2.rs:33` `use super::types::{HostPort, OutboundTcp};`
- `crates/sb-core/src/outbound/hysteria2.rs:1123` `let conn = match super::quic::common::connect(&self.quic_config).await {`
- `crates/sb-core/src/outbound/hysteria2.rs:1148` `let mut hysteria2_stream = super::quic::io::QuicBidiStream::new(send_stream, recv_stream);`
- `crates/sb-core/src/outbound/naive_h2.rs:20` `use super::types::{HostPort, OutboundTcp};`
- `crates/sb-core/src/outbound/observe.rs:3` `use super::selector::{PoolSelector, Selector};`
- `crates/sb-core/src/outbound/optimizations.rs:378` `use super::*;`
- `crates/sb-core/src/outbound/registry.rs:1` `use super::endpoint::ProxyEndpoint;`
- `crates/sb-core/src/outbound/selector.rs:6` `use super::endpoint::ProxyEndpoint;`
- `crates/sb-core/src/outbound/socks5.rs:9` `use super::{Outbound, OutboundContext, TargetAddr, TcpConnectRequest, UdpBindRequest};`
- `crates/sb-core/src/router/analyze_fix.rs:2` `use super::analyze::Report;`
- `crates/sb-core/src/router/cache_hot.rs:2` `use super::minijson;`
- `crates/sb-core/src/router/cache_wire.rs:5` `use super::{cache_hot, cache_stats};`
- `crates/sb-core/src/router/cache_wire.rs:67` `use super::*;`
- `crates/sb-core/src/router/dns_bridge.rs:8` `use super::engine::{DnsResolve, DnsResult};`
- `crates/sb-core/src/router/dns_integration.rs:6` `use super::{EnhancedDnsResolver, RouterHandle};`
- `crates/sb-core/src/router/explain_bridge.rs:2` `use super::explain::{ExplainQuery, ExplainResult, ExplainTrace};`
- `crates/sb-core/src/router/explain_bridge.rs:3` `use super::explain_index::{self, ExplainIndex};`
- `crates/sb-core/src/router/explain_bridge.rs:108` `q: &'a super::explain::ExplainQuery,`
- `crates/sb-core/src/router/explain_index.rs:366` `if let Err(err) = super::explain_bridge::rebuild_index(&rules) {`
- `crates/sb-core/src/router/explain_util.rs:1` `use super::{RouterHandle, ip_in_v4net, ip_in_v6net};`
- `crates/sb-core/src/router/explain_util.rs:6` `_q: &super::explain::ExplainQuery,`
- `crates/sb-core/src/router/explain_util.rs:129` `let normalized = super::normalize_host(sni);`
- `crates/sb-core/src/router/explain_util.rs:165` `let normalized = super::normalize_host(sni);`
- `crates/sb-core/src/router/hot_reload.rs:17` `use super::router_build_index_from_str;`
- `crates/sb-core/src/router/mod.rs:1918` `use super::*;`
- `crates/sb-core/src/router/mod.rs:1922` `super::router_build_index_from_str(text, 1 << 24).expect("bench build index")`
- `crates/sb-core/src/router/patch_plan.rs:3` `use super::analyze_fix;`
- `crates/sb-core/src/router/patch_plan.rs:4` `use super::minijson;`
- `crates/sb-core/src/router/patch_plan.rs:6` `use super::{analyze, patch_apply};`
- `crates/sb-core/src/router/preview.rs:2` `use super::*;`
- `crates/sb-core/src/router/preview.rs:5` `pub use super::dsl_derive::{derive_compare_targets, derive_targets};`
- `crates/sb-core/src/router/preview.rs:7` `pub use super::dsl_inspect::{analysis_to_json, analyze_dsl};`
- `crates/sb-core/src/router/preview.rs:9` `use super::dsl_plus::expand_dsl_plus;`
- `crates/sb-core/src/router/preview.rs:13` `let max = super::router_rules_max_from_env();`
- `crates/sb-core/src/router/preview.rs:31` `if let Some(d) = super::router_index_decide_exact_suffix(idx, &host) {`
- `crates/sb-core/src/router/preview.rs:65` `if let Some(d) = super::router_index_decide_ip(idx, ip) {`
- `crates/sb-core/src/router/preview.rs:75` `if let Some(d) = super::router_index_decide_transport_port(idx, port_opt, Some("tcp")) {`
- `crates/sb-core/src/router/preview.rs:104` `if let Some(d) = super::router_index_decide_exact_suffix(idx, &host_norm) {`
- `crates/sb-core/src/router/preview.rs:138` `if let Some(d) = super::router_index_decide_ip(idx, ip) {`
- `crates/sb-core/src/router/preview.rs:148` `if let Some(d) = super::router_index_decide_transport_port(idx, None, Some("udp")) {`
- `crates/sb-core/src/router/route_connection.rs:10` `use super::rules::Decision;`
- `crates/sb-core/src/router/route_connection.rs:11` `use super::RouteCtx;`
- `crates/sb-core/src/router/ruleset/binary.rs:5` `use super::*;`
- `crates/sb-core/src/router/ruleset/binary.rs:784` `super::DomainRule::Exact(_) | super::DomainRule::Suffix(_)`
- `crates/sb-core/src/router/ruleset/binary.rs:819` `if let super::DomainRule::Exact(s) = d {`
- `crates/sb-core/src/router/ruleset/binary.rs:823` `if let super::DomainRule::Suffix(s) = d {`
- `crates/sb-core/src/router/ruleset/binary.rs:932` `super::LogicalMode::And => 0,`
- `crates/sb-core/src/router/ruleset/binary.rs:933` `super::LogicalMode::Or => 1,`
- `crates/sb-core/src/router/ruleset/matcher.rs:9` `use super::*;`
- `crates/sb-core/src/router/ruleset/remote.rs:12` `use super::*;`
- `crates/sb-core/src/router/ruleset/remote.rs:58` `super::binary::parse_binary(&data, RuleSetSource::Remote(url.to_string())).or_else(`
- `crates/sb-core/src/router/ruleset/remote.rs:59` `|_| super::binary::parse_json(&data, RuleSetSource::Remote(url.to_string())),`
- `crates/sb-core/src/router/ruleset/remote.rs:229` `super::binary::load_from_file(cache_file, format).await`
- `crates/sb-core/src/router/ruleset/source.rs:4` `pub fn infer_format_from_path(path: &str) -> Option<super::RuleSetFormat> {`
- `crates/sb-core/src/router/ruleset/source.rs:6` `Some(super::RuleSetFormat::Binary)`
- `crates/sb-core/src/router/ruleset/source.rs:8` `Some(super::RuleSetFormat::Source)`
- `crates/sb-core/src/router/ruleset/source.rs:15` `pub fn infer_format_from_url(url: &str) -> Option<super::RuleSetFormat> {`
- `crates/sb-core/src/router/sniff.rs:297` `if let Some(outcome) = super::sniff_quic::sniff_quic_sni(buf) {`
- `crates/sb-core/src/router/sniff.rs:316` `pub use super::sniff_quic::{QuicReassembly, SniffQuicResult};`
- `crates/sb-core/src/router/sniff.rs:372` `match super::sniff_quic::sniff_quic_sni_multi(buf, None) {`
- `crates/sb-core/src/router/sniff.rs:399` `match super::sniff_quic::sniff_quic_sni_multi(buf, Some(ctx)) {`
- `crates/sb-core/src/router/sniff_quic.rs:10` `use super::sniff::{sniff_tls_client_hello, SniffOutcome};`
- `crates/sb-core/src/services/derp/client_registry.rs:3` `use super::protocol::{DerpFrame, PeerGoneReason, PublicKey};`
- `crates/sb-core/src/services/derp/client_registry.rs:509` `use super::protocol::peer_present_flags;`
- `crates/sb-core/src/services/derp/server.rs:3` `use super::client_registry::ClientRegistry;`
- `crates/sb-core/src/services/derp/server.rs:4` `use super::protocol::{`
- `crates/sb-core/src/services/ssmapi/api.rs:3` `use super::{traffic::TrafficManager, user::UserManager};`
- `crates/sb-core/src/services/ssmapi/api.rs:47` `users: Vec<super::user::UserObject>,`
- `crates/sb-core/src/services/ssmapi/api.rs:72` `users: Vec<super::user::UserObject>,`
- `crates/sb-core/src/services/ssmapi/api.rs:129` `) -> Result<Json<super::user::UserObject>, StatusCode> {`
- `crates/sb-core/src/services/ssmapi/api.rs:135` `let mut user = super::user::UserObject::new(username, Some(password));`
- `crates/sb-core/src/services/ssmapi/registry.rs:10` `use super::ManagedSSMServer;`
- `crates/sb-core/src/services/ssmapi/server.rs:3` `use super::{api, registry, traffic::TrafficManager, user::UserManager};`
- `crates/sb-core/src/services/ssmapi/server.rs:139` `server: Arc<dyn super::ManagedSSMServer>,`
- `crates/sb-core/src/services/ssmapi/traffic.rs:178` `impl super::TrafficTracker for TrafficManager {`
- `crates/sb-core/src/services/ssmapi/user.rs:5` `use super::traffic::TrafficManager;`
- `crates/sb-core/src/services/ssmapi/user.rs:6` `use super::ManagedSSMServer;`
- `crates/sb-core/src/tls/trust.rs:79` `.set_certificate_verifier(Arc::new(super::danger::NoVerify));`
- `crates/sb-core/src/tls/trust.rs:89` `.set_certificate_verifier(Arc::new(super::danger::PinVerify::new(`
- `crates/sb-metrics/src/lib.rs:388` `use super::{register_collector, IntCounterVec, LazyLock};`
- `crates/sb-metrics/src/lib.rs:393` `let vec = super::guarded_counter_vec(`
- `crates/sb-metrics/src/lib.rs:413` `use super::{register_collector, HistogramVec, IntCounterVec, LazyLock};`
- `crates/sb-metrics/src/lib.rs:417` `let v = super::guarded_counter_vec(`
- `crates/sb-metrics/src/lib.rs:428` `let v = super::guarded_counter_vec(`
- `crates/sb-metrics/src/lib.rs:440` `let v = super::guarded_histogram_vec(`
- `crates/sb-metrics/src/lib.rs:510` `use super::{register_collector, HistogramVec, IntCounterVec, LazyLock};`
- `crates/sb-metrics/src/lib.rs:515` `let vec = super::guarded_counter_vec(`
- `crates/sb-metrics/src/lib.rs:527` `let v = super::guarded_histogram_vec(`
- `crates/sb-metrics/src/lib.rs:543` `let vec = super::guarded_counter_vec(`
- `crates/sb-metrics/src/lib.rs:556` `use super::{register_collector, IntCounterVec, LazyLock};`
- `crates/sb-metrics/src/lib.rs:562` `let vec = super::guarded_counter_vec(`
- `crates/sb-metrics/src/lib.rs:574` `super::labels::ensure_allowed_labels("active_connections", &["proxy"]);`
- `crates/sb-metrics/src/lib.rs:593` `let vec = super::guarded_counter_vec(`
- `crates/sb-metrics/src/lib.rs:677` `use super::{guarded_counter_vec, guarded_histogram_vec, register_collector, LazyLock};`
- `crates/sb-metrics/src/lib.rs:691` `super::labels::ensure_allowed_labels("derp_clients", &["tag"]);`
- `crates/sb-metrics/src/lib.rs:795` `use super::{`
- `crates/sb-metrics/src/lib.rs:822` `let v = super::guarded_counter_vec(`
- `crates/sb-metrics/src/lib.rs:862` `use super::{LazyLock, Opts};`
- `crates/sb-metrics/src/lib.rs:866` `LazyLock::new(|| super::registered_int_gauge("udp_map_size", "UDP NAT table size"));`
- `crates/sb-metrics/src/lib.rs:869` `super::registered_counter_vec("udp_evict_total", "UDP NAT eviction total", &["reason"])`
- `crates/sb-metrics/src/lib.rs:873` `super::registered_counter_vec("udp_fail_total", "UDP failure total", &["class"])`
- `crates/sb-metrics/src/lib.rs:877` `super::registered_int_counter("route_explain_total", "Route explain invocations")`
- `crates/sb-metrics/src/lib.rs:881` `super::registered_histogram(`
- `crates/sb-metrics/src/lib.rs:897` `super::register_collector("proxy_select_score", &v);`
- `crates/sb-metrics/src/lib.rs:910` `super::register_collector("outbound_up", &v);`
- `crates/sb-metrics/src/lib.rs:915` `super::registered_counter_vec(`
- `crates/sb-metrics/src/lib.rs:923` `super::registered_histogram(`
- `crates/sb-metrics/src/lib.rs:931` `super::registered_counter_vec(`
- `crates/sb-platform/src/process/android.rs:5` `use super::{ConnectionInfo, ProcessInfo, ProcessMatchError, Protocol};`
- `crates/sb-platform/src/process/android.rs:23` `linux_impl: super::linux::LinuxProcessMatcher,`
- `crates/sb-platform/src/process/android.rs:40` `linux_impl: super::linux::LinuxProcessMatcher::new()?,`
- `crates/sb-platform/src/process/linux.rs:5` `use super::{ConnectionInfo, ProcessInfo, ProcessMatchError, Protocol};`
- `crates/sb-platform/src/process/macos.rs:10` `use super::{ConnectionInfo, ProcessInfo, ProcessMatchError};`
- `crates/sb-platform/src/process/macos.rs:66` `super::macos_common::find_process_with_lsof(conn).await`
- `crates/sb-platform/src/process/macos_common.rs:3` `use super::{ConnectionInfo, ProcessMatchError, Protocol};`
- `crates/sb-platform/src/process/native_macos.rs:19` `use super::{ConnectionInfo, ProcessInfo, ProcessMatchError, Protocol};`
- `crates/sb-platform/src/process/native_windows.rs:16` `use super::{ConnectionInfo, ProcessInfo, ProcessMatchError, Protocol};`
- `crates/sb-platform/src/process/windows.rs:9` `use super::{ConnectionInfo, ProcessInfo, ProcessMatchError, Protocol};`
- `crates/sb-platform/src/tun/linux.rs:3` `use super::{TunConfig, TunDevice, TunError};`
- `crates/sb-platform/src/tun/macos.rs:3` `use super::{TunConfig, TunDevice, TunError};`
- `crates/sb-platform/src/tun/windows.rs:3` `use super::{TunConfig, TunDevice, TunError};`
- `crates/sb-platform/src/tun/windows.rs:291` `use super::*;`
- `crates/sb-tls/src/ech/config.rs:36` `pub fn from_base64(private_b64: &str, public_b64: &str) -> Result<Self, super::EchError> {`
- `crates/sb-tls/src/ech/config.rs:42` `.map_err(|e| super::EchError::InvalidConfig(format!("Invalid private key: {e}")))?;`
- `crates/sb-tls/src/ech/config.rs:46` `.map_err(|e| super::EchError::InvalidConfig(format!("Invalid public key: {e}")))?;`
- `crates/sb-tls/src/ech/config.rs:50` `return Err(super::EchError::InvalidConfig(format!(`
- `crates/sb-tls/src/ech/config.rs:57` `return Err(super::EchError::InvalidConfig(format!(`
- `crates/sb-tls/src/ech/config.rs:121` `pub fn new(config_base64: String) -> Result<Self, super::EchError> {`
- `crates/sb-tls/src/ech/config.rs:127` `.map_err(|e| super::EchError::InvalidConfig(format!("Invalid config: {e}")))?;`
- `crates/sb-tls/src/ech/config.rs:138` `pub(crate) fn resolve_config_list(&self) -> Result<Vec<u8>, super::EchError> {`
- `crates/sb-tls/src/ech/config.rs:146` `super::EchError::InvalidConfig("ECH enabled but no config provided".to_string())`
- `crates/sb-tls/src/ech/config.rs:151` `.map_err(|e| super::EchError::InvalidConfig(format!("Invalid config: {e}")))`
- `crates/sb-tls/src/ech/config.rs:158` `pub fn validate(&self) -> Result<(), super::EchError> {`
- `crates/sb-tls/src/ech/config.rs:164` `super::parser::parse_ech_config_list(&config_list)?;`
- `crates/sb-tls/src/ech/config.rs:173` `pub fn to_rustls_ech_mode(&self) -> Result<rustls::client::EchMode, super::EchError> {`
- `crates/sb-tls/src/ech/config.rs:175` `return Err(super::EchError::InvalidConfig(`
- `crates/sb-tls/src/ech/config.rs:186` `.map_err(|e| super::EchError::InvalidConfig(format!("Invalid ECH config: {e}")))?;`
- `crates/sb-tls/src/ech/config.rs:223` `pub fn validate(&self) -> Result<(), super::EchError> {`
- `crates/sb-tls/src/ech/config.rs:229` `return Err(super::EchError::InvalidConfig(`
- `crates/sb-tls/src/ech/hpke.rs:13` `use super::{EchError, EchResult, HpkeAead, HpkeKdf, HpkeKem};`
- `crates/sb-tls/src/ech/parser.rs:44` `use super::{EchError, EchResult, EchVersion, HpkeAead, HpkeKdf, HpkeKem};`
- `crates/sb-tls/src/global.rs:197` `super::ensure_crypto_provider();`
- `crates/sb-tls/src/reality/client.rs:3` `use super::auth::{RealityAuth, compute_temp_cert_signature, derive_auth_key};`
- `crates/sb-tls/src/reality/client.rs:4` `use super::config::RealityClientConfig;`
- `crates/sb-tls/src/reality/client.rs:5` `use super::tls_record::{ClientHello, ContentType, HandshakeType, TlsExtension};`
- `crates/sb-tls/src/reality/client.rs:6` `use super::{RealityError, RealityResult};`
- `crates/sb-tls/src/reality/server.rs:3` `use super::auth::{RealityAuth, compute_temp_cert_signature, derive_auth_key};`
- `crates/sb-tls/src/reality/server.rs:4` `use super::config::RealityServerConfig;`
- `crates/sb-tls/src/reality/server.rs:5` `use super::{RealityError, RealityResult};`
- `crates/sb-tls/src/reality/server.rs:192` `use super::tls_record::{ClientHello, ContentType, ExtensionType};`
- `crates/sb-transport/src/failpoint_dialer.rs:23` `use super::dialer::{DialError, Dialer, IoStream};`
- `crates/sb-transport/src/mem.rs:26` `use super::dialer::{DialError, Dialer, IoStream};`
- `crates/sb-transport/src/resource_pressure.rs:287` `use super::*;`
- `crates/sb-transport/src/tls.rs:23` `use super::dialer::{DialError, Dialer, IoStream};`
- `crates/sb-transport/src/tls_secure.rs:20` `use super::dialer::{DialError, Dialer, IoStream};`
- `crates/sb-transport/src/tls_secure.rs:21` `use super::tls::TlsDialer;`

### pub_use (188)
- 判定：需复核，仅 facade/prelude/显式 API 组成允许
- 对应层：Layer 1

- `app/src/admin_debug/endpoints/mod.rs:20` `pub use config::{handle_get as handle_config_get, handle_put as handle_config_put};`
- `app/src/admin_debug/endpoints/mod.rs:21` `pub use geoip::handle as handle_geoip;`
- `app/src/admin_debug/endpoints/mod.rs:22` `pub use health::handle as handle_health;`
- `app/src/admin_debug/endpoints/mod.rs:23` `pub use normalize::handle as handle_normalize;`
- `app/src/admin_debug/endpoints/mod.rs:30` `pub use subs::{handle as handle_subs, handle_with_metrics as handle_subs_with_metrics};`
- `app/src/admin_debug/endpoints/mod.rs:33` `pub use analyze::handle as handle_analyze;`
- `app/src/admin_debug/endpoints/mod.rs:36` `pub use route_dryrun::handle as handle_route_dryrun;`
- `app/src/analyze/builders/mod.rs:6` `pub use core_adapters::register_core_adapters;`
- `app/src/bin/sb-explaind.rs:12` `pub use app::telemetry::*;`
- `app/src/cli/check/mod.rs:5` `pub use args::CheckArgs;`
- `app/src/cli/check/mod.rs:6` `pub use run::run;`
- `app/src/cli/check/types.rs:12` `pub use sb_types::IssueCode;`
- `app/src/telemetry.rs:92` `pub use imp::*;`
- `crates/sb-adapters/src/inbound/socks/udp.rs:6` `pub use sb_core::net::datagram::UdpTargetAddr;`
- `crates/sb-adapters/src/lib.rs:201` `pub use traits::{`
- `crates/sb-adapters/src/lib.rs:211` `pub use transport_config::{TransportConfig, TransportType};`
- `crates/sb-adapters/src/lib.rs:214` `pub use register::build_default_registry;`
- `crates/sb-adapters/src/lib.rs:217` `pub use register::register_all;`
- `crates/sb-adapters/src/outbound/mod.rs:17` `pub use crate::error::{AdapterError, Result};`
- `crates/sb-adapters/src/outbound/mod.rs:18` `pub use crate::traits::{BoxedStream, DialOpts, OutboundConnector, Target, TransportKind};`
- `crates/sb-adapters/src/outbound/mod.rs:19` `pub use async_trait::async_trait;`
- `crates/sb-adapters/src/outbound/mod.rs:20` `pub use std::fmt::Debug;`
- `crates/sb-adapters/src/outbound/mod.rs:21` `pub use std::time::Duration;`
- `crates/sb-adapters/src/outbound/mod.rs:95` `pub use crate::traits::*;`
- `crates/sb-api/src/clash/mod.rs:16` `pub use server::ClashApiServer;`
- `crates/sb-api/src/lib.rs:41` `pub use error::{ApiError, ApiResult};`
- `crates/sb-api/src/lib.rs:42` `pub use monitoring::{MonitoringSystem, MonitoringSystemHandle, ReportConfig};`
- `crates/sb-api/src/lib.rs:43` `pub use types::*;`
- `crates/sb-api/src/lib.rs:46` `pub use clash::ClashApiServer;`
- `crates/sb-api/src/lib.rs:49` `pub use v2ray::V2RayApiServer;`
- `crates/sb-api/src/monitoring/mod.rs:10` `pub use bridge::{MetricsBridge, MetricsBridgeHandle};`
- `crates/sb-api/src/monitoring/mod.rs:11` `pub use collector::{ConnectionCollector, PerformanceCollector, TrafficCollector};`
- `crates/sb-api/src/monitoring/mod.rs:12` `pub use reporter::{RealtimeReporter, ReportConfig};`
- `crates/sb-api/src/v2ray/mod.rs:517` `pub use server::V2RayApiServer;`
- `crates/sb-api/src/v2ray/mod.rs:518` `pub use simple::SimpleV2RayApiServer;`
- `crates/sb-api/src/v2ray/server.rs:108` `pub use grpc_impl::V2RayApiServer;`
- `crates/sb-api/src/v2ray/server.rs:111` `pub use simple_impl::V2RayApiServer;`
- `crates/sb-api/src/v2ray/services.rs:26` `pub use crate::v2ray::generated::handler_service_server::{HandlerService, HandlerServiceServer};`
- `crates/sb-api/src/v2ray/services.rs:27` `pub use crate::v2ray::generated::logger_service_server::{LoggerService, LoggerServiceServer};`
- `crates/sb-api/src/v2ray/services.rs:28` `pub use crate::v2ray::generated::routing_service_server::{RoutingService, RoutingServiceServer};`
- `crates/sb-api/src/v2ray/services.rs:29` `pub use crate::v2ray::generated::stats_service_server::{StatsService, StatsServiceServer};`
- `crates/sb-common/src/lib.rs:35` `pub use badtls::{is_valid_tls, is_weak_cipher, TlsAnalyzer, TlsIssue, TlsVersion};`
- `crates/sb-common/src/lib.rs:36` `pub use conntrack::{shared_tracker, ConnId, ConnMetadata, ConnTracker, Network};`
- `crates/sb-common/src/lib.rs:37` `pub use ja3::Ja3Fingerprint;`
- `crates/sb-common/src/lib.rs:38` `pub use tlsfrag::{extract_sni, fragment_client_hello, is_client_hello, FragmentConfig};`
- `crates/sb-common/src/lib.rs:41` `pub use convertor::{parse_subscription, ConfigConverter, ConfigFormat, ProxyNode};`
- `crates/sb-config/src/ir/mod.rs:2443` `pub use experimental::*;`
- `crates/sb-core/src/adapter/mod.rs:26` `pub use crate::outbound::selector::Member as SelectorMember;`
- `crates/sb-core/src/config/schema_v2.rs:16` `pub use super::types_route::{`
- `crates/sb-core/src/conntrack/mod.rs:10` `pub use inbound_tcp::{`
- `crates/sb-core/src/conntrack/mod.rs:13` `pub use inbound_udp::{register_inbound_udp, register_inbound_udp_with_tracker};`
- `crates/sb-core/src/context.rs:15` `pub use sb_types::ports::service::Startable;`
- `crates/sb-core/src/diagnostics/mod.rs:14` `pub use http_server::DebugServer;`
- `crates/sb-core/src/diagnostics/mod.rs:15` `pub use memory::MemoryStats;`
- `crates/sb-core/src/diagnostics/mod.rs:16` `pub use options::DebugOptions;`
- `crates/sb-core/src/dns/client.rs:281` `pub use super::timer::Timer;`
- `crates/sb-core/src/dns/transport/mod.rs:117` `pub use registry::TransportRegistry;`
- `crates/sb-core/src/dns/transport/mod.rs:122` `pub use dhcp::DhcpTransport;`
- `crates/sb-core/src/dns/transport/mod.rs:133` `pub use enhanced_udp::EnhancedUdpTransport;`
- `crates/sb-core/src/dns/transport/mod.rs:134` `pub use local::LocalTransport;`
- `crates/sb-core/src/dns/transport/mod.rs:135` `pub use tcp::TcpTransport;`
- `crates/sb-core/src/dns/transport/mod.rs:136` `pub use udp::{DefaultUdpDialer, UdpDialer, UdpTransport, UdpUpstream};`
- `crates/sb-core/src/dns/transport/mod.rs:141` `pub use resolved::{ResolvedTransport, ResolvedTransportConfig};`
- `crates/sb-core/src/dns/transport/mod.rs:144` `pub use doh::{DohConfig, DohServers, DohTransport};`
- `crates/sb-core/src/dns/transport/mod.rs:146` `pub use doh3::Doh3Transport;`
- `crates/sb-core/src/dns/transport/mod.rs:148` `pub use doq::DoqTransport;`
- `crates/sb-core/src/dns/transport/mod.rs:150` `pub use dot::DotTransport;`
- `crates/sb-core/src/endpoint/mod.rs:6` `pub use crate::service::StartStage;`
- `crates/sb-core/src/error.rs:104` `pub use sb_types::IssueCode;`
- `crates/sb-core/src/error_map.rs:2` `pub use sb_types::IssueCode;`
- `crates/sb-core/src/http.rs:13` `pub use crate::admin::http as admin;`
- `crates/sb-core/src/http.rs:14` `pub use crate::metrics::http as metrics;`
- `crates/sb-core/src/inbound/mod.rs:41` `pub use manager::InboundManager;`
- `crates/sb-core/src/lib.rs:109` `pub use crate::outbound::observe::*;`
- `crates/sb-core/src/lib.rs:115` `pub use adapter::*; // 兼容 re-export`
- `crates/sb-core/src/metrics/mod.rs:82` `pub use http::{`
- `crates/sb-core/src/metrics/mod.rs:88` `pub use outbound::{`
- `crates/sb-core/src/metrics/mod.rs:94` `pub use udp::{`
- `crates/sb-core/src/metrics/mod.rs:101` `pub use dns::{`
- `crates/sb-core/src/metrics/mod.rs:108` `pub use error_class::{classify_display as classify_error, record_outbound_error, ErrorClass};`
- `crates/sb-core/src/metrics/mod.rs:109` `pub use inbound::{`
- `crates/sb-core/src/metrics/outbound.rs:18` `pub use crate::outbound::OutboundKind;`
- `crates/sb-core/src/net/mod.rs:23` `pub use rate_limit::RateLimiter;`
- `crates/sb-core/src/net/mod.rs:26` `pub use self::util::Address;`
- `crates/sb-core/src/outbound/hysteria/mod.rs:10` `pub use v1::{HysteriaV1Config, HysteriaV1Inbound, HysteriaV1Outbound};`
- `crates/sb-core/src/outbound/mod.rs:100` `pub use direct_connector::{DirectConnector, DirectUdpTransport};`
- `crates/sb-core/src/outbound/mod.rs:101` `pub use manager::OutboundManager;`
- `crates/sb-core/src/outbound/mod.rs:102` `pub use traits::{OutboundConnector, UdpTransport};`
- `crates/sb-core/src/outbound/mod.rs:111` `pub use crate::net::dial::{`
- `crates/sb-core/src/outbound/types.rs:10` `pub use crate::net::udp_nat::TargetAddr;`
- `crates/sb-core/src/router/mod.rs:94` `pub use self::explain::{ExplainDto, ExplainQuery, ExplainResult, ExplainStep, ExplainTrace};`
- `crates/sb-core/src/router/mod.rs:96` `pub use explain_bridge::rebuild_index;`
- `crates/sb-core/src/router/mod.rs:98` `pub use explain_index::get_index;`
- `crates/sb-core/src/router/mod.rs:100` `pub use self::conn::{`
- `crates/sb-core/src/router/mod.rs:104` `pub use self::dns_bridge::{DnsResolverBridge, EnhancedDnsResolver};`
- `crates/sb-core/src/router/mod.rs:105` `pub use self::dns_integration::{`
- `crates/sb-core/src/router/mod.rs:109` `pub use self::engine::{decide_http_explain, decide_udp_async_explain, DecisionExplain};`
- `crates/sb-core/src/router/mod.rs:110` `pub use self::engine::{DnsResolve, DnsResult, Router, RouterHandle, Transport};`
- `crates/sb-core/src/router/mod.rs:111` `pub use self::hot_reload::{HotReloadConfig, HotReloadError, HotReloadEvent, HotReloadManager};`
- `crates/sb-core/src/router/mod.rs:112` `pub use self::hot_reload_cli::{`
- `crates/sb-core/src/router/mod.rs:115` `pub use self::route_connection::{ConnectionRouter, DirectRouter, RouteResult};`
- `crates/sb-core/src/router/mod.rs:116` `pub use crate::outbound::RouteTarget;`
- `crates/sb-core/src/router/mod.rs:117` `pub use crate::routing::engine::Input;`
- `crates/sb-core/src/router/mod.rs:2762` `pub use preview::{build_index_from_rules, preview_decide_http, preview_decide_udp};`
- `crates/sb-core/src/router/mod.rs:3194` `pub use cache_hot::{register_hot_provider, HotItem};`
- `crates/sb-core/src/router/mod.rs:3196` `pub use cache_stats::{register_provider, CacheStats};`
- `crates/sb-core/src/router/mod.rs:3198` `pub use cache_wire::{register_router_decision_cache_adapter, register_router_hot_adapter};`
- `crates/sb-core/src/router/preview.rs:5` `pub use super::dsl_derive::{derive_compare_targets, derive_targets};`
- `crates/sb-core/src/router/preview.rs:7` `pub use super::dsl_inspect::{analysis_to_json, analyze_dsl};`
- `crates/sb-core/src/router/rules.rs:9` `pub use crate::dns::RecordType as DnsRecordType;`
- `crates/sb-core/src/router/sniff.rs:316` `pub use super::sniff_quic::{QuicReassembly, SniffQuicResult};`
- `crates/sb-core/src/routing/mod.rs:26` `pub use crate::router::sniff;`
- `crates/sb-core/src/routing/mod.rs:30` `pub use explain::{ExplainDto, ExplainEngine, ExplainResult};`
- `crates/sb-core/src/routing/mod.rs:31` `pub use trace::Trace;`
- `crates/sb-core/src/runtime/mod.rs:18` `pub use supervisor::{Supervisor, SupervisorHandle};`
- `crates/sb-core/src/service.rs:15` `pub use sb_types::ports::service::{Lifecycle, Service, StartStage};`
- `crates/sb-core/src/service/ntp.rs:8` `pub use crate::services::ntp::*;`
- `crates/sb-core/src/services/derp/mod.rs:9` `pub use sb_transport::derp::protocol;`
- `crates/sb-core/src/services/derp/mod.rs:11` `pub use client_registry::{ClientHandle, ClientRegistry, DerpMetrics};`
- `crates/sb-core/src/services/derp/mod.rs:12` `pub use protocol::{DerpFrame, FrameType, ProtocolError, PublicKey, PROTOCOL_VERSION};`
- `crates/sb-core/src/services/derp/mod.rs:13` `pub use server::{build_derp_service, DerpService};`
- `crates/sb-core/src/services/ssmapi/mod.rs:23` `pub use server::{build_ssmapi_service, SsmapiService};`
- `crates/sb-core/src/services/ssmapi/mod.rs:24` `pub use traffic::TrafficManager;`
- `crates/sb-core/src/services/ssmapi/mod.rs:25` `pub use user::UserManager;`
- `crates/sb-core/src/tls/danger.rs:6` `pub use sb_tls::danger::{NoVerify, PinVerify};`
- `crates/sb-core/src/tls/global.rs:25` `pub use sb_tls::global::get_effective;`
- `crates/sb-core/src/tls/global.rs:28` `pub use sb_tls::global::base_root_store;`
- `crates/sb-core/src/tls/mod.rs:11` `pub use trust::{alpn_from_env, mk_client, pins_from_env, TlsOpts};`
- `crates/sb-platform/src/lib.rs:86` `pub use monitor::{NetworkEvent, NetworkMonitor};`
- `crates/sb-platform/src/tun/mod.rs:370` `pub use macos::MacOsTun;`
- `crates/sb-proto/src/lib.rs:67` `pub use connector::*;`
- `crates/sb-proto/src/lib.rs:69` `pub use outbound_registry::*;`
- `crates/sb-proto/src/lib.rs:70` `pub use ss2022::*;`
- `crates/sb-proto/src/lib.rs:71` `pub use trojan::*;`
- `crates/sb-proto/src/lib.rs:72` `pub use trojan_connector::*;`
- `crates/sb-runtime/src/lib.rs:91` `pub use handshake::*;`
- `crates/sb-runtime/src/lib.rs:94` `pub use jsonl::{basic_verify, replay_decode as jsonl_replay_decode, stream_frames};`
- `crates/sb-runtime/src/lib.rs:97` `pub use loopback::{`
- `crates/sb-runtime/src/lib.rs:103` `pub use protocols::*;`
- `crates/sb-runtime/src/lib.rs:106` `pub use scenario::*;`
- `crates/sb-runtime/src/lib.rs:109` `pub use tcp_local::*;`
- `crates/sb-runtime/src/lib.rs:140` `pub use crate::handshake::*;`
- `crates/sb-runtime/src/lib.rs:141` `pub use crate::jsonl::{basic_verify, replay_decode as jsonl_replay_decode, stream_frames};`
- `crates/sb-runtime/src/lib.rs:142` `pub use crate::loopback::{`
- `crates/sb-runtime/src/lib.rs:146` `pub use crate::protocols::*;`
- `crates/sb-runtime/src/lib.rs:147` `pub use crate::scenario::*;`
- `crates/sb-runtime/src/lib.rs:150` `pub use crate::tcp_local::*;`
- `crates/sb-runtime/src/protocols/mod.rs:12` `pub use trojan::*;`
- `crates/sb-runtime/src/protocols/mod.rs:13` `pub use vmess::*;`
- `crates/sb-security/src/lib.rs:67` `pub use credentials::{verify_credentials, verify_credentials_required, verify_secret};`
- `crates/sb-security/src/lib.rs:68` `pub use key_loading::{KeySource, LoadedSecret, SecretLoader};`
- `crates/sb-security/src/lib.rs:69` `pub use redact::{redact_credential, redact_key, redact_token};`
- `crates/sb-subscribe/src/providers.rs:56` `pub use providers::*;`
- `crates/sb-tls/src/ech/mod.rs:77` `pub use config::{EchClientConfig, EchKeypair, EchServerConfig};`
- `crates/sb-tls/src/ech/mod.rs:78` `pub use parser::{EchConfigList, parse_ech_config_list};`
- `crates/sb-tls/src/lib.rs:128` `pub use standard::StandardTlsConnector;`
- `crates/sb-tls/src/lib.rs:131` `pub use reality::{RealityAcceptor, RealityClientConfig, RealityConnector, RealityServerConfig};`
- `crates/sb-tls/src/lib.rs:134` `pub use ech::{EchClientConfig, EchConnector, EchKeypair, EchServerConfig};`
- `crates/sb-tls/src/lib.rs:137` `pub use utls::{CustomFingerprint, UtlsConfig, UtlsFingerprint, available_fingerprints};`
- `crates/sb-tls/src/lib.rs:140` `pub use global::CertificateWatcher;`
- `crates/sb-tls/src/reality/mod.rs:60` `pub use auth::{RealityAuth, generate_keypair};`
- `crates/sb-tls/src/reality/mod.rs:61` `pub use client::RealityConnector;`
- `crates/sb-tls/src/reality/mod.rs:62` `pub use config::{RealityClientConfig, RealityServerConfig};`
- `crates/sb-tls/src/reality/mod.rs:63` `pub use server::RealityAcceptor;`
- `crates/sb-transport/src/lib.rs:108` `pub use yamux;`
- `crates/sb-transport/src/lib.rs:246` `pub use dialer::*;`
- `crates/sb-transport/src/lib.rs:249` `pub use tls::*;`
- `crates/sb-transport/src/lib.rs:252` `pub use tls_secure::*;`
- `crates/sb-transport/src/lib.rs:255` `pub use tls::RealityDialer;`
- `crates/sb-transport/src/lib.rs:258` `pub use tls::EchDialer;`
- `crates/sb-transport/src/lib.rs:260` `pub use circuit_breaker::*;`
- `crates/sb-transport/src/lib.rs:261` `pub use mem::*;`
- `crates/sb-transport/src/lib.rs:262` `pub use resource_pressure::*;`
- `crates/sb-transport/src/lib.rs:263` `pub use retry::*;`
- `crates/sb-transport/src/lib.rs:264` `pub use util::*;`
- `crates/sb-transport/src/lib.rs:267` `pub use builder::TransportBuilder;`
- `crates/sb-transport/src/lib.rs:270` `pub use failpoint_dialer::*;`
- `crates/sb-transport/src/multiplex.rs:49` `pub use padding::PaddingStream;`
- `crates/sb-types/src/lib.rs:41` `pub use errors::{CoreError, DnsError, ErrorClass, TransportError};`
- `crates/sb-types/src/lib.rs:42` `pub use ports::{`
- `crates/sb-types/src/lib.rs:48` `pub use session::{InboundTag, OutboundTag, Session, SessionId, SessionMeta, TargetAddr, UserId};`
- `crates/sb-types/src/ports/mod.rs:19` `pub use admin::*;`
- `crates/sb-types/src/ports/mod.rs:20` `pub use dns::*;`
- `crates/sb-types/src/ports/mod.rs:21` `pub use http::*;`
- `crates/sb-types/src/ports/mod.rs:22` `pub use inbound::*;`
- `crates/sb-types/src/ports/mod.rs:23` `pub use metrics::*;`
- `crates/sb-types/src/ports/mod.rs:24` `pub use outbound::*;`
- `crates/sb-types/src/ports/mod.rs:25` `pub use service::*;`

### arc_mutex (50)
- 判定：并发设计复核面，不等于全部错误，但默认不应使用
- 对应层：Layer 3

- `app/src/admin_debug/middleware/rate_limit.rs:132` `buckets: Arc<Mutex<HashMap<String, TokenBucket>>>,`
- `crates/sb-adapters/src/inbound/anytls.rs:65` `shutdown_tx: Arc<Mutex<Option<mpsc::Sender<()>>>>,`
- `crates/sb-adapters/src/inbound/naive.rs:425` `shutdown_tx: Arc<Mutex<Option<mpsc::Sender<()>>>>,`
- `crates/sb-adapters/src/inbound/shadowtls.rs:757` `hash_state: Arc<Mutex<V2HashState>>,`
- `crates/sb-adapters/src/inbound/shadowtls.rs:788` `hash_state: Arc<Mutex<V2HashState>>,`
- `crates/sb-adapters/src/inbound/tun_macos.rs:46` `tun: Arc<Mutex<MacOsTun>>,`
- `crates/sb-adapters/src/outbound/anytls.rs:37` `session: Arc<Mutex<Option<Arc<Session>>>>,`
- `crates/sb-adapters/src/outbound/hysteria2.rs:139` `last_reset: Arc<Mutex<Instant>>,`
- `crates/sb-adapters/src/outbound/hysteria2.rs:140` `up_tokens: Arc<Mutex<u32>>,`
- `crates/sb-adapters/src/outbound/hysteria2.rs:141` `down_tokens: Arc<Mutex<u32>>,`
- `crates/sb-adapters/src/outbound/hysteria2.rs:211` `connection_pool: Arc<Mutex<Option<Connection>>>,`
- `crates/sb-adapters/src/outbound/socks5.rs:510` `control: Arc<Mutex<TcpStream>>,`
- `crates/sb-adapters/src/outbound/tailscale.rs:175` `wireguard: Arc<Mutex<Option<Arc<crate::outbound::wireguard::WireGuardOutbound>>>>,`
- `crates/sb-api/src/monitoring/bridge.rs:28` `outbound_metrics: Arc<Mutex<HashMap<String, OutboundMetrics>>>,`
- `crates/sb-api/src/monitoring/bridge.rs:30` `dns_metrics: Arc<Mutex<DnsMetrics>>,`
- `crates/sb-api/src/monitoring/bridge.rs:32` `last_update: Arc<Mutex<SystemTime>>,`
- `crates/sb-api/src/monitoring/collector.rs:40` `bytes_transferred: Arc<Mutex<(u64, u64)>>, // (up, down)`
- `crates/sb-api/src/v2ray/services.rs:71` `stats: Arc<Mutex<HashMap<String, i64>>>,`
- `crates/sb-api/src/v2ray/simple.rs:52` `stats: Arc<Mutex<HashMap<String, i64>>>,`
- `crates/sb-core/src/dns/cache.rs:166` `cache: Arc<Mutex<HashMap<Key, CacheEntry>>>,`
- `crates/sb-core/src/dns/transport/dhcp.rs:63` `probe_lock: Arc<Mutex<()>>,`
- `crates/sb-core/src/dns/transport/registry.rs:21` `transports: Arc<Mutex<HashMap<String, Arc<dyn DnsTransport>>>>,`
- `crates/sb-core/src/dns/transport/registry.rs:23` `constructors: Arc<Mutex<HashMap<String, TransportConstructor>>>,`
- `crates/sb-core/src/dns/transport/registry.rs:25` `dependencies: Arc<Mutex<HashMap<String, Vec<String>>>>,`
- `crates/sb-core/src/dns/transport/udp.rs:86` `shared: Arc<Mutex<Option<Arc<SharedUdpConn>>>>,`
- `crates/sb-core/src/inbound/direct.rs:62` `udp_sessions: Arc<Mutex<HashMap<SocketAddr, UdpSession>>>,`
- `crates/sb-core/src/net/tcp_rate_limit.rs:78` `connection_tracker: Arc<Mutex<LruCache<IpAddr, VecDeque<Instant>>>>,`
- `crates/sb-core/src/net/tcp_rate_limit.rs:79` `auth_failure_tracker: Arc<Mutex<LruCache<IpAddr, VecDeque<Instant>>>>,`
- `crates/sb-core/src/net/tcp_rate_limit.rs:81` `qps_tracker: Arc<Mutex<LruCache<IpAddr, (f64, Instant)>>>,`
- `crates/sb-core/src/net/udp_processor.rs:44` `nat: Arc<Mutex<UdpNat>>,`
- `crates/sb-core/src/outbound/feedback.rs:17` `inner: Arc<Mutex<dyn SelectorFeedback + Send + Sync>>,`
- `crates/sb-core/src/outbound/feedback.rs:21` `pub fn new(inner: Arc<Mutex<dyn SelectorFeedback + Send + Sync>>) -> Self {`
- `crates/sb-core/src/outbound/feedback.rs:40` `inner: Arc<Mutex<crate::outbound::selector_p3::ScoreSelector>>, // concrete selector`
- `crates/sb-core/src/outbound/feedback.rs:44` `pub fn new(inner: Arc<Mutex<crate::outbound::selector_p3::ScoreSelector>>) -> Self {`
- `crates/sb-core/src/outbound/hysteria/v1.rs:60` `connection_pool: Arc<Mutex<Option<Connection>>>,`
- `crates/sb-core/src/outbound/hysteria/v1.rs:305` `endpoint: Arc<Mutex<Option<Endpoint>>>,`
- `crates/sb-core/src/outbound/hysteria/v1.rs:580` `sessions: Arc<Mutex<std::collections::HashMap<u32, UdpSession>>>,`
- `crates/sb-core/src/outbound/hysteria2.rs:79` `pub connection_pool: Arc<Mutex<Option<Connection>>>,`
- `crates/sb-core/src/outbound/hysteria2.rs:90` `last_reset: Arc<Mutex<Instant>>,`
- `crates/sb-core/src/outbound/hysteria2.rs:91` `up_tokens: Arc<Mutex<u32>>,`
- `crates/sb-core/src/outbound/hysteria2.rs:92` `down_tokens: Arc<Mutex<u32>>,`
- `crates/sb-core/src/outbound/selector.rs:41` `state: Arc<Mutex<HashMap<String, Stat>>>,`
- `crates/sb-core/src/outbound/socks5_udp.rs:15` `type UdpReceiver = Arc<Mutex<mpsc::Receiver<(SocketAddr, Vec<u8>)>>>;`
- `crates/sb-core/src/router/cache_wire.rs:74` `inner: Arc<Mutex<LruCache<u64, u64>>>,`
- `crates/sb-core/src/udp_nat_instrument.rs:51` `inner: Arc<Mutex<HashMap<(SocketAddr, SocketAddr), Entry>>>,`
- `crates/sb-transport/src/derp/client.rs:24` `stream: Arc<Mutex<Option<TcpStream>>>,`
- `crates/sb-transport/src/http2.rs:84` `type Http2Pool = Arc<Mutex<HashMap<(String, u16), SendRequest<Bytes>>>>;`
- `crates/sb-transport/src/multiplex.rs:147` `last_used: Arc<Mutex<Instant>>,`
- `crates/sb-transport/src/multiplex.rs:194` `type MultiplexPool = Arc<Mutex<HashMap<(String, u16), Vec<MultiplexConnection>>>>;`
- `crates/sb-transport/src/multiplex.rs:539` `stream_rx: Arc<Mutex<tokio::sync::mpsc::UnboundedReceiver<(IoStream, std::net::SocketAddr)>>>,`
