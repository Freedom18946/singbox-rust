<!-- tier: S -->
# app Layer 1/2 审议工作包（维护模式）

> **日期**：2026-03-22
> **范围**：`app/`
> **依据**：`AGENTS.md`、`agents-only/active_context.md`、`agents-only/Rust_spec_v2.md`
> **目标**：按 Layer 1 / Layer 2 规则审议并治理 `app/` 生产路径热点，跟踪修复收口状态。

---

## 本轮约束

- 仓库处于 **maintenance mode**。
- 只按 **Layer 1 / Layer 2** 记录问题，不展开 Layer 3 / Layer 4。
- 不恢复 GitHub Actions / `.github/workflows/*`。
- 不把普通测试、repo 级测试或构建通过表述为 dual-kernel parity 完成。
- 本轮重点覆盖 `app/src` 与 `app/src/bin` 生产路径；`tests/`、`benches/`、`scripts/` 默认不记入发现，除非直接影响生产行为。

---

## 审议结论

- 首轮静态审议已完成，确认 `app/` 存在 **6 个** 需要纳入 Layer 1 / 2 治理的问题点。
- 热点集中在：
  - 进程级单例初始化与全局可变状态
  - 生产路径 `unwrap()` / `expect()` / `lazy_static!`
  - `.ok()` / `let _ = ...` 导致的静默丢错
- `app/src/bin/*` 本轮未见额外高优先级热点；大部分命中属于顶层 CLI/工具入口的允许型 `expect` / `unwrap`，暂未单列。

---

## 执行进展（2026-03-22）

- 已按“显式注入 + 兼容壳”策略完成本轮主修：
  - 新增 `AppRuntimeDeps`，统一持有 `Redactor` / `AnalyzeRegistry` / `SecurityMetricsState` / `started_at`，`observe` 构建下再显式携带 `MetricsRegistryHandle`
  - `redact.rs` 改为 `Redactor` 实例化初始化，移除生产路径 `lazy_static!` 与 `Regex::new(...).unwrap()`
  - `tracing_init.rs` 改为显式返回 `Result`；`tls_provider.rs` 移除决策缓存并把安装冲突改为真实错误传播
  - `analyze::registry` 改为 `AnalyzeRegistry` 对象，builder 注册走显式实例，不再使用 `OnceLock<Mutex<_>> + expect(...)`
  - `admin_debug/security_metrics` 改为 `SecurityMetricsState` 实例；全局原子/`OnceCell` 单例迁移进状态对象，`snapshot()` 改为显式 `Result`
  - `admin_debug/http_server` / `health` / `metrics` / `analyze` 改为接收 `AdminDebugState`，`started_at` 不再依赖 `START: OnceLock<_>`
  - `inbound_starter` 的 TUN 配置转换保留具体错误上下文，停机/直连路径的 `let _ = ...` 改为具名 `warn!`
  - `run_engine` 的 shutdown 链补上 join/send failure surfacing
- `security_metrics` 仍保留了一个 `DEFAULT_STATE: OnceLock<Arc<...>>` 兼容壳，用于平滑承接旧的模块级调用面；统计数据本体已经不再是进程级散落静态状态。
- 本轮未继续处理 `logging.rs` 自身的 `OnceLock` 配置/采样单例；它不在首轮高优先级发现内，暂保留到下一批 `app/` Layer 1/2 尾项。
- 带 `adapters` 的 `cargo check -p app --features "admin_debug sbcore_rules_tool dev-cli adapters"` 未能作为 `app/` 回归完成，因为当前工作树存在 `sb-adapters` 侧未完成改动：
  - `crates/sb-adapters/src/inbound/dns.rs`
  - `crates/sb-adapters/src/inbound/ssh.rs`
  - `crates/sb-adapters/src/inbound/shadowsocks.rs`
  - 共同症状为若干初始化器缺失 `conn_tracker` 字段；本轮未回退或改写这些外部未完成改动。

## 本轮验证

- `cargo check -p app` ✅
- `cargo check -p app --features "admin_debug sbcore_rules_tool dev-cli"` ✅
- `cargo test -p app --lib --features "admin_debug sbcore_rules_tool dev-cli"` ✅
- `cargo test -p sb-api --test connections_snapshot_test --test clash_websocket_e2e` ✅

---

## 发现总表

| ID | 文件 | Layer | 类型 | 严重级别 | 摘要 |
|------|------|------|------|------|------|
| `APP-L12-001` | `app/src/tracing_init.rs` | L1/L2 | 全局状态 + 静默吞错 | 高 | `TRACING` / `METRICS` 使用 `OnceLock`，并对 tracing 初始化结果直接 `let _ = ...` |
| `APP-L12-002` | `app/src/tls_provider.rs` | L1/L2 | 全局状态 + 错误折叠 | 高 | `ensure_default_provider()` 用 `OnceLock` 缓存决策，安装失败被折叠成 `"already_present"` |
| `APP-L12-003` | `app/src/redact.rs` | L1 | 全局状态 + panic 路径 | 高 | `lazy_static!` + `Regex::new(...).unwrap()` 直接进入生产路径 |
| `APP-L12-004` | `app/src/analyze/registry.rs` | L1 | 全局状态 + panic 路径 | 高 | `OnceLock<Mutex<...>>` 注册表配合多处 `.expect("... poisoned")` |
| `APP-L12-005` | `app/src/admin_debug/security_metrics.rs` | L1/L2 | 全局状态 + panic/吞错 | 高 | 大范围原子/`OnceCell` 统计单例，并在快照路径混用 `.unwrap()` / `.ok()` / `let _ = ...` |
| `APP-L12-006` | `app/src/inbound_starter.rs` | L2 | 静默吞错 | 中 | TUN 配置转换用 `.ok().and_then(...ok())` 折叠错误，停机/直连路径多处 `let _ = ...` |

---

## 详细发现

### `APP-L12-001` `app/src/tracing_init.rs`

- **命中位置**：
  - `TRACING` / `METRICS`：17-21
  - tracing init：26-38、46-57
  - metrics init：66-86
- **问题说明**：
  - `OnceLock<()>` 把 observability 初始化做成了进程级隐式单例，违反 Layer 1 “禁止全局可变状态”的口径。
  - `builder.json().try_init()` / `builder.compact().try_init()` 的返回值被 `let _ = ...` 直接吞掉，调用方无法区分“首次成功初始化”和“因重复 subscriber / 配置冲突而失败”，命中 Layer 2 的静默失败问题。
- **建议方向**：
  - 通过显式初始化句柄或运行时上下文管理 tracing / metrics bootstrap。
  - 至少把 `try_init()` 失败改成显式日志或返回错误。

### `APP-L12-002` `app/src/tls_provider.rs`

- **命中位置**：
  - 决策缓存：29-31
  - 安装结果折叠：65-72
- **问题说明**：
  - `ensure_default_provider()` 把 TLS provider 选择与安装结果缓存到 `OnceLock`，继续依赖进程级隐式共享状态。
  - `install_provider(provider).is_ok()` 失败时直接回落为 `"already_present"`，把真实安装错误与“已有 provider”混为一谈，后续探针/日志无法准确判断失败原因。
- **建议方向**：
  - 将 provider 决策与安装结果显式注入到启动链。
  - 保留安装错误原文，避免把失败折叠为成功语义。

### `APP-L12-003` `app/src/redact.rs`

- **命中位置**：8-27
- **问题说明**：
  - 使用 `lazy_static!` 维护进程级 regex 单例，违反 Layer 1 全局状态禁令。
  - 四个 `Regex::new(...).unwrap()` 都位于生产路径；一旦模式常量未来被误改，运行时将直接 panic。
- **建议方向**：
  - 改为显式注入或封装初始化流程，并把 regex 构造失败转成具名错误或启动期硬失败入口处理。

### `APP-L12-004` `app/src/analyze/registry.rs`

- **命中位置**：
  - 全局注册表：26-28
  - lock panic：37、56、66、80、92、104、119
- **问题说明**：
  - `REGISTRY` / `ASYNC_REGISTRY` 使用 `OnceLock<Mutex<HashMap<...>>>` 维护全局分析器注册表，命中 Layer 1 全局状态问题。
  - 对 poisoned lock 的处理全部是 `.expect("...")`，会在生产 CLI 路径直接 panic。
- **建议方向**：
  - 将 registry 收敛到显式上下文或构建期注册对象。
  - 以错误返回替代 `.expect(...)`。

### `APP-L12-005` `app/src/admin_debug/security_metrics.rs`

- **命中位置**：
  - 全局统计状态：52-106
  - 延迟快照更新：387-400
  - 快照读取：577-598
- **问题说明**：
  - 文件内维护了大量 `AtomicU64`、`OnceCell<Mutex<_>>` 和全局快照缓存，是目前 `app/` 内最重的全局状态聚集点之一。
  - `record_latency_ms()` 使用 `LAT_COUNTS.get().unwrap().lock().ok()`，既存在 panic 路径，也会在锁失败时静默清空 buckets。
  - `LATENCY_SNAPSHOT.set(...)` 结果被 `let _ = ...` 吞掉；`snapshot()` 多处 `.and_then(|m| m.lock().ok())` 将错误折叠为默认值，导致观测面静默失真。
- **建议方向**：
  - 将统计容器迁移为显式 registry/context。
  - 避免在快照路径用默认值吞掉锁错误或 `set()` 失败。

### `APP-L12-006` `app/src/inbound_starter.rs`

- **命中位置**：
  - 停机吞错：63-75
  - TUN 配置折叠：555-557
  - direct inbound 结果丢弃：622-624
- **问题说明**：
  - `serde_json::to_value(tun).ok().and_then(|value| serde_json::from_value::<TunInboundConfig>(value).ok())` 把序列化与反序列化错误统一折叠为 `None`，最终只留下 `"invalid tun options"` 的泛化告警，错误上下文完全丢失。
  - `tx.send(()).await`、`self.join.await`、`forward_spawn.serve()` 等返回值被 `let _ = ...` 直接忽略，没有解释性注释或结构化日志。
- **建议方向**：
  - 为 TUN 配置转换保留具体错误链。
  - 停机和直连路径至少增加具名 best-effort 注释，或把失败写入 `tracing::warn!`。

---

## 状态

| 任务 ID | 内容 | 状态 | 备注 |
|------|------|------|------|
| `T0` | 建立 `app/` Layer 1 / 2 审议跟踪文档 | ✅ DONE | 本文件 |
| `T1` | 完成 `app/` 首轮静态审议 | ✅ DONE | 以 `app/src` 为主，`app/src/bin` 做快速补扫 |
| `T2` | 按显式注入策略完成首轮热点修复 | ✅ DONE | 已覆盖 `APP-L12-001` ~ `APP-L12-006` 主体路径 |
| `T3` | 做一轮 `app/` Layer 1 / 2 尾项静态扫尾 | ⏳ TODO | 重点看 `logging.rs`、`run_engine.rs` 其余 shutdown best-effort、以及兼容壳是否可继续收紧 |

---

## 下一步

1. 继续 `app/` 尾项时，优先处理 `logging.rs` 现存 `OnceLock` / `let _ = ...` shutdown 路径，评估是否需要并入 `AppRuntimeDeps` 第二波。
2. 若要完成带 `adapters` 的 `app` 编译面验证，需要先协调/收口当前 `sb-adapters` 工作树里的 `conn_tracker` 字段缺失问题。
3. 如需扩展审议范围，再单独覆盖 `app/tests` / `app/benches`，但不与生产路径问题混报。
