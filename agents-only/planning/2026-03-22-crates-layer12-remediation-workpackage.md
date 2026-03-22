<!-- tier: S -->
# crates Layer 1/2 修复归并工作包（维护模式）

> **日期**：2026-03-22
> **范围**：`crates/`
> **依据**：`active_context.md`、`workpackage_latest.md`、`planning/2026-03-22-crates-layer12-review-workpackage.md`、`Rust_spec_v2.md`、`log.md`（2026-03-22 审议记录）
> **目标**：将已发现的 Layer 1 / 2 问题按严重级别、可修复性、影响范围归并为统一修复批次，并冻结建议推进顺序。

---

## 本轮约束

- 仓库处于 **maintenance mode**；本轮只做 `agents-only` 归并与排程，不改 `crates/` 源码。
- 继续遵守 `Rust_spec_v2.md`，只按 **Layer 1 / Layer 2** 排程，不展开 Layer 3 / Layer 4。
- 不恢复 GitHub Actions / `.github/workflows/*`。
- 不把普通测试、repo 级测试或构建通过表述为 dual-kernel parity 完成。
- `sb-metrics` 作为特殊尾项处理：其 Layer 1 / 2 问题与现有注册表架构耦合，默认不作为首个修复批次入口。

---

## 归并总览

- 已完成审议：`16` 个 crates
- 存在生产路径问题：`11` 个 crates
- 本轮零生产路径问题：`3` 个生产 crate
  - `sb-admin-contract`
  - `sb-proto`
  - `sb-subscribe`
- 测试辅助 crate 收尾关闭：`1` 个
  - `sb-test-utils`
- 仅有轻量风格问题：`1` 个
  - `sb-types`

| 分类 | crate |
|------|------|
| 生产路径问题 | `sb-common`、`sb-security`、`sb-metrics`、`sb-config`、`sb-platform`、`sb-tls`、`sb-transport`、`sb-runtime`、`sb-core`、`sb-api`、`sb-adapters` |
| 零问题生产 crate | `sb-admin-contract`、`sb-proto`、`sb-subscribe` |
| 仅风格问题 | `sb-types` |
| 非生产主路径收尾 | `sb-test-utils` |

---

## 归并桶定义

| 桶 | 定义 | 严重级别 | 可修复性 | 影响范围 | 优先级 | 默认批次 |
|------|------|------|------|------|------|------|
| `G1` | 可导致运行时崩溃的正确性债务：生产 `unwrap/expect/unreachable!()`、解析/缓冲区直接下标访问 | 高 | 中 | 广且位于核心/边界路径 | `P0` | `Batch A` |
| `G2` | 静默失败债务：`let _ = ...`、`.ok()`、解析失败折叠、send/register/close/system-call 结果被吞 | 中高 | 中 | 最广 | `P1` | `Batch B` |
| `G3` | 全局状态债务：`OnceLock` / `LazyLock` / 全局原子计数器 / 单例注册表 | 高 | 低 | 广且架构敏感 | `P1` | `Batch C` |
| `G4` | 模块路径债务：生产代码 `super::` 相对路径 | 低 | 高 | 广但机械 | `P2` | `Batch D` |
| `G5` | API 卫生债务：通配符导入、`&String` / `&PathBuf` / `Option<&String>` 等不惯用借用签名 | 低 | 高 | 中 | `P2` | `Batch D` |

> `sb-metrics` 例外：虽然命中 `G1` / `G2`，但默认并入 `Batch C` 特殊尾项统一处理，避免在未处理注册表架构前做局部修补。

---

## 发现映射总表

> 下表按 2026-03-22 审议工作包中的“已发现问题”逐条映射；每条发现只映射到一个 `G*` 桶和一个批次。

| crate | 已发现问题 | Layer | 归并桶 | 批次 |
|------|------|------|------|------|
| `sb-types` | `IssueCode::as_str()` 生产代码通配符导入 | L2 | `G5` | `Batch D` |
| `sb-common` | `conntrack.rs` 全局 `OnceLock<ConnTracker>` / `global_tracker()` | L1 | `G3` | `Batch C` |
| `sb-common` | `interrupt.rs` 静默丢弃 broadcast `recv/send` 结果 | L2 | `G2` | `Batch B` |
| `sb-common` | `ja3.rs` / `tlsfrag.rs` / `badtls.rs` / `pipelistener.rs` 直接下标访问 | L2 | `G1` | `Batch A` |
| `sb-security` | `key_loading.rs` 用 `.ok()` 将 `std::env::var` 错误折叠为 `None` | L2 | `G2` | `Batch B` |
| `sb-metrics` | `LazyLock` 全局注册表 / 全局指标静态 | L1 | `G3` | `Batch C` |
| `sb-metrics` | dummy metric fallback / `export_prometheus()` 中生产 `unwrap()` / `expect()` | L1 | `G1` | `Batch C` |
| `sb-metrics` | `REGISTRY.register(...).ok()` 静默丢弃注册失败 | L2 | `G2` | `Batch C` |
| `sb-config` | `validator/v2.rs` 使用 `OnceLock<HashSet<_>>` 缓存 allowed key 集合 | L1 | `G3` | `Batch C` |
| `sb-config` | `merge.rs`、`ir/diff.rs` 使用生产 `super::` 相对路径 | L1 | `G4` | `Batch D` |
| `sb-config` | `validator/v2.rs` 存在生产路径 `unwrap()` | L1 | `G1` | `Batch A` |
| `sb-config` | `let _ = e`、`serde_json::from_value(...).ok()`、`mask.parse::<u8>().ok()` 等静默丢错 | L2 | `G2` | `Batch B` |
| `sb-platform` | `process/*`、`tun/*` 广泛使用生产 `super::` 相对路径 | L1 | `G4` | `Batch D` |
| `sb-platform` | Windows 路径 `use winreg::enums::*;` 通配符导入 | L2 | `G5` | `Batch D` |
| `sb-platform` | `system_proxy.rs`、`tun/*` 中大量 `let _ = ...` 静默丢弃系统调用/命令/close 结果 | L2 | `G2` | `Batch B` |
| `sb-platform` | `process/linux.rs`、`process/native_windows.rs`、`tun/macos.rs` 的直接下标访问 | L2 | `G1` | `Batch A` |
| `sb-tls` | `lib.rs` 使用 `OnceLock` 维护全局 crypto provider 安装状态 | L1 | `G3` | `Batch C` |
| `sb-tls` | `standard.rs`、`utls.rs` 的生产 `expect()` | L1 | `G1` | `Batch A` |
| `sb-tls` | `reality/*`、`ech/*`、`global.rs` 的生产 `super::` 相对路径 | L1 | `G4` | `Batch D` |
| `sb-tls` | `lib.rs`、`global.rs`、`acme.rs`、`ech_keygen.rs` 的静默丢弃结果 | L2 | `G2` | `Batch B` |
| `sb-tls` | `ech/parser.rs`、`reality/client.rs`、`reality/server.rs` 的直接下标访问 | L2 | `G1` | `Batch A` |
| `sb-transport` | `tls.rs` 使用 `OnceLock` 维护全局 rustls provider 安装状态 | L1 | `G3` | `Batch C` |
| `sb-transport` | `mem.rs`、`tls.rs`、`tls_secure.rs`、`failpoint_dialer.rs` 的生产 `super::` 相对路径 | L1 | `G4` | `Batch D` |
| `sb-transport` | `quic.rs`、`trojan.rs`、`uot.rs` 的生产 `unwrap()` / `expect()` / `unreachable!()` | L1 | `G1` | `Batch A` |
| `sb-transport` | `dialer.rs`、`metrics_ext.rs`、`http2.rs`、`wireguard.rs`、`tls.rs` 的静默丢弃结果 | L2 | `G2` | `Batch B` |
| `sb-transport` | `trojan.rs`、`uot.rs`、`tailscale_dns.rs`、`grpc_lite.rs`、`simple_obfs.rs` 的直接下标访问 | L2 | `G1` | `Batch A` |
| `sb-runtime` | `loopback.rs` 的 `let _ = write!(...)` 静默丢弃格式化结果 | L2 | `G2` | `Batch B` |
| `sb-runtime` | `tcp_local.rs` 的 `let _ = s.write_all(&out).await` 静默丢弃 I/O 错误 | L2 | `G2` | `Batch B` |
| `sb-core` | `context.rs`、`router/*`、`dns/*`、`log/mod.rs`、`service.rs` 等广泛全局可变状态 | L1 | `G3` | `Batch C` |
| `sb-core` | `context.rs`、`dns/fakeip.rs`、`dns/transport/*` 等生产 `unwrap()` / `expect()` | L1 | `G1` | `Batch A` |
| `sb-core` | `router/*`、`dns/*` 多模块广泛使用生产 `super::` 相对路径 | L1 | `G4` | `Batch D` |
| `sb-core` | `log/mod.rs`、`inbound/socks5.rs`、`dns/mod.rs`、`dns/transport/*` 的静默丢弃结果 | L2 | `G2` | `Batch B` |
| `sb-core` | `router/sniff.rs`、`socks5/mod.rs`、`admin/http.rs`、`dns/transport/*` 的直接下标访问 | L2 | `G1` | `Batch A` |
| `sb-core` | `router/normalize.rs` 的通配符导入与 `router/engine.rs`、`router/dsl_plus.rs` 的不惯用借用签名 | L2 | `G5` | `Batch D` |
| `sb-api` | `managers.rs` 的 `DnsResolver::new()` 使用 `expect()` | L1 | `G1` | `Batch A` |
| `sb-api` | `monitoring/reporter.rs`、`v2ray/services.rs` 多处 broadcast `send` 结果静默丢弃 | L2 | `G2` | `Batch B` |
| `sb-api` | `clash/websocket.rs` 多处 WebSocket `send(...).await` 结果静默丢弃 | L2 | `G2` | `Batch B` |
| `sb-api` | `clash/server.rs` 的 `super::auth::...` 相对路径 | L1 | `G4` | `Batch D` |
| `sb-api` | `clash/handlers.rs` 的 `normalize_provider_detail(value: Option<&String>)` | L2 | `G5` | `Batch D` |
| `sb-adapters` | `inbound/http.rs` 的 `OnceLock` 标志位、`inbound/tun/mod.rs` 的全局原子计数器 | L1 | `G3` | `Batch C` |
| `sb-adapters` | `outbound/tailscale.rs`、`inbound/socks/mod.rs`、`service/resolve1.rs` 的生产 `unwrap()` / `expect()` | L1 | `G1` | `Batch A` |
| `sb-adapters` | `outbound/hysteria.rs`、`outbound/tuic.rs`、`inbound/trojan.rs` 等生产 `super::` 相对路径 | L1 | `G4` | `Batch D` |
| `sb-adapters` | `register.rs`、`service/resolved_impl.rs`、`inbound/socks/udp.rs`、`inbound/tun/platform/*` 的静默丢弃结果 | L2 | `G2` | `Batch B` |
| `sb-adapters` | `inbound/socks/udp.rs`、`outbound/trojan.rs`、`outbound/tuic.rs`、`service/resolve1.rs`、`inbound/tun_macos.rs` 的直接下标访问 | L2 | `G1` | `Batch A` |
| `sb-adapters` | `outbound/hysteria.rs` 等多处 `use crate::outbound::prelude::*;` 通配符导入 | L2 | `G5` | `Batch D` |
| `sb-adapters` | `register.rs` 的 `Option<&String>` 等不惯用借用签名 | L2 | `G5` | `Batch D` |

---

## 修复批次

### Batch A / `P0` / Crash Surface

- **处理桶**：`G1`
- **严重级别**：高
- **可修复性**：中
- **影响范围**：广且位于核心/边界路径
- **涉及 crates**：`sb-config`、`sb-common`、`sb-platform`、`sb-tls`、`sb-transport`、`sb-core`、`sb-api`、`sb-adapters`
- **推荐推进顺序**：`sb-config` → `sb-common` + `sb-platform` + `sb-tls` + `sb-transport` → `sb-core` → `sb-api` → `sb-adapters`
- **说明**：
  - 先从 `sb-config` 入手，优先收口配置入口 panic 面与下标访问。
  - 中层解析与传输底座可并行，但必须在 `sb-core` 前完成，减少核心层返工。
  - `sb-metrics` 的 `G1` 问题默认不进入首批，后移至 `Batch C` 特殊尾项。

### Batch B / `P1` / Failure Surfacing

- **处理桶**：`G2`
- **严重级别**：中高
- **可修复性**：中
- **影响范围**：最广
- **涉及 crates**：`sb-common`、`sb-security`、`sb-config`、`sb-platform`、`sb-tls`、`sb-transport`、`sb-runtime`、`sb-core`、`sb-api`、`sb-adapters`
- **推荐推进顺序**：`sb-security` + `sb-runtime` + `sb-config` → `sb-platform` + `sb-tls` + `sb-transport` → `sb-core` + `sb-api` → `sb-adapters`
- **说明**：
  - 先修低耦合、小范围静默失败点，统一“忽略必须有注释或 tracing”的口径。
  - `sb-core` / `sb-api` 在底层统一告警与返回策略后再收口，避免重复设计。
  - `sb-metrics` 的 `register(...).ok()` 默认后移到 `Batch C`，仅在确认可局部收口时回提。

### Batch C / `P1` / Singleton Reduction

- **处理桶**：`G3`
- **严重级别**：高
- **可修复性**：低
- **影响范围**：广且架构敏感
- **涉及 crates**：`sb-common`、`sb-metrics`、`sb-config`、`sb-tls`、`sb-transport`、`sb-core`、`sb-adapters`
- **推荐推进顺序**：`sb-common` tracker 注入模式 → `sb-tls` / `sb-transport` provider 安装状态 → `sb-config` validator cache 与 `sb-adapters` 全局标志/计数器 → `sb-core` runtime/router/dns/log/service 全局状态 → `sb-metrics` 注册表架构
- **说明**：
  - 本批是架构敏感批次，需以依赖注入和上下文显式传递替代单例。
  - `sb-metrics` 在本批作为特殊尾项统一处理；其 `G1` / `G2` 发现也默认在本批收口。

### Batch D / `P2` / Mechanical Sweep

- **处理桶**：`G4` + `G5`
- **严重级别**：低
- **可修复性**：高
- **影响范围**：广但以机械修改为主
- **涉及 crates**：`sb-types`、`sb-config`、`sb-platform`、`sb-tls`、`sb-transport`、`sb-core`、`sb-api`、`sb-adapters`
- **推荐推进顺序**：优先在 `Batch A-C` 触碰到的文件中顺手收口，再做剩余纯风格 sweep
- **说明**：
  - 不提前单独启动纯风格批次，避免与行为修复产生 rebase 噪音。
  - `sb-types` 仅在本批处理即可，无需提前占用修复窗口。

---

## 执行进展（2026-03-22）

### 已完成或大部完成的推进

- `Batch A / Crash Surface`
  - 已对 `sb-config`、`sb-common`、`sb-platform`、`sb-tls`、`sb-transport`、`sb-core`、`sb-api`、`sb-adapters` 的已审议 panic / 越界热点做首轮落地修复。
  - 已把配置校验、TLS/传输解析、DNS/路由入口、SOCKS/适配器解析路径上的 `unwrap()` / `expect()` / `unreachable!()` 与直接下标访问大面积改为显式校验与错误返回。
  - 当前判断：主线 crash surface 已大幅收缩，但仍需在最终静态扫尾时复核残余 `G1` 命中，暂不在文档中宣告全量清零。

- `Batch B / Failure Surfacing`
  - 已对 `sb-common`、`sb-runtime`、`sb-config`、`sb-transport`、`sb-core`、`sb-api`、`sb-adapters` 的主要静默失败点做首轮收口。
  - 已将多处 broadcast / websocket / registry / close / write / formatting 的吞错路径改为显式返回、结构化日志或具名 best-effort 路径。
  - 当前判断：主线 failure surfacing 已进入收尾阶段，但仍需配合最终静态审计确认剩余 `let _ = ...` / `.ok()` 是否仅保留在允许场景。

- `Batch C / Singleton Reduction`
  - `conntrack`：`sb-common` / `sb-core` / `sb-api` / `sb-adapters` / `app` 的生产 wiring 已改为显式 `Arc<ConnTracker>` 透传。
  - `context`：生产代码中 `context_registry()` / `install_context_registry()` 读链已移除。
  - `sb-tls` / `sb-transport`：仓内 rustls provider 额外 `OnceLock` 包装已去除，provider 初始化路径已显式化。
  - `metrics startup`：`app` 启动链已改为显式传递 `MetricsRegistryHandle`，不再依赖隐式全局 exporter 入口。
  - 当前判断：`Batch C` 已完成最重要的 `conntrack/context` 生产路径收口，剩余高价值尾项集中在 `sb-metrics` 内部 `REGISTRY + LazyLock` 指标静态架构。

- `Batch D / Mechanical Sweep`
  - 尚未单独启动。
  - 仅在 A-C 触碰到的文件中顺手处理了部分风格项，不足以视为完整收尾。

### 当前验证基线

- 已通过：`cargo check -p sb-core -p sb-api -p sb-adapters -p app`
- 已通过：`cargo test -p sb-api --test connections_snapshot_test --test clash_websocket_e2e`
- 已通过：`cargo test -p app --lib`
- 已通过：多轮 `sb-adapters` / `sb-common` / `sb-core` / `sb-metrics` / `sb-tls` / `sb-transport` 定向 `cargo check` 与针对性测试
- 说明：这些结果仅说明 Layer 1 / 2 维护验证在收敛，不构成 dual-kernel parity 完成声明

---

## 任务状态

| 任务 ID | 内容 | 状态 | 备注 |
|------|------|------|------|
| T0 | 建立 Layer 1 / 2 修复归并工作包 | ✅ DONE | 本文件已建立 |
| T1 | 执行 `Batch A / P0 / Crash Surface` | 🚧 IN PROGRESS | 主线热点已落地，待最终残项复核 |
| T2 | 执行 `Batch B / P1 / Failure Surfacing` | 🚧 IN PROGRESS | 主线吞错路径已收口，待静态尾项审计 |
| T3 | 执行 `Batch C / P1 / Singleton Reduction` | 🚧 IN PROGRESS | `conntrack/context` 已收口，`sb-metrics` 内部注册表架构待继续 |
| T4 | 执行 `Batch D / P2 / Mechanical Sweep` | ⏳ TODO | 只做收尾，不抢跑 |

---

## 下一步

1. 继续 `Batch C`：优先处理 `sb-metrics` 内部 `REGISTRY + LazyLock` 静态架构的显式 handle 化与残余注册入口收口。
2. 启动 `Batch D` 收尾：对 `super::` 相对路径、通配符导入、非惯用借用签名做统一机械性 sweep。
3. 在收尾前做一次最终静态审计，确认 `G1` / `G2` 残项只剩允许范围；保持 maintenance mode 口径，不把普通测试完成表述成 dual-kernel parity 完成。
