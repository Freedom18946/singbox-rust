<!-- tier: S -->
# crates 专项审议工作包（Layer 1 / 2）

> **日期**：2026-03-22
> **范围**：`crates/`
> **审议口径**：优先适用 `Rust_spec_v2.md` 的 Layer 1 与 Layer 2；本轮**跳过** Layer 3 / Layer 4。
> **目标**：按 crate 逐个审议生产源码与关键联调调用，记录任务推进状态。

---

## 本轮约束

- 只审议 `crates/*`，不把 repo 级测试、workflow、单纯 CI 通过视为完成。
- 先看 `src/` 生产路径；`tests/`、`examples/`、`benches/` 仅在其直接暴露 Layer 1/2 问题时补查。
- 审议重点：
  - Layer 1：panic 路径、`super::` 相对路径、随意 `pub use`、全局可变状态
  - Layer 2：集合安全访问、结果不可静默丢弃、禁用通配符导入、禁用调试输出、`main/lib` 边界、惯用借用签名、禁用占位宏
- 审议顺序遵循：**低依赖基础层 → 共享能力层 → 内核层 → 外围接口/协议边界层**。

---

## crates 构成速览

### 基础契约 / 共享能力

- `sb-types`：领域类型、ports、错误契约
- `sb-admin-contract`：admin/CLI JSON envelope 与错误契约
- `sb-common`：共享工具、连接跟踪、兼容辅助
- `sb-security`：凭据加载、脱敏、安全辅助
- `sb-metrics`：指标结构与导出辅助
- `sb-test-utils`：测试辅助 crate，非生产主路径

### 配置 / 平台 / 传输底座

- `sb-config`：配置解析、IR、校验、schema v2
- `sb-platform`：tun / process / system proxy / 平台能力
- `sb-tls`：TLS / REALITY / ECH / uTLS / ACME
- `sb-transport`：WS / H2 / gRPC / QUIC / WireGuard 等传输层
- `sb-proto`：协议连接器与出站注册桥接
- `sb-runtime`：运行时场景、loopback、协议跑测辅助

### 内核 / 控制面 / 协议边界

- `sb-core`：内核合集层，路由、DNS、上下文、生命周期、桥接
- `sb-subscribe`：订阅拉取、解析、转换、provider 处理
- `sb-api`：Clash API / V2Ray API / 监控桥接
- `sb-adapters`：inbound / outbound / service / endpoint 协议适配器

---

## 审议顺序

| 顺序 | crate | 角色 | 进入理由 | 联调关注点 | 状态 |
|------|------|------|------|------|------|
| 0 | 工作包建立 | 入口任务 | 完成 crates 摸底并冻结顺序 | `agents-only` 记录 | ✅ DONE |
| 1 | `sb-types` | 契约层 | 最低层，先锁定类型/ports 的 Layer 1/2 基线 | 被 `sb-config` / `sb-core` / `sb-api` 等广泛依赖 | ✅ DONE |
| 2 | `sb-admin-contract` | 控制面契约 | 体量小、边界清晰，适合快速校准错误/serde 纪律 | admin/CLI JSON 交互 | ✅ DONE |
| 3 | `sb-common` | 共享工具 | 常见通用模式集中地，便于提前发现 panic/调试输出等共性问题 | `sb-core` / `sb-api` 共享调用 | ✅ DONE |
| 4 | `sb-security` | 安全辅助 | 处理敏感数据，优先排查 `unwrap`/占位宏/静默失败 | 凭据加载与密钥读入链路 | ✅ DONE |
| 5 | `sb-metrics` | 可观测性 | 结构较集中，适合确认结果处理与导出边界 | `sb-core` / `sb-transport` 指标接线 | ✅ DONE |
| 6 | `sb-config` | 配置编译 | 输入边界关键层，优先检查 `serde` 模型与错误传播 | app / core / subscribe 配置入口 | ✅ DONE |
| 7 | `sb-platform` | 平台能力 | OS 路径多，先做 Layer 1/2 纪律排查，避免系统调用分支劣化 | tun / process / system proxy | ✅ DONE |
| 8 | `sb-tls` | TLS 子系统 | 独立性较强，先于 transport 审议可减小后续噪音 | rustls / reality / ech 集成 | ✅ DONE |
| 9 | `sb-transport` | 传输底座 | 上承 adapters/core，先排查基础传输实现问题 | ws / h2 / grpc / quic / wireguard | ✅ DONE |
| 10 | `sb-proto` | 协议桥接 | 体量较小，位于 transport 与上层注册之间 | connector / outbound registry | ✅ DONE |
| 11 | `sb-runtime` | 跑测/运行时辅助 | 依赖面有限，放在 core 前完成外围运行时清点 | scenario / protocol runtime | ✅ DONE |
| 12 | `sb-core` | 内核合集层 | 架构中心，需在基础层稳定后审议 | router / dns / lifecycle / admin / endpoint | ✅ DONE |
| 13 | `sb-subscribe` | 订阅处理 | 与 config/core 交互明显，适合在 core 后看 | provider fetch / parse / convert | ✅ DONE |
| 14 | `sb-api` | 控制面接口 | 在 core 之后审议，便于聚焦 Layer 1/2 接线问题 | clash / v2ray / monitoring bridge | ✅ DONE |
| 15 | `sb-adapters` | 协议适配器 | 面积最大、分支最多，放在最后做汇总性审议 | inbound / outbound / endpoint / service 联调 | ✅ DONE |
| 16 | `sb-test-utils` | 测试辅助 | 非生产主路径；考虑 Layer 1 测试例外，后置处理 | 各 crate 测试支撑 | ✅ DONE |

---

## 任务清单

| 任务 ID | 内容 | 状态 | 备注 |
|------|------|------|------|
| T0 | 盘点 `crates/` 构成并定义审议顺序 | ✅ DONE | 本文件已建立 |
| T1 | 审议 `sb-types` | ✅ DONE | 发现 1 个 Layer 2 问题；未见 Layer 1 生产路径问题 |
| T2 | 审议 `sb-admin-contract` | ✅ DONE | 本轮未发现 Layer 1 / 2 问题 |
| T3 | 审议 `sb-common` | ✅ DONE | 发现 3 类 Layer 1 / 2 问题 |
| T4 | 审议 `sb-security` | ✅ DONE | 发现 1 个 Layer 2 问题 |
| T5 | 审议 `sb-metrics` | ✅ DONE | 发现 3 类 Layer 1 / 2 问题 |
| T6 | 审议 `sb-config` | ✅ DONE | 发现 4 类 Layer 1 / 2 问题 |
| T7 | 审议 `sb-platform` | ✅ DONE | 发现 4 类 Layer 1 / 2 问题 |
| T8 | 审议 `sb-tls` | ✅ DONE | 发现 5 类 Layer 1 / 2 问题 |
| T9 | 审议 `sb-transport` | ✅ DONE | 发现 5 类 Layer 1 / 2 问题 |
| T10 | 审议 `sb-proto` | ✅ DONE | 本轮未发现 Layer 1 / 2 问题 |
| T11 | 审议 `sb-runtime` | ✅ DONE | 发现 2 个 Layer 2 问题 |
| T12 | 审议 `sb-core` | ✅ DONE | 发现 6 类 Layer 1 / 2 问题 |
| T13 | 审议 `sb-subscribe` | ✅ DONE | 本轮未发现 Layer 1 / 2 问题 |
| T14 | 审议 `sb-api` | ✅ DONE | 发现 5 类 Layer 1 / 2 问题 |
| T15 | 审议 `sb-adapters` | ✅ DONE | 发现 7 类 Layer 1 / 2 问题 |
| T16 | 审议 `sb-test-utils` | ✅ DONE | 本轮未发现 Layer 1 / 2 问题 |

---

## 状态维护规则

- 每完成一个 crate 审议，就将对应 `T*` 从 `TODO` 改为 `DONE`，必要时补 `BLOCKED` / `PARTIAL`。
- 若发现问题跨 crate 扩散，不改顺序，只在对应任务备注中追加“联调追踪”。
- 若后续用户要求缩小范围到某个子目录，可在本文件追加子任务，不重排已冻结顺序。

---

## 已完成审议记录

### T1 `sb-types`（2026-03-22）

- 范围：`crates/sb-types/src/*`
- 结论：完成 Layer 1 / 2 静态审议
- 结果摘要：
  - 未见生产代码 `unwrap()` / `expect()` / `panic!()` / `todo!()` / `unimplemented!()` / `unreachable!()`
  - 未见全局可变状态、`super::` 相对路径滥用、调试输出、结果静默丢弃、`&String` / `&Vec<_>` / `&PathBuf` 参数签名
  - 发现 1 个 Layer 2 问题：`IssueCode::as_str()` 内存在生产代码通配符导入 `use IssueCode::*;`
  - `ports/mod.rs` 的 `pub use ...::*` 视为 facade 式再导出，本轮未计为问题

### T2 `sb-admin-contract`（2026-03-22）

- 范围：`crates/sb-admin-contract/src/lib.rs`
- 结论：完成 Layer 1 / 2 静态审议
- 结果摘要：
  - 未见生产代码 `unwrap()` / `expect()` / `panic!()` / `todo!()` / `unimplemented!()` / `unreachable!()`
  - 未见全局可变状态、`super::` 相对路径滥用、通配符导入、调试输出、结果静默丢弃、`&String` / `&Vec<_>` / `&PathBuf` 参数签名
  - `as_result()` 的 `unwrap_or_else` 带防御性回退值，不构成 panic 路径
  - 本轮未发现需要立刻处理的 Layer 1 / 2 问题

### T3 `sb-common`（2026-03-22）

- 范围：`crates/sb-common/src/*`
- 结论：完成 Layer 1 / 2 静态审议
- 结果摘要：
  - 发现 1 个 Layer 1 问题：`conntrack.rs` 使用全局 `OnceLock<ConnTracker>` 暴露 `global_tracker()`
  - 发现 1 个 Layer 2 问题：`interrupt.rs` 使用 `let _ = ...` 静默丢弃 broadcast `recv/send` 的 `Result`
  - 发现 1 个 Layer 2 系统性问题：`ja3.rs` / `tlsfrag.rs` / `badtls.rs` / `pipelistener.rs` 的解析路径存在大量切片直接下标访问，未按 `.get()` / 显式安全访问约束收口
  - 其余命中的 `unwrap()` / `panic!()` / `eprintln!()` 主要位于 `#[cfg(test)]` 测试代码，未计入生产路径问题

### T4 `sb-security`（2026-03-22）

- 范围：`crates/sb-security/src/*`
- 结论：完成 Layer 1 / 2 静态审议
- 结果摘要：
  - 未见生产代码 `unwrap()` / `expect()` / `panic!()` / `todo!()` / `unimplemented!()` / `unreachable!()`
  - 未见全局可变状态、`super::` 相对路径滥用、生产代码通配符导入、调试输出、`let _ = ...` 静默丢弃、`&String` / `&Vec<_>` / `&PathBuf` 参数签名
  - 发现 1 个 Layer 2 问题：`key_loading.rs` 使用 `std::env::var(name).ok()` 将环境变量读取错误静默折叠为 `None`
  - `lib.rs` 中文档示例含 `.expect(...)` / `println!`，但不属于本轮生产路径问题

### T5 `sb-metrics`（2026-03-22）

- 范围：`crates/sb-metrics/src/*`
- 结论：完成 Layer 1 / 2 静态审议
- 结果摘要：
  - 发现 1 个 Layer 1 系统性问题：大量 `LazyLock` 全局注册表 / 全局指标静态（`REGISTRY`、各模块 `pub static ...`）
  - 发现 1 个 Layer 1 系统性问题：生产代码中存在大量 `unwrap()` / `expect()`，主要集中在 dummy metric fallback 和 `export_prometheus()`
  - 发现 1 个 Layer 2 系统性问题：大量 `REGISTRY.register(...).ok()` 静默丢弃注册失败结果
  - 本 crate 的 Layer 1 违规不是局部点状问题，而是当前指标架构实现模式本身与规则冲突

### T6 `sb-config`（2026-03-22）

- 范围：`crates/sb-config/src/*`
- 结论：完成 Layer 1 / 2 静态审议
- 结果摘要：
  - 发现 1 个 Layer 1 系统性问题：`validator/v2.rs` 使用多处 `OnceLock<HashSet<_>>` 缓存 allowed key 集合
  - 发现 1 个 Layer 1 问题：生产代码存在 `super::` 相对路径（`merge.rs`、`ir/diff.rs`）
  - 发现 1 个 Layer 1 系统性问题：`validator/v2.rs` 存在生产路径 `unwrap()`（如 `ib.get("type").unwrap()`、`v.as_array().unwrap()`）
  - 发现 1 个 Layer 2 系统性问题：存在静默丢弃错误/解析失败的写法（如 `let _ = e`、`serde_json::from_value(...).ok()`、`mask.parse::<u8>().ok()`）

### T7 `sb-platform`（2026-03-22）

- 范围：`crates/sb-platform/src/*`
- 结论：完成 Layer 1 / 2 静态审议
- 结果摘要：
  - 发现 1 个 Layer 1 系统性问题：生产代码广泛使用 `super::` 相对路径（如 `process/linux.rs`、`process/macos.rs`、`tun/linux.rs`）
  - 发现 1 个 Layer 2 问题：Windows 路径存在生产代码通配符导入（如 `wininet.rs`、`system_proxy.rs` 的 `use winreg::enums::*;`）
  - 发现 1 个 Layer 2 系统性问题：存在大量 `let _ = ...` 静默丢弃系统命令/系统调用/关闭返回值（如 `system_proxy.rs`、`tun/{linux,macos,windows}.rs`）
  - 发现 1 个 Layer 2 系统性问题：若干解析/缓冲区处理路径依赖直接下标访问（如 `process/linux.rs`、`process/native_windows.rs`、`tun/macos.rs`）

### T8 `sb-tls`（2026-03-22）

- 范围：`crates/sb-tls/src/*`
- 结论：完成 Layer 1 / 2 静态审议
- 结果摘要：
  - 发现 1 个 Layer 1 问题：`lib.rs` 使用 `OnceLock` 维护全局 crypto provider 安装状态
  - 发现 1 个 Layer 1 问题：生产代码存在 `expect()`（如 `standard.rs` 的 `Default` 实现、`utls.rs` 的协议版本构造）
  - 发现 1 个 Layer 1 系统性问题：生产代码广泛使用 `super::` 相对路径（`reality/*`、`ech/*`、`global.rs`）
  - 发现 1 个 Layer 2 系统性问题：存在 `let _ = ...`/`.add(...)` 等静默丢弃结果（如 `lib.rs`、`global.rs`、`acme.rs`、`ech_keygen.rs`）
  - 发现 1 个 Layer 2 系统性问题：若干 TLS/ECH/REALITY 解析路径依赖直接下标访问（如 `ech/parser.rs`、`reality/client.rs`、`reality/server.rs`）

### T9 `sb-transport`（2026-03-22）

- 范围：`crates/sb-transport/src/*`
- 结论：完成 Layer 1 / 2 静态审议
- 结果摘要：
  - 发现 1 个 Layer 1 问题：`tls.rs` 使用 `OnceLock` 维护全局 rustls provider 安装状态
  - 发现 1 个 Layer 1 系统性问题：生产代码存在 `super::` 相对路径（如 `mem.rs`、`tls.rs`、`tls_secure.rs`、`failpoint_dialer.rs`）
  - 发现 1 个 Layer 1 问题：生产代码存在 `unwrap()` / `expect()` / `unreachable!()`（如 `quic.rs`、`trojan.rs`、`uot.rs`）
  - 发现 1 个 Layer 2 系统性问题：存在大量 `let _ = ...` / `.ok()` 静默丢弃结果（如 `dialer.rs`、`metrics_ext.rs`、`http2.rs`、`wireguard.rs`、`tls.rs`）
  - 发现 1 个 Layer 2 系统性问题：多种协议解析路径依赖直接下标访问（如 `trojan.rs`、`uot.rs`、`tailscale_dns.rs`、`grpc_lite.rs`、`simple_obfs.rs`）

### T10 `sb-proto`（2026-03-22）

- 范围：`crates/sb-proto/src/*`
- 结论：完成 Layer 1 / 2 静态审议
- 结果摘要：
  - 未见生产代码 `unwrap()` / `expect()` / `panic!()` / `todo!()` / `unimplemented!()` / `unreachable!()`
  - 未见全局可变状态、`super::` 相对路径滥用、调试输出、结果静默丢弃、直接下标访问、`&String` / `&Vec<_>` / `&PathBuf` 参数签名
  - `lib.rs` 的 `pub use ...::*` 视为 crate 根 facade 式再导出，本轮未计为问题

### T11 `sb-runtime`（2026-03-22）

- 范围：`crates/sb-runtime/src/*`
- 结论：完成 Layer 1 / 2 静态审议
- 结果摘要：
  - 未见生产代码 `unwrap()` / `expect()` / `panic!()` / `todo!()` / `unimplemented!()` / `unreachable!()`
  - 未见全局可变状态、`super::` 相对路径滥用、调试输出、通配符导入、`&String` / `&Vec<_>` / `&PathBuf` 参数签名
  - 发现 2 个 Layer 2 问题：`loopback.rs` 的 `hex_encode()` 使用 `let _ = write!(...)` 静默丢弃格式化结果；`tcp_local.rs` 的 `spawn_echo_once()` 使用 `let _ = s.write_all(&out).await` 静默丢弃 I/O 错误
  - `lib.rs` / `protocols/mod.rs` 的 `pub use ...::*` 视为 crate 根 facade 式再导出，本轮未计为问题

### T12 `sb-core`（2026-03-22）

- 范围：`crates/sb-core/src/*`
- 结论：完成 Layer 1 / 2 静态审议
- 结果摘要：
  - 发现 1 个 Layer 1 系统性问题：全局可变状态使用范围很广（如 `context.rs`、`router/{engine,mod}.rs`、`adapter/registry.rs`、`dns/{fakeip,global,stub}.rs`、`log/mod.rs`、`service.rs`）
  - 发现 1 个 Layer 1 系统性问题：生产代码仍存在 `unwrap()` / `expect()`（如 `context.rs` 的多处 `RwLock::*().unwrap()`、`dns/fakeip.rs`、`dns/transport/{doq,doh3,mod}.rs`）
  - 发现 1 个 Layer 1 系统性问题：生产代码广泛使用 `super::` 相对路径（如 `router/*`、`dns/*` 多模块）
  - 发现 1 个 Layer 2 系统性问题：存在大量 `let _ = ...` / `.ok()` / `.set(...)` 静默丢弃结果（如 `log/mod.rs`、`inbound/socks5.rs`、`dns/mod.rs`、`dns/transport/*`）
  - 发现 1 个 Layer 2 系统性问题：多条协议/控制面解析路径依赖直接下标访问（如 `router/sniff.rs`、`socks5/mod.rs`、`inbound/socks5.rs`、`admin/http.rs`、`dns/transport/{local,resolved}.rs`）
  - 发现 1 个 Layer 2 风格问题：仍有生产代码通配符导入与不惯用借用签名（如 `router/normalize.rs` 的 `use Kind::*;`，`router/engine.rs` 的 `&String`，`router/dsl_plus.rs` 的 `Option<&PathBuf>`）

### T13 `sb-subscribe`（2026-03-22）

- 范围：`crates/sb-subscribe/src/*`
- 结论：完成 Layer 1 / 2 静态审议
- 结果摘要：
  - 未见生产代码 `unwrap()` / `expect()` / `panic!()` / `todo!()` / `unimplemented!()` / `unreachable!()`
  - 未见全局可变状态、`super::` 相对路径滥用、调试输出、结果静默丢弃、直接下标访问、`&String` / `&Vec<_>` / `&PathBuf` 参数签名
  - `providers.rs` 的 `pub use providers::*` 视为 feature-gated facade 式再导出，本轮未计为问题
  - `convert_full.rs` / `lint.rs` 中的 `let _ = ...` 仅用于禁用分支或未用值消警，不属于结果静默丢弃

### T14 `sb-api`（2026-03-22）

- 范围：`crates/sb-api/src/*`
- 结论：完成 Layer 1 / 2 静态审议
- 结果摘要：
  - 发现 1 个 Layer 1 问题：`managers.rs` 的 `DnsResolver::new()` 使用 `expect()` 构造硬编码 DNS 服务器地址
  - 发现 1 个 Layer 2 系统性问题：`monitoring/reporter.rs`、`v2ray/services.rs` 等多处 broadcast `send` 结果被静默丢弃
  - 发现 1 个 Layer 2 系统性问题：`clash/websocket.rs` 多处 WebSocket `send(...).await` 结果被静默丢弃
  - 发现 1 个 Layer 1 风格问题：`clash/server.rs` 仍有生产代码 `super::auth::...` 相对路径
  - 发现 1 个 Layer 2 风格问题：`clash/handlers.rs` 的 `normalize_provider_detail(value: Option<&String>)` 使用不惯用借用签名

### T15 `sb-adapters`（2026-03-22）

- 范围：`crates/sb-adapters/src/*`
- 结论：完成 Layer 1 / 2 静态审议
- 结果摘要：
  - 发现 1 个 Layer 1 系统性问题：存在全局可变状态（如 `inbound/http.rs` 的 `OnceLock` 标志位，`inbound/tun/mod.rs` 的全局原子计数器）
  - 发现 1 个 Layer 1 系统性问题：生产代码存在 `unwrap()` / `expect()`（如 `outbound/tailscale.rs`、`inbound/socks/mod.rs`、`service/resolve1.rs`）
  - 发现 1 个 Layer 1 系统性问题：生产代码仍有 `super::` 相对路径（如 `outbound/hysteria.rs`、`outbound/tuic.rs`、`inbound/trojan.rs`）
  - 发现 1 个 Layer 2 系统性问题：存在大量 `let _ = ...` 静默丢弃结果（如 `register.rs`、`service/resolved_impl.rs`、`inbound/socks/udp.rs`、`inbound/tun/platform/*`）
  - 发现 1 个 Layer 2 系统性问题：多条协议/报文解析路径依赖直接下标访问（如 `inbound/socks/udp.rs`、`outbound/trojan.rs`、`outbound/tuic.rs`、`service/resolve1.rs`、`inbound/tun_macos.rs`）
  - 发现 1 个 Layer 2 系统性问题：生产代码存在通配符导入（如 `outbound/hysteria.rs` 等多处 `use crate::outbound::prelude::*;`）
  - 发现 1 个 Layer 2 风格问题：仍有不惯用借用签名（如 `register.rs` 的 `Option<&String>`）

### T16 `sb-test-utils`（2026-03-22）

- 范围：`crates/sb-test-utils/src/*`
- 结论：完成 Layer 1 / 2 静态审议
- 结果摘要：
  - 本 crate 为测试辅助 crate，本轮按“非生产主路径”口径收尾审议
  - 未见需要单列的 Layer 1 / 2 问题；命中的 `unwrap()` / `panic!()` / `println!` / `eprintln!` 主要位于文档示例、测试代码或显式跳过辅助
  - `socks5.rs` 中少量 `let _ = udp.send_to(...).await` 与直接下标访问服务于 mock server / test harness，本轮未上升为生产路径问题
