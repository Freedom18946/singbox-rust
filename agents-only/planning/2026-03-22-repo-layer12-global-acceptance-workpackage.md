<!-- tier: S -->
# 全仓库 Layer 1/2 全局验收工作包（维护模式）

> **日期**：2026-03-22
> **范围**：全仓库（重点：`app/`、`crates/`、`labs/interop-lab/src`、`xtask/`、`xtests/`、`benches/`）
> **依据**：`AGENTS.md`、`agents-only/active_context.md`、`agents-only/Rust_spec_v2.md`
> **目标**：把 Layer 1 / Layer 2 要求扩散到全仓库剩余区域，并完成 maintenance acceptance / integration validation。

---

## 本轮约束

- 仓库处于 **maintenance mode**。
- 仅以 **Layer 1 / Layer 2** 为验收口径，不扩展为 parity 完成声明。
- 不恢复 GitHub Actions / `.github/workflows/*`。
- 不把普通构建、repo 级测试、acceptance 脚本或 interop smoke 表述为 dual-kernel parity 完成。
- 不回退用户未明确要求回退的现有工作树改动。

---

## 目录分层

### 第一层：必须清零 blocker

- `app/`
- `crates/`
- `labs/interop-lab/src`

### 第二层：机械收口并要求通过 `clippy -D warnings`

- `xtask/`
- `xtests/`
- `benches/`

### 第三层：仅核对例外，不当作生产 blocker

- `**/tests/**`
- `#[cfg(test)]` 测试模块
- 文档示例、bench 驱动中的测试式 `unwrap/expect`

---

## 执行进展（2026-03-22）

- 已建立全仓库静态审计基线，并按 `Layer 1 / Layer 2` 对 `app crates labs/interop-lab/src xtask xtests benches/src` 做了 repo-wide 扫描与分类。
- workspace 首批 blocker 已清零：
  - `sb-metrics`：补齐 `# Errors` 文档、`#[must_use]`、移除无必要 `async`，并修正 exporter / handler 调用面
  - `labs/interop-lab`：补齐 `conn_tracker` 显式注入链，修正 `upstream.rs` / `kernel.rs` / `orchestrator.rs` / `go_collector.rs` / `gui_replay.rs` / `main.rs` 的静默失败与 cleanup 路径
  - `xtask` / `xtests` / `benches`：收口一批 `let _ = ...` / `.ok()` / tracing init / 文件写入噪音
  - `app/tests`：补齐大量与主实现演进脱节的 `conn_tracker` / `AdminDebugState` / feature alias 兼容尾项，使全仓 `check-cfg` 与 `clippy` 可跑透
- workspace 验收硬门槛已恢复为全绿：
  - `cargo check --workspace` ✅
  - `cargo clippy --workspace --all-features --all-targets -- -D warnings` ✅
- 定向维护回归已完成：
  - `cargo test -p app --lib --features "admin_debug sbcore_rules_tool dev-cli"` ✅
  - `cargo test -p sb-api --test connections_snapshot_test --test clash_websocket_e2e` ✅
  - `cargo test -p sb-core --lib` ✅
  - `cargo test -p sb-subscribe --all-features --lib` ✅
  - `cargo check -p interop-lab` ✅
- 本地 maintenance acceptance 已执行完毕：`bash scripts/ci/accept.sh` ✅
  - `pprof`、`explain snapshot`、`quick soak` 通过
  - `inbound_errors` 子任务已完成 maintenance harness 收口，不再因固定 UDP 端口假设与主 acceptance runtime 端口串台导致假阴性
  - 当前脚本改为先经 TCP `UDP ASSOCIATE` 学习真实 relay，再向返回的随机 UDP 端口注入坏包；同时用隔离的 `127.0.0.1:11081` 避开主 acceptance runtime 的 `127.0.0.1:11080`
- 当前环境未设置 `GO_SINGBOX_BIN`，因此 `scripts/e2e/run.sh` 的 Go/Rust compat 子集本轮未执行，按计划记为 skipped
- 收尾复核已补跑：
  - `git status` 仍为 clean，`git log --oneline -5` 确认当前 HEAD 为 `1912050f`
  - `cargo check --workspace`、`cargo clippy --workspace --all-features --all-targets -- -D warnings`、`cargo test -p app --lib --features "admin_debug sbcore_rules_tool dev-cli"` 均再次通过
  - `bash scripts/ci/tasks/inbound-errors.sh` 单独复跑已稳定返回 `ok=true`
  - 手工探针确认 `run` 在 supervisor/registry 路径下监听 `11081/tcp` + 随机 UDP relay；注入前 `inbound_error_total{protocol="socks_udp"}` 不存在，注入后出现 `class="other"` 的 unified metric 行

## 追加收口（2026-03-23，生产路径严格口径）

- 在不改变 CLI/JSON/stdout 合约、metrics 名称、admin API 合约和 oracle ignore 口径的前提下，继续对生产路径做 Layer 1 / Layer 2 机械收口。
- 本轮新增完成：
  - `app/src/logging.rs`、`app/src/hardening.rs`、`labs/interop-lab/src/{upstream,gui_replay,kernel,orchestrator}.rs`
    - 生产态内部 `eprintln!` / best-effort 静默失败改为 `tracing::{debug,info,warn,error}` 或内部 stderr helper
  - `app/src/admin_debug/security_async.rs`
    - 移除全局 `OnceCell` resolver，改成显式 `build_resolver()`
    - 清理生产态 `super::`
  - `crates/sb-config/src/validator/v2.rs`
    - 纯查表 `OnceLock<HashSet<_>>` 缓存改成普通局部构造
  - `crates/sb-common/src/conntrack.rs`
    - `shared_tracker()` 不再依赖进程级 singleton；`GLOBAL_TRACKER` 仅保留在 `#[cfg(test)]`
  - `crates/sb-core/src/router/engine.rs`
  - `crates/sb-core/src/dns/config_builder.rs`
  - `crates/sb-adapters/src/inbound/tun/mod.rs`
    - 非测试 `super::` 改为稳定 `crate::...` 路径
  - `crates/sb-core/src/http_client.rs`、`app/src/runtime_deps.rs`、`app/src/run_engine.rs`
    - `sb-core` 默认 HTTP client 从全局强持有 owner 收口为弱引用兼容注册表
    - 显式 owner 上提到 `AppRuntimeDeps`
    - `run_engine` 不再重复安装全局强持有 owner
  - `app/src/main.rs`、`app/src/runtime_deps.rs`
    - logging 初始化改为只构造 `Redactor`，不再为了 startup redactor 临时构造整包 `AppRuntimeDeps`
    - 默认 `http_client` / `security_metrics` owner 只在真正 runtime 持有路径上安装，避免弱注册表在启动早期出现瞬时 install-then-drop 抖动
  - `app/src/logging.rs`、`app/src/main.rs`
    - `main` 启动路径改为显式持有 `LoggingOwner`
    - `ACTIVE_RUNTIME` 收窄为 `init_logging()` / `flush_logs()` 的兼容包装层，不再是生产启动路径的首选 owner
  - `crates/sb-core/src/router/engine.rs`、`crates/sb-core/src/router/explain_util.rs`
    - router 主决策链里的 legacy GeoIP fallback 改为优先走 `RouterHandle` 已持有的 `geoip_mux` / `geoip` / `geoip_db`
    - `crate::geoip` 全局服务不再是这些主路径的直接依赖；剩余全局注册点收窄到兼容工具面
  - `crates/sb-core/src/geoip/mod.rs`
    - 旧的强全局安装路径继续保留兼容
    - 新增默认弱 owner 注册表；内部 lookup 先走显式 owner，再 fallback 到旧全局安装路径
  - `app/src/admin_debug/security_async.rs`、`app/src/admin_debug/prefetch.rs`、`app/src/admin_debug/breaker.rs`、`app/src/admin_debug/endpoints/subs.rs`
    - subscription fetch / prefetch / breaker / async DNS 主链补齐显式 `SecurityMetricsState` owner 入口
    - `PrefetchJob` 可携带 runtime metrics owner，`fetch_with_limits_to_cache(...)` 新增 owner-aware 入口并沿调用链透传
    - `security_metrics.rs` 的默认 `Weak` 注册表继续保留为兼容包装层，但不再是这些主路径的首选 owner 来源
  - `app/Cargo.toml`
    - 补齐 `sbcore_analyze_json = ["sb-core/analyze_json"]`
    - 补齐 `transport_ech = ["sb-adapters/transport_ech", "sb-transport/transport_ech"]`
  - `labs/interop-lab/Cargo.toml`
    - 补入 `tracing` 依赖以承接内部诊断日志迁移
- 追加验证已通过：
  - `cargo check --workspace` ✅
  - `cargo clippy --workspace --all-features --all-targets -- -D warnings` ✅
  - `cargo test -p sb-core --lib` ✅
  - `cargo test -p sb-core --lib http_client -- --nocapture` ✅
  - `cargo check -p app` ✅
  - `cargo clippy -p app --all-features --all-targets -- -D warnings` ✅
  - `cargo test -p app --lib runtime_deps --features "admin_debug sbcore_rules_tool dev-cli" -- --nocapture` ✅
  - `cargo test -p app explicit_owner_does_not_install_compat_registry --features "admin_debug sbcore_rules_tool dev-cli" -- --nocapture` ✅
  - `cargo test -p sb-core --lib weak_default_registry_uses_explicit_owner -- --nocapture` ✅
  - `cargo test -p sb-core --lib enhanced_geoip_lookup_uses_router_local_provider_without_global_service --features geoip_mmdb -- --nocapture` ✅
  - `cargo clippy -p sb-core --features geoip_mmdb --all-targets -- -D warnings` ✅
  - `cargo test -p sb-metrics --lib explicit_owner_registry_lifecycle_controls_shared_handle -- --nocapture` ✅
  - `cargo test -p sb-metrics --lib shared_handle_keeps_global_metrics_visible_after_owner_install -- --nocapture` ✅
  - `cargo clippy -p sb-metrics --all-features --all-targets -- -D warnings` ✅
  - `cargo test -p app --lib explicit_metrics_owner --features "admin_debug sbcore_rules_tool dev-cli admin_tests" -- --nocapture` ✅
  - `cargo test -p app --lib runtime_deps --features "admin_debug sbcore_rules_tool dev-cli" -- --nocapture` ✅
  - `cargo check -p app` ✅
  - `cargo test -p app --lib --features "admin_debug sbcore_rules_tool dev-cli"` ✅
  - `bash scripts/ci/tasks/inbound-errors.sh` ✅
  - `bash scripts/ci/accept.sh` ✅
- 追加静态审计结论：
  - 点名高风险文件里的生产态 `super::` 已收口到测试域外零命中
  - 本轮未强行继续下探的剩余全局状态，主要落在 `app/src/logging.rs`、`app/src/admin_debug/security_metrics.rs`、`crates/sb-core/src/geoip/mod.rs` 以及 `crates/sb-metrics` 内部静态指标定义层
  - `app/src/admin_debug/security_metrics.rs` / `app/src/logging.rs` 的默认全局 owner 已收敛为 `Weak` 注册表；其中 subs/prefetch/breaker/security_async 主链与 `main` logging 启动路径都已优先改走显式 owner
  - `crates/sb-core/src/geoip/mod.rs` 的全局服务仍保留为兼容壳，但现已收敛为“弱默认 owner 优先、强全局 fallback”；`router/engine.rs` / `router/explain_util.rs` 主路径继续优先改走 `RouterHandle` 自有 geo owner
  - `crates/sb-metrics/src/lib.rs` 的 shared registry owner 已收敛为 `AppRuntimeDeps` 显式持有；`shared_registry()` 现保留“弱默认 owner 优先、强全局 fallback，并合并 owner 安装前旧全局指标”的兼容入口
  - 这些保留项当前记为 maintenance follow-up，不把本轮结果表述成 dual-kernel parity 完成

---

## 发现归类（当前）

| 类别 | 状态 | 说明 |
|------|------|------|
| `must-fix` | 已清零 | workspace `clippy -D warnings` 暴露的真实 blocker 已完成收口 |
| `allowed-test-only` | 已识别 | `#[cfg(test)]` / bench 驱动内部的 `unwrap/expect/panic`，不当作生产 blocker |
| `allowed-cli-boundary` | 少量 | 顶层工具初始化失败、CLI 致命退出边界上的显式 panic/expect |
| `follow-up-nonblocking` | 已归档 | `sb-metrics` 内部剩余 `LazyLock` 指标静态、少量兼容弱默认注册表包装层、以及若干解析辅助中的 `.ok()?` 风格债 |

---

## 当前验证面

- `cargo check -p sb-metrics` ✅
- `cargo clippy -p sb-metrics --all-features --all-targets -- -D warnings` ✅
- `cargo check -p interop-lab` ✅
- `cargo check --workspace` ✅
- `cargo clippy --workspace --all-features --all-targets -- -D warnings` ✅
- `cargo test -p app --lib --features "admin_debug sbcore_rules_tool dev-cli"` ✅
- `cargo test -p sb-api --test connections_snapshot_test --test clash_websocket_e2e` ✅
- `cargo test -p sb-core --lib` ✅
- `cargo test -p sb-subscribe --all-features --lib` ✅
- `bash scripts/ci/accept.sh` ✅
- `bash scripts/ci/tasks/inbound-errors.sh` ✅
- `bash scripts/e2e/run.sh` ⏭️ skipped（`GO_SINGBOX_BIN` 未设置）

---

## 任务状态

| 任务 ID | 内容 | 状态 | 备注 |
|------|------|------|------|
| `R0` | 新建全仓库 Layer 1 / 2 验收工作包 | ✅ DONE | 本文件 |
| `R1` | 建立全仓静态审计与 blocker 清单 | ✅ DONE | 已形成第一轮目录分层与问题分类 |
| `R2` | 清理 workspace 首批 blocker（`sb-metrics` / `interop-lab`） | ✅ DONE | `cargo check --workspace` 已恢复通过 |
| `R3` | 继续清理 `sb-api` / `sb-adapters` / `labs` / `xtask` / `xtests` / `benches` 尾项 | ✅ DONE | 全仓 `clippy -D warnings` 已通过 |
| `R4` | 跑定向测试与 acceptance / e2e 联调 | ✅ DONE | maintenance acceptance 已完成；compat 子集因环境缺 `GO_SINGBOX_BIN` skipped |
| `R5` | 更新 `active_context.md` / `log.md` 并整理提交 | ✅ DONE | 最终收尾结论已归档，保持 maintenance mode 口径 |

---

## 下一步

1. 如后续提供 `GO_SINGBOX_BIN`，补跑 `bash scripts/e2e/run.sh`，并只按 compat smoke / oracle regression confidence 归档，不上升为 parity 完成。
2. 若未来单独开 maintenance follow-up，可再审议：
   - `sb-metrics` 内部 `LazyLock` 指标静态架构是否继续去全局化
   - `app/src/logging.rs` / `app/src/admin_debug/security_metrics.rs` / `crates/sb-core/src/geoip/mod.rs` 的 compat 弱默认注册表是否继续裁薄
3. 当前工作包到此收口：maintenance acceptance / integration validation 已完成，保留 follow-up 不等于 dual-kernel parity 完成。
