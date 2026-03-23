<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: **L25 CLOSED — 生产加固 + 跨平台补全 + 文档完善**
**历史阶段**: L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 当前维护动作（2026-03-23）

- 本轮从“maintenance acceptance 收尾”继续推进到“生产路径 Layer 1 / Layer 2 严格收口”，范围限定为 `app/src`、`crates/*/src`、`labs/interop-lab/src`、`xtask/src`、`xtests/src` 的非测试生产源码；明确排除 `tests/`、`#[cfg(test)]`、`examples/`、`benches/`、`app/src/bin/*`、CLI stdout 边界输出和 `.github/workflows/*`
- 已完成的主收口动作：
  - `app/src/logging.rs`、`app/src/hardening.rs`、`labs/interop-lab/src/{upstream,gui_replay,kernel,orchestrator}.rs`：内部 `eprintln!` / best-effort 静默失败改为结构化 `tracing`，保留 CLI/协议输出边界
  - `app/src/admin_debug/security_async.rs`：移除全局 `OnceCell` resolver，改为显式构造；生产态 `super::` 改为 `crate::...`
  - `crates/sb-config/src/validator/v2.rs`：移除一组纯查表 `OnceLock<HashSet<_>>` 缓存，改为普通构造路径
  - `crates/sb-common/src/conntrack.rs`：去掉生产态 `shared_tracker()` 的进程级 singleton；全局 tracker 只保留在 `#[cfg(test)]`
  - `crates/sb-core/src/router/engine.rs`、`crates/sb-core/src/dns/config_builder.rs`、`crates/sb-adapters/src/inbound/tun/mod.rs`：非测试 `super::` 改写为稳定 `crate::...` 绝对路径
  - `crates/sb-core/src/http_client.rs` + `app/src/runtime_deps.rs`：
    - `sb-core` 的默认 HTTP client owner 已从进程级 `OnceLock<Box<dyn HttpClient>>` 收敛为弱引用兼容注册表
    - 真正 owner 改由 `AppRuntimeDeps` 显式持有；`run_engine` 不再额外安装全局强持有 owner
  - `app/src/main.rs` + `app/src/runtime_deps.rs`：
    - logging 初始化不再为了拿 `redactor` 临时构造整包 `AppRuntimeDeps`
    - 默认 `http_client` / `security_metrics` owner 只在真正会被显式持有的 runtime 路径里安装，避免启动期瞬时注册后立刻 drop 的弱注册表抖动
  - `crates/sb-core/src/router/engine.rs` + `crates/sb-core/src/router/explain_util.rs`：
    - router 主决策链的 legacy GeoIP fallback 不再直连 `crate::geoip` 全局服务
    - `RouterHandle` 现有的 `geoip_mux` / `geoip` / `geoip_db` owner 已成为优先查询路径；`geoip/mod.rs` 的全局注册点被收窄为兼容壳而非主路径依赖
  - `app/src/admin_debug/{security_async,prefetch,breaker,endpoints/subs.rs}`：
    - subscription fetch / prefetch / breaker / async DNS 主链已补齐显式 `SecurityMetricsState` owner 入口
    - `PrefetchJob` 现可携带 runtime metrics owner，`fetch_with_limits_to_cache(...)` 可直接沿调用链传递，不再默认依赖弱注册表记账
    - `security_metrics.rs` 的默认 `Weak` 注册表保留为兼容包装层，但不再是这些主路径的首选 owner 来源
  - `app/Cargo.toml`：补齐 `sbcore_analyze_json`、`transport_ech` 的 feature 透传，恢复 `--all-features --all-targets` 下的依赖一致性
- 本轮关键验证已通过：
  - `cargo check --workspace`
  - `cargo clippy --workspace --all-features --all-targets -- -D warnings`
  - `cargo test -p sb-core --lib`
  - `cargo test -p app --lib --features "admin_debug sbcore_rules_tool dev-cli"`
  - `bash scripts/ci/tasks/inbound-errors.sh`
  - `bash scripts/ci/accept.sh`
  - `cargo test -p sb-core --lib http_client -- --nocapture`
  - `cargo check -p app`
  - `cargo clippy -p app --all-features --all-targets -- -D warnings`
  - `cargo test -p app --lib runtime_deps --features "admin_debug sbcore_rules_tool dev-cli" -- --nocapture`
  - `cargo test -p sb-core --lib enhanced_geoip_lookup_uses_router_local_provider_without_global_service --features geoip_mmdb -- --nocapture`
  - `cargo clippy -p sb-core --features geoip_mmdb --all-targets -- -D warnings`
  - `cargo test -p app --lib explicit_metrics_owner --features "admin_debug sbcore_rules_tool dev-cli admin_tests" -- --nocapture`
- `scripts/e2e/socks5/udp-errors.sh` / `scripts/ci/tasks/inbound-errors.sh` 已完成 maintenance harness 收口：
  - 不再把 malformed UDP datagram 直接打到假定固定端口
  - 改为先经 TCP `UDP ASSOCIATE` 学习真实 relay，再向返回的随机 UDP 端口注入坏包
  - 子任务默认改用隔离的 `127.0.0.1:11081`，避免和 `accept.sh` 主 runtime 的 `127.0.0.1:11080` SOCKS 入口串台
- 最新 `target/acceptance.json` 结论维持 maintenance 口径不变：`pprof` / `explain snapshot` / `quick soak` / `inbound_errors` 全部通过；`inbound_errors.ok=true`
- 当前环境仍未设置 `GO_SINGBOX_BIN`，因此 `bash scripts/e2e/run.sh` compat smoke 继续按 skipped 归档
- 现阶段剩余 follow-up 仍以非阻塞 maintenance 债务记录，不上升为 dual-kernel parity 结论：
  - `app/src/logging.rs`：仍有全局兼容入口，但已降为 `Weak<LoggingRuntime>` 注册表，不再持有额外 runtime owner
  - `app/src/admin_debug/security_metrics.rs`：默认查找入口仍保留为 `Weak<SecurityMetricsState>` 兼容壳，但 subs/prefetch/breaker/security_async 主链已优先走显式 owner
  - `crates/sb-core/src/geoip/mod.rs` 仍保留兼容全局注册点，但主 router 决策链已不再依赖它
  - `crates/sb-metrics` 的共享静态 registry 架构

## L25 完成总结（2026-03-17）

**10/10 任务完成，4 批次全部交付**

| 批次 | 任务 | 状态 |
|------|------|------|
| B1 | T2 VMess fuzz 可见性, T3 WS 测试隔离, T6 TUN 栈评估 | ✅ |
| B2 | T4 消除 transmute+Box::leak, T5 sb-adapters 集成测试 | ✅ |
| B3 | T1 TUN UDP Linux/Windows, T7 Provider 热更新 | ✅ |
| B4 | T8 跨平台发布, T9 用户文档, T10 CI 增强 | ✅ |

### 关键交付物

- **T1**: Linux/Windows TUN UDP 转发实现（`parse_raw_udp` + `LinuxTunWriter` + `WintunTunWriter`）
- **T2**: VMess/HTTP/Naive parsers 暴露为 `pub`，fuzz target 直接调用真实解析器
- **T3**: `serial_test` 注解消除 WS e2e 全局 tracker race
- **T4**: `Engine<'a>` → `Engine` (Arc<ConfigIR>)，移除 1 transmute + 5 Box::leak + 1 unsafe ptr
- **T5**: sb-adapters 集成测试 1 → 144 non-ignored
- **T6**: TUN 栈评估文档 → `agents-only/planning/L25-tun-stack-eval.md`
- **T7**: Provider 热更新管线：增强 HTTP fetcher + 内容解析 + `ReloadMsg::UpdateProviders`
- **T8**: ARM Windows target + Helm chart + SBOM (cargo-auditable) + smoke test
- **T9**: schema-migration.md (398 行) + config-reference.md (891 行) + faq.md (291 行)
- **T10**: fuzz-nightly.yml + coverage.yml + bench-regression 增强

## 构建基线（2026-03-17，L25 后）

| 构建 | 状态 |
|------|------|
| `cargo clippy --workspace --all-features --all-targets -- -D warnings` | ✅ pass |
| `cargo test -p sb-core --lib` | ✅ 509 passed |
| `cargo test -p sb-api` | ✅ pass |
| `cargo test -p sb-subscribe --all-features --lib` | ✅ 16 passed |

## 已知 PARTIAL 项：全部解决

1. ~~L23-T1 TUN UDP~~ → ✅ T1 实现 Linux/Windows UDP 转发
2. ~~T1-04 Protocol fuzz~~ → ✅ T2 暴露 VMess 真实解析器
