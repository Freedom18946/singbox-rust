<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: **L25 CLOSED — 生产加固 + 跨平台补全 + 文档完善**
**历史阶段**: L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 当前维护动作（2026-03-22）

- `crates/` Layer 1 / 2 修复工作包已进入执行态：`Batch A` 与 `Batch B` 已完成大部分已审议热点收口，`Batch C` 中 `conntrack/context` 生产 wiring 已显式注入化
- 生产代码里 `shared_tracker()` / `global_tracker()` / `context_registry()` / `install_context_registry()` 读链已清零；剩余单例尾项主要集中在 `sb-metrics` 内部 `REGISTRY + LazyLock` 架构与 `Batch D` 机械性 sweep
- `app/` Layer 1 / 2 首轮热点已进入执行并完成主修：`AppRuntimeDeps` / `AdminDebugState` 已接入，`tracing_init` / `tls_provider` / `redact` / `analyze::registry` / `admin_debug::security_metrics` / `inbound_starter` 已按显式注入 + failure surfacing 收口
- `app/src/logging.rs` 第二波尾项也已继续收口：分散 `OnceLock` 已压缩为单一 runtime 兼容壳，signal/panic/shutdown 的静默 best-effort 已改为具名处理
- 已通过 `cargo check -p app`、`cargo check -p app --features "admin_debug sbcore_rules_tool dev-cli"`、`cargo test -p app --lib --features "admin_debug sbcore_rules_tool dev-cli"`、`cargo test -p sb-api --test connections_snapshot_test --test clash_websocket_e2e`
- 当前 `app` 维护剩余尾项主要是 `security_metrics` / `logging` 兼容壳是否继续完全去全局化，以及其他低风险 Layer 1/2 机械 sweep
- 带 `adapters` 的 `app` 编译面暂被工作树内 `sb-adapters` 的未完成 `conn_tracker` 字段补线阻塞；不回退用户未明确要求回退的现有改动
- 下一步继续只按 Layer 1 / 2 维护：保留 `crates/` 尾项收口，同时按 `app` 工作包做第二波尾项 sweep；不恢复 GitHub Actions，也不把普通测试完成表述为 dual-kernel parity 完成

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
