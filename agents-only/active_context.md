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

- 全仓库 Layer 1 / 2 扩散与标准验收已进入收口态：`cargo check --workspace` 与 `cargo clippy --workspace --all-features --all-targets -- -D warnings` 已双绿
- `app/` 与 `crates/` 的主修面已基本完成，`labs/interop-lab` / `xtask` / `xtests` / `benches` 也已完成一轮 repo-wide 机械收口
- 本轮已通过关键维护验证：
  - `cargo check --workspace`
  - `cargo clippy --workspace --all-features --all-targets -- -D warnings`
  - `cargo test -p app --lib --features "admin_debug sbcore_rules_tool dev-cli"`
  - `cargo test -p sb-api --test connections_snapshot_test --test clash_websocket_e2e`
  - `cargo test -p sb-core --lib`
  - `cargo test -p sb-subscribe --all-features --lib`
  - `cargo check -p interop-lab`
- `bash scripts/ci/accept.sh` 已完成并生成 `target/acceptance.json`；`pprof` / `explain snapshot` / `quick soak` 通过
- acceptance 中 `inbound_errors` 仍为 `ok=false`，原因是 `runtime-exited-before-metrics`；已从“整轮失败”降级为结构化 follow-up，不把它包装成 parity 信号
- 当前环境未设置 `GO_SINGBOX_BIN`，因此 `scripts/e2e/run.sh` compat smoke 本轮未跑，按 maintenance validation 记录为 skipped
- 下一步优先整理提交与推送，同时继续保留一个 follow-up：`sb-metrics` 内部静态 registry/LazyLock 架构，以及 acceptance `inbound_errors` 子任务的 runtime 常驻假设

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
