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

- 全仓库 Layer 1 / 2 maintenance 收尾已完成最终复核：`git status` 仍为干净工作树，`git log --oneline -5` 确认当前 HEAD 为 `1912050f`（docs-only），其后是 `3142a9aa`、`eb56fd19`
- 本轮再次复跑的关键 maintenance 验证均为绿色：
  - `cargo check --workspace`
  - `cargo clippy --workspace --all-features --all-targets -- -D warnings`
  - `cargo test -p app --lib --features "admin_debug sbcore_rules_tool dev-cli"`
  - `bash scripts/ci/accept.sh`
- 重新生成的 `target/acceptance.json` 与上一轮结论一致：`pprof` / `explain snapshot` / `quick soak` 通过；`inbound_errors` 仍为结构化 `ok=false`
- 已单独复跑 `bash scripts/ci/tasks/inbound-errors.sh` 并做手工探针复核：
  - 现象仍为 `reason=runtime-exited-before-metrics`
  - 手工探针显示 runtime 启动后很快进入 graceful shutdown，`/metrics` 抓取为空
  - 当前更接近 runtime/脚本假设失配的 maintenance follow-up，收益低且不确定性高，不在本轮强行扩改
- 当前环境仍未设置 `GO_SINGBOX_BIN`，因此 `bash scripts/e2e/run.sh` compat smoke 本轮继续按 maintenance validation 记为 skipped
- repo-wide 最终静态审计未发现新的 Layer 1 / Layer 2 回归；剩余 `OnceLock` / 静态 registry 等项维持既有 follow-up 口径，不上升为本轮 blocker，更不表述为 dual-kernel parity 完成

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
