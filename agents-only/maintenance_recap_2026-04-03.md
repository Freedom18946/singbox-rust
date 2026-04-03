# MT-RECAP-01 maintenance recap and next-stage convergence

## 定位

- 新线名称：`MT-RECAP-01`
- 主题：maintenance recap and next-stage convergence
- 性质：maintenance / planning-quality work
- 目标：基于当前仓库事实复盘已完成 maintenance 线，收束“下一阶段是否还值得继续拆卡”的结论
- 非目标：dual-kernel parity completion、恢复 `.github/workflows/*`、重开 `WP-30k` 式细碎 maintenance 排程、误推进 public `RuntimePlan` / public `PlannedConfigIR` / generic query API

## 本卡使用的当前仓库事实

### 文档重建

- 已重新阅读：
  - `AGENTS.md`
  - `agents-only/{active_context,workpackage_latest,planned_preflight_inventory}.md`
  - `agents-only/{mt_obs_01,mt_rtc_01,mt_rtc_02,mt_rtc_03,mt_hot_obs_01,mt_svc_01,mt_test_01,mt_rd_01,mt_perf_01,mt_adp_01,mt_mlog_01,mt_adm_01,mt_deep_01}_inventory.md`
  - `重构package相关/2026-03-25_5.4pro第三次审计核验记录.md`
  - `重构package相关/singbox_rust_rebuild_workpackage.md`

### Git / 工作区事实

- `git status --short --branch`：当前在 `main...origin/main`，workspace 仍有大量无关在制改动；本卡不回滚、不覆盖这些改动
- `git diff --stat`：脏改动覆盖 `app`、`sb-config`、`sb-core`、`sb-adapters` 等多处，其中包含本卡明确不能误推进的：
  - `app/src/admin_debug/middleware/rate_limit.rs`
  - `app/src/admin_debug/prefetch.rs`
  - `crates/sb-config/src/ir/planned.rs`
- `git log --oneline --decorate -n 20`：最近主线提交从 `748edee7` 到 `a7eb1e4e` 连续覆盖 `MT-OBS-01` 到 `MT-DEEP-01`，`WP-30` 归档提交为 `ef333bb7`

### 源码抽样复核

- `crates/sb-config/src/ir/planned.rs`
  - 仍明确写为 staged crate-private seam
  - `collect_planned_facts` / `validate_with_planned_facts` / `validate_planned_facts` 仍为 `pub(crate)`
  - `Config::validate()` 继续走 thin entry
  - 当前仍无 public `RuntimePlan`、public `PlannedConfigIR`
- `app/src/run_engine_runtime/context.rs` + `app/src/admin_debug/mod.rs`
  - `RuntimeContext` / `RuntimeLifecycle` / `AdminDebugState` 继续承担 owner-first runtime/admin wiring
  - runtime actor/context 主线已 close-out，不再是“继续拆 helper seam”的阶段
- `crates/sb-core/src/router/{shared_index,runtime_override}.rs` + `crates/sb-core/src/dns/upstream_pool.rs`
  - shared-state / helper owner 已抽离，但 router/dns mega-file bulk 仍在
  - 这更像高层 structural boundary，不是新的最前置 blocker
- `crates/sb-adapters/src/outbound/shadowtls.rs` + `crates/sb-adapters/src/inbound/{tun_session,tun_enhanced}.rs`
  - ShadowTLS wrapper raw-stream 语义、`OwnedBridgeStream` owner、TUN detached/draining session seam 均按现口径存在
  - 这类债务已收成高层 contract / lifecycle boundary，不应再拆单点 protocol-corner 卡

## 最小充分验证

### 通过的命令

- `cargo test -p app --all-features --lib -- --test-threads=1`
- `cargo test -p sb-core --all-features --lib -- --test-threads=1`
- `cargo test -p sb-adapters --all-features --lib -- --test-threads=1`
- `cargo clippy -p app --all-features --all-targets -- -D warnings`
- `cargo clippy -p sb-core --all-features --all-targets -- -D warnings`
- `cargo clippy -p sb-adapters --all-features --all-targets -- -D warnings`

### 验证结论

- 当前仓库并不存在“文档口径已收口，但 app / sb-core / sb-adapters 基线已明显失效”的反证
- 复盘结论可以建立在当前源码与最小充分验证之上，而不是停留在历史文档

## 维护线重新分类

| 线 | 分类 | 以当前仓库事实为准的结论 |
| --- | --- | --- |
| `WP-30` archive baseline / planned seam baseline | archive-safe close-out | `planned.rs` 当前稳定停在 crate-private seam；后续不再按 `WP-30k` 微卡继续排程 |
| `MT-SVC-01` | archive-safe close-out | DERP/services baseline 已达到维护期可接受状态；未来若再出信号，也应并入更高层主题 |
| `MT-TEST-01` | archive-safe close-out | patch-plan blocker 已消除；当前无理由继续维持独立 test-baseline 线 |
| `MT-ADP-01` | archive-safe close-out | adapter baseline failures 已清零；后续 ShadowTLS/TUN 债务已迁移为更高层 protocol/lifecycle boundary |
| `MT-OBS-01` | close-out but future boundary remains | control-plane / observability owner/query 收口完成，但仍有少量 compat/default shell |
| `MT-RTC-01` | close-out but future boundary remains | runtime owner/context seam 已立住；未来只剩更高层 manager/conductor boundary |
| `MT-RTC-02` | close-out but future boundary remains | admin/watch/bootstrap carrier 已稳定；后续不再按 helper seam 细拆 |
| `MT-RTC-03` | close-out but future boundary remains | runtime actorization 已 close-out；future work 只剩更统一的 signal/reload/shutdown manager |
| `MT-HOT-OBS-01` | close-out but future boundary remains | tun/dns/router/logging/metrics 的第一轮热点治理已完成；剩余是更高层 hotspot / compat boundary |
| `MT-RD-01` | close-out but future boundary remains | router/dns shared-state owner 已抽离；剩余是 mega-file / structural boundary |
| `MT-PERF-01` | close-out but future boundary remains | tun/outbound hotspot 已收一轮；剩余是 queue/backpressure/session cleanup policy |
| `MT-MLOG-01` | close-out but future boundary remains | metrics/logging compat cleanup 已收口；剩余是 exporter lifecycle 与 static metric family 级边界 |
| `MT-ADM-01` | close-out but future boundary remains | admin_debug compat/query seam 已收口；剩余是更高层 control-plane manager/query/lifecycle 统一 |
| `MT-DEEP-01` | close-out but future boundary remains | ShadowTLS / TUN TCP deep corner-case 已收成 contract / lifecycle boundary，不应继续散修 |

### 仍处于 active 状态的旧 maintenance 线

- 无
- 当前没有哪条旧 maintenance 线还应继续维持为“单独 active 卡”
- 未来如果继续，也应把剩余债务 regroup 成少数跨线主题，而不是重开老线的小尾巴

## 当前阶段结论

### 1. 哪些主线已经可以 archive-safe close-out

- `WP-30` archive baseline / planned seam baseline
- `MT-SVC-01`
- `MT-TEST-01`
- `MT-ADP-01`

这些线按当前仓库事实都已达到“继续拆只会制造排程噪音”的状态；后续即使再出问题，也不建议回到原线名继续排小卡。

### 2. 哪些主线 close-out 了，但仍保留清晰 future boundary

- runtime / control-plane / observability 组：
  - `MT-OBS-01`
  - `MT-RTC-01`
  - `MT-RTC-02`
  - `MT-RTC-03`
  - `MT-HOT-OBS-01`
  - `MT-MLOG-01`
  - `MT-ADM-01`
- router / dns structural 组：
  - `MT-RD-01`
- tun / outbound / deep protocol 组：
  - `MT-PERF-01`
  - `MT-DEEP-01`

这些 future boundary 是真的，但已经不适合再以原来的细卡粒度继续排。

### 3. 当前仓库有没有新的最前置 blocker

- 没有
- 现有工作区虽然很脏，但本卡按当前事实做的跨模块测试与 clippy 抽样均通过，没有暴露出新的“必须先处理”的基线阻塞
- 因此当前更合理的结论是“暂停继续扩散”，而不是硬造新的优先级

## 下一阶段路线收束

### 默认建议

- **当前阶段应暂停继续拆新的细卡**
- 已关闭 maintenance 线不再维护成滚动 backlog
- `future boundary` 只保留为高层 gate，不自动变成下一张卡

### 若未来必须继续，只保留 1-3 条高层主题

1. `runtime / control-plane / observability convergence`
   - 合并 runtime actor/context、admin_debug、metrics/logging 的剩余 boundary
   - 只在需要统一 signal/reload/shutdown manager、exporter lifecycle、owner/query surface 时推进
2. `router / dns / tun / outbound convergence`
   - 合并 router/dns structural seam、TUN/outbound hotspot、ShadowTLS/TUN TCP lifecycle boundary
   - 只在出现明确结构收益、perf 证据或重复 corner-case 信号时推进
3. `planned/private seam consumer gate`
   - 这是条件性 gate，不是默认 active 主题
   - 只有在出现真实稳定 consumer 时才评估 exact accessor / private query seam
   - 当前明确不推进 public `RuntimePlan`、public `PlannedConfigIR`、generic query API

## 明确应暂停的主题

- 不再恢复 `WP-30k` ~ `WP-30as` 式细碎 maintenance 排程
- 不再把 `planned.rs` 当成默认继续拆的主线
- 不再继续按 `metrics/logging/admin_debug` 的 compat 小尾巴开散修卡
- 不再把 ShadowTLS / TUN corner case 继续拆成单点 protocol-corner 卡
- 不再把 maintenance / quality work 误写成 parity completion

## 本卡的收束结论

- 当前仓库事实支持的结论不是“继续扩散 maintenance backlog”，而是：
  - 多数 maintenance 线已经达到 archive-safe close-out
  - 少数真实剩余项已收缩成跨线高层 boundary
  - 当前没有新的最前置 blocker
  - 下一阶段若继续，只应围绕极少数 convergence 主题成组推进

换句话说，**这轮 maintenance 的正确后续动作是收束，不是再拆卡。**
