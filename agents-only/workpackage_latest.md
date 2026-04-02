<!-- tier: S -->
# 工作阶段总览（Workpackage Map）
> **用途**：阶段划分 + 当前位置。S-tier，每次会话必读。
> **纪律**：Phase 关闭后压缩为一行状态。本文件严格 ≤120 行。
> **对比**：本文件管“在哪”；`active_context.md` 管“刚做了什么 / 当前基线”。
---
## 已关闭阶段（一行总结）
| 阶段 | 交付 | 关闭时间 |
|------|------|----------|
| L1-L17 | 架构整固、功能对齐、CI / 发布收口 | 2026-01 ~ 2026-02 |
| MIG-02 / L21 | 隐式回退消除，541 V7 assertions，生产路径零隐式直连回退 | 2026-03-07 |
| L18 Phase 1-4 | 认证替换、证据模型收口、GUI gate 复验、长跑恢复决策门 | 2026-03-11 |
| L22 | dual-kernel parity 52/60 (86.7%)，16 个 both-case，Sniff Phase A+B | 2026-03-15 |
| 后 L22 补丁 | QUIC 多包重组、OverrideDestination、UDP datagram sniff、编译修复 | 2026-03-15 |
| L23 | TUN/Sniff 运行时补全、Provider wiring、T4 Protocol Suite、parity 92.9% | 2026-03-16 |
| L24 | 性能/安全/质量/功能补全，30 任务 (B1-B4)，综合验收 39/41 PASS | 2026-03-17 |
| L25 | 生产加固 + 跨平台补全 + 文档完善，10/10 任务，4 批次全部交付 | 2026-03-17 |

---

## 当前状态：维护模式（L1-L25 全部 Closed）

**全部阶段关闭**。项目处于稳定维护；dual-kernel parity 状态以 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 为准。

### 维护归档（2026-04-02）

- **MT-OBS-01**: runtime / control-plane / observability ownership consolidation — 已完成
  - `app/src/admin_debug/reloadable.rs` 已收成 `ReloadableConfigStore` + `ReloadSignalHandle`；reload signal lifecycle 现在由 `AdminDebugHandle` / `admin_debug::init()` / `run_engine_runtime::admin_start` 显式接线，而不是裸后台 `tokio::spawn`
  - `app/src/admin_debug/cache.rs` / `breaker.rs` 已新增 owner-first store；`app/src/admin_debug/security_metrics.rs` 新增 `snapshot_with_query(SecuritySnapshotQuery)`；`AdminDebugState` / `runtime_deps` 显式持有 breaker/cache/reloadable/security_metrics owner，`health` / `metrics` endpoint 走显式 query path
  - `crates/sb-metrics/src/lib.rs` 已补 `active_registry()` 与 owner-first encode helper；`crates/sb-core/src/metrics/registry_ext.rs` 已把 collector registration / fallback helper 收口，保留当前 compat 语义但减少散落 wrapper / `eprintln!`
  - 本卡性质是 maintenance / quality work，不是 dual-kernel parity completion；也没有推进 `planned.rs`、public `RuntimePlan`、public `PlannedConfigIR` 或更大的 runtime actor/context 化
  - 验收通过：`cargo test -p app --features admin_debug,admin_tests,dev-cli --lib -- --test-threads=1`、`cargo test -p sb-metrics --lib -- --test-threads=1`、`cargo test -p sb-core --features metrics --lib registry_ext::tests -- --test-threads=1`、`cargo clippy -p app --features admin_debug,admin_tests,dev-cli --lib -- -D warnings`、`cargo clippy -p sb-metrics --all-targets -- -D warnings`、`cargo clippy -p sb-core --features metrics --lib --tests -- -D warnings`

- **WP-30at**: `WP-30k` ~ `WP-30as` maintenance line 总体验收 / 归档收口 — 已完成
  - 已按仓库当前事实复核 owner/facade：`ir/mod.rs` / `validator/v2/mod.rs` 为稳定 facade，`planned.rs` 为 staged crate-private seam，`dns_raw.rs` / `dns.rs` 为 DNS Raw/Validated boundary，`run_engine.rs` / `bootstrap.rs` 为 app runtime facade/legacy shell
  - 已确认 `WP-30k` ~ `WP-30as` 的主要 owner 收口都已落在代码，而不只是文档；对应 source pins / 回归测试分布在 `crates/sb-config/src/ir/*.rs`、`crates/sb-config/src/validator/v2/*.rs`、`app/src/*` 与 `app/tests/wp30ap_baseline_gates.rs`
  - 强制基线通过：`cargo test -p sb-config --lib`、`cargo clippy -p sb-config --all-features --all-targets -- -D warnings`、`cargo test -p app --lib`、`cargo test -p app`、`cargo clippy -p app --all-features --all-targets -- -D warnings`
  - 文档已压缩归档：`active_context.md`、`workpackage_latest.md`、`planned_preflight_inventory.md` 与审计 / rebuild 文档均改成 archive-safe 口径，不再保留“下一卡继续拆 facade / 既有 app baseline 失败”之类过期叙述

### WP-30 Maintenance Archive（compressed）

- `WP-30k` ~ `WP-30as`：`planned.rs` fact graph、`normalize/minimize` compat seam、`validator-v2` facade/helpers、`ir` shared compat seam、app runtime seam、DNS raw/validated/planned boundary、baseline stabilization 全部已收口并通过回归
- 这条线的性质是 maintenance stabilization / archive，不是 parity completion，也不是 `RuntimePlan` 实现线
- 当前明确未做且继续保留为 future work：public `RuntimePlan`、public `PlannedConfigIR`、generic query API、exact private accessor、更大的 runtime actor/context 化

### 当前维护重点（高层）

- 后续 maintenance work 继续围绕质量/稳定性债务推进：runtime actorization、DNS/router mega-file、TUN 热路径、metrics compat/global 更深层治理
- 若开启新卡，按高层主题立项，不再恢复 `WP-30k` ~ `WP-30as` 式逐卡排程

### 构建基线（2026-04-02）

| 构建 | 状态 |
|------|------|
| `cargo test -p sb-config --lib` | ✅ pass (`WP-30at`) |
| `cargo clippy -p sb-config --all-features --all-targets -- -D warnings` | ✅ pass (`WP-30at`) |
| `cargo test -p app --features admin_debug,admin_tests,dev-cli --lib -- --test-threads=1` | ✅ pass (`MT-OBS-01`) |
| `cargo test -p sb-metrics --lib -- --test-threads=1` | ✅ pass (`MT-OBS-01`) |
| `cargo test -p sb-core --features metrics --lib registry_ext::tests -- --test-threads=1` | ✅ pass (`MT-OBS-01`) |
| `cargo clippy -p app --features admin_debug,admin_tests,dev-cli --lib -- -D warnings` | ✅ pass (`MT-OBS-01`) |
| `cargo clippy -p sb-metrics --all-targets -- -D warnings` | ✅ pass (`MT-OBS-01`) |
| `cargo clippy -p sb-core --features metrics --lib --tests -- -D warnings` | ✅ pass (`MT-OBS-01`) |
