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

### 当前维护线（2026-04-02）

- **MT-RD-01**: router / dns structural consolidation — 已完成
  - 当前源码事实下，最值得优先治理的结构债是：
    - `crates/sb-core/src/router/mod.rs` 内部 shared index owner / ENV cache / hot reload / runtime override query seam 仍混在一起
    - `crates/sb-core/src/dns/upstream.rs` 内部 DHCP / resolved 的 file-backed upstream pool、watcher、reload、fallback、metrics helper 重复堆叠
  - 本轮收口：
    - 新增 `crates/sb-core/src/router/shared_index.rs`，收走 shared index owner、ENV refresh/cache、reload bootstrap、empty unresolved index helper
    - 新增 `crates/sb-core/src/router/runtime_override.rs`，收走 runtime override parse/cache/query seam
    - `crates/sb-core/src/router/explain_util.rs` 改为复用 runtime override query seam；`crates/sb-core/src/router/engine.rs` 改为复用 empty index helper
    - 新增 `crates/sb-core/src/dns/upstream_pool.rs`，统一 file-backed upstream pool 的 watcher / reload / fallback / round-robin / metrics helper
    - `crates/sb-core/src/dns/upstream.rs` 的 DHCP / resolved 改为显式持有 pool owner，不再重复维护同类 shared state
    - `crates/sb-core/src/dns/config_builder.rs` 只补 specialized helper source pin，不把 builder owner 再往 `upstream.rs` 回灌
  - 本卡明确是 maintenance / structural quality work，不是 dual-kernel parity completion；也没有推进 `planned.rs`、public `RuntimePlan`、public `PlannedConfigIR`、generic query API
  - 验收通过：`cargo test -p sb-core --all-features router::migration_tests -- --test-threads=1`、`cargo test -p sb-core --all-features dns::config_builder::tests -- --test-threads=1`、`cargo test -p sb-core --all-features dns::upstream::tests -- --test-threads=1`、`cargo test -p sb-core --all-features --lib -- --test-threads=1`、`cargo test -p sb-core --all-features --tests -- --test-threads=1`、`cargo clippy -p sb-core --all-features --all-targets -- -D warnings`
  - 当前基线备注：本卡结束后，`router/dns` 剩余债务已压缩成少数高层 future boundary，不再是 shared index / file-backed pool 这一层四散 helper 杂糅

- **MT-TEST-01**: patch-plan / test baseline stabilization — 已完成
  - patch 生成与 patch 应用语义不一致的真实根因已修复，当前继续保持稳定

- **MT-SVC-01**: DERP / services baseline stabilization — 已完成
  - mesh lifecycle / task ownership / TLS baseline 收口继续保持稳定

- **MT-HOT-OBS-01**: hotpath stabilization + metrics/logging consolidation — 已完成
  - tun/dns/router/outbound optimizations 与 logging/sb-metrics owner-first 收口继续保持稳定

### 已完成维护归档（2026-04-02）

- **MT-RTC-03**: runtime actorization close-out — 已完成
- **MT-RTC-02**: runtime actorization follow-up — 已完成
- **MT-RTC-01**: runtime actor/context consolidation — 已完成
- **MT-OBS-01**: runtime / control-plane / observability ownership consolidation — 已完成
- **WP-30at**: `WP-30k` ~ `WP-30as` maintenance line 总体验收 / 归档收口 — 已完成

### 当前维护重点（高层）

- runtime actor/context 主线当前已达到维护期可接受 close-out；后续不再按散乱 seam 继续细拆
- 当前更合适的维护主题排序：
  - `router/dns` 剩余 mega-file 的高层 boundary
  - `tun/outbound` 生命周期与 perf hotspot
  - metrics/logging 剩余 compat/global 壳
  - patch/preview 或 DERP/services 若再出现真实 baseline failure，再按事实切回处理
- 配置高层 future boundary 保持不变：不恢复 `WP-30k` 式拆卡，不误推进 public `RuntimePlan` / `PlannedConfigIR`

### 构建基线（2026-04-02）

| 构建 | 状态 |
|------|------|
| `cargo test -p sb-core --all-features router::migration_tests -- --test-threads=1` | ✅ pass (`MT-RD-01`) |
| `cargo test -p sb-core --all-features dns::config_builder::tests -- --test-threads=1` | ✅ pass (`MT-RD-01`) |
| `cargo test -p sb-core --all-features dns::upstream::tests -- --test-threads=1` | ✅ pass (`MT-RD-01`) |
| `cargo test -p sb-core --all-features --lib -- --test-threads=1` | ✅ pass (`MT-RD-01`) |
| `cargo test -p sb-core --all-features --tests -- --test-threads=1` | ✅ pass (`MT-RD-01`) |
| `cargo clippy -p sb-core --all-features --all-targets -- -D warnings` | ✅ pass (`MT-RD-01`) |
| `cargo test -p sb-metrics --all-features --lib -- --test-threads=1` | ✅ pass (`MT-HOT-OBS-01`) |
| `cargo test -p app --all-features --lib -- --test-threads=1` | ✅ pass (`MT-HOT-OBS-01`) |
| `cargo clippy -p sb-metrics --all-features --all-targets -- -D warnings` | ✅ pass (`MT-HOT-OBS-01`) |
| `cargo clippy -p app --all-features --all-targets -- -D warnings` | ✅ pass (`MT-HOT-OBS-01`) |
