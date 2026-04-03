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

### 当前维护线（2026-04-03）

- **MT-ADM-01**: admin_debug compat surface close-out — 已完成
  - 当前源码事实下，这条线处理的是 `admin_debug` control-plane 中仍真实存在的 cache / breaker / reloadable / subs compat/query/read-path seam，不是 parity completion
  - 本轮收口：
    - `app/src/admin_debug/cache.rs`：`CacheStore` 新增 owner-first `entry()` / `store()` / `note_head_request()`
    - `app/src/admin_debug/breaker.rs`：`BreakerStore` 新增 owner-first `allows()` / `record_success()` / `record_failure()`
    - `app/src/admin_debug/reloadable.rs`：`ReloadableConfigStore` 显式拥有 `apply()` / `apply_with_dryrun()`；legacy free helper 退成 compat shell
    - `app/src/admin_debug/endpoints/subs.rs`：新增 `SubsControlPlane`，`fetch_with_limits*` / `fetch_with_limits_to_cache*` 的 compat 面集中到 `SubsControlPlane::compat()`
    - `app/src/admin_debug/mod.rs` / `app/src/admin_debug/endpoints/config.rs` / `app/src/admin_debug/http_server.rs`：`__config` GET/PUT 改走 `AdminDebugState` owner-first reloadable query/apply seam
    - `app/src/admin_debug/security_metrics.rs`：测试 reset path 改走 cache/breaker owner helper，不再摸 compat/global 锁
  - 本卡明确是 maintenance / admin-control-plane quality work，不是 dual-kernel parity completion；也没有推进 `planned.rs`、public `RuntimePlan`、public `PlannedConfigIR`、generic query API
  - 验收通过：`cargo test -p app --all-features --lib -- --test-threads=1`、`cargo test -p app --all-features --test admin_auth_contract -- --test-threads=1`、`cargo test -p app --all-features --test e2e_subs_security -- --test-threads=1`、`cargo clippy -p app --all-features --all-targets -- -D warnings`

- **MT-MLOG-01**: metrics / logging compat-global cleanup — 已完成
- **MT-ADP-01**: sb-adapters test baseline stabilization — 已完成
- **MT-PERF-01**: tun / outbound hotspot stabilization — 已完成
- **MT-RD-01**: router / dns structural consolidation — 已完成
- **MT-TEST-01**: patch-plan / test baseline stabilization — 已完成
- **MT-SVC-01**: DERP / services baseline stabilization — 已完成
- **MT-HOT-OBS-01**: hotpath stabilization + metrics/logging consolidation — 已完成

### 已完成维护归档（2026-04-03）

- **MT-RTC-03**: runtime actorization close-out — 已完成
- **MT-RTC-02**: runtime actorization follow-up — 已完成
- **MT-RTC-01**: runtime actor/context consolidation — 已完成
- **MT-OBS-01**: runtime / control-plane / observability ownership consolidation — 已完成
- **WP-30at**: `WP-30k` ~ `WP-30as` maintenance line 总体验收 / 归档收口 — 已完成

### 当前维护重点（高层）

- `admin_debug` 这条线当前更合适的表达已经是少数高层 future boundary，而不是继续把 compat/read-path 尾巴拆成很多小卡：
  - `security_metrics` 默认 owner / compat wrapper
  - `subs` limiter static state (`MAX_CONC` / `RPS_*`)
  - 更大范围的 admin-control-plane manager/query/lifecycle 统一化
- 配置高层 future boundary 保持不变：不恢复 `WP-30k` 式拆卡，不误推进 public `RuntimePlan` / `PlannedConfigIR`

### 构建基线（2026-04-03）

| 构建 | 状态 |
|------|------|
| `cargo test -p app --all-features --lib -- --test-threads=1` | ✅ pass (`MT-ADM-01`) |
| `cargo test -p app --all-features --test admin_auth_contract -- --test-threads=1` | ✅ pass (`MT-ADM-01`) |
| `cargo test -p app --all-features --test e2e_subs_security -- --test-threads=1` | ✅ pass (`MT-ADM-01`) |
| `cargo clippy -p app --all-features --all-targets -- -D warnings` | ✅ pass (`MT-ADM-01`) |
