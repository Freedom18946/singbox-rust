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

- **MT-PERF-01**: tun / outbound hotspot stabilization — 已完成
  - 当前源码事实下，最值得优先治理的热点债是：
    - `crates/sb-core/src/inbound/tun.rs` 的 session table 仍存在表锁外再套 per-session lock，热路径 mutation / expiry / stats 更新会反复穿透两层 owner
    - `crates/sb-adapters/src/inbound/tun_session.rs`、`crates/sb-adapters/src/inbound/tun/udp.rs` 的 relay task lifecycle 仍偏隐式，cleanup / eviction 没有稳定的 task owner
    - `crates/sb-core/src/outbound/mod.rs`、`crates/sb-core/src/outbound/optimizations.rs` 的 registry lookup / TTL cache 仍残留分散 query seam、panic / stale-entry 面
  - 本轮收口：
    - `crates/sb-core/src/inbound/tun.rs` 把 session table 收成 `Arc<TunSession>` 单 owner 模式；热字段 mutation 改走 session helper，而不是整 session 再套 `RwLock`
    - `crates/sb-adapters/src/inbound/tun_session.rs` 让 `TcpSession` 显式拥有 relay task；`remove()` / `initiate_close()` 会 abort owned tasks
    - `crates/sb-adapters/src/inbound/tun/udp.rs` 让 NAT entry / maintenance owner 显式持有并终止 reverse relay task
    - `crates/sb-core/src/outbound/mod.rs` 新增 `resolve(...)` query seam；`chain.rs` 改为复用该 seam
    - `crates/sb-core/src/outbound/optimizations.rs` 去掉 `current_time_ms()` panic 面，并让 TTL cache 在过期读取时即时清掉 stale entry
  - 本卡明确是 maintenance / hotspot quality work，不是 dual-kernel parity completion；也没有推进 `planned.rs`、public `RuntimePlan`、public `PlannedConfigIR`、generic query API
  - 验收通过：`cargo test -p sb-core --all-features inbound::tun::tests -- --test-threads=1`、`cargo test -p sb-core --all-features outbound::optimizations::tests -- --test-threads=1`、`cargo test -p sb-core --all-features outbound::tests -- --test-threads=1`、`cargo test -p sb-core --all-features --lib -- --test-threads=1`、`cargo test -p sb-core --all-features --tests -- --test-threads=1`、`cargo test -p sb-adapters --all-features --lib tun_session::tests -- --test-threads=1`、`cargo test -p sb-adapters --all-features --lib inbound::tun::udp::tests -- --test-threads=1`、`cargo clippy -p sb-core --all-features --all-targets -- -D warnings`、`cargo clippy -p sb-adapters --all-features --all-targets -- -D warnings`
  - 当前基线备注：`cargo test -p sb-adapters --all-features --lib -- --test-threads=1` 仍有既有失败，集中在 hysteria2 / tuic / tun_enhanced / register；这些不属于本卡主轴

- **MT-RD-01**: router / dns structural consolidation — 已完成
  - shared index owner / runtime override seam / file-backed upstream pool owner 已完成结构收口

- **MT-TEST-01**: patch-plan / test baseline stabilization — 已完成
  - patch 生成与 patch 应用语义不一致的真实根因已修复，当前继续保持稳定

- **MT-SVC-01**: DERP / services baseline stabilization — 已完成
  - mesh lifecycle / task ownership / TLS baseline 收口继续保持稳定

- **MT-HOT-OBS-01**: hotpath stabilization + metrics/logging consolidation — 已完成
  - tun/dns/router/outbound optimizations 与 logging/sb-metrics owner-first 收口继续保持稳定

### 已完成维护归档（2026-04-03）

- **MT-RTC-03**: runtime actorization close-out — 已完成
- **MT-RTC-02**: runtime actorization follow-up — 已完成
- **MT-RTC-01**: runtime actor/context consolidation — 已完成
- **MT-OBS-01**: runtime / control-plane / observability ownership consolidation — 已完成
- **WP-30at**: `WP-30k` ~ `WP-30as` maintenance line 总体验收 / 归档收口 — 已完成

### 当前维护重点（高层）

- runtime actor/context 主线当前已达到维护期可接受 close-out；后续不再按散乱 seam 继续细拆
- 当前更合适的维护主题排序：
  - `tun/outbound` 剩余 queue/backpressure / eviction-policy / protocol-reuse 高层 boundary
  - `router/dns` 剩余 mega-file 的高层 boundary
  - metrics/logging 剩余 compat/global 壳
  - patch/preview 或 DERP/services 若再出现真实 baseline failure，再按事实切回处理
- 配置高层 future boundary 保持不变：不恢复 `WP-30k` 式拆卡，不误推进 public `RuntimePlan` / `PlannedConfigIR`

### 构建基线（2026-04-03）

| 构建 | 状态 |
|------|------|
| `cargo test -p sb-core --all-features inbound::tun::tests -- --test-threads=1` | ✅ pass (`MT-PERF-01`) |
| `cargo test -p sb-core --all-features outbound::optimizations::tests -- --test-threads=1` | ✅ pass (`MT-PERF-01`) |
| `cargo test -p sb-core --all-features outbound::tests -- --test-threads=1` | ✅ pass (`MT-PERF-01`) |
| `cargo test -p sb-adapters --all-features --lib tun_session::tests -- --test-threads=1` | ✅ pass (`MT-PERF-01`) |
| `cargo test -p sb-adapters --all-features --lib inbound::tun::udp::tests -- --test-threads=1` | ✅ pass (`MT-PERF-01`) |
| `cargo test -p sb-core --all-features --lib -- --test-threads=1` | ✅ pass (`MT-PERF-01`) |
| `cargo test -p sb-core --all-features --tests -- --test-threads=1` | ✅ pass (`MT-PERF-01`) |
| `cargo clippy -p sb-core --all-features --all-targets -- -D warnings` | ✅ pass (`MT-PERF-01`) |
| `cargo clippy -p sb-adapters --all-features --all-targets -- -D warnings` | ✅ pass (`MT-PERF-01`) |
| `cargo test -p sb-core --all-features router::migration_tests -- --test-threads=1` | ✅ pass (`MT-RD-01`) |
| `cargo test -p sb-core --all-features dns::config_builder::tests -- --test-threads=1` | ✅ pass (`MT-RD-01`) |
| `cargo test -p sb-core --all-features dns::upstream::tests -- --test-threads=1` | ✅ pass (`MT-RD-01`) |
| `cargo test -p sb-metrics --all-features --lib -- --test-threads=1` | ✅ pass (`MT-HOT-OBS-01`) |
| `cargo test -p app --all-features --lib -- --test-threads=1` | ✅ pass (`MT-HOT-OBS-01`) |
| `cargo clippy -p sb-metrics --all-features --all-targets -- -D warnings` | ✅ pass (`MT-HOT-OBS-01`) |
| `cargo clippy -p app --all-features --all-targets -- -D warnings` | ✅ pass (`MT-HOT-OBS-01`) |
