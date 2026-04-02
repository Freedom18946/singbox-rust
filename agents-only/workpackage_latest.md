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

- **MT-ADP-01**: sb-adapters test baseline stabilization — 已完成
  - 当前源码事实下，这条线处理的是 `cargo test -p sb-adapters --all-features --lib -- --test-threads=1` 的既有 baseline failures，不是 parity completion
  - 开工前复核到的真实失败固定为：
    - `inbound::hysteria2::tests::connect_via_router_reaches_upstream`
    - `inbound::tuic::tests::connect_via_router_reaches_upstream`
    - `inbound::tun_enhanced::tests::bootstrap_tcp_session_fin_with_payload_forwards_then_closes`
    - `inbound::tun_enhanced::tests::packet_loop_forwards_fin_payload_and_cleans_up`
    - `register::tests::test_shadowtls_outbound_registration_connect_io_only_for_configured_server`
  - 本轮收口：
    - `crates/sb-adapters/src/testsupport/mod.rs` 新增 deterministic `direct_route_fixture()`
    - `crates/sb-adapters/src/inbound/{hysteria2,tuic}.rs` 的 route tests 改吃显式 direct fixture，不再依赖 `RouterHandle::from_env()` 的 unresolved baseline
    - `crates/sb-adapters/src/inbound/tun_session.rs` 新增 `request_shutdown()` 与 `TcpSessionManager::detach()`，`crates/sb-adapters/src/inbound/tun_enhanced.rs` 的 FIN path 改为 graceful drain + detach
    - `crates/sb-adapters/src/outbound/shadowtls.rs` 为 detour wrapper 增加 requested-endpoint guard；`crates/sb-adapters/src/register.rs` 的测试 fixture 改成 handshake 后回到底层 raw stream
  - 本卡明确是 maintenance / adapter-baseline quality work，不是 dual-kernel parity completion；也没有推进 `planned.rs`、public `RuntimePlan`、public `PlannedConfigIR`、generic query API
  - 验收通过：`cargo test -p sb-adapters --all-features hysteria2 -- --test-threads=1`、`cargo test -p sb-adapters --all-features tuic -- --test-threads=1`、`cargo test -p sb-adapters --all-features tun_enhanced -- --test-threads=1`、`cargo test -p sb-adapters --all-features register -- --test-threads=1`、`cargo test -p sb-adapters --all-features --lib tun_session::tests -- --test-threads=1`、`cargo test -p sb-adapters --all-features --lib -- --test-threads=1`、`cargo clippy -p sb-adapters --all-features --all-targets -- -D warnings`

- **MT-PERF-01**: tun / outbound hotspot stabilization — 已完成
  - TUN session owner、TCP/UDP relay task owner、registry query seam、optimization stale-entry 面已保持稳定

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

- `sb-adapters --lib` 当前已恢复到维护期可接受基线；后续若再出现 adapter failures，应按少数高层 boundary 分线，而不是把同一主题继续拆成大量细卡
- 当前更适合继续观察的高层方向：
  - ShadowTLS transport-wrapper / detour consumer owner 的更完整模型
  - TUN TCP lifecycle 的更深层半关闭 corner cases
  - 若 future baseline 再出现，才切回 protocol-specific integration / e2e 维护线
- 配置高层 future boundary 保持不变：不恢复 `WP-30k` 式拆卡，不误推进 public `RuntimePlan` / `PlannedConfigIR`

### 构建基线（2026-04-03）

| 构建 | 状态 |
|------|------|
| `cargo test -p sb-adapters --all-features hysteria2 -- --test-threads=1` | ✅ pass (`MT-ADP-01`) |
| `cargo test -p sb-adapters --all-features tuic -- --test-threads=1` | ✅ pass (`MT-ADP-01`) |
| `cargo test -p sb-adapters --all-features tun_enhanced -- --test-threads=1` | ✅ pass (`MT-ADP-01`) |
| `cargo test -p sb-adapters --all-features register -- --test-threads=1` | ✅ pass (`MT-ADP-01`) |
| `cargo test -p sb-adapters --all-features --lib tun_session::tests -- --test-threads=1` | ✅ pass (`MT-ADP-01`) |
| `cargo test -p sb-adapters --all-features --lib -- --test-threads=1` | ✅ pass (`MT-ADP-01`) |
| `cargo clippy -p sb-adapters --all-features --all-targets -- -D warnings` | ✅ pass (`MT-ADP-01`) |
| `cargo test -p sb-core --all-features --lib -- --test-threads=1` | ✅ pass (`MT-PERF-01` / `MT-SVC-01`) |
| `cargo clippy -p sb-core --all-features --all-targets -- -D warnings` | ✅ pass (`MT-PERF-01` / `MT-SVC-01`) |
