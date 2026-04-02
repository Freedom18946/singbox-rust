<!-- tier: S -->
# 当前上下文（Active Context）
> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。
---
## 战略状态
**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)，以 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 为准
**当前维护线**: `MT-ADP-01` sb-adapters test baseline stabilization — 已完成；`MT-PERF-01`、`MT-RD-01`、`MT-TEST-01`、`MT-SVC-01`、`MT-HOT-OBS-01`、`MT-RTC-03`、`MT-RTC-02`、`MT-RTC-01`、`MT-OBS-01` 与 `WP-30` 继续保持已完成 / 已归档状态

## 最近完成（2026-04-03）

### MT-ADP-01：sb-adapters test baseline stabilization — 已完成
- 本卡按当前源码与工作区事实推进，性质明确为 maintenance / adapter-baseline quality work，不是 dual-kernel parity completion；没有恢复 `.github/workflows/*`，也没有推进 `planned.rs`、public `RuntimePlan`、public `PlannedConfigIR`、generic query API
- 开工前复核到的真实基线失败固定为 5 个：
  - `inbound::hysteria2::tests::connect_via_router_reaches_upstream`
  - `inbound::tuic::tests::connect_via_router_reaches_upstream`
  - `inbound::tun_enhanced::tests::bootstrap_tcp_session_fin_with_payload_forwards_then_closes`
  - `inbound::tun_enhanced::tests::packet_loop_forwards_fin_payload_and_cleans_up`
  - `register::tests::test_shadowtls_outbound_registration_connect_io_only_for_configured_server`
- 真实根因按源码收口为 3 组：
  - `hysteria2 / tuic` 测试夹具错误依赖 `RouterHandle::from_env()`；当前仓库默认 router baseline 是 `unresolved`，不是测试想要的显式 direct route
  - `tun_enhanced` 的 FIN+payload 路径在上一轮 owner 收口后变成“发 shutdown 后立刻 abort tracked tasks”，导致 queued payload 还没 drain 到 outbound 就被截断
  - `shadowtls` register 测试夹具把 detour wrapper 当成普通 TLS stream 使用；同时 wrapper 本身缺少“requested endpoint 必须等于 configured server”的显式 guard
- 本轮收口：
  - `crates/sb-adapters/src/testsupport/mod.rs` 新增 `direct_route_fixture()`，把 direct router + direct outbound registry 收成显式共享 fixture
  - `crates/sb-adapters/src/inbound/hysteria2.rs` 与 `crates/sb-adapters/src/inbound/tuic.rs` 的 router baseline tests 改吃显式 direct fixture，不再受 ENV / shared router state 影响
  - `crates/sb-adapters/src/inbound/tun_session.rs` 新增 `request_shutdown()` 与 `TcpSessionManager::detach()`，把“graceful drain”与“hard abort”语义分开
  - `crates/sb-adapters/src/inbound/tun_enhanced.rs` 的 existing-session FIN path 改为 `request_shutdown + detach`，先 drain payload，再让 relay 自行 shutdown/cleanup
  - `crates/sb-adapters/src/outbound/shadowtls.rs` 在 `connect_detour_stream(...)` 入口显式校验 requested endpoint 必须匹配 configured wrapper server
  - `crates/sb-adapters/src/register.rs` 的 ShadowTLS 测试 server 改成“先完成 TLS handshake，再回到底层 raw stream 收发”，并显式安装 rustls CryptoProvider
- 本轮新增 / 强化的关键 pin：
  - `inbound::tun_session::tests::test_request_shutdown_drains_pending_payload_before_detach`
  - 既有 `hysteria2` / `tuic` route tests、`tun_enhanced` FIN payload tests、`register` shadowtls bridge test 现已恢复并共同 pin 住本轮修复语义

## 当前稳定事实
- `cargo test -p sb-adapters --all-features --lib -- --test-threads=1` 当前通过（199 passed, 1 ignored）
- `hysteria2 / tuic / tun_enhanced / register` 这条 adapter baseline failure map 已按当前阶段收口，不再是 `sb-adapters --lib` blocker
- `planned.rs` 仍是 staged crate-private seam；当前仓库仍无 public `RuntimePlan`、public `PlannedConfigIR`、generic query API
- 当前 workspace 仍存在大量无关在制改动；本卡只触达 `sb-adapters` 失败链路与 `agents-only` 文档，没有回滚或覆盖 unrelated workspace changes

## 当前验证事实
- 已通过：
  - `cargo test -p sb-adapters --all-features hysteria2 -- --test-threads=1`
  - `cargo test -p sb-adapters --all-features tuic -- --test-threads=1`
  - `cargo test -p sb-adapters --all-features tun_enhanced -- --test-threads=1`
  - `cargo test -p sb-adapters --all-features register -- --test-threads=1`
  - `cargo test -p sb-adapters --all-features --lib tun_session::tests -- --test-threads=1`
  - `cargo test -p sb-adapters --all-features --lib -- --test-threads=1`
  - `cargo clippy -p sb-adapters --all-features --all-targets -- -D warnings`

## Future Work（高层方向）
- `sb-adapters` 后续若再推进，应只围绕少数高层 boundary：
  - transport-wrapper / detour 模型的更完整 ShadowTLS consumer owner，而不是继续放大 register bridge
  - TUN TCP lifecycle 的更完整半关闭 / FIN-first corner cases，但仅在出现真实新基线失败时再处理
  - protocol-specific integration / e2e baseline 若再出现真实失败，再单独按高层链路分线
- 当前阶段不再把 `sb-adapters` debt 继续拆成很多细碎小卡；`--lib` 基线已恢复，剩余债务应保持高层边界表达

## 归档判断
- `WP-30` 继续视为 archive baseline，`ef333bb7` 仍是归档基线
- `MT-ADP-01` 已完成；当前没有证据表明应把这条 adapter baseline 线继续细拆
