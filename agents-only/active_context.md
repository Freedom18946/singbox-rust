<!-- tier: S -->
# 当前上下文（Active Context）
> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。
---
## 战略状态
**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)，以 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 为准
**当前维护线**: `MT-DEEP-01` ShadowTLS / TUN TCP corner-case hardening — 已完成；`MT-ADM-01`、`MT-MLOG-01`、`MT-ADP-01`、`MT-PERF-01`、`MT-RD-01`、`MT-TEST-01`、`MT-SVC-01`、`MT-HOT-OBS-01`、`MT-RTC-03`、`MT-RTC-02`、`MT-RTC-01`、`MT-OBS-01` 与 `WP-30` 继续保持已完成 / 已归档状态

## 最近完成（2026-04-03）

### MT-DEEP-01：ShadowTLS / TUN TCP corner-case hardening — 已完成
- 本卡按当前源码与工作区事实推进，性质明确为 maintenance / protocol-corner quality work，不是 dual-kernel parity completion；没有恢复 `.github/workflows/*`，也没有推进 `planned.rs`、public `RuntimePlan`、public `PlannedConfigIR`、generic query API
- 开工前复核确认：
  - `cargo test -p sb-adapters --all-features shadowtls -- --test-threads=1` 在当前仓库事实下暴露 7 个真实失败，集中在 `tests/shadowtls_e2e.rs` 仍沿用“wrapper 必须等于 configured endpoint / requested target 被忽略”的旧口径，与当前 transport-wrapper / detour 链真实语义冲突
  - `cargo test -p sb-adapters --all-features tun_session -- --test-threads=1` 与 `tun_enhanced -- --test-threads=1` 基线通过，但当前实现仍缺 detached/draining owner seam：FIN 后 tuple 会立即从 active map 消失，payload-after-fin / retransmitted FIN 仍可能落回“无 session”路径
- 本轮真实收口：
  - `crates/sb-adapters/src/outbound/shadowtls.rs`：去掉把 requested endpoint 硬等同于 wrapper server 的 guard；`connect_detour_stream(...)` 现显式表达“拨 configured wrapper server，为 requested endpoint 暴露 raw stream”；v2/v3 bridge 改成 `OwnedBridgeStream` 持有 `JoinHandle`，stream drop 时 abort bridge task，不再是无主后台桥接任务
  - `crates/sb-adapters/src/register.rs`：ShadowTLS register test 口径改成“`connect_io()` 暴露 wrapped raw stream”而不是“只允许 configured server”；仍保留 `connect()` reject 作为 leaf misuse guardrail
  - `crates/sb-adapters/tests/shadowtls_e2e.rs`：e2e / detour / shadowsocks-chain pin 统一改成 requested-endpoint-vs-wrapper-endpoint 双语义口径；当前仓库事实下，v1/v2 wrapper 与 register/chain fixture 重新一致
  - `crates/sb-adapters/src/inbound/tun_session.rs`：`TcpSessionManager` 新增 detached/draining registry；`detach()` 不再简单丢失 owner，而是把 half-close 中的 tuple 移到 detached map，relay 结束时才统一清理 active/detached state
  - `crates/sb-adapters/src/inbound/tun_enhanced.rs`：`bootstrap_tcp_session(...)` 新增 detached-session 分支；FIN retransmit 继续回 FIN-ACK，payload-after-fin 显式回 RST 并禁止重新拨号；active-session RST 路径也收成单一 `remove()` owner 关闭入口
- 本轮新增 / 强化的关键 pin：
  - `outbound::shadowtls::tests::dropping_owned_bridge_stream_aborts_bridge_task`
  - `register::tests::test_shadowtls_outbound_registration_connect_io_exposes_wrapped_raw_stream`
  - `tests/shadowtls_e2e.rs`：`shadowtls_detour_wrapper_connects_for_requested_endpoint_via_configured_wrapper`、`shadowtls_detour_wrapper_uses_configured_wrapper_for_arbitrary_requested_target`、`shadowtls_v2_detour_wrapper_connects_for_requested_endpoint_via_configured_wrapper`
  - `inbound::tun_session::tests::test_detach_moves_session_into_draining_registry`
  - `inbound::tun_enhanced::tests::bootstrap_tcp_session_fin_retransmit_uses_detached_session_state`
  - `inbound::tun_enhanced::tests::bootstrap_tcp_session_payload_after_fin_is_rejected_without_reconnect`

## 当前稳定事实
- ShadowTLS 当前稳定事实已经重新统一为：
  - configured wrapper endpoint 负责 TCP/TLS camouflage 握手
  - requested endpoint 是 wrapper 建立后交给上层 protocol/detour consumer 的语义目标，不再被误当成 wrapper server 做拒绝判断
  - v2/v3 wrapper stream 现在显式拥有 bridge task，drop 后不会继续无主桥接
- TUN TCP 当前稳定事实已经重新统一为：
  - active session 与 detached/draining session 分离，FIN-first / half-close 不再把 tuple 直接打回“无 session”
  - retransmitted FIN 会复用 detached owner state 回 FIN-ACK，不再误回 RST
  - payload-after-fin 会被拒绝且不会重新拨第二条 outbound TCP 连接
- `middleware/rate_limit.rs`、`prefetch.rs`、`planned.rs`、public `RuntimePlan` / `PlannedConfigIR` / generic query API 均未被本卡触达
- `planned.rs` 仍是 staged crate-private seam；当前仓库仍无 public `RuntimePlan`、public `PlannedConfigIR`、generic query API
- 当前 workspace 仍存在大量无关在制改动；本卡只触达 `sb-adapters` 的 ShadowTLS / TUN 直接相关文件与 `agents-only` 文档，没有回滚或覆盖 unrelated workspace changes

## 当前验证事实
- 已通过：
  - `cargo test -p sb-adapters --all-features shadowtls -- --test-threads=1`
  - `cargo test -p sb-adapters --all-features tun_session -- --test-threads=1`
  - `cargo test -p sb-adapters --all-features tun_enhanced -- --test-threads=1`
  - `cargo test -p sb-adapters --all-features register -- --test-threads=1`
  - `cargo test -p sb-adapters --all-features --lib -- --test-threads=1`
  - `cargo clippy -p sb-adapters --all-features --all-targets -- -D warnings`

## Future Work（高层方向）
- ShadowTLS 剩余债务现在应压缩成少数高层 boundary：
  - 若 runtime 未来真的需要 typed transport-wrapper contract，再评估“wrapper endpoint / requested endpoint / detour consumer metadata”统一建模；当前阶段不把它硬扩成新的 public API
  - v1/v2/v3 wrapper 自身协议实现若再继续推进，应围绕更高层的 wrapper consumer contract 成组处理，不回到“某个 endpoint 判断再加一个 if”
- TUN TCP 剩余债务现在应压缩成少数高层 boundary：
  - detached/draining session 的更系统 grace timeout / simultaneous-close policy
  - 更高层的 TCP lifecycle/cleanup owner（如果未来需要跨 packet loop / session manager 统一治理）
- 当前阶段不值得继续把 ShadowTLS / TUN TCP 债务拆成很多细碎小尾巴；本卡已经把真实存在的 protocol-corner seam 压成少数 future boundary

## 归档判断
- `WP-30` 继续视为 archive baseline，`ef333bb7` 仍是归档基线
- `MT-DEEP-01` 已完成；ShadowTLS / TUN TCP 深水区质量线剩余债务已压缩成少数高层 future boundary，不值得继续拆很多 protocol-corner 小尾巴
