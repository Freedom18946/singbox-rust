<!-- tier: S -->
# 当前上下文（Active Context）
> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。
---
## 战略状态
**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)，以 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 为准
**当前维护线**: `MT-PERF-01` tun / outbound hotspot stabilization — 已完成；`MT-RD-01`、`MT-TEST-01`、`MT-SVC-01`、`MT-HOT-OBS-01`、`MT-RTC-03`、`MT-RTC-02`、`MT-RTC-01`、`MT-OBS-01` 与 `WP-30` 继续保持已完成 / 已归档状态

## 最近完成（2026-04-03）

### MT-PERF-01：tun / outbound hotspot stabilization — 已完成
- 本卡按当前源码事实推进，性质明确为 maintenance / hotspot quality work，不是 dual-kernel parity completion，也没有恢复 `.github/workflows/*`
- 当前最值得优先收口的真实热点，是 `tun / outbound` 链路里仍然存在的 lock-heavy / owner 不清 / lifecycle 隐式路径：
  - `crates/sb-core/src/inbound/tun.rs` 的 session table 仍有表锁外再套 per-session `RwLock`
  - `crates/sb-adapters/src/inbound/tun_session.rs` 与 `crates/sb-adapters/src/inbound/tun/udp.rs` 仍有 relay task owner 不显式、cleanup 靠旁路状态兜底的风险
  - `crates/sb-core/src/outbound/mod.rs` 与 `crates/sb-core/src/outbound/optimizations.rs` 仍有 registry lookup seam 分散、panic / stale-entry 面
- 本轮收口：
  - `crates/sb-core/src/inbound/tun.rs` 把 session table 收成 `RwLock<HashMap<FlowKey, Arc<TunSession>>>`，去掉 hotpath 的 `Arc<RwLock<TunSession>>` 嵌套；session 的 outbound / SNI / activity tick 改为单 owner 内部字段 helper
  - `TunSession` 新增 `mark_active()`、`touch(...)`、`set_outbound(...)`、`set_sni_if_absent(...)` query/helper seam，bridge task 不再为了更新热字段拿整 session 写锁
  - `crates/sb-adapters/src/inbound/tun_session.rs` 改为由 `TcpSession` 显式拥有 relay `JoinHandle`；`remove()` / `initiate_close()` 会发送 shutdown 并 abort owned tasks
  - `crates/sb-adapters/src/inbound/tun/udp.rs` 改为由 NAT entry 持有 reverse relay task，eviction 与 maintenance owner 会显式 abort 背景任务
  - `crates/sb-core/src/outbound/mod.rs` 把 registry 读路径统一到 `resolve(...)` query seam；`chain.rs` 复用该 seam
  - `crates/sb-core/src/outbound/optimizations.rs` 去掉 `current_time_ms()` 的 panic 面，并让 TTL cache 在过期读取时同步移除 stale entry
- 本轮新增 / 迁移的关键 pin：
  - `inbound::tun::tests::test_session_mutation_helpers_keep_hot_fields_off_nested_lock`
  - `inbound::tun::tests::test_session_table_owner_stays_in_single_session_arc`
  - `tun_session::tests::test_initiate_close_aborts_tracked_tasks`
  - `inbound::tun::udp::tests::test_evict_expired_aborts_owned_reverse_relay`
  - `outbound::tests::registry_handle_resolve_uses_dedicated_query_seam`
  - `outbound::tests::registry_handle_source_pin_uses_owner_first_lookup_helper`
  - `outbound::optimizations::tests::source_pin_current_time_ms_avoids_unwrap_panic_path`
- 本轮没有推进 `planned.rs`、public `RuntimePlan`、public `PlannedConfigIR`、generic query API，也没有把维护工作误写成 parity completion

## 当前稳定事实
- `planned.rs` 仍是 staged crate-private seam；当前仓库仍无 public `RuntimePlan`、public `PlannedConfigIR`、generic query API
- runtime actor/context、router/dns、DERP/services 主线当前仍保持 close-out；`MT-PERF-01` 只触达 `tun / outbound` 直接相关 owner seam，没有把已稳定主题重新打开
- 当前 workspace 仍存在大量无关在制改动；本卡只顺着 `tun / outbound` 目标切口推进，没有回滚或覆盖 unrelated workspace changes
- `ssh.rs`、`anytls.rs`、`outbound/manager.rs`、`context/` 经复核后本轮没有值得为凑卡硬改的真实热点；当前更高收益的是 TUN session owner、TCP/UDP cleanup owner、registry lookup seam 与 optimization stale-entry 面

## 当前验证事实
- 已通过：
  - `cargo test -p sb-core --all-features inbound::tun::tests -- --test-threads=1`
  - `cargo test -p sb-core --all-features outbound::optimizations::tests -- --test-threads=1`
  - `cargo test -p sb-core --all-features outbound::tests -- --test-threads=1`
  - `cargo test -p sb-core --all-features --lib -- --test-threads=1`
  - `cargo test -p sb-core --all-features --tests -- --test-threads=1`
  - `cargo test -p sb-adapters --all-features --lib tun_session::tests -- --test-threads=1`
  - `cargo test -p sb-adapters --all-features --lib inbound::tun::udp::tests -- --test-threads=1`
  - `cargo clippy -p sb-core --all-features --all-targets -- -D warnings`
  - `cargo clippy -p sb-adapters --all-features --all-targets -- -D warnings`
- 额外观察到的当前仓库事实：
  - `cargo test -p sb-adapters --all-features --lib -- --test-threads=1` 仍有既有失败，集中在 `inbound::hysteria2`、`inbound::tuic`、`inbound::tun_enhanced`、`register::tests::test_shadowtls_outbound_registration_connect_io_only_for_configured_server`
  - 这些失败与本卡实际触达的 `tun_session` / `tun udp nat` / registry lookup / optimizations seam 不直接重合，本轮不借题扩散到其他维护主题

## Future Work（高层方向）
- `tun / outbound` 后续若再推进，应只围绕少数高层 boundary：queue/backpressure 证据、session-table eviction policy、protocol-specific connection reuse，而不是回到这轮已经收掉的 session owner / task owner / registry query seam
- `sb-adapters` 当前 broader `--lib` 失败若要处理，应单独按 hysteria2 / tuic / tun_enhanced / register baseline 分线复核，不应混入本卡
- 维护主题后续仍应按少数高层 boundary 排序，不再展开成大量细碎 perf/lock 小尾巴

## 归档判断
- `WP-30` 继续视为 archive baseline，`ef333bb7` 仍是归档基线
- `MT-RD-01`、`MT-TEST-01`、`MT-SVC-01`、`MT-HOT-OBS-01` 与 `MT-PERF-01` 当前都已完成；`tun / outbound` 热路径剩余债务已压缩成少数 future boundary，不值得继续为凑卡细拆
