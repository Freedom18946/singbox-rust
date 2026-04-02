# MT-PERF-01 inventory

## 定位

- 主题：tun / outbound hotspot stabilization
- 性质：maintenance / hotspot quality work
- 形式：10 合 1；但只围绕当前源码里真实存在的 `tun / outbound` perf / lock / owner / lifecycle seam 收口
- 非目标：dual-kernel parity completion、恢复 `.github/workflows/*`、推进 `planned.rs` 公共化、public `RuntimePlan`、public `PlannedConfigIR`、generic query API、扩散到 router/dns、runtime actor/context、DERP/services、metrics/logging 主线

## 开工前复核结论

- 仓库处于 maintenance mode，L1-L25 全部 Closed；`WP-30` 已归档，`ef333bb7` 仍是 archive baseline
- `MT-OBS-01`、`MT-RTC-01`、`MT-RTC-02`、`MT-RTC-03`、`MT-HOT-OBS-01`、`MT-SVC-01`、`MT-TEST-01`、`MT-RD-01` 均已完成；本卡不能把维护工作表述成 parity completion
- 当前工作区有大量无关在制改动；本卡只围住 `tun / outbound` 直接相关文件推进，没有回滚或覆盖 unrelated workspace changes
- 复核 `crates/sb-adapters/src/outbound/ssh.rs`、`crates/sb-adapters/src/outbound/anytls.rs`、`crates/sb-core/src/outbound/manager.rs`、`crates/sb-core/src/context/` 后，当前并没有比 TUN session owner / relay task owner / outbound query seam 更值得优先处理的真实热点；不为凑 10 个切口硬改

## 本轮真正收口的热点层

### 1. `crates/sb-core/src/inbound/tun.rs`

- `SessionTable` 从 `RwLock<HashMap<FlowKey, Arc<RwLock<TunSession>>>>` 收成 `RwLock<HashMap<FlowKey, Arc<TunSession>>>`
- 热路径不再需要“表锁命中后，再进 per-session write lock”才能更新活动时间、SNI、outbound tag 与字节统计
- `TunSession` 现在显式承载：
  - `outbound: RwLock<String>`
  - `last_activity_tick_ms: AtomicU64`
  - `sni: Mutex<Option<String>>`
- 新 helper / query seam：
  - `mark_active()`
  - `touch(bytes, is_tx)`
  - `outbound()`
  - `set_outbound(...)`
  - `sni()`
  - `set_sni_if_absent(...)`
- cleanup / expiry 改为直接基于 session owner 上的 activity tick 语义，不再依赖外层拿写锁做简单字段更新

### 2. `crates/sb-adapters/src/inbound/tun_session.rs`

- `TcpSession` 改为显式拥有 relay task handle 列表
- `create_session_with_state(...)` 先 `into_split()` outbound stream，再分别创建 upload / download relay，并把 `JoinHandle` 注册到 session owner
- `remove(...)` 与 `initiate_close()` 现在都会：
  - 发送 shutdown signal
  - abort session owner 追踪的 relay tasks
- `shutdown_tx` 改用 `parking_lot::Mutex`，去掉 poison unwrap 面
- 收掉了 `relay_tun_to_outbound(...)` 内再额外 fire-and-forget 一个 reverse relay 的隐式生命周期路径

### 3. `crates/sb-adapters/src/inbound/tun/udp.rs`

- `UdpSession` 改为显式拥有 reverse relay task
- `evict_expired()` 会在删 NAT entry 之前 abort owned reverse relay
- `spawn_eviction_task(...)` 改为返回 `UdpNatMaintenanceTask`
- `TunInbound` 在启动时保留 maintenance owner，drop 时可终止后台 eviction loop，而不是无主定时任务

### 4. `crates/sb-core/src/outbound/mod.rs` / `crates/sb-core/src/outbound/chain.rs`

- `OutboundRegistryHandle` 内部锁改用 `parking_lot::RwLock`
- 新增 `resolve(&self, name: &str) -> Option<OutboundImpl>` query seam
- `connect_tcp()`、`connect_io()` 与 `chain.rs` 都复用该 seam
- 收掉“每个 consumer 自己开 registry 读锁 + match + fallback”的分散 lookup 方式

### 5. `crates/sb-core/src/outbound/optimizations.rs`

- `current_time_ms()` 不再走 `duration_since(...).unwrap()` panic 路径
- `TtlCache::get()` 在发现 entry 过期时会同步删除 stale entry，而不是继续让过期缓存残留在 shared state 里
- 保持当前 helper 规模，不借题扩成新的抽象层

## 本轮测试 / source pin

- `crates/sb-core/src/inbound/tun.rs`
  - `test_session_mutation_helpers_keep_hot_fields_off_nested_lock`
  - `test_session_table_owner_stays_in_single_session_arc`
- `crates/sb-adapters/src/inbound/tun_session.rs`
  - `test_initiate_close_aborts_tracked_tasks`
- `crates/sb-adapters/src/inbound/tun/udp.rs`
  - `test_evict_expired_aborts_owned_reverse_relay`
- `crates/sb-core/src/outbound/mod.rs`
  - `registry_handle_resolve_uses_dedicated_query_seam`
  - `registry_handle_source_pin_uses_owner_first_lookup_helper`
- `crates/sb-core/src/outbound/optimizations.rs`
  - `test_ttl_cache_expiration`
  - `source_pin_current_time_ms_avoids_unwrap_panic_path`

## 验收命令

- `cargo test -p sb-core --all-features inbound::tun::tests -- --test-threads=1`
- `cargo test -p sb-core --all-features outbound::optimizations::tests -- --test-threads=1`
- `cargo test -p sb-core --all-features outbound::tests -- --test-threads=1`
- `cargo test -p sb-core --all-features --lib -- --test-threads=1`
- `cargo test -p sb-core --all-features --tests -- --test-threads=1`
- `cargo test -p sb-adapters --all-features --lib tun_session::tests -- --test-threads=1`
- `cargo test -p sb-adapters --all-features --lib inbound::tun::udp::tests -- --test-threads=1`
- `cargo clippy -p sb-core --all-features --all-targets -- -D warnings`
- `cargo clippy -p sb-adapters --all-features --all-targets -- -D warnings`

## 当前验证结论

- 上述定向测试与两条 clippy 已通过
- 额外复核 `cargo test -p sb-adapters --all-features --lib -- --test-threads=1` 时，当前仓库仍有既有失败：
  - `inbound::hysteria2::tests::connect_via_router_reaches_upstream`
  - `inbound::tuic::tests::connect_via_router_reaches_upstream`
  - `inbound::tun_enhanced::tests::bootstrap_tcp_session_fin_with_payload_forwards_then_closes`
  - `inbound::tun_enhanced::tests::packet_loop_forwards_fin_payload_and_cleans_up`
  - `register::tests::test_shadowtls_outbound_registration_connect_io_only_for_configured_server`
- 这些失败不与本卡实际收口的 TUN session owner / TCP-UDP relay owner / registry lookup seam / optimization stale-entry seam 直接重合；本轮不借题扩散到其他维护线

## 当前边界

- 本卡没有把 maintenance 工作误写成 parity completion
- 本卡没有推进 `planned.rs`、public `RuntimePlan`、public `PlannedConfigIR`、generic query API
- 本卡没有把 `tun / outbound` 以外的主题卷进来
- 本卡没有为了“降热点”再引入新的 shared-state owner 混乱或无主后台任务

## Future Work（高层方向）

- `tun / outbound` 若后续还有必要继续推进，应压成少数高层 boundary：
  - queue / backpressure 证据充分后的数据面治理
  - session-table eviction policy 与 cleanup cadence 的更高层策略
  - protocol-specific connection reuse / pool policy 的收益评估
- `sb-adapters --lib` 的既有失败若要处理，应独立分到 hysteria2 / tuic / tun_enhanced / register baseline 线，不与本卡继续混做
- 当前阶段不值得再继续拆细小 perf/lock 卡；本卡已经把 `tun / outbound` 剩余债务压缩成少数 future boundary
