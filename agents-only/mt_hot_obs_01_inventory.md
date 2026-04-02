# MT-HOT-OBS-01 inventory

## 定位

- 主题：hotpath stabilization + metrics/logging consolidation
- 性质：maintenance / quality work
- 形式：10 合 1，同线推进；实现上分 Stage A / Stage B
- 非目标：dual-kernel parity completion、恢复 `.github/workflows/*`、public `RuntimePlan`、public `PlannedConfigIR`、generic query API、把 runtime actor/context 主线重新做大

## 本轮复核结论

- `crates/sb-adapters/src/inbound/tun/mod.rs`、`crates/sb-core/src/router/explain_util.rs`、`crates/sb-core/src/metrics/registry_ext.rs` 当前没有值得为凑卡继续硬改的真实热点；工作区里的目标相关 diff 也主要是既有轻量整理
- 当前更值得处理的真实 debt 是：
  - `tun` 的热路径锁与桥接 task 生命周期
  - DHCP upstream 构建期对 Tokio runtime 的隐式依赖
  - shared router hot reload 的无效后台启动
  - `logging` signal task 与 `sb-metrics` HTTP exporter 的无主后台任务语义
  - `outbound optimizations` 的全局池面与 `unwrap()` 锁路径

## Stage A：hotpath stabilization

### `crates/sb-core/src/inbound/tun.rs`

- session / router / outbound manager / stats 相关锁改用 `parking_lot::RwLock`
- 去掉多处 hotpath `.unwrap()` poison 面
- 新增 `bridge_dependencies()`，在建桥时一次性快照 owner 依赖，避免异步任务内部重复偷读共享状态
- TCP / UDP bridge task 现在由 `BridgeChannels` 持有 `JoinHandle<()>`
- session 回收、socket 移除、service 退出都会 abort bridge task，避免无主后台桥接
- `SessionTable` 补最小回归：容量已满且没有过期项时返回 `None`，而不是继续冒进创建

### `crates/sb-core/src/dns/upstream.rs`

- `DhcpUpstream::from_spec()` 不再在构建阶段强依赖 Tokio runtime
- 有 runtime 时仍会尝试预启动 transport；无 runtime 时延后到 async query/exchange/health_check 按需启动
- Tailscale local upstream 去掉 built-in 地址 `.parse().unwrap()`，改为显式错误
- 回归覆盖 DHCP upstream 可在无 Tokio runtime 的同步构建路径中安全创建

### `crates/sb-core/src/dns/config_builder.rs`

- 补 builder 级回归，确认 `build_upstream_from_server(...)` 在 DHCP spec 下不再因 runtime 缺失 panic

### `crates/sb-core/src/router/mod.rs`

- 新增 `shared_hot_reload_enabled_from_env()`
- `shared_index()` 只在“存在 runtime + 真正配置了 rules file + 正 reload interval”时才尝试后台热重载
- 避免默认 query 路径无意义地拉起 once-only noop task

### `crates/sb-core/src/outbound/optimizations.rs`

- buffer pool / connection pool / TTL cache 锁改用 `parking_lot::Mutex`
- protocol buffer pool 收口为 crate-local helper，而不是公开 global static surface
- 保持现有 metrics 兼容语义，不借题扩散到其他 outbound runtime seam

## Stage B：metrics/logging consolidation

### `app/src/logging.rs`

- `ACTIVE_RUNTIME` 与 sampler 锁改用 `parking_lot::Mutex`
- `LoggingOwner` 现在显式拥有 signal task
- `init_logging_with_owner()` 返回的 owner 会接管 exit signal background task
- `LoggingOwner::flush()` 先 cancel/join signal task，再执行 flush
- compat/global 路径仍保留，但 signal lifecycle 不再是 fire-and-forget 壳
- 回归覆盖 owner flush 会清理已拥有的 signal task

### `crates/sb-metrics/src/lib.rs`

- HTTP exporter accept loop 改为 `JoinSet` 跟踪 per-connection serve task
- exporter 退出时连接任务跟随 owner 生命周期结束，不再是散落 detached spawn
- 回归覆盖 exporter 能通过 TCP 暴露 metrics

## 本轮测试 / pins

- `crates/sb-core/src/inbound/tun.rs`
  - `test_session_table_capacity_rejects_when_full_without_expired_entries`
- `crates/sb-core/src/dns/upstream.rs`
  - `dhcp_upstream_with_transport_builds_without_tokio_runtime`
- `crates/sb-core/src/dns/config_builder.rs`
  - `build_upstream_from_server_supports_dhcp_without_tokio_runtime`
- `crates/sb-core/src/router/mod.rs`
  - `shared_hot_reload_requires_file_and_positive_interval`
- `app/src/logging.rs`
  - `explicit_owner_flush_cancels_owned_signal_task`
- `crates/sb-metrics/src/lib.rs`
  - `spawned_exporter_serves_metrics_over_tcp`

## 验收命令

- `cargo test -p sb-core --all-features inbound::tun::tests -- --test-threads=1`
- `cargo test -p sb-core --all-features dns::config_builder::tests -- --test-threads=1`
- `cargo test -p sb-core --all-features dns::upstream::tests -- --test-threads=1`
- `cargo test -p sb-core --all-features outbound::optimizations::tests -- --test-threads=1`
- `cargo test -p sb-core --all-features router::migration_tests -- --test-threads=1`
- `cargo test -p sb-core --all-features --tests -- --test-threads=1`
- `cargo test -p sb-metrics --all-features --lib -- --test-threads=1`
- `cargo test -p app --all-features --lib -- --test-threads=1`
- `cargo clippy -p sb-core --all-features --all-targets -- -D warnings`
- `cargo clippy -p sb-metrics --all-features --all-targets -- -D warnings`
- `cargo clippy -p app --all-features --all-targets -- -D warnings`

## 当前验证结论

- 上述定向 Stage A / Stage B 测试与三条 clippy 已通过
- `cargo test -p sb-core --all-features --tests -- --test-threads=1` 当前仍被现有 DERP 基线失败阻塞：
  - `services::derp::mesh_test::tests::test_mesh_forwarding`
  - 失败位置：`crates/sb-core/src/services/derp/mesh_test.rs:266`
  - 现象：`timeout waiting for RecvPacket`
- 该失败与本卡触达的 `tun/dns/router/optimizations/logging/metrics` 切口无直接交集，本轮不借题扩散到 DERP 主线

## 当前边界

- 本卡没有把维护工作表述成 parity completion
- 本卡没有推进 `planned.rs`、public `RuntimePlan`、public `PlannedConfigIR`
- 本卡没有重新打开 runtime actor/context 主线
- 本卡没有引入新的无主后台任务、明显 panic 面或更糟 shared-state 路径

## Future Work（高层方向）

- `router/dns` 更深层 mega-file 拆分仍是未来高层 maintenance boundary，但要以真实 consumer / profiler / churn 成本为前提
- `tun` / `outbound` 若后续出现明确 perf 证据，可继续围绕 queue/backpressure/session owner 做第二轮治理
- metrics/logging 仍有少量 compat/global 壳未完全收尽；后续只在出现真实 owner/query 收益时再推进
