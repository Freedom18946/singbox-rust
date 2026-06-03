# MT-SVC-01 inventory

## 定位

- 主题：DERP / services baseline stabilization
- 性质：maintenance / services quality work
- 形式：10 合 1 的高层维护卡，但实际实现严格按当前源码事实收口
- 非目标：dual-kernel parity completion、恢复 `.github/workflows/*`、`planned.rs` 公共化、public `RuntimePlan`、public `PlannedConfigIR`、generic query API、扩散到 router/dns/tun 非 DERP 主线

## 本轮复核结论

- 当前真实代码布局与预设候选路径不完全一致：
  - 直接相关 owner/lifecycle/forwarding 逻辑主要集中在 `crates/sb-core/src/services/derp/server.rs`
  - remote route / mesh watcher 映射主要在 `crates/sb-core/src/services/derp/client_registry.rs`
  - 当前基线失败固定复现在 `crates/sb-core/src/services/derp/mesh_test.rs`
  - 当前仓库里不存在可单独治理的 `mesh.rs` / `mesh_forward.rs` / `packet_conn.rs`
- `services::derp::mesh_test::tests::test_mesh_forwarding` 的真实根因不是 timeout 太短，而是：
  - test harness 只调用了 `Initialize` + `Start`
  - DERP mesh peer 按当前实现只在 `StartStage::PostStart` 启动
  - 因此服务实际停在“DERP/TLS 监听已起、mesh client 尚未启动”的半初始化状态
- 在补齐 lifecycle 后，第二层真实问题也按当前源码事实暴露出来：
  - mesh peer fixture 没有 outbound TLS 配置
  - 当前 DERP service 强制 TLS，旧 `localhost:port` shorthand 会明文去敲 TLS 端口并触发 `InvalidContentType`

## 本轮源码收口

### `crates/sb-core/src/services/derp/mesh_test.rs`

- 不再通过 `build_derp_service()` 丢失 concrete query seam；改为直接使用 `DerpService::from_ir(...)`
- 新增完整启动 helper，显式跑完：
  - `Initialize`
  - `Start`
  - `PostStart`
  - `Started`
- mesh peer fixture 改为显式 `DerpMeshPeerIR { tls: Some(...) }`，按当前源码事实配置 outbound TLS root，而不是继续假设 shorthand 会自动对齐 TLS
- 去掉脆弱的魔法 `sleep(3s)` / `sleep(2s)`，改为等待 remote client route 就绪后再发包
- 发送路径改为 `DerpFrame::write_to_async(...) + flush()`，与当前 DERP tests 其余路径保持一致

### `crates/sb-core/src/services/derp/server.rs`

- 新增 `#[cfg(test)] pub(crate) fn has_remote_client(...)`，提供最小 test-only query seam，避免为了 pin 当前 read 路径去公共化 DERP owner state
- `close()` 不再仅 `drop` `stun_task` / `http_task` / `mesh_tasks` 的 `JoinHandle`
- `close()` 现在会显式 `abort()` 已拥有的 background tasks，避免 detached task 漏出 service owner 生命周期
- 新增回归：
  - `test_close_aborts_owned_background_tasks`

### `crates/sb-core/src/services/derp/client_registry.rs`

- `is_remote_registered(...)` 收成 `pub(crate)`，仅供同 crate 的 DERP tests / owner-first query seam 使用
- 没有引入 public services query API，也没有让其他模块开始直接偷读 DERP live state

## 本轮测试 / pins

- `services::derp::mesh_test::tests::test_mesh_forwarding`
  - pin 住完整 lifecycle + TLS-accurate mesh fixture + explicit route readiness
- `services::derp::server::tests::test_close_aborts_owned_background_tasks`
  - pin 住 DERP service 对已拥有 background task handle 的 abort owner 语义

## 验收命令

- `cargo test -p sb-core --all-features services::derp::mesh_test::tests::test_mesh_forwarding -- --test-threads=1`
- `cargo test -p sb-core --all-features services::derp::server::tests::test_close_aborts_owned_background_tasks -- --test-threads=1`
- `cargo test -p sb-core --all-features services::derp -- --test-threads=1`
- `cargo test -p sb-core --all-features --lib -- --test-threads=1`
- `cargo test -p sb-core --all-features --tests -- --test-threads=1`
- `cargo clippy -p sb-core --all-features --all-targets -- -D warnings`

## 当前验证结论

- 已通过：
  - `cargo test -p sb-core --all-features services::derp::mesh_test::tests::test_mesh_forwarding -- --test-threads=1`
  - `cargo test -p sb-core --all-features services::derp::server::tests::test_close_aborts_owned_background_tasks -- --test-threads=1`
  - `cargo test -p sb-core --all-features services::derp -- --test-threads=1`
  - `cargo test -p sb-core --all-features --lib -- --test-threads=1`
  - `cargo clippy -p sb-core --all-features --all-targets -- -D warnings`
- 当前 workspace 的 `cargo test -p sb-core --all-features --tests -- --test-threads=1` 已不再被 DERP 基线失败阻塞
- 同一条命令在本卡修复后的首个失败点是与本卡无关的：
  - `crates/sb-core/tests/patch_plan_test.rs::plan_and_apply`
- 结合当前 dirty workspace 现状，本卡验收结论是：
  - DERP / services baseline 已达到“当前阶段可接受”
  - 但仓库全局仍存在非本卡测试面上的独立 debt，需要后续高层维护线单独处理

## 当前边界

- 本卡没有把 maintenance 工作误写成 parity completion
- 本卡没有推进 `planned.rs`、public `RuntimePlan`、public `PlannedConfigIR`
- 本卡没有为了让测试过而单纯放大 timeout 或增加 sleep 掩盖问题
- 本卡没有引入新的 public query API、无主后台任务或更糟 cleanup 路径
- 本卡没有卷入当前工作区的 unrelated app / config / metrics / audit 变更

## Future Work（高层方向）

- DERP/services 若后续仍出现真实 flaky 信号，可继续观察：
  - mesh reconnect/backoff 与 shutdown 的更一致 cancel 语义
  - remote client route 的更显式 owner/query seam，但只在真实 consumer 出现时推进
- 除此之外，本线暂不继续拆细卡；剩余高层维护债务应回到：
  - 非 DERP 的 `sb-core --tests` 现状失败面
  - router/dns mega-file 风险
  - tun/outbound perf / lifecycle hotspot
