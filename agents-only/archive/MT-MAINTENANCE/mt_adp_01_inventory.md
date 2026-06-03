# MT-ADP-01 inventory

## 定位

- 主题：sb-adapters test baseline stabilization
- 性质：maintenance / adapter-baseline quality work
- 形式：10 合 1，但只围绕当前真实存在的 `sb-adapters --lib` baseline failures 与其相邻 fixture / lifecycle / registration seam 收口
- 非目标：dual-kernel parity completion、恢复 `.github/workflows/*`、推进 `planned.rs` 公共化、public `RuntimePlan`、public `PlannedConfigIR`、generic query API、扩散到 router/dns、runtime actor/context、DERP/services 主线

## 开工前复核结论

- 仓库处于 maintenance mode，L1-L25 全部 Closed；`WP-30` 已归档，`ef333bb7` 仍是 archive baseline
- `MT-OBS-01`、`MT-RTC-01`、`MT-RTC-02`、`MT-RTC-03`、`MT-HOT-OBS-01`、`MT-SVC-01`、`MT-TEST-01`、`MT-RD-01`、`MT-PERF-01` 均已完成；本卡不能把维护工作表述成 parity completion
- 当前工作区有大量无关在制改动；本卡只围住 `sb-adapters` failure chain 与 `agents-only` 文档推进，没有回滚或覆盖 unrelated workspace changes
- 按当前源码事实重跑 `cargo test -p sb-adapters --all-features --lib -- --test-threads=1` 后，真实失败固定为 5 个：
  - `inbound::hysteria2::tests::connect_via_router_reaches_upstream`
  - `inbound::tuic::tests::connect_via_router_reaches_upstream`
  - `inbound::tun_enhanced::tests::bootstrap_tcp_session_fin_with_payload_forwards_then_closes`
  - `inbound::tun_enhanced::tests::packet_loop_forwards_fin_payload_and_cleans_up`
  - `register::tests::test_shadowtls_outbound_registration_connect_io_only_for_configured_server`

## 真实根因

### 1. router fixture baseline 漂移

- `crates/sb-adapters/src/inbound/hysteria2.rs`
- `crates/sb-adapters/src/inbound/tuic.rs`
- 当前失败不是 adapter connect 逻辑本体坏掉，而是测试夹具错误依赖 `RouterHandle::from_env()`
- 在当前仓库事实下，shared router baseline 默认是 `unresolved`，因此 helper 会把 route target 落到不存在的 named outbound，而不是显式 direct

### 2. TUN FIN+payload lifecycle 被 hard abort 截断

- `crates/sb-adapters/src/inbound/tun_enhanced.rs`
- `crates/sb-adapters/src/inbound/tun_session.rs`
- 上一轮 owner 收口后，`initiate_close()` 语义是“发 shutdown + abort tracked tasks”
- existing-session FIN path 复用了这个 hard-close helper，导致 FIN packet 附带的 payload 还没从 channel drain 到 outbound，就被 writer task abort

### 3. ShadowTLS detour bridge / test fixture 语义不匹配

- `crates/sb-adapters/src/outbound/shadowtls.rs`
- `crates/sb-adapters/src/register.rs`
- detour wrapper 真实语义是“先做 camouflage handshake，再回到底层 raw stream”；旧测试却把返回流当普通 TLS stream 使用
- 同时 wrapper 入口缺少对 requested endpoint 的显式 guard，导致“误把 wrapper 当 leaf outbound”时没有被立刻拒绝

## 本轮源码收口

### 共享 fixture seam

- `crates/sb-adapters/src/testsupport/mod.rs`
  - 新增 `direct_route_fixture()`
  - 把 deterministic direct router + direct outbound registry 收成共享 helper，避免多个 adapter tests 再依赖 `RouterHandle::from_env()`

### Hysteria2 / TUIC baseline

- `crates/sb-adapters/src/inbound/hysteria2.rs`
- `crates/sb-adapters/src/inbound/tuic.rs`
  - `connect_via_router_reaches_upstream` 统一改吃 `direct_route_fixture()`
  - 不再依赖 ENV / shared unresolved router state

### TUN lifecycle seam

- `crates/sb-adapters/src/inbound/tun_session.rs`
  - 新增 `request_shutdown()`，只发送 shutdown signal，不立即 abort tracked tasks
  - 新增 `TcpSessionManager::detach()`，允许先把 session 从 owner map 移除，再让 relay task 自行 drain / shutdown
  - 新增回归：`test_request_shutdown_drains_pending_payload_before_detach`
- `crates/sb-adapters/src/inbound/tun_enhanced.rs`
  - existing-session FIN path 改为 `request_shutdown + detach`
  - 不再把 queued payload 与 graceful FIN cleanup 一起走 hard-abort 语义

### ShadowTLS registration seam

- `crates/sb-adapters/src/outbound/shadowtls.rs`
  - `connect_detour_stream(...)` 入口新增 configured-endpoint validation
  - requested host/port 不等于 configured wrapper server 时，显式报错，而不是静默忽略
- `crates/sb-adapters/src/register.rs`
  - ShadowTLS register test 显式安装 rustls CryptoProvider
  - 测试 server 改成“完成 TLS handshake 后回到底层 raw stream 收发”，与 detour wrapper 真实语义对齐

## 本轮 10 合 1 实际切口

- `crates/sb-adapters/src/inbound/hysteria2.rs`
- `crates/sb-adapters/src/inbound/tuic.rs`
- `crates/sb-adapters/src/inbound/tun_enhanced.rs`
- `crates/sb-adapters/src/inbound/tun_session.rs`
- `crates/sb-adapters/src/register.rs`
- `crates/sb-adapters/src/outbound/shadowtls.rs`
- `crates/sb-adapters/src/testsupport/mod.rs`
- 与上述直接相关的 router fixture seam
- 与上述直接相关的 TCP lifecycle seam
- 与上述直接相关的 ShadowTLS detour test harness seam

## 本轮测试 / pins

- `inbound::hysteria2::tests::connect_via_router_reaches_upstream`
- `inbound::tuic::tests::connect_via_router_reaches_upstream`
- `inbound::tun_enhanced::tests::bootstrap_tcp_session_fin_with_payload_forwards_then_closes`
- `inbound::tun_enhanced::tests::packet_loop_forwards_fin_payload_and_cleans_up`
- `inbound::tun_session::tests::test_request_shutdown_drains_pending_payload_before_detach`
- `register::tests::test_shadowtls_outbound_registration_connect_io_only_for_configured_server`

## 验收命令

- `cargo test -p sb-adapters --all-features hysteria2 -- --test-threads=1`
- `cargo test -p sb-adapters --all-features tuic -- --test-threads=1`
- `cargo test -p sb-adapters --all-features tun_enhanced -- --test-threads=1`
- `cargo test -p sb-adapters --all-features register -- --test-threads=1`
- `cargo test -p sb-adapters --all-features --lib tun_session::tests -- --test-threads=1`
- `cargo test -p sb-adapters --all-features --lib -- --test-threads=1`
- `cargo clippy -p sb-adapters --all-features --all-targets -- -D warnings`

## 当前验证结论

- 上述命令已按当前 workspace 事实通过
- `cargo test -p sb-adapters --all-features --lib -- --test-threads=1` 当前通过（199 passed, 1 ignored）
- 本卡没有把 maintenance 工作误写成 parity completion
- 本卡没有推进 `planned.rs`、public `RuntimePlan`、public `PlannedConfigIR`
- 本卡没有为了让测试过而单纯加 sleep、放宽断言、扩大模糊匹配范围
- 本卡没有引入新的无主资源、初始化顺序问题、cleanup 缺口或 feature wiring 混乱

## Future Work（高层方向）

- ShadowTLS 若后续继续推进，应围绕少数高层 boundary：
  - transport-wrapper 的更完整 consumer owner / detour wiring
  - 更明确的 wrapper-vs-leaf misuse reporting
- TUN TCP 若后续继续推进，应围绕少数高层 boundary：
  - 半关闭 / FIN-first / simultaneous-close corner cases
  - 更系统的 lifecycle / cleanup 策略，而不是继续散修单个 helper
- 除此之外，本线暂不继续细拆；`sb-adapters` 剩余债务应保持高层边界表达
