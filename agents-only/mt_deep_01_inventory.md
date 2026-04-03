# MT-DEEP-01 inventory

## 定位

- 主题：ShadowTLS / TUN TCP corner-case hardening
- 性质：maintenance / protocol-corner quality work
- 形式：10 合 1，但实际实现严格按当前源码事实，只围绕 `ShadowTLS wrapper/detour semantics` 与 `TUN TCP FIN-first / half-close / detach / drain lifecycle seam` 收口
- 非目标：dual-kernel parity completion、恢复 `.github/workflows/*`、推进 `planned.rs` 公共化、public `RuntimePlan`、public `PlannedConfigIR`、generic query API、扩散到 metrics/logging、admin_debug、router/dns、DERP/services 主线

## 开工前复核结论

- 仓库处于 maintenance mode，L1-L25 全部 Closed；`WP-30` 已归档，`ef333bb7` 仍是 archive baseline
- `MT-ADM-01`、`MT-MLOG-01`、`MT-ADP-01`、`MT-PERF-01` 等维护线均已完成；本卡不能把维护工作表述成 parity completion
- 当前工作区有大量无关在制改动；本卡只围住 ShadowTLS / TUN TCP 直接相关文件与 `agents-only` 文档推进，没有回滚或覆盖 unrelated workspace changes
- 当前源码事实下，先复跑得到：
  - `cargo test -p sb-adapters --all-features shadowtls -- --test-threads=1` 暴露 7 个真实失败，全部来自 `crates/sb-adapters/tests/shadowtls_e2e.rs`
  - 失败根因不是 ShadowTLS protocol 本体“完全坏掉”，而是 e2e / register / wrapper 当前口径已经分裂：
    - `connect_detour_stream(...)` 已被建模成 transport-wrapper raw stream seam
    - `tests/shadowtls_e2e.rs` 仍把 requested endpoint 当成必须等于 configured wrapper server
    - Shadowsocks-over-ShadowTLS detour chain 则依赖“requested endpoint 是外层 protocol 语义目标，wrapper 只负责拨 configured server”
  - `cargo test -p sb-adapters --all-features tun_session -- --test-threads=1` 与 `tun_enhanced -- --test-threads=1` 当前通过，但源码仍缺 detached/draining owner seam：
    - `detach()` 直接把 tuple 从 active map 丢掉
    - FIN 后 retransmitted FIN / payload-after-fin 会退回“无 session”路径
    - 这意味着 retransmit 可能误回 RST，payload-after-fin 甚至可能误触发第二次 outbound connect

## 本轮源码收口

### 1. ShadowTLS wrapper / requested-endpoint 语义统一

- `crates/sb-adapters/src/outbound/shadowtls.rs`
  - 去掉 `validate_detour_endpoint(...)` 这类把 requested endpoint 硬绑到 configured wrapper server 的 guard
  - `connect_detour_stream(...)` 现在显式表达：拨 configured wrapper server 做 camouflage handshake，然后把 handshake 后 raw stream 暴露给 requested endpoint 对应的上层 consumer
  - debug trace 也改成“configured wrapper server + requested endpoint”双字段，不再继续误导成同一个 endpoint

### 2. ShadowTLS bridge owner / lifecycle seam

- `crates/sb-adapters/src/outbound/shadowtls.rs`
  - v2 / v3 bridge 由原先裸 `tokio::spawn(...)` + 返回 `DuplexStream` 改成 `OwnedBridgeStream`
  - `OwnedBridgeStream` 显式持有 `JoinHandle<()>`
  - stream drop 时 abort bridge task，不再留下无主后台桥接任务
  - 新增 pin：`dropping_owned_bridge_stream_aborts_bridge_task`

### 3. register / e2e / detour-chain fixture 口径统一

- `crates/sb-adapters/src/register.rs`
  - ShadowTLS register test 改成验证 `connect_io()` 暴露 wrapped raw stream，而不是“只允许 configured wrapper endpoint”
- `crates/sb-adapters/tests/shadowtls_e2e.rs`
  - e2e 测试重新命名并改断言，明确 requested endpoint 与 configured wrapper endpoint 是两层语义
  - `shadowtls_shadowsocks_detour_chain_*` 与 wrapper tests 现在使用同一套语义，不再互相打架

### 4. TUN TCP detached/draining owner seam

- `crates/sb-adapters/src/inbound/tun_session.rs`
  - `TcpSessionManager` 从单一 `sessions` map 扩成：
    - `active_sessions`
    - `detached_sessions`
  - `detach()` 不再简单删除，而是把 half-close 中的 session 转移到 detached/draining registry
  - relay task 结束时同时清理 active / detached state
  - `remove()` 现在也能统一处理 detached session

### 5. TUN TCP FIN-first / payload-after-fin 语义收口

- `crates/sb-adapters/src/inbound/tun_enhanced.rs`
  - `bootstrap_tcp_session(...)` 新增 detached-session 分支
  - detached state 下：
    - ACK 继续更新已知 server ack state，但不重开连接
    - retransmitted FIN 继续回 FIN-ACK，不误回 RST
    - payload-after-fin 显式回 RST，且不再重连 outbound
    - RST 统一走 `session_manager.remove(...)`
  - active-session RST 路径去掉重复 `initiate_close()`，只保留单一 owner close 入口

## 本轮 10 合 1 实际切口

- `crates/sb-adapters/src/outbound/shadowtls.rs`
- `crates/sb-adapters/src/register.rs`
- `crates/sb-adapters/tests/shadowtls_e2e.rs`
- `crates/sb-adapters/src/inbound/tun_session.rs`
- `crates/sb-adapters/src/inbound/tun_enhanced.rs`
- 与上述直接相关的 ShadowTLS v2/v3 bridge owner test
- 与上述直接相关的 detour/register semantics pin
- 与上述直接相关的 TUN detached/draining registry seam
- 与上述直接相关的 FIN retransmit / payload-after-fin regression pin
- `agents-only/{active_context,workpackage_latest}.md`

## 本轮测试 / pins

- `crates/sb-adapters/src/outbound/shadowtls.rs`
  - `dropping_owned_bridge_stream_aborts_bridge_task`
- `crates/sb-adapters/src/register.rs`
  - `test_shadowtls_outbound_registration_connect_io_exposes_wrapped_raw_stream`
- `crates/sb-adapters/tests/shadowtls_e2e.rs`
  - `shadowtls_detour_wrapper_connects_for_requested_endpoint_via_configured_wrapper`
  - `shadowtls_detour_wrapper_uses_configured_wrapper_for_arbitrary_requested_target`
  - `shadowtls_v2_detour_wrapper_connects_for_requested_endpoint_via_configured_wrapper`
  - `shadowtls_shadowsocks_detour_chain_completes_mock_handshake`
  - `shadowtls_v2_shadowsocks_detour_chain_completes_mock_handshake`
- `crates/sb-adapters/src/inbound/tun_session.rs`
  - `test_detach_moves_session_into_draining_registry`
- `crates/sb-adapters/src/inbound/tun_enhanced.rs`
  - `bootstrap_tcp_session_fin_retransmit_uses_detached_session_state`
  - `bootstrap_tcp_session_payload_after_fin_is_rejected_without_reconnect`

## 验收命令

- `cargo test -p sb-adapters --all-features shadowtls -- --test-threads=1`
- `cargo test -p sb-adapters --all-features tun_session -- --test-threads=1`
- `cargo test -p sb-adapters --all-features tun_enhanced -- --test-threads=1`
- `cargo test -p sb-adapters --all-features register -- --test-threads=1`
- `cargo test -p sb-adapters --all-features --lib -- --test-threads=1`
- `cargo clippy -p sb-adapters --all-features --all-targets -- -D warnings`

## 当前验证结论

- 上述命令已按当前 workspace 事实通过
- 本卡没有把 maintenance 工作误写成 parity completion
- 本卡没有推进 `planned.rs`、public `RuntimePlan`、public `PlannedConfigIR`
- 本卡没有为了让 corner-case 测试过而单纯加 sleep、放宽断言或改成过宽匹配掩盖问题；新增 TUN regressions 明确用“不会重连 / 不会误回 RST / detached state 可复用”来 pin 行为
- 本卡没有把 metrics/logging、admin_debug、router/dns、DERP/services、配置公共化这些无关主题卷进来

## Future Work（高层方向）

- ShadowTLS 若后续继续推进，应围绕少数高层 boundary：
  - typed transport-wrapper contract：wrapper endpoint / requested endpoint / detour consumer metadata 的更明确建模
  - 更宽的 wrapper consumer owner contract（如果 runtime 以后需要比 `connect_io()` 更明确的 wrapper-only surface）
- TUN TCP 若后续继续推进，应围绕少数高层 boundary：
  - detached/draining session 的更系统 grace timeout / simultaneous-close / cleanup policy
  - packet loop 与 session manager 之间更高层的 lifecycle owner 统一
- 当前阶段不值得继续拆很多 ShadowTLS/TUN TCP 小尾巴；本卡结束后，剩余债务应保持高层边界表达
