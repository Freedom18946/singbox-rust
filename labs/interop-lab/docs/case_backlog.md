# L5 Case Backlog

联测执行基线与实战流程见：`labs/interop-lab/docs/REALWORLD-TEST-PLAN.md`。

## P0 (gating)

| Case ID | Goal | Status |
| --- | --- | --- |
| `l6_local_harness_smoke` | self-contained harness smoke (no external kernel) | implemented |
| `p0_clash_api_contract` | replay GUI P0 HTTP/WS contract against Go+Rust APIs | implemented (needs env endpoints) |
| `p0_subscription_json` | JSON `outbounds` parser | implemented |
| `p0_subscription_yaml` | YAML `proxies` parser | implemented |
| `p0_subscription_base64` | Base64 mixed-link parser | implemented |

备注（2026-02-10）：实网订阅 URL 采样显示，标准 Clash 订阅可解析；部分 URL 因站点风控/人机检测返回挑战页，标记为环境限制，不作为当前阻塞项。

## P1 (next)

- `p1_rust_core_http_via_socks`: 本地仿公网 HTTP echo，经 Rust SOCKS 入站转发验证核心链路（implemented）。
- `p1_rust_core_tcp_via_socks`: 本地仿公网 TCP echo，经 Rust SOCKS 入站转发验证核心链路（implemented）。
- `p1_rust_core_udp_via_socks`: 本地仿公网 UDP echo，经 Rust SOCKS UDP ASSOCIATE 转发验证核心链路（implemented）。
- `p1_rust_core_dns_via_socks`: 本地仿公网 DNS stub，经 Rust SOCKS UDP ASSOCIATE 查询验证核心链路（implemented）。
- `p1_fault_disconnect_http_via_socks`: 断开 upstream 后验证 Rust 核心存活且数据面失败可观测（implemented）。
- `p1_fault_delay_http_via_socks`: 上游延迟注入触发超时，验证 Rust 核心存活且失败可观测（implemented）。
- `p1_recovery_disconnect_reconnect_http_via_socks`: 断开后重连 upstream，验证“先失败后恢复”（implemented）。
- `p1_recovery_multi_flap_http_via_socks`: 连续两次 upstream 抖动（断开/重连）后均可恢复，验证恢复稳定性（implemented）。
- `p1_recovery_dns_disconnect_reconnect_via_socks`: DNS UDP 链路在断开/重连后恢复，验证 UDP/DNS 恢复语义（implemented）。
- `p1_subscription_file_urls`: 使用维护中的订阅文件批量解析（implemented）。
- restart/reload lifecycle replay.
- auth negative paths (wrong token / expired token).
- provider/rules/script/profile optional endpoints.
- fault injection matrix for upstream disconnect and jitter.

执行顺序（固定）：
1. 先完成 P1 核心与恢复类场景（当前阶段）。
2. 再进入协议层：Trojan 与 Shadowsocks 的公网仿真联测（不提前）。
3. 最后进入 GUI/Wails 长链路与长稳回归。

协议层首轮进展（2026-02-10）：
- Trojan：`app` 的 net_e2e 协议验证通过（TLS/二进制协议/多用户）。
- Shadowsocks：首轮发现并修复握手兼容、cipher 支持与大包分片问题；修复后 `app` 的两套 net_e2e 协议验证均通过。
- 下一步：将 Trojan/Shadowsocks 协议验证迁移为 `interop-lab` 的 `p2_trojan_*` / `p2_shadowsocks_*` 可编排 case（含 fault/recovery）。

## P2 (later)

- `p2_trojan_fault_recovery_suite`: Trojan 协议“错误凭据失败 -> 正确凭据恢复”语义回放（implemented）。
- `p2_shadowsocks_fault_recovery_suite`: Shadowsocks 协议“错误密码失败 -> 正常密码恢复”语义回放（implemented）。
- `p2_trojan_fault_recovery_concurrency_suite`: Trojan 协议“错凭据注入后并发恢复（>=90%）”语义验证（implemented）。
- `p2_shadowsocks_fault_recovery_concurrency_suite`: Shadowsocks 协议“错密码注入后并发恢复（>=90%）”语义验证（implemented）。
- `p2_trojan_protocol_suite`: 通过 `interop-lab` command action 执行 Trojan 协议 net_e2e 套件（implemented）。
- `p2_shadowsocks_protocol_suite`: 通过 `interop-lab` command action 执行 Shadowsocks 协议 net_e2e 套件（implemented）。
- `p2_connections_ws_concurrency_suite`: `/connections` WebSocket 高并发 + 多波次稳定性（短时 soak）验证（implemented）。
- `p2_trojan_network_restart_suite`: Trojan 实网“同端口下线->重启->恢复 + 连续抖动恢复 + 重启后并发突发恢复”语义验证（implemented）。
- `p2_shadowsocks_network_restart_suite`: Shadowsocks 实网“同端口下线->重启->恢复 + 连续抖动恢复 + 重启后并发突发恢复”语义验证（implemented）。
- `p2_connections_ws_soak_suite`: `/connections` WebSocket 长时 soak 稳定性验证（implemented）。
- `scripts/run_case_trend_gate.sh`: 循环运行 case 并执行趋势门禁（errors/traffic/diff mismatch，支持缺失 diff 容忍）（implemented）。
- full GUI desktop smoke through Wails bridge.
- extreme-scale stress for `/connections` websocket（>1k 并发，nightly）。
