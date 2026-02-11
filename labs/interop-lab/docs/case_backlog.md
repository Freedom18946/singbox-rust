# L5 Case Backlog

联测执行基线与实战流程见：`labs/interop-lab/docs/REALWORLD-TEST-PLAN.md`。

## 统计快照（2026-02-11）

- 总 case：57
- `strict`：50
- `env_limited`：6
- `env_limited` → `strict` 升级：1（`p0_clash_api_contract` → `p0_clash_api_contract_strict`）
- 状态口径：`implemented` / `planned` / `blocked`

## P0 (gating)

| Case ID | Goal | Env Class | Status |
| --- | --- | --- | --- |
| `l6_local_harness_smoke` | self-contained harness smoke (no external kernel) | `strict` | implemented |
| `p0_subscription_json` | JSON `outbounds` parser | `strict` | implemented |
| `p0_subscription_yaml` | YAML `proxies` parser | `strict` | implemented |
| `p0_subscription_base64` | Base64 mixed-link parser | `strict` | implemented |
| `p0_clash_api_contract` | replay GUI P0 HTTP/WS contract against Go+Rust APIs | `env_limited` | implemented |
| `p0_clash_api_contract_strict` | strict version of P0 contract (no external kernel) | `strict` | implemented |

## P1 (contract + dataplane)

### 控制面契约

| Case ID | Goal | Env Class | Status |
| --- | --- | --- | --- |
| `p1_auth_negative_wrong_token` | wrong token HTTP/WS rejection | `env_limited` | implemented |
| `p1_auth_negative_missing_token` | missing token HTTP/WS rejection | `env_limited` | implemented |
| `p1_optional_endpoints_contract` | providers/rules/script/profile response semantics | `env_limited` | implemented |
| `p1_lifecycle_restart_reload_replay` | restart + reload health semantics | `strict` | implemented |

### 数据面连通/故障/恢复

| Case ID | Goal | Env Class | Status |
| --- | --- | --- | --- |
| `p1_rust_core_http_via_socks` | HTTP 核心链路连通 | `strict` | implemented |
| `p1_rust_core_tcp_via_socks` | TCP 核心链路连通 | `strict` | implemented |
| `p1_rust_core_udp_via_socks` | UDP 核心链路连通 | `strict` | implemented |
| `p1_rust_core_dns_via_socks` | DNS 核心链路连通 | `strict` | implemented |
| `p1_fault_disconnect_http_via_socks` | upstream disconnect 故障可观测 | `strict` | implemented |
| `p1_fault_delay_http_via_socks` | upstream delay 超时可观测 | `strict` | implemented |
| `p1_fault_jitter_http_via_socks` | jitter 故障可观测 | `strict` | implemented |
| `p1_recovery_disconnect_reconnect_http_via_socks` | 断开后重连恢复 | `strict` | implemented |
| `p1_recovery_multi_flap_http_via_socks` | 多次抖动恢复 | `strict` | implemented |
| `p1_recovery_dns_disconnect_reconnect_via_socks` | DNS 断开后恢复 | `strict` | implemented |
| `p1_recovery_jitter_http_via_socks` | jitter 清除后恢复 | `strict` | implemented |
| `p1_fault_disconnect_tcp_via_socks` | TCP upstream disconnect 故障可观测 | `strict` | implemented |
| `p1_fault_delay_tcp_via_socks` | TCP upstream delay 超时可观测 | `strict` | implemented |
| `p1_fault_jitter_tcp_via_socks` | TCP jitter 故障可观测 | `strict` | implemented |
| `p1_recovery_disconnect_reconnect_tcp_via_socks` | TCP 断开后重连恢复 | `strict` | implemented |
| `p1_fault_disconnect_udp_via_socks` | UDP upstream disconnect 故障可观测 | `strict` | implemented |
| `p1_fault_delay_udp_via_socks` | UDP upstream delay 超时可观测 | `strict` | implemented |
| `p1_fault_jitter_udp_via_socks` | UDP jitter 故障可观测 | `strict` | implemented |
| `p1_recovery_disconnect_reconnect_udp_via_socks` | UDP 断开后重连恢复 | `strict` | implemented |
| `p1_fault_delay_dns_via_socks` | DNS upstream delay 超时可观测 | `strict` | implemented |
| `p1_fault_jitter_dns_via_socks` | DNS jitter 故障可观测 | `strict` | implemented |
| `p1_fault_disconnect_ws_upstream` | WS upstream disconnect 故障可观测 | `strict` | implemented |
| `p1_fault_delay_ws_upstream` | WS upstream delay 超时可观测 | `strict` | implemented |
| `p1_fault_jitter_ws_upstream` | WS jitter 故障可观测 | `strict` | implemented |
| `p1_recovery_disconnect_reconnect_ws_upstream` | WS 断开后重连恢复 | `strict` | implemented |
| `p1_fault_disconnect_tls_upstream` | TLS upstream disconnect 故障可观测 | `strict` | implemented |
| `p1_fault_delay_tls_upstream` | TLS upstream delay 超时可观测 | `strict` | implemented |
| `p1_fault_jitter_tls_upstream` | TLS jitter 故障可观测 | `strict` | implemented |
| `p1_recovery_disconnect_reconnect_tls_upstream` | TLS 断开后重连恢复 | `strict` | implemented |

### GUI Replay（L7）

| Case ID | Goal | Env Class | Status |
| --- | --- | --- | --- |
| `p1_gui_full_boot_replay` | WsParallel + HTTP GUI 启动全序列回放 | `strict` | implemented |
| `p1_gui_proxy_switch_replay` | selector PUT 切换回放 | `strict` | implemented |
| `p1_gui_proxy_delay_replay` | proxy delay 测试回放 | `strict` | implemented |
| `p1_gui_group_delay_replay` | group delay 测试回放 | `strict` | implemented |
| `p1_gui_ws_reconnect_behavior` | WS 重连行为（kernel restart 后） | `strict` | implemented |
| `p1_gui_connections_tracking` | connections tracking 断言 (chains/rule) | `strict` | implemented |
| `p1_gui_full_session_replay` | 完整用户会话端到端回放 capstone | `strict` | implemented |

### 订阅样本治理

| Case ID | Goal | Env Class | Status |
| --- | --- | --- | --- |
| `p1_subscription_file_urls` | URL 样本集合解析与环境归因 | `env_limited` | implemented |

## P2 (protocol + stress)

| Case ID | Goal | Env Class | Status |
| --- | --- | --- | --- |
| `p2_trojan_protocol_suite` | Trojan protocol suite | `strict` | implemented |
| `p2_trojan_fault_recovery_suite` | Trojan fault/recovery semantics | `strict` | implemented |
| `p2_trojan_fault_recovery_concurrency_suite` | Trojan 并发恢复门限 | `strict` | implemented |
| `p2_trojan_network_restart_suite` | Trojan 重启/抖动恢复 | `strict` | implemented |
| `p2_shadowsocks_protocol_suite` | Shadowsocks protocol suite | `strict` | implemented |
| `p2_shadowsocks_fault_recovery_suite` | Shadowsocks fault/recovery semantics | `strict` | implemented |
| `p2_shadowsocks_fault_recovery_concurrency_suite` | Shadowsocks 并发恢复门限 | `strict` | implemented |
| `p2_shadowsocks_network_restart_suite` | Shadowsocks 重启/抖动恢复 | `strict` | implemented |
| `p2_connections_ws_concurrency_suite` | `/connections` WS 并发稳定性 | `strict` | implemented |
| `p2_connections_ws_soak_suite` | `/connections` WS 长时 soak | `strict` | implemented |

## 协议 × 故障类型矩阵（L5.2.1）

| 协议 | disconnect | delay | jitter | recovery |
| --- | --- | --- | --- | --- |
| HTTP | implemented | implemented | implemented | implemented |
| TCP | implemented | implemented | implemented | implemented |
| UDP | implemented | implemented | implemented | implemented |
| DNS | implemented | implemented | implemented | implemented |
| WS | implemented | implemented | implemented | implemented |
| TLS | implemented | implemented | implemented | implemented |

## 基础设施新增（L5/L7）

| 组件 | 描述 | 状态 |
| --- | --- | --- |
| `TrafficAction::WsRoundTrip` | WS round-trip traffic action | implemented |
| `TrafficAction::TlsRoundTrip` | TLS round-trip traffic action | implemented |
| `GuiStep::WsParallel` | 并行 WS 流采集 GUI step | implemented |
| TCP/TLS echo delay injection | echo 服务端延迟注入 | implemented |
| `post_traffic_gui_sequence` | CaseSpec 字段：traffic 后 GUI 序列 | implemented |
| `connections.count` / `connections.N.rule` / `connections.N.chains` | 连接断言键 | implemented |
| `attribution.rs` | env_limited 失败归因分类模块 | implemented |
| `aggregate_trend_report.sh` | 趋势报告聚合脚本 | implemented |
| `interop-lab-smoke.yml` | CI smoke workflow | implemented |
| `interop-lab-nightly.yml` | CI nightly workflow | implemented |

## 阻塞项（Blockers）

| Blocker ID | 描述 | 影响 case | 状态 |
| --- | --- | --- | --- |
| `BLK-L5-URL-RISK` | 部分订阅 URL 返回 403/429/挑战页 | `p1_subscription_file_urls` | active (env-limited) |
| `BLK-L5-EXT-ENDPOINTS` | `env_limited` case 依赖外部 Go/Rust API 参数 | `p0_clash_api_contract`、`p1_auth_negative_*`、`p1_optional_endpoints_contract` | active (expected) |

## 执行顺序（固定）

1. `strict` P0 + P1 控制面/数据面回归（含全协议故障矩阵）。
2. P1 GUI replay 回归（L7 启动序列 + 切换序列）。
3. P2 协议层与 WS 长稳回归。
4. `env_limited` 样本补测并归因入档。
