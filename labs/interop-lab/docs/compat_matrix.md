# L5 Compat Matrix (Go / GUI / Rust)

## 控制面契约矩阵（含 case 反查）

| Surface | 语义目标 | Case ID | Env Class | 状态 |
| --- | --- | --- | --- | --- |
| `GET /configs` | 启动配置读取 | `p0_clash_api_contract` / `p0_clash_api_contract_strict` | `env_limited`/`strict` | implemented |
| `PATCH /configs` | 运行模式切换 | `p0_clash_api_contract` / `p0_clash_api_contract_strict` | `env_limited`/`strict` | implemented |
| `GET /proxies` | 代理列表展示 | `p0_clash_api_contract` / `p1_gui_proxy_switch_replay` | `env_limited`/`strict` | implemented |
| `PUT /proxies/{group}` | selector 切换 | `p1_gui_proxy_switch_replay` | `strict` | implemented |
| `GET /proxies/{name}/delay` | 延迟探测 | `p0_clash_api_contract` / `p1_gui_proxy_delay_replay` | `env_limited`/`strict` | implemented |
| `GET /meta/group/{name}/delay` | 组延迟探测 | `p1_gui_group_delay_replay` | `strict` | implemented |
| `GET /connections` | 连接面板快照 | `p0_clash_api_contract` / `p1_gui_connections_tracking` | `env_limited`/`strict` | implemented |
| `DELETE /connections/{id}` | 关闭连接可观测 | `p0_clash_api_contract` | `env_limited` | implemented |
| `WS /memory` | 内存流图表 | `p0_clash_api_contract` / `p1_gui_full_boot_replay` | `env_limited`/`strict` | implemented |
| `WS /traffic` | 流量流图表 | `p0_clash_api_contract` / `p1_gui_full_boot_replay` | `env_limited`/`strict` | implemented |
| `WS /connections` | 连接流推送 | `p0_clash_api_contract` / `p2_connections_ws_*` | `env_limited`/`strict` | implemented |
| `WS /logs` | 日志流推送 | `p0_clash_api_contract` / `p1_gui_full_boot_replay` | `env_limited`/`strict` | implemented |
| WS parallel (4 streams) | 4 WS 流并行连接 | `p1_gui_full_boot_replay` / `p0_clash_api_contract_strict` | `strict` | implemented |
| WS reconnect | kernel restart 后 WS 重连 | `p1_gui_ws_reconnect_behavior` | `strict` | implemented |
| wrong token | 鉴权失败语义 | `p1_auth_negative_wrong_token` | `env_limited` | implemented |
| missing token | 鉴权失败语义 | `p1_auth_negative_missing_token` | `env_limited` | implemented |
| optional endpoints | `/providers` `/rules` `/script` `/profile` 行为可解释 | `p1_optional_endpoints_contract` | `env_limited` | implemented |
| lifecycle restart/reload | 同端口重启与 reload 后控制面可用 | `p1_lifecycle_restart_reload_replay` | `strict` | implemented |

## 订阅解析契约矩阵

| 输入类型 | 目标语义 | Case ID | Env Class | 状态 |
| --- | --- | --- | --- | --- |
| JSON `outbounds` | 解析节点与协议类型 | `p0_subscription_json` | `strict` | implemented |
| YAML `proxies` | 解析节点与协议类型 | `p0_subscription_yaml` | `strict` | implemented |
| Base64 | 自动解码后复用解析链 | `p0_subscription_base64` | `strict` | implemented |
| URL 文件输入 | 样本治理与环境归因 | `p1_subscription_file_urls` | `env_limited` | implemented |
| Malformed JSON | 恶意输入优雅报错 | `p2_subscription_malformed_json` | `strict` | implemented |
| Truncated Base64 | 截断编码处理 | `p2_subscription_truncated_base64` | `strict` | implemented |
| Empty input | 空输入报错 | `p2_subscription_empty_input` | `strict` | implemented |
| Unknown protocol | 未知协议链接提取 | `p2_subscription_unknown_protocol` | `strict` | implemented |

## 数据面覆盖矩阵（协议 × 故障/恢复）

| 协议/路径 | 连通 | 故障 | 恢复 | Jitter | Case ID |
| --- | --- | --- | --- | --- | --- |
| HTTP via SOCKS | yes | disconnect/delay | reconnect/multi-flap | yes | `p1_rust_core_http_via_socks` `p1_fault_*_http_*` `p1_recovery_*_http_*` |
| TCP via SOCKS | yes | disconnect/delay | reconnect | yes | `p1_rust_core_tcp_via_socks` `p1_fault_*_tcp_*` `p1_recovery_*_tcp_*` |
| UDP via SOCKS | yes | disconnect/delay | reconnect | yes | `p1_rust_core_udp_via_socks` `p1_fault_*_udp_*` `p1_recovery_*_udp_*` |
| DNS via SOCKS UDP | yes | disconnect/delay | reconnect | yes | `p1_rust_core_dns_via_socks` `p1_fault_*_dns_*` `p1_recovery_dns_*` |
| WS upstream | — | disconnect/delay | reconnect | yes | `p1_fault_*_ws_*` `p1_recovery_*_ws_*` |
| TLS upstream | — | disconnect/delay | reconnect | yes | `p1_fault_*_tls_*` `p1_recovery_*_tls_*` |
| WS 稳定性 | concurrency | soak | trend gate | — | `p2_connections_ws_concurrency_suite` `p2_connections_ws_soak_suite` |
| Trojan 协议 | suite | auth fault | recovery/restart | — | `p2_trojan_*` |
| Shadowsocks 协议 | suite | auth fault | recovery/restart | — | `p2_shadowsocks_*` |
| Large TCP (128KB) | yes | — | — | — | `p1_dataplane_large_payload_tcp` |
| Large UDP (8KB) | yes | — | — | — | `p1_dataplane_large_payload_udp` |
| Large HTTP (256KB) | yes | — | — | — | `p1_dataplane_large_payload_http` |
| Chain proxy (2-hop) | yes | — | — | — | `p2_dataplane_chain_proxy` |

## 双核差分维度矩阵（L10.2.1）

| Diff 维度 | 比较内容 | Oracle 支持 | Status |
| --- | --- | --- | --- |
| HTTP status + body_hash | 端点状态码 + 内容摘要 | `ignore_http_paths` | implemented |
| WS frame_count + frame_hash | 帧数 + 帧内容摘要 | `ignore_ws_paths` | implemented |
| Subscription format + node_count | 解析格式 + 节点数 | — | implemented |
| Traffic action success | 流量动作成功率 | — | implemented |
| Connections count + totals | 连接数 + 上下行总量 | `tolerate_counter_jitter` | implemented |
| Memory peak ratio | 内存峰值比率（>2x 报警） | — | implemented |

## 参考实现映射

- Go reference: `experimental/clashapi/*.go`
- Rust reference: `crates/sb-api/src/clash/{handlers.rs,websocket.rs}`
- interop harness: `labs/interop-lab/src/{case_spec.rs,orchestrator.rs,diff_report.rs,upstream.rs}`
- Go collector: `labs/interop-lab/src/go_collector.rs`
- Leak detector: `labs/interop-lab/src/leak_detector.rs`
