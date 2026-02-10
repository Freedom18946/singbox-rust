# L5 Compat Matrix (Go / GUI / Rust)

## 控制面契约矩阵（含 case 反查）

| Surface | 语义目标 | Case ID | Env Class | 状态 |
| --- | --- | --- | --- | --- |
| `GET /configs` | 启动配置读取 | `p0_clash_api_contract` | `env_limited` | implemented |
| `PATCH /configs` | 运行模式切换 | `p0_clash_api_contract` | `env_limited` | implemented |
| `GET /proxies` | 代理列表展示 | `p0_clash_api_contract` | `env_limited` | implemented |
| `GET /proxies/{name}/delay` | 延迟探测 | `p0_clash_api_contract` | `env_limited` | implemented |
| `GET /connections` | 连接面板快照 | `p0_clash_api_contract` | `env_limited` | implemented |
| `DELETE /connections/{id}` | 关闭连接可观测 | `p0_clash_api_contract` | `env_limited` | implemented |
| `WS /memory` | 内存流图表 | `p0_clash_api_contract` | `env_limited` | implemented |
| `WS /traffic` | 流量流图表 | `p0_clash_api_contract` | `env_limited` | implemented |
| `WS /connections` | 连接流推送 | `p0_clash_api_contract` / `p2_connections_ws_*` | `env_limited`/`strict` | implemented |
| `WS /logs` | 日志流推送 | `p0_clash_api_contract` | `env_limited` | implemented |
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

## 数据面覆盖矩阵（协议 × 故障/恢复）

| 协议/路径 | 连通 | 故障 | 恢复 | Jitter | Case ID |
| --- | --- | --- | --- | --- | --- |
| HTTP via SOCKS | yes | disconnect/delay | reconnect/multi-flap | yes | `p1_rust_core_http_via_socks` `p1_fault_*` `p1_recovery_*` `p1_fault_jitter_http_via_socks` `p1_recovery_jitter_http_via_socks` |
| TCP via SOCKS | yes | planned | planned | planned | `p1_rust_core_tcp_via_socks` |
| UDP via SOCKS | yes | planned | planned | planned | `p1_rust_core_udp_via_socks` |
| DNS via SOCKS UDP | yes | disconnect | reconnect | planned | `p1_rust_core_dns_via_socks` `p1_recovery_dns_disconnect_reconnect_via_socks` |
| WS 稳定性 | concurrency | soak | trend gate | planned | `p2_connections_ws_concurrency_suite` `p2_connections_ws_soak_suite` |
| Trojan 协议 | suite | auth fault | recovery/restart | planned | `p2_trojan_*` |
| Shadowsocks 协议 | suite | auth fault | recovery/restart | planned | `p2_shadowsocks_*` |

## 参考实现映射

- Go reference: `experimental/clashapi/*.go`
- Rust reference: `crates/sb-api/src/clash/{handlers.rs,websocket.rs}`
- interop harness: `labs/interop-lab/src/{case_spec.rs,orchestrator.rs,diff_report.rs,upstream.rs}`
