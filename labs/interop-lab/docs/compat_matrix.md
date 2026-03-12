# L5 Compat Matrix (Go / GUI / Rust)

## 控制面契约矩阵（含 case 反查）

| Surface | 语义目标 | Case ID | Env Class | 状态 |
| --- | --- | --- | --- | --- |
| `GET /configs` | 启动配置读取 | `p0_clash_api_contract` / `p0_clash_api_contract_strict` / `p1_gui_full_boot_replay` | `env_limited`/`strict` | implemented (`p0_clash_api_contract_strict` = both, `p1_gui_full_boot_replay` = both) |
| `PATCH /configs` | 运行模式切换 | `p0_clash_api_contract` / `p0_clash_api_contract_strict` | `env_limited`/`strict` | implemented (`p0_clash_api_contract_strict` = both) |
| `GET /proxies` | 代理列表展示 | `p0_clash_api_contract` / `p1_gui_proxy_switch_replay` / `p1_gui_full_boot_replay` / `p1_gui_full_session_replay` | `env_limited`/`strict` | implemented (`p1_gui_proxy_switch_replay` = both, `p1_gui_full_boot_replay` = both, `p1_gui_full_session_replay` = both) |
| `PUT /proxies/{group}` | selector 切换 | `p1_gui_proxy_switch_replay` | `strict` | implemented (`p1_gui_proxy_switch_replay` = both) |
| `GET /proxies/{name}/delay` | 延迟探测 | `p0_clash_api_contract` / `p1_gui_proxy_delay_replay` | `env_limited`/`strict` | implemented (`p1_gui_proxy_delay_replay` = both) |
| `GET /meta/group/{name}/delay` | 组延迟探测 | `p1_gui_group_delay_replay` | `strict` | implemented |
| `GET /connections` | 连接面板快照 | `p0_clash_api_contract` / `p0_clash_api_contract_strict` / `p1_gui_connections_tracking` / `p1_gui_full_session_replay` | `env_limited`/`strict` | implemented (`p0_clash_api_contract_strict` = both, `p1_gui_full_session_replay` = both) |
| `DELETE /connections/{id}` | 关闭连接可观测 | `p0_clash_api_contract` / `p0_clash_api_contract_strict` | `env_limited`/`strict` | implemented (`p0_clash_api_contract_strict` = both) |
| `GET /version` | 版本信息可读 | `p1_version_endpoint_contract` | `strict` | implemented (`p1_version_endpoint_contract` = both) |
| `WS /memory` | 内存流图表 | `p0_clash_api_contract` / `p0_clash_api_contract_strict` / `p1_gui_full_boot_replay` | `env_limited`/`strict` | implemented (`p0_clash_api_contract_strict` = both, `p1_gui_full_boot_replay` = both) |
| `WS /traffic` | 流量流图表 | `p0_clash_api_contract` / `p0_clash_api_contract_strict` / `p1_gui_full_boot_replay` | `env_limited`/`strict` | implemented (`p0_clash_api_contract_strict` = both, `p1_gui_full_boot_replay` = both) |
| `WS /connections` | 连接流推送 | `p0_clash_api_contract` / `p2_connections_ws_*` | `env_limited`/`strict` | implemented |
| `WS /logs` | 日志流推送 | `p0_clash_api_contract` / `p0_clash_api_contract_strict` / `p1_gui_full_boot_replay` | `env_limited`/`strict` | implemented (`p0_clash_api_contract_strict` = both, `p1_gui_full_boot_replay` = both) |
| WS parallel (4 streams) | 4 WS 流并行连接 | `p1_gui_full_boot_replay` / `p0_clash_api_contract_strict` | `strict` | implemented (`p0_clash_api_contract_strict` = both, `p1_gui_full_boot_replay` = both) |
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
| HTTP via SOCKS | yes | disconnect/delay | reconnect/multi-flap | yes | `p1_rust_core_http_via_socks` (both) `p1_fault_*_http_*` `p1_recovery_*_http_*` |
| TCP via SOCKS | yes | disconnect/delay | reconnect | yes | `p1_rust_core_tcp_via_socks` (both) `p1_fault_*_tcp_*` `p1_recovery_*_tcp_*` |
| UDP via SOCKS | yes | disconnect/delay | reconnect | yes | `p1_rust_core_udp_via_socks` (both) `p1_fault_*_udp_*` `p1_recovery_*_udp_*` |
| DNS via SOCKS UDP | yes | disconnect/delay | reconnect | yes | `p1_rust_core_dns_via_socks` (both) `p1_fault_*_dns_*` `p1_recovery_dns_*` |
| Block outbound via SOCKS | reject | — | — | — | `p1_block_outbound_via_socks` (both) |
| WS upstream | — | disconnect/delay | reconnect | yes | `p1_fault_*_ws_*` `p1_recovery_*_ws_*` |
| TLS upstream | — | disconnect/delay | reconnect | yes | `p1_fault_*_tls_*` `p1_recovery_*_tls_*` |
| WS 稳定性 | concurrency | soak | trend gate | dual-core diff | `p2_connections_ws_concurrency_suite` `p2_connections_ws_soak_suite` `p2_connections_ws_soak_dual_core` |
| Trojan 协议 | suite | auth fault | recovery/restart | — | `p2_trojan_*` |
| Shadowsocks 协议 | suite | auth fault | recovery/restart | — | `p2_shadowsocks_*` |
| Large TCP (128KB) | yes | — | — | — | `p1_dataplane_large_payload_tcp` |
| Large UDP (8KB) | yes | — | — | — | `p1_dataplane_large_payload_udp` |
| Large HTTP (256KB) | yes | — | — | — | `p1_dataplane_large_payload_http` |
| Chain proxy (2-hop) | yes | — | — | — | `p2_dataplane_chain_proxy` (both) |

## 行为 Spec 交叉映射（仓库级自动化）

> 说明：本节补齐 `dual_kernel_golden_spec.md` 中“Both/Rust-Only 未挂 case”但已存在仓库级自动化的行为。

| BHV ID | 行为 | 已有测试 |
| --- | --- | --- |
| `BHV-CP-020` | `GET /version returns version info` | `crates/sb-api/tests/clash_http_e2e.rs::test_get_version` |
| `BHV-CP-021` | `GET /dns/query resolves domain` | `crates/sb-api/tests/clash_http_e2e.rs::test_dns_query_valid` |
| `BHV-CP-010` | `/connections streams conn updates` | `crates/sb-api/tests/clash_websocket_e2e.rs::test_connections_ws_single_client_snapshot`, `crates/sb-api/tests/clash_websocket_e2e.rs::test_connections_ws_reflects_close_all_updates` |
| `BHV-DP-008` | `Block outbound rejects connection` | `app/tests/direct_block_outbound_test.rs::test_block_outbound_always_fails` |
| `BHV-DP-012` | `Domain rules match FQDN` | `app/tests/parity_spec_routing.rs::parity_spec_domain_rules_match_fqdn_before_default` |
| `BHV-DP-013` | `IP-CIDR rules match addresses` | `app/tests/parity_spec_routing.rs::parity_spec_ip_cidr_rules_match_addresses_before_default` |
| `BHV-DP-014` | `Sniff detects protocol from payload` | `app/tests/router_sniff_sni_alpn.rs`, `crates/sb-core/tests/tun_sni_routing.rs` |
| `BHV-DP-016` | `FakeIP pool allocates addresses` | `crates/sb-core/tests/router_fakeip_integration.rs` |
| `BHV-DP-017` | `FakeIP cache flush via API` | `crates/sb-api/tests/clash_http_e2e.rs::test_flush_fakeip_cache` |
| `BHV-DP-018` | `DNS result caching and TTL` | `crates/sb-core/tests/dns_cache.rs`, `crates/sb-core/tests/dns_cache_basic.rs`, `crates/sb-core/tests/dns_steady.rs` |
| `BHV-LC-006` | `State preservation across reload` | `crates/sb-core/tests/supervisor_reload_state.rs::selector_selection_survives_reload_via_cache_file` |
| `BHV-LC-007` | `Graceful shutdown drains connections` | `crates/sb-core/tests/shutdown_lifecycle.rs::graceful_shutdown_waits_for_http_connection_to_drain` |
| `BHV-LC-008` | `Connection close notification` | `crates/sb-api/tests/clash_websocket_e2e.rs::test_connections_ws_closes_on_server_shutdown` |
| `BHV-LC-009` | `Resource cleanup on exit` | `crates/sb-core/tests/shutdown_lifecycle.rs::graceful_shutdown_releases_listener_and_clears_runtime_trackers` |
| `BHV-PF-003` | `Peak RSS within bounds` | `labs/interop-lab/src/diff_report.rs::peak_memory_ratio_over_2x_is_mismatch`, `labs/interop-lab/cases/p2_connections_ws_soak_dual_core.yaml` |
| `BHV-PF-002` | `API response p95 latency` | `crates/sb-api/tests/clash_http_e2e.rs::test_get_proxies_p95_latency` |
| `BHV-PF-004` | `WS connection memory stable` | `crates/sb-api/tests/clash_websocket_e2e.rs::test_connections_ws_memory_remains_bounded_over_time` |
| `BHV-SV-005` | `Proxy provider list via API` | `crates/sb-api/tests/clash_http_e2e.rs::test_get_proxy_providers` |
| `BHV-SV-006` | `Rule provider list via API` | `crates/sb-api/tests/clash_http_e2e.rs::test_get_rule_providers` |
| `BHV-SV-007` | `Provider healthcheck via API` | `crates/sb-api/tests/clash_http_e2e.rs::test_healthcheck_proxy_provider` |

## 双核差分维度矩阵（L10.2.1）

| Diff 维度 | 比较内容 | Oracle 支持 | Status |
| --- | --- | --- | --- |
| HTTP status + body_hash | 端点状态码 + 内容摘要 | `ignore_http_paths` | implemented |
| WS frame_count + frame_hash | 帧数 + 帧内容摘要 | `ignore_ws_paths` | implemented |
| Subscription format + node_count | 解析格式 + 节点数 | — | implemented |
| Traffic action success | 流量动作成功率 | — | implemented |
| Connections count + totals | 连接数 + 上下行总量 | `tolerate_counter_jitter` | implemented |
| Memory peak ratio | 内存峰值比率（>2x 报警） | — | implemented |

## 迁移兼容 / Deprecation 覆盖矩阵（L12）

| Deprecation 类型 | 检测目标 | Case ID | 状态 |
| --- | --- | --- | --- |
| WireGuard outbound → endpoint | outbound type "wireguard" 迁移到 endpoint 模型检测 | `p1_deprecated_wireguard_outbound` | implemented |
| V1→V2 field rename: `tag`→`name` | V1 风格 `tag` 字段重命名为 `name` | `p1_deprecated_v1_style_config` | implemented |
| V1→V2 field rename: `server_port`→`port` | V1 风格 `server_port` 重命名为 `port` | `p1_deprecated_v1_style_config` | implemented |
| V1→V2 protocol rename: `socks5`→`socks` | V1 风格 `socks5` 协议名重命名为 `socks` | `p1_deprecated_v1_style_config` | implemented |
| Flat conditions → `when` wrapper | 平铺条件迁移到 `when` 包装结构 | `p1_deprecated_mixed_config` | implemented |
| `default_outbound` → `route.default` | 顶层 `default_outbound` 迁移到 `route.default` | `p1_deprecated_mixed_config` | implemented |
| Non-localhost binding warning | 非 localhost 绑定地址安全警告 | `p1_deprecated_mixed_config` | implemented |

## 服务安全覆盖矩阵（L13）

| 安全能力 | 检测目标 | Case ID | 状态 |
| --- | --- | --- | --- |
| Clash API Bearer auth | token 为空→跳过; 正确→200; 错误→401; 缺失→401 | `p1_clash_api_auth_enforcement` | implemented |
| SSMAPI Bearer auth | ServiceIR.auth_token 独立鉴权 | — (单元测试覆盖) | implemented |
| WS ?token= auth | WebSocket 升级请求 query param 鉴权 | `p1_clash_api_auth_enforcement` | implemented |
| 非 localhost 绑定警告 | 0.0.0.0 绑定 + 无 secret → InsecureBinding | — (单元测试覆盖) | implemented |
| 服务故障隔离 | 单服务启动失败不阻塞其他服务 | `p1_service_failure_isolation` | implemented |
| 健康 API 端点 | GET /services/health 聚合状态 | `p1_service_failure_isolation` | implemented |

## TLS 能力覆盖矩阵（L14）

| TLS 能力 | 实现状态 | Case ID | 状态 |
| --- | --- | --- | --- |
| 证书存储: System | rustls-native-certs + Mozilla 回退 | — (单元测试覆盖) | implemented |
| 证书存储: Mozilla | webpki_roots 内置根证书 | `p1_tls_cert_store_mozilla` | implemented |
| 证书存储: None | 空池 + 仅自定义 CA | `p1_tls_cert_store_none_custom_ca` | implemented |
| 证书目录加载 | 递归 PEM 目录扫描 | — (单元测试覆盖) | implemented |
| 证书热重载 | notify 文件监听 + CancellationToken | — (单元测试覆盖) | implemented |
| TLS fragment | tls_fragment/tls_record_fragment/tls_fragment_fallback_delay | `p1_tls_fragment_activation` / `p1_tls_fragment_wiring` | implemented |
| uTLS 能力诊断 | 非 chrome 指纹 → info 诊断 | — (单元测试覆盖) | implemented |
| ECH 能力诊断 | ECH 配置 → 实现状态 info | — (单元测试覆盖) | implemented |
| REALITY 能力诊断 | REALITY 配置 → 实现状态 info | — (单元测试覆盖) | implemented |

## 参考实现映射

- Go reference: `experimental/clashapi/*.go`
- Rust reference: `crates/sb-api/src/clash/{handlers.rs,websocket.rs}`
- interop harness: `labs/interop-lab/src/{case_spec.rs,orchestrator.rs,diff_report.rs,upstream.rs}`
- Go collector: `labs/interop-lab/src/go_collector.rs`
- Leak detector: `labs/interop-lab/src/leak_detector.rs`
