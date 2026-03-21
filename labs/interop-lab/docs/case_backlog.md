# L5 Case Backlog

联测执行基线与实战流程见：`labs/interop-lab/docs/REALWORLD-TEST-PLAN.md`。

## 统计快照（2026-02-12）

- 总 case：83
- `strict`：72
- `env_limited`：10
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
| `p0_clash_api_contract_strict` | strict version of P0 contract (self-managed dual kernel) + repeated `/proxies` p95 latency contract | `strict` | implemented (`kernel_mode: both`) |

## P1 (contract + dataplane)

### 控制面契约

| Case ID | Goal | Env Class | Status |
| --- | --- | --- | --- |
| `p1_auth_negative_wrong_token` | wrong token HTTP/WS rejection | `env_limited` | implemented |
| `p1_auth_negative_missing_token` | missing token HTTP/WS rejection | `env_limited` | implemented |
| `p1_optional_endpoints_contract` | providers/rules/script/profile response semantics | `env_limited` | implemented |
| `p1_version_endpoint_contract` | `/version` 返回带 version 字段的 JSON | `strict` | implemented (`kernel_mode: both`) |
| `p1_dns_query_endpoint_contract` | `/dns/query` 返回 200 且可解析域名 | `strict` | implemented (`kernel_mode: both`) |
| `p1_lifecycle_restart_reload_replay` | restart + reload health semantics，并验证 shutdown 后同端口 restart 恢复 | `strict` | implemented (`kernel_mode: both`) |
| `p1_graceful_shutdown_drain` | 优雅关闭时活跃 TCP 连接一致性验证 | `strict` | implemented (`kernel_mode: both`) |

### 数据面连通/故障/恢复

| Case ID | Goal | Env Class | Status |
| --- | --- | --- | --- |
| `p1_rust_core_http_via_socks` | HTTP 核心链路连通 + repeated HTTP via SOCKS p95 latency contract | `strict` | implemented (`kernel_mode: both`) |
| `p1_http_connect_via_http_proxy` | HTTP CONNECT 隧道链路连通 | `strict` | implemented (`kernel_mode: both`) |
| `p1_mixed_inbound_dual_protocol` | 混合入站端口自动检测 SOCKS5 和 HTTP CONNECT | `strict` | implemented (`kernel_mode: both`) |
| `p1_selector_switch_traffic_replay` | selector 从 block 切到 direct 后流量恢复，并在 reload 后保持选中态 | `strict` | implemented (`kernel_mode: both`) |
| `p1_urltest_auto_select_replay` | URLTest 组健康检查后自动选择最低延迟出站 | `strict` | implemented (`kernel_mode: both`) |
| `p1_rust_core_tcp_via_socks` | TCP 核心链路连通 | `strict` | implemented (`kernel_mode: both`) |
| `p1_rust_core_udp_via_socks` | UDP 核心链路连通 | `strict` | implemented (`kernel_mode: both`) |
| `p1_rust_core_dns_via_socks` | DNS 核心链路连通 | `strict` | implemented (`kernel_mode: both`) |
| `p1_dns_cache_ttl_via_socks` | DNS 缓存命中保持于 TTL 内，并在 TTL 过期后重新查询 | `strict` | implemented (`kernel_mode: both`) |
| `p1_fakeip_dns_query_contract` | FakeIP DNS 查询返回池内地址 | `strict` | implemented (`kernel_mode: both`) |
| `p1_fakeip_cache_flush_contract` | FakeIP cache flush 后分配序列重置 | `strict` | implemented (`kernel_mode: both`) |
| `p1_ip_cidr_rule_via_socks` | IP-CIDR 路由命中优先于 final block | `strict` | implemented (`kernel_mode: both`) |
| `p1_domain_rule_via_socks` | 域名规则精确匹配 FQDN 优先于 final block | `strict` | implemented (`kernel_mode: both`) |
| `p1_block_outbound_via_socks` | Block outbound 拒绝 SOCKS TCP CONNECT | `strict` | implemented (`kernel_mode: both`) |
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
| `p1_gui_full_boot_replay` | WsParallel + HTTP GUI 启动全序列回放 | `strict` | implemented (`kernel_mode: both`) |
| `p1_gui_proxy_switch_replay` | selector PUT 切换回放 | `strict` | implemented (`kernel_mode: both`) |
| `p1_gui_proxy_delay_replay` | proxy delay 测试回放 | `strict` | implemented (`kernel_mode: both`) |
| `p1_gui_group_delay_replay` | group delay 测试回放 | `strict` | implemented |
| `p1_gui_ws_reconnect_behavior` | WS 重连行为（kernel restart 后） | `strict` | implemented (`kernel_mode: both`) |
| `p1_gui_connections_tracking` | connections tracking 断言 (chains/rule) | `strict` | implemented (`kernel_mode: both`) |
| `p1_gui_full_session_replay` | 完整用户会话端到端回放 capstone | `strict` | implemented (`kernel_mode: both`) |

### 迁移兼容 / Deprecation（L12）

| Case ID | Goal | Env Class | Status |
| --- | --- | --- | --- |
| `p1_deprecated_wireguard_outbound` | WireGuard outbound → endpoint 迁移检测 | `strict` | implemented |
| `p1_deprecated_v1_style_config` | V1→V2 字段重命名检测（tag→name, server_port→port, socks5→socks 等） | `strict` | implemented |
| `p1_deprecated_mixed_config` | 混合配置检测（flat conditions→when wrapper, default_outbound→route.default 等） | `strict` | implemented |

### 服务安全（L13）

| Case ID | Goal | Env Class | Status |
| --- | --- | --- | --- |
| `p1_clash_api_auth_enforcement` | Clash API auth enforcement: 无 token→401, Bearer→200, 错误→401 | `strict` | implemented |
| `p1_service_failure_isolation` | 单服务故障不阻塞核心启动，Clash API 可达 | `strict` | implemented (Rust-only diagnostic; not promotable with current harness/API model: no real broken-service config and `/services/health` is still static) |

### TLS 高级能力（L14）

| Case ID | Goal | Env Class | Status |
| --- | --- | --- | --- |
| `p1_tls_cert_store_mozilla` | mozilla 模式 TLS 连接验证 | `strict` | implemented |
| `p1_tls_cert_store_none_custom_ca` | none 模式+自定义 CA 验证 | `env_limited` | implemented |
| `p1_tls_fragment_activation` | TLS fragment 激活验证 | `strict` | implemented |
| `p1_tls_fragment_wiring` | TLS fragment 配置→运行时接线验证 | `strict` | implemented |

### CLI 工具 (L15)

| Case ID | Goal | Env Class | Status |
| --- | --- | --- | --- |
| `p1_cli_generate_uuid_format` | generate uuid 产生合法 UUID v4 | `strict` | implemented |
| `p1_cli_generate_rand_base64` | generate rand 16 --base64 产生 24 字符 base64 | `strict` | implemented |
| `p1_cli_ruleset_convert_adguard` | rule-set convert --type adguard 转换 AdGuard filter 含 domain_suffix | `strict` | implemented |
| `p1_cli_ech_keypair_pem_format` | generate ech-keypair 产生 ECH CONFIGS/KEYS PEM | `strict` | implemented |

### 订阅样本治理

| Case ID | Goal | Env Class | Status |
| --- | --- | --- | --- |
| `p1_subscription_file_urls` | URL 样本集合解析与环境归因 | `env_limited` | implemented |

### 大包传输（L8.1.1）

| Case ID | Goal | Env Class | Status |
| --- | --- | --- | --- |
| `p1_dataplane_large_payload_tcp` | 128KB TCP echo via SOCKS5 + hash 校验 | `strict` | implemented |
| `p1_dataplane_large_payload_udp` | 8KB UDP echo via SOCKS5 + hash 校验 | `strict` | implemented |
| `p1_dataplane_large_payload_http` | 256KB HTTP body echo via SOCKS5 | `strict` | implemented |

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

### 协议单测编入（L8.1.2）

| Case ID | Goal | Env Class | Status |
| --- | --- | --- | --- |
| `p2_protocol_unit_shadowsocks` | SS 编解码 cargo test 编入 | `strict` | implemented |
| `p2_protocol_unit_vmess` | VMess 编解码 cargo test 编入 | `strict` | implemented |

### 多出站拓扑（L8.2.1）

| Case ID | Goal | Env Class | Status |
| --- | --- | --- | --- |
| `p2_dataplane_chain_proxy` | SOCKS5→SOCKS5→direct 双跳连通 | `strict` | implemented (`kernel_mode: both`) |

### 订阅容错（L9.1.1）

| Case ID | Goal | Env Class | Status |
| --- | --- | --- | --- |
| `p2_subscription_malformed_json` | 恶意 JSON 输入优雅报错 | `strict` | implemented |
| `p2_subscription_truncated_base64` | 截断 base64 输入处理 | `strict` | implemented |
| `p2_subscription_empty_input` | 空输入优雅报错 | `strict` | implemented |
| `p2_subscription_unknown_protocol` | 未知协议链接提取 | `strict` | implemented |

### 双核对照（L10.3.1）

| Case ID | Goal | Env Class | Status |
| --- | --- | --- | --- |
| `p2_connections_ws_soak_dual_core` | WS soak 双核对照 + 自动 diff | `strict` | implemented |

### 性能基准 (L16)

| Case ID | Goal | Env Class | Status |
| --- | --- | --- | --- |
| `p2_bench_socks5_throughput` | SOCKS5 throughput Criterion benchmark exit 0 | `env_limited` | implemented |
| `p2_bench_shadowsocks_throughput` | Shadowsocks throughput Criterion benchmark exit 0 | `env_limited` | implemented |

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
| `go_collector.rs` | Go Clash API 被动快照采集（L10.1.1） | implemented |
| `leak_detector.rs` | 资源泄漏检测（内存 + FD 线性回归）（L10.2.2） | implemented |
| `GoApiConfig` + dual-kernel diff | orchestrator 双核快照 + 自动 diff（L10.1.2） | implemented |
| `connection_mismatches` / `memory_mismatches` | diff 维度扩展（L10.2.1） | implemented |
| `payload_size` / `resolve_payload()` | 大包 payload 生成 + hash 校验（L8.1.1） | implemented |
| `save_go_snapshot_to_dir()` | Go 快照直接目录保存 | implemented |
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
