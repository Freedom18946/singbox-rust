# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护
> **优先级**：AI 启动时优先读取此文件

---

## 🔗 战略链接

**当前阶段**: **L4 治理闭环执行中 + L5 联测仿真已开工**（L1 ✅ Closed, L2 ✅ Closed；功能对齐已完成）
**注**：历史 L3.1~L3.5 为服务补全/连接增强编号，现归并到 L2/M2.4；L3 仅指质量里程碑（M3.1~M3.3）。
**Parity（权威口径）**: 99.52% (208/209)，见 `agents-only/02-reference/GO_PARITY_MATRIX.md`（2026-02-10 Recalibration）
**Remaining**: 1（`PX-015` Linux runtime/system bus 实机验证）
**Tests**: 1492+ passed；boundary gate snapshot (2026-02-10): `check-boundaries.sh` pass（V4a=24 <= 25）

### 联测运行约束（2026-02-10 新增）

- Go 版本 sing-box + GUI + TUN 为网络基础，联测期间不得中断或替换。
- Rust 内核仅作并行对照，默认使用独立 API 端口，不接管现网路由。
- 每轮 Rust 联测后必须回收进程并确认端口释放，避免干扰用户侧网络。
- 实战场景清单见：`labs/interop-lab/docs/REALWORLD-TEST-PLAN.md`。

### 规划增量（2026-02-11 新增）

- 已导入并阅读 Go 版本功能分析资料：`agents-only/dump/go-version-analysis/2026-02-11-intake/sing-box-core-specs/`。
- 基于导入资料新增下一阶段工作包规划：`agents-only/03-planning/08-L12-L14-GO-SPECS-WORKPACKAGES.md`。
- 规划主轴：迁移兼容治理（L12）→ Services 安全与生命周期（L13）→ TLS/Endpoint 高级能力与趋势门禁 CI 化（L14）。

### L5/L6 二级/三级实现增量（2026-02-11 新增）

- `interop-lab` 已完成 `CaseSpec` 扩展：`tags/env_class/owner`（兼容老 case）。
- `TrafficAction` 新增：`kernel_control(restart/reload)`、`fault_jitter`。
- `AssertionSpec` 新增算子：`gt/gte/lt/lte/contains/regex`，并支持 `ws.*.frame_count`、`errors.count`、`subscription.node_count`、`traffic.*.detail.*`。
- `diff_report` 已接线 `oracle.ignore_http_paths` / `oracle.ignore_ws_paths` / `counter_jitter_abs`，并输出 ignored 统计与 `gate_score`。
- 新增 P1 case：`p1_auth_negative_*`、`p1_optional_endpoints_contract`、`p1_lifecycle_restart_reload_replay`、`p1_fault_jitter_http_via_socks`、`p1_recovery_jitter_http_via_socks`。
- CI 状态更新：`interop-lab-smoke` 已切到 `strict`；`interop-lab-nightly` 已覆盖 `strict + env_limited`。

### 已关闭里程碑

| 里程碑 | 关闭日期 | 内容 |
|--------|---------|------|
| **L1 架构整固** | 2026-02-07 | M1.1 + M1.2 + M1.3，check-boundaries.sh exit 0 |
| **L2 功能对齐** | 2026-02-08 | Tier 1 (L2.1-L2.5) + Tier 2 (L2.6-L2.10)，88% → 99% parity |

### 关键参考

- **Clash API 审计报告**: `agents-only/05-analysis/CLASH-API-AUDIT.md`
- **L2 缺口分析**: `agents-only/05-analysis/L2-PARITY-GAP-ANALYSIS.md`
- **DNS 栈分析**: `agents-only/05-analysis/L2.10-DNS-STACK-ANALYSIS.md`
- **L4 开工前置分析**: `agents-only/05-analysis/L4-PREWORK-INFO.md`
- **L4 质量复验报告**: `reports/L4_QUALITY_RECHECK_2026-02-10.md`
- **PX-015 Linux 验证记录**: `reports/PX015_LINUX_VALIDATION_2026-02-10.md`
- **L5-L11 联测仿真计划（实施版）**: `agents-only/03-planning/07-L5-L11-INTEROP-LAB-PLAN.md`
- **历史 L3 Scope（服务补全）**: 见下方（已并入 M2.4）

---

## ✅ 最新完成：L5/L6 联测底座首版入库（interop-lab）

**日期**: 2026-02-10

**完成项**:
- 新增 `labs/interop-lab` workspace 子项目，提供 `CaseSpec`/`NormalizedSnapshot`/CLI
- 已实现 `case list/run/diff` 与 `report open` 命令面
- 已落地 upstream 仿真器（HTTP/TCP/UDP/WS/DNS/TLS）与 traffic plan 执行器
- 已落地 GUI 回放（HTTP/WS）与订阅解析（JSON/YAML/Base64）基础路径

**待补项**:
- 扩展 jitter/recovery 到 TCP/UDP/WS/TLS 组合矩阵
- 增强 env-limited 失败归因与趋势报告聚合

## ✅ 最新完成：Rust 核心链路实战联测（仿公网 upstream）

**日期**: 2026-02-10

**完成项**:
- 修复 CLI 运行路径适配器未注册问题：`app/src/run_engine.rs` 在 `Supervisor::start` 前补 `sb_adapters::register_all()`。
- 新增 `interop-lab` 核心链路 case：`p1_rust_core_http_via_socks`。
  - 启动 Rust 内核（独立端口）+ SOCKS 入站
  - 通过本地仿公网 `http_echo` 验证经内核转发返回 200
  - 连续 5 轮稳定通过（errors=[]，无失败项）
- 新增 `interop-lab` 核心链路 case：`p1_rust_core_tcp_via_socks`。
  - 通过本地仿公网 `tcp_echo` + SOCKS5 CONNECT 验证原始 TCP 往返链路
  - 连续 3 轮稳定通过（errors=[]，无失败项）
- 新增 `interop-lab` 核心链路 case：`p1_rust_core_udp_via_socks`。
  - 通过本地仿公网 `udp_echo` + SOCKS5 UDP ASSOCIATE 验证 UDP 往返链路
  - 连续 3 轮稳定通过（errors=[]，无失败项）
- 新增 `interop-lab` 核心链路 case：`p1_rust_core_dns_via_socks`。
  - 通过本地仿公网 `dns_stub` + SOCKS5 UDP ASSOCIATE 验证 DNS 查询链路（`rcode=NoError`）
  - 连续 3 轮稳定通过（errors=[]，无失败项）
- 新增故障注入 case：`p1_fault_disconnect_http_via_socks`。
  - 在流量阶段前断开 `local_http` upstream，验证“控制面健康 + 数据面失败可观测”
  - 连续 2 轮复验：`/healthz` 保持 200，traffic 明确记录失败（proxy 连接关闭）
- 新增故障注入 case：`p1_fault_delay_http_via_socks`。
  - 对 `local_http` 注入 13s 延迟，验证“控制面健康 + 数据面超时失败可观测”
  - 复验通过：`/healthz` 200，traffic 记录 curl timeout（exit 28）
- 新增恢复 case：`p1_recovery_disconnect_reconnect_http_via_socks`。
  - 断开后重连 upstream，验证“先失败后恢复”
  - 连续 5 轮稳定通过（errors=[]，before=true / during=false / after=true）
- 新增恢复 case：`p1_recovery_multi_flap_http_via_socks`。
  - 连续两次 upstream 抖动（断开/重连）后均恢复
  - 连续 2 轮稳定通过（errors=[]，两次 during=false，reconnect 后恢复为 true）
- 新增恢复 case：`p1_recovery_dns_disconnect_reconnect_via_socks`。
  - DNS UDP 链路断开后失败、重连后恢复（`rcode=NoError`）
  - 连续 2 轮稳定通过（errors=[]，before=true / during=false / after=true）
- 进程级恢复复验：`p1_rust_core_http_via_socks` 连续两轮独立启停通过，`/healthz` PID 变化且端口回收正常，确认“停-启-恢复”链路可复现。
- 新增订阅文件 case：`p1_subscription_file_urls`，直接消费 `labs/interop-lab/subscriptions/subscription_urls.txt`。
- 修复订阅 link-lines 解析：忽略注释/空行，避免把 `# https://...` 识别为协议。
- 修复 SOCKS 入站 UDP 联测阻塞：`SocksInboundAdapter::serve()` 改为走 `run()` 路径，使 `SB_SOCKS_UDP_ENABLE=1` 在 runtime 生效。
- `interop-lab` 流量模型增强：`http_get`/`tcp_round_trip`/`udp_round_trip`/`dns_query` 均支持 `proxy` 字段（支持 `socks5://`）。
- `interop-lab` 故障模型接线：`FaultSpec` 已接入执行链（支持 `disconnect` 与 `delay`）。
- `delay` 故障语义已增强：对目标 `http_echo` 服务注入真实请求处理延迟，不再是单纯等待。
- `interop-lab` 断言模型增强：支持 `eq/ne/exists/not_exists/gt/gte/lt/lte/contains/regex`，覆盖 `http.*`、`ws.*.frame_count`、`errors.count`、`subscription.node_count`、`traffic.*.detail.*`。
- 计划顺序已冻结：先完成核心恢复类，再进入 Trojan + Shadowsocks 协议层联测。

## ✅ 最新完成：Trojan + Shadowsocks 协议层联测（P2 首轮）

**日期**: 2026-02-10

**Trojan 结果**:
- `cargo test -p app --test trojan_protocol_validation --features net_e2e,tls_reality -- --nocapture`：2/2 通过。
- `cargo test -p app --test trojan_binary_protocol_test --features net_e2e,tls_reality -- --nocapture`：5/5 通过。
- 覆盖：TLS 握手、连接池、binary 协议认证（正/负）、多用户与兼容路径。

**Shadowsocks 首轮问题与修复**:
- 初始失败现象：`Connection reset by peer`、`Unsupported cipher method: aes-128-gcm`、大包用例卡住、高并发仅 100/500。
- 根因与修复：
  - 修复 SS 握手兼容：inbound 鉴权允许 outbound 首个空 AEAD chunk（不再把 `len=0` 直接判无效）。
  - 补齐 outbound cipher：新增 `aes-128-gcm` 支持（此前仅 `aes-256-gcm` + `chacha20-poly1305`）。
  - 修复大包分片：inbound/outbound `write_aead_chunk` 支持按 `u16::MAX` 分片，避免 1MB 传输长度溢出卡住。
  - 解除高并发测试默认限流干扰：`app/tests/shadowsocks_protocol_validation.rs` 在并发用例内临时关闭 `SB_INBOUND_RATE_LIMIT_PER_IP`。

**Shadowsocks 复验结果（修复后）**:
- `cargo test -p app --test shadowsocks_protocol_validation --features net_e2e -- --nocapture`：7/7 通过。
- `cargo test -p app --test shadowsocks_validation_suite --features net_e2e -- --nocapture`：5/5 通过。
- `cargo test -p sb-adapters --test shadowsocks_integration --features adapter-shadowsocks,shadowsocks -- --nocapture`：13/13 通过（1 ignored）。

**运行约束执行**:
- 未改动 Go+GUI+TUN 基线；
- 本轮未启用 Rust 内核接管现网；
- 结束后已确认无测试残留监听/进程。

## ✅ 最新完成：Interop-lab P2 协议套件可编排化

**日期**: 2026-02-10

**完成项**:
- `interop-lab` 流量模型新增 `TrafficAction::Command`，支持在 case 中执行命令并记录 `exit_code/stdout/stderr/elapsed_ms`。
- 新增 P2 case：
  - `labs/interop-lab/cases/p2_trojan_protocol_suite.yaml`
  - `labs/interop-lab/cases/p2_shadowsocks_protocol_suite.yaml`
  - `labs/interop-lab/cases/p2_trojan_fault_recovery_suite.yaml`
  - `labs/interop-lab/cases/p2_shadowsocks_fault_recovery_suite.yaml`
- 两个 case 已在 `interop-lab` 内实跑通过（assertions 通过、errors=[]）：
  - Trojan：`trojan_protocol_validation` + `trojan_binary_protocol_test`
  - Shadowsocks：`shadowsocks_protocol_validation` + `shadowsocks_validation_suite`
- 两个故障恢复 case 已在 `interop-lab` 内实跑通过（assertions 通过、errors=[]）：
  - Trojan：`wrong_password`（故障）后 `correct_password`（恢复）
  - Shadowsocks：`wrong_password`（故障）后 `aes256` 连通（恢复）

**运行约束执行**:
- 未改动 Go+GUI+TUN 基线；
- 本轮无 Rust 内核常驻进程残留；
- 11801/19190 端口均未被占用。

**运行约束执行**:
- 全过程未改动 Go+GUI+TUN 基线；
- Rust 联测均使用独立端口；
- 每轮结束后执行进程/端口回收检查（11801/19190 均已释放）。

## ✅ 最新完成：P2 实网重启恢复场景（Trojan + Shadowsocks）

**日期**: 2026-02-10

**完成项**:
- 新增真实网络恢复测试：
  - `app/tests/trojan_network_fault_recovery.rs`
  - `app/tests/shadowsocks_network_fault_recovery.rs`
- 两项测试均扩展为“单次重启 + 连续两次抖动（multi-flap）”，并通过：
  - `cargo test -p app --test trojan_network_fault_recovery --features net_e2e,tls_reality -- --nocapture`
  - `cargo test -p app --test shadowsocks_network_fault_recovery --features net_e2e -- --nocapture`
- 新增 `interop-lab` 可编排 case：
  - `labs/interop-lab/cases/p2_trojan_network_restart_suite.yaml`
  - `labs/interop-lab/cases/p2_shadowsocks_network_restart_suite.yaml`
- 两个 case 已实跑通过（`errors=[]`，command action `exit_code=0`）：
  - `cargo run -p interop-lab -- case run p2_trojan_network_restart_suite`
  - `cargo run -p interop-lab -- case run p2_shadowsocks_network_restart_suite`

**验证语义**:
- 同一监听端口下，验证“baseline 可用 -> server 下线失败 -> server 重启恢复”。
- 连续两次抖动（下线->重启）后，链路均可恢复。
- 重启恢复后执行并发突发拨测（Trojan/SS 各 30 并发），恢复后成功率达门限（>=90%）。
- 为后续 GUI 长链路阶段提供可重复的恢复回归入口。

**运行约束执行**:
- 全过程未改动 Go+GUI+TUN 基线；
- Rust 仅作为并行对照测试，不接管现网；
- 结束后已确认无 Rust 测试残留监听/进程（11801/19190 未占用）。

## ✅ 最新完成：P2 协议故障注入后并发恢复（Trojan + Shadowsocks）

**日期**: 2026-02-10

**完成项**:
- 两个恢复测试文件新增“错凭据注入 -> 并发恢复”用例：
  - `test_trojan_auth_fault_then_concurrent_recovery`
  - `test_shadowsocks_auth_fault_then_concurrent_recovery`
- 整文件回归通过：
  - `cargo test -p app --test trojan_network_fault_recovery --features net_e2e,tls_reality -- --nocapture`（4/4）
  - `cargo test -p app --test shadowsocks_network_fault_recovery --features net_e2e -- --nocapture`（4/4）
- 新增 `interop-lab` 可编排 case：
  - `labs/interop-lab/cases/p2_trojan_fault_recovery_concurrency_suite.yaml`
  - `labs/interop-lab/cases/p2_shadowsocks_fault_recovery_concurrency_suite.yaml`
- 两个 case 已实跑通过（`errors=[]`，`exit_code=0`）：
  - `cargo run -p interop-lab -- case run p2_trojan_fault_recovery_concurrency_suite`
  - `cargo run -p interop-lab -- case run p2_shadowsocks_fault_recovery_concurrency_suite`

**验证语义**:
- 故障注入：单次错误凭据连接必须失败（0 成功）。
- 恢复验证：随后正确凭据并发突发（30 并发）成功率需达到门限（>=90%）。

**运行约束执行**:
- 全过程未改动 Go+GUI+TUN 基线；
- Rust 仅并行测试，不接管现网；
- 结束后确认无 Rust 测试残留监听/进程（11801/19190 未占用）。

## ✅ 最新完成：`/connections` WebSocket 高并发稳定性（P2）

**日期**: 2026-02-10

**完成项**:
- 新增 `sb-api` WebSocket E2E 测试：
  - `crates/sb-api/tests/clash_websocket_e2e.rs`
  - 覆盖单连接快照与高并发连接（64 clients）稳定性。
- 新增 `sb-api` 测试依赖：
  - `crates/sb-api/Cargo.toml` 增加 `tokio-tungstenite`（dev-dependency）。
- 测试通过：
  - `cargo test -p sb-api --test clash_websocket_e2e -- --nocapture`（3/3）
- 新增 `interop-lab` 可编排 case：
  - `labs/interop-lab/cases/p2_connections_ws_concurrency_suite.yaml`
- case 已实跑通过（`errors=[]`，`exit_code=0`）：
  - `cargo run -p interop-lab -- case run p2_connections_ws_concurrency_suite`

**验证语义**:
- `/connections` WebSocket 单连接必须收到有效快照。
- 并发 64 个 WebSocket 客户端时，成功率需满足门限（>=95%）。
- 多波次稳定性（8 waves x 32 clients）总体成功率需满足门限（>=97%）。

**运行约束执行**:
- 全过程未改动 Go+GUI+TUN 基线；
- 仅做 Rust 并行测试，不接管现网；
- 结束后确认无 Rust 常驻监听/进程残留。

## ✅ 最新完成：`/connections` WebSocket 长时 soak + 趋势门禁（P2）

**日期**: 2026-02-10

**完成项**:
- `clash_websocket_e2e` 增强为可参数化，并新增 ignored 长时 soak 用例：
  - `test_connections_ws_long_running_soak`
  - 文件：`crates/sb-api/tests/clash_websocket_e2e.rs`
- 新增 `interop-lab` soak case：
  - `labs/interop-lab/cases/p2_connections_ws_soak_suite.yaml`
- 新增趋势门禁脚本：
  - `labs/interop-lab/scripts/run_case_trend_gate.sh`
  - 支持循环运行 case，并对 `errors` / `failed traffic` / `diff mismatches` 做阈值与非增长门禁（可配置）。
- 实跑通过：
  - `cargo test -p sb-api --test clash_websocket_e2e -- --nocapture`（3 passed, 1 ignored）
  - `cargo test -p sb-api --test clash_websocket_e2e test_connections_ws_long_running_soak -- --ignored --nocapture`（1/1）
  - `cargo run -p interop-lab -- case run p2_connections_ws_soak_suite`（`errors=[]`, `exit_code=0`）
  - `ITERATIONS=2 KERNEL=rust ALLOW_MISSING_DIFF=1 labs/interop-lab/scripts/run_case_trend_gate.sh p2_connections_ws_soak_suite`（pass）

**验证语义**:
- 长时 soak：多波次持续 WS 连接下，单波与总体成功率均需达门限。
- 趋势门禁：迭代回归中，错误/失败项不得超过阈值，且综合分数不允许上升。
- 在双核快照可用时，脚本可启用严格 diff 门禁（`ALLOW_MISSING_DIFF=0`）。

**运行约束执行**:
- 全过程未改动 Go+GUI+TUN 基线；
- Rust 仅并行测试，不接管现网；
- 结束后确认无 Rust 常驻监听/进程残留（11801/19190 未占用）。

---

## ✅ 最新完成：L9 订阅联测（基础闭环）

**日期**: 2026-02-10

**结论（标记为基本完成）**:
- 标准 Clash 订阅链路可解析（URL1 验证通过）。
- 其余样本（含中转转换 URL）在当前网络环境下受站点风控/人机检测/反代理策略影响，返回 403/429 或挑战页，未获得可解析订阅正文。
- 该类失败判定为**环境访问限制**，非核心解析器崩溃；不阻塞主线推进。

**主线决策**:
- 订阅专项按“基础可用”结项，主线继续推进 L5-L11 后续工作。
- 后续仅在可直连/白名单网络环境下补采样复验，不作为当前阻塞项。

---

## ✅ 最新完成：L4.2 门禁回归清零 + L4.5 质量复验证据固化

**日期**: 2026-02-10

**完成项**:
- L4.2：`check-boundaries.sh` 恢复 `exit 0`（V4a: `26 -> 24`）
- L4.5：新增 `reports/L4_QUALITY_RECHECK_2026-02-10.md`，将复验命令统一按 `PASS-STRICT / PASS-ENV-LIMITED` 记录

**待补项**:
- L4.4：`PX-015` Linux 双场景实机验证（本机 Darwin 无 `systemctl/busctl`，待 Linux 主机执行）

---

## ✅ 最新完成：L2.8.x ConnMetadata Rule/Chain + TCP/UDP/QUIC Conntrack

**备注**：原文档编号为 L3.5.x，现归并为 L2.8 扩展（连接面板/conntrack 增强）。

**日期**: 2026-02-10
**目标**: 打通 TCP + UDP/QUIC conntrack wiring，补齐 `/connections` 的 rule/chains，并支持 `DELETE /connections` 跨协议中断 I/O。

**关键改动**:
- 规则元信息：`Engine::decide_with_meta`、`ProcessRouter::*_meta`、`RouterHandle::select_ctx_and_record_with_meta` 增补稳定 rule label。
- Conntrack 扩展：新增 `register_inbound_udp` 与通用 wiring；新增 `compute_chain_for_decision`。
- UDP 生命周期：`UdpNatEntry`/`UdpNatMap` 增加 conntrack 元数据与取消传播，NAT 淘汰触发 cancel。
- Inbound 接线：覆盖 HTTP/SOCKS/VLESS/VMESS/TROJAN/SS/ShadowTLS/Naive/AnyTLS/SSH/Hy2/TUIC/Redirect/TProxy/TUN-macos 等 TCP；SOCKS UDP、Trojan UDP、Shadowsocks UDP、TUIC UDP、DNS UDP 等路径接入 UDP conntrack。

**新增测试**:
- `crates/sb-core/tests/conntrack_wiring_udp.rs`
- `crates/sb-core/tests/router_rules_decide_with_meta.rs`
- `crates/sb-core/tests/router_select_ctx_meta.rs`
- `crates/sb-api/tests/connections_snapshot_test.rs`（新增 UDP 断言）

**验证**:
- `cargo check -p sb-core -p sb-adapters -p sb-api`

---

## ✅ L2 关闭决策（功能闭环）

**日期**: 2026-02-10  
**结论**: L2 Tier 1~Tier 3 功能闭环已完成（含 M2.4 服务补全），L2 阶段在“功能面”关闭。

**后补项（不阻塞 L2 关闭）**:
- **M3.1~M3.3 质量里程碑**（测试覆盖/性能基准/稳定验证）全部后补
- Resolved Linux runtime/system bus 验证（systemd-resolved 真实环境验证）后补

**说明**:
- 以上后补项进入后续质量阶段统一安排，不影响当前 L3 功能闭环结论。

---

<details>
<summary>L2 详细实施记录（已归档至 implementation-history.md）</summary>

## ✅ L2.10 DNS 栈对齐

**日期**: 2026-02-08
**Parity**: 94% → ~99%

### 修复的核心问题

1. **DnsRouter.exchange() 死代码** — 返回 "not yet supported"。实现: parse query → resolve_with_context → build_dns_response wire-format 往返
2. **RDRC 从未调用** — CacheFileService 有 RDRC 存储但无 transport-aware API。新增 `check_rdrc_rejection(transport, domain, qtype)` / `save_rdrc_rejection()`
3. **FakeIP 全局 env-gated 而非规则驱动** — 新增 `FakeIpUpstream` adapter 实现 DnsUpstream trait，由规则路由；lookup() 跳过 FakeIP
4. **无 Hosts upstream** — 新增 `HostsUpstream` adapter，支持 predefined JSON + /etc/hosts 文件
5. **DnsServerIR 缺 server_type** — GUI 生成 `type: "fakeip"/"hosts"` 等，IR 只有 address 前缀判断
6. **DNS 规则动作不完整** — 新增 RouteOptions（修改选项继续匹配）、Predefined（返回预定义响应）
7. **DNS hijack 路由动作为占位** — `Decision::HijackDns` 从 Reject 变为独立决策
8. **缓存无 transport 隔离** — 新增 independent_cache: Key 包含 transport_tag
9. **缓存无 disable_expire** — 新增 disable_expire: 跳过 TTL 过期检查
10. **ECS 仅 UDP 注入** — 新增 wire-format 层 `inject_edns0_client_subnet()` / `parse_edns0_client_subnet()`
11. **无反向映射** — 新增 reverse_mapping LruCache(1024) + `DnsRouter.lookup_reverse_mapping(ip)`

### 4 Phase 实施

| Phase | 内容 | 状态 |
|-------|------|------|
| Phase 1 | 核心链路联通 (exchange, RDRC, DNS inbound, bootstrap wiring) | ✅ |
| Phase 2 | Transport 类型补齐 (server_type, FakeIP, Hosts, 规则驱动, 反向映射) | ✅ |
| Phase 3 | DNS 规则动作补齐 (route-options, predefined, address-limit, hijack-dns) | ✅ |
| Phase 4 | 缓存增强 + EDNS0 (independent cache, disable_expire, ECS inject, per-rule subnet) | ✅ |

### 修改文件

| 文件 | 变更 |
|------|------|
| `crates/sb-core/src/dns/message.rs` | +build_dns_response(), +extract_rcode(), +parse_all_answer_ips(), +get_query_id(), +set_response_id(), +inject_edns0_client_subnet(), +parse_edns0_client_subnet(), +18 tests |
| `crates/sb-core/src/dns/rule_engine.rs` | exchange() 实现, +RouteOptions/Predefined actions, +fakeip_tags, +reverse_mapping, +client_subnet propagation |
| `crates/sb-core/src/dns/config_builder.rs` | +cache_file param, +fakeip/hosts support, +mark_fakeip_upstream, +route-options/predefined parsing |
| `crates/sb-core/src/dns/dns_router.rs` | +lookup_reverse_mapping() trait method |
| `crates/sb-core/src/dns/upstream.rs` | +FakeIpUpstream, +HostsUpstream, +11 tests |
| `crates/sb-core/src/dns/cache.rs` | +transport_tag in Key, +disable_expire, +10 tests |
| `crates/sb-core/src/services/cache_file.rs` | +check_rdrc_rejection(), +save_rdrc_rejection(), +1 test |
| `crates/sb-config/src/ir/mod.rs` | DnsServerIR +server_type/inet4_range/inet6_range/hosts_path/predefined, DnsIR +disable_expire |
| `crates/sb-adapters/src/inbound/dns.rs` | +dns_router field, +DnsRouter exchange path with fallback |
| `crates/sb-core/src/router/rules.rs` | +Decision::HijackDns variant |
| `crates/sb-core/src/router/engine.rs` | +HijackDns match arm |
| `crates/sb-core/src/endpoint/handler.rs` | +HijackDns match arm |
| `crates/sb-adapters/src/inbound/{socks,http,anytls}` | +HijackDns match arm |

### 构建验证

| 构建 | 状态 |
|------|------|
| `cargo check --workspace` | ✅ |
| `cargo check -p app --features router` | ✅ |
| `cargo check -p app --features parity` | ✅ |
| `cargo test --workspace` | ✅ 1492 passed (+51 new) |
| `make boundaries` | ✅ exit 0 |

---

## ✅ 已完成：L2.9 Lifecycle 编排

**日期**: 2026-02-08
**Parity**: 93% → 94%

### 修复的核心问题

1. **拓扑排序死代码** — `OutboundManager` 有完整的 Kahn's 算法和 `add_dependency()` 方法，但**从未被调用**。`get_startup_order()` 存在但 `start_all()` 不使用它
2. **Outbound 未注册到 OutboundManager** — `populate_bridge_managers()` 显式跳过 outbound 注册（"Skip for now" 注释），导致 dependency tracking 和 default resolution 无效
3. **无默认 outbound 解析** — Go 有完整的 default outbound 解析（explicit tag → first → direct fallback），Rust 没有
4. **无启动失败回滚** — supervisor `start()` 中间阶段失败后不清理已启动的组件

### 核心策略

提取纯函数 `compute_outbound_deps()` + `validate_and_sort()` 实现依赖解析和拓扑排序，在 `populate_bridge_managers()` 中接线到 OutboundManager，两路径（Supervisor + legacy bootstrap）同步改。

### 子任务

| 步骤 | 子任务 | 状态 |
|------|--------|------|
| L2.9.1 | compute_outbound_deps + validate_and_sort 纯函数 | ✅ |
| L2.9.2 | Bridge 新增 outbound_deps 字段 + build_bridge 填充 | ✅ |
| L2.9.3 | Supervisor populate_bridge_managers 接线 (Result + 注册 + 验证) | ✅ |
| L2.9.4 | Legacy bootstrap 依赖验证 + default 解析 | ✅ |
| L2.9.5 | OutboundManager::resolve_default() (Go parity) | ✅ |
| L2.9.6 | Startup checkpoint 日志 (OUTBOUND READY CHECKPOINT) | ✅ |
| L2.9.7 | 失败回滚 (shutdown_context + stop endpoints/services/inbounds) | ✅ |
| L2.9.8 | OutboundManager Startable impl 升级 (info 日志) | ✅ |
| L2.9.9 | 12 新测试 (topo sort, cycle, default, resolve) | ✅ |

### 修改文件

| 文件 | 变更 |
|------|------|
| `crates/sb-core/src/outbound/manager.rs` | +compute_outbound_deps(), +validate_and_sort(), +resolve_default(), 重构 get_startup_order(), +12 tests |
| `crates/sb-core/src/adapter/mod.rs` | Bridge +outbound_deps 字段, Bridge::new() 初始化, Debug impl |
| `crates/sb-core/src/adapter/bridge.rs` | build_bridge() 两变体: 调用 compute_outbound_deps() |
| `crates/sb-core/src/runtime/supervisor.rs` | populate_bridge_managers → Result + outbound 注册 + 验证 + default + 回滚 |
| `crates/sb-core/src/context.rs` | OutboundManager Startable: no-op → info 日志 |
| `app/src/bootstrap.rs` | +deps 验证 + default 解析 |

### 构建验证

| 构建 | 状态 |
|------|------|
| `cargo check --workspace` | ✅ |
| `cargo check -p app --features router` | ✅ |
| `cargo check -p app --features parity` | ✅ |
| `cargo test -p sb-core -- manager::tests` | ✅ 16 passed (12 new) |
| `cargo test --workspace` | ✅ |
| `make boundaries` | ✅ exit 0 |

---

## ✅ 已完成：L2.8 ConnectionTracker + 连接面板

**日期**: 2026-02-08
**Commit**: `d708ecb`
**Parity**: 92% → 93%

### 修复的核心问题

1. **全链路断裂** — `sb-common::ConnTracker` 有完善的 DashMap + 原子计数器，但从未被调用。`/connections` GET 始终返回空列表，`/traffic` WS 发送 mock 数据 (+1000/+4000)，`close_connection()` 仅删 HashMap 不关闭 socket
2. **I/O path 未注册** — `new_connection()`/`new_packet_connection()` 做 dial + 双向拷贝，但不通知任何 tracker
3. **ConnectionManager 空壳** — `sb-api/managers.rs::ConnectionManager` 从未被填充，是死代码

### 核心策略

复用 `sb-common::conntrack::ConnTracker` 作为全局连接跟踪器（已有 DashMap、per-connection `Arc<AtomicU64>` 计数器、proper register/unregister lifecycle、全局 upload/download 累计）。只需: (1) 在 I/O path 注册连接 + 传入 byte counters, (2) 暴露给 API 层, (3) 添加 CancellationToken close 能力。

### 子任务

| 步骤 | 子任务 | 状态 |
|------|--------|------|
| L2.8.1 | ConnMetadata 扩展 + CancellationToken (sb-common) | ✅ |
| L2.8.2 | I/O path 注册 + 字节计数 (sb-core/router/conn.rs) | ✅ |
| L2.8.3 | ApiState 接线 (移除 ConnectionManager, 添加 sb-common dep) | ✅ |
| L2.8.4 | /connections WebSocket handler | ✅ |
| L2.8.5 | handlers.rs 重写 (GET + DELETE) | ✅ |
| L2.8.6 | /traffic WebSocket 真实化 | ✅ |

### 修改文件

| 文件 | 变更 |
|------|------|
| `crates/sb-common/Cargo.toml` | +tokio-util (CancellationToken) |
| `crates/sb-common/src/conntrack.rs` | ConnMetadata +5 字段, +6 builder 方法, close/close_all cancel token |
| `crates/sb-core/Cargo.toml` | +sb-common 依赖 |
| `crates/sb-core/src/router/conn.rs` | new_connection/new_packet_connection 注册 tracker, copy_with_recording/tls_fragment +conn_counter, cancel token select 分支 |
| `crates/sb-api/Cargo.toml` | +sb-common 依赖 |
| `crates/sb-api/src/clash/server.rs` | 移除 connection_manager 字段, /connections 路由改为双模式 |
| `crates/sb-api/src/clash/handlers.rs` | 新增 get_connections_or_ws (双HTTP/WS), 重写 close_connection/close_all, 移除 convert_connection 及 dead helpers |
| `crates/sb-api/src/clash/websocket.rs` | 新增 handle_connections_websocket + build_connections_snapshot, 重写 handle_traffic_websocket (真实 delta) |
| `crates/sb-api/tests/clash_endpoints_integration.rs` | 移除 connection_manager 断言 |

### 构建验证

| 构建 | 状态 |
|------|------|
| `cargo check --workspace` | ✅ |
| `cargo check -p app --features router` | ✅ |
| `cargo check -p app --features parity` | ✅ |
| `cargo test --workspace` | ✅ all passed |
| `make boundaries` | ✅ exit 0 |

---

## ✅ 已完成：L2.7 URLTest 历史 + 健康检查对齐

**日期**: 2026-02-08
**Parity**: 91% → 92%

### 修复的核心问题

1. **无共享历史存储** — Go 有全局 `URLTestHistoryStorage`（`map[string]*URLTestHistory`），Rust 没有 → 新增 `URLTestHistoryStorage` trait + `URLTestHistoryService`（DashMap 实现）
2. **history 始终空** — API 返回 `history: []`，GUI 无法显示延迟/判断活性 → 健康检查 + delay 测试 + API 4 处端点均写入/删除历史，proxyInfo 填充真实 history
3. **tolerance 未使用** — `select_by_latency()` 总取绝对最低延迟，无 sticky 防抖 → 实现 Go 的 tolerance 逻辑：当前选择在容差范围内则保持不变

### 子任务

| 步骤 | 子任务 | 状态 |
|------|--------|------|
| L2.7.1 | URLTestHistoryStorage trait + URLTestHistoryService 实现 | ✅ |
| L2.7.2 | Bootstrap/ApiState 接线 | ✅ |
| L2.7.3 | 健康检查写入 + 构造函数扩展 (~35 call sites) | ✅ |
| L2.7.4 | API delay 端点写入 (get_proxy_delay, get_meta_group_delay) | ✅ |
| L2.7.5 | proxyInfo 填充 history (get_proxies, get_proxy, get_meta_groups, get_meta_group) | ✅ |
| L2.7.6 | Tolerance 实现 + 默认值 Go 对齐 | ✅ |

### 修改文件

| 文件 | 变更 |
|------|------|
| `crates/sb-core/src/context.rs` | 新增 URLTestHistory struct + URLTestHistoryStorage trait + urltest_history 字段 (Context/ContextRegistry) |
| `crates/sb-core/src/services/urltest_history.rs` | **新文件**: URLTestHistoryService (DashMap) + 3 单元测试 |
| `crates/sb-core/src/services/mod.rs` | 新增 pub mod urltest_history |
| `crates/sb-core/src/outbound/selector_group.rs` | +urltest_history 字段, 3 构造函数加参数, 健康检查写入历史, select_by_latency tolerance 重写 |
| `crates/sb-core/src/outbound/selector_group_tests.rs` | 12 处构造函数更新 + 3 新 tolerance 测试 |
| `crates/sb-api/src/clash/server.rs` | ApiState +urltest_history 字段, ClashApiServer +with_urltest_history() |
| `crates/sb-api/src/clash/handlers.rs` | +lookup_proxy_history() helper, 4 处 proxyInfo 填充, 2 处 delay 端点写入, 默认值对齐 (15s/https) |
| `crates/sb-api/Cargo.toml` | +humantime = "2.1" |
| `crates/sb-adapters/src/outbound/selector.rs` | 传入 urltest_history |
| `crates/sb-adapters/src/outbound/urltest.rs` | 传入 urltest_history |
| `app/src/bootstrap.rs` | 创建 URLTestHistoryService, 接线 Context + API, 默认值对齐 (180s/15s/https) |
| 5 个测试文件 (31 call sites) | 构造函数参数加 None |

### 默认值 Go 对齐

| 参数 | 旧值 | 新值 (Go 对齐) |
|------|------|----------------|
| test_url | `http://www.gstatic.com/generate_204` | `https://www.gstatic.com/generate_204` |
| interval | 60s | 180s (3 min) |
| timeout | 5s | 15s (Go TCPTimeout) |
| API delay timeout | 5s | 15s |

### 构建验证

| 构建 | 状态 |
|------|------|
| `cargo check --workspace` | ✅ |
| `cargo check -p app --features router` | ✅ |
| `cargo check -p app --features parity` | ✅ |
| `cargo test --workspace` | ✅ 1441 passed (+6 new tests) |
| `make boundaries` | ✅ exit 0 |

---

## ✅ 已完成：L2.6 Selector 持久化 + Proxy 状态真实化

**日期**: 2026-02-08
**Parity**: 89% → 91%

### 修复的核心问题

1. **Latent bug 修复**: `SelectorOutbound`/`UrlTestOutbound` 未覆盖 `as_any()`，导致 handlers.rs 中所有 `downcast_ref::<SelectorGroup>()` **静默失败** — GUI 看不到任何 selector group 信息
2. **CacheFile 持久化联通**: SelectorGroup 构造时从 CacheFile 恢复选择，select_by_name 时持久化到 CacheFile
3. **OutboundGroup trait**: 新增抽象 trait 替代 downcast，正确返回 "Selector"/"URLTest"/"LoadBalance" 类型名

---

## ✅ 已完成：WP-L2.1 Clash API 对接审计

**Commit**: `9bd745a`
**审计报告**: `agents-only/05-analysis/CLASH-API-AUDIT.md`

</details>

---

## 📋 M2.4 服务补全（历史 L3 Scope）

**注**：以下 L3.1~L3.5 为历史编号，对应 M2.4 服务补全与 L2.8 连接增强，保留以便对齐旧文档与日志。

**目标**: 边缘服务补全 + 残余 polish，从 99% → 99.5%+ parity

**规划**: `agents-only/03-planning/L3-WORKPACKAGES.md`（一级工作包的范围/依赖/验收/排序）

### L3 工作包

| 包 | 名称 | 来源 PX | 工作量 | 优先级 | 说明 |
|----|------|---------|--------|--------|------|
| L3.1 | SSMAPI 对齐 | PX-011 | 中 | 低 | ✅ 已完成（2026-02-09）：per-endpoint 绑定闭环 + API 行为对齐 + cache 兼容 + Shadowsocks tracker 接线 |
| L3.2 | DERP 配置对齐 | PX-014 | 中 | 低 | ✅ 已完成（2026-02-09）：schema + runtime 语义对齐（verify_client_url/mesh_with/verify_client_endpoint tag/STUN/bootstrap-dns/ListenOptions） |
| L3.3 | Resolved 完整化 | PX-015 | 中 | 低 | ✅ 已完成（2026-02-09）：resolved 替代模型 + resolve1 Resolve* + UDP/TCP stub + `type:\"resolved\"` 接线 + transport 对齐；Linux runtime/system bus 验证待做 |
| L3.4 | Cache File 深度对齐 | PX-009/013 | 中 | 中 | ✅ 已完成（2026-02-09）：cache_id（仅 Clash 三项隔离）+ FakeIP metadata debounce（10s）+ ruleset cache 策略固定为 file cache 权威 |
| L3.5 | ConnMetadata chain/rule 填充 | L2.8 延后 | 小 | 中 | 连接详情显示命中的规则链。需 Router 层统一路由入口 |

### ✅ 已完成：L3.1 SSMAPI 对齐（PX-011）

**日期**: 2026-02-09
**范围**: SSMAPI per-endpoint 绑定闭环 + HTTP API 行为对齐 + cache 读兼容/写 Go 格式 + Shadowsocks inbound 动态用户/多用户鉴权/流量统计接线。

**关键落点**:
- `crates/sb-core/src/services/ssmapi/registry.rs`：ManagedSSMServer 注册表（tag -> Weak<dyn ManagedSSMServer>）
- `crates/sb-adapters/src/register.rs`：Shadowsocks inbound build 时注册 managed server
- `crates/sb-core/src/services/ssmapi/server.rs`：按 endpoint 构建独立 EndpointCtx，并启动 1min 定时保存 cache（diff-write）
- `crates/sb-core/src/services/ssmapi/api.rs`：路由/状态码/错误体（text/plain）与字段行为对齐
- `crates/sb-adapters/src/inbound/shadowsocks.rs`：update_users 生效、TCP 多用户鉴权、UDP correctness 修复、tracker 统计接线

**验证**:
- `cargo test -p sb-core --features service_ssmapi`
- `cargo test -p sb-adapters --features "adapter-shadowsocks,router,service_ssmapi"`
- `cargo check -p sb-core --all-features`

### ✅ 已完成：L3.2 DERP 配置对齐（PX-014）

**日期**: 2026-02-09
**范围**: DERP 配置 schema + 关键运行时语义对齐（verify_client_url per-URL dialer；mesh_with per-peer dial/TLS + PostStart；verify_client_endpoint tag 语义；STUN enable/defaults；ListenOptions bind；bootstrap-dns 注入 DNSRouter）。

**关键落点**:
- `crates/sb-config/src/ir/mod.rs`：新增 `Listable`/`StringOrObj` + DERP IR（Dial/VerifyURL/MeshPeer/TLS；stun 支持 `bool|number|object`）
- `crates/sb-core/src/service.rs` + `crates/sb-core/src/adapter/{bridge.rs,mod.rs}`：ServiceContext 注入 `dns_router/outbounds/endpoints`
- `crates/sb-core/src/services/derp/server.rs`：dialer factory + verify/mesh/endpoint/bootstrap-dns/listen/stun 行为对齐
- `crates/sb-core/src/endpoint/tailscale.rs`：LocalAPI unix socket path 支持（daemon-only）
- `crates/sb-transport/src/{dialer.rs,builder.rs}`：connect_timeout 生效 + Linux netns 支持

**验证**:
- `CARGO_TARGET_DIR=target-alt cargo test -p sb-config`
- `CARGO_TARGET_DIR=target-alt cargo test -p sb-core --features service_derp`

### ✅ 已完成：L3.3 Resolved 完整化（PX-015）

**日期**: 2026-02-09
**范围**: Linux-only resolved 集成对齐 Go（替代 systemd-resolved 行为）：system bus 导出 `org.freedesktop.resolve1.Manager` + `DoNotQueue` 请求 name；DNS stub 支持 UDP+TCP 且统一走 DNSRouter.exchange；补齐 Resolve* 方法族并 best-effort 采集 sender 进程元信息；配置层补齐 dns server `type:\"resolved\"` 并接线到 ResolvedTransport；transport 支持 bind_interface best-effort + 并行 fqdn racer + 默认值对齐。

**关键落点**:
- `crates/sb-adapters/src/service/{resolved_impl.rs,resolve1.rs}`
- `crates/sb-core/src/dns/{rule_engine.rs,message.rs,upstream.rs,dns_router.rs}`
- `crates/sb-core/src/dns/transport/{resolved.rs,dot.rs}`
- `crates/sb-config/src/{ir/mod.rs,validator/v2.rs}`
- `crates/sb-core/src/dns/config_builder.rs`

**验证**:
- `cargo test -p sb-core`
- `cargo test -p sb-config`
- `cargo test -p sb-adapters`
- `cargo check -p sb-core --features service_resolved`

**待补 Linux runtime 验证**:
- systemd-resolved 运行时：`org.freedesktop.resolve1` name Exists → 启动失败且错误明确
- systemd-resolved 未运行时：可成功请求 name 并处理 UDP/TCP stub DNS query（至少 A/AAAA）

### ✅ 已完成：L3.4 Cache File 深度对齐（PX-013 / PX-009）

**日期**: 2026-02-09  
**实现提交**: `fc541ef`  
**实现报告**: `agents-only/dump/2026-02-09_report_L3.4-cachefile-impl.md`

**锁定决策（已落地）**:
- `cache_id`：仅隔离 Clash 相关持久化（`clash_mode` + `selected` + `expand`）
- FakeIP：接线 mapping + metadata，并实现 metadata 写盘 10s strict debounce（对齐 Go）
- ruleset cache：维持 `router/ruleset/remote.rs` 的 file cache 为权威缓存；`CacheFileService` ruleset API 不接线下载链路（仅保留接口/注释）

**关键落点**:
- `crates/sb-config/src/ir/experimental.rs`：`CacheFileIR.cache_id`
- `crates/sb-core/src/services/cache_file.rs`：Clash 三项按 namespace tree 隔离；FakeIP metadata 存取 + debounce thread + flush/join
- `crates/sb-core/src/dns/fakeip.rs`：`FakeIpStorage` 扩展（metadata load/save）；`set_storage()` 恢复指针并校验范围；allocate 更新 metadata（debounced）
- `crates/sb-core/src/dns/config_builder.rs`：在 FakeIP env 注入后接线 `fakeip::set_storage(cache_file.clone())`
- `crates/sb-core/src/router/ruleset/remote.rs`：补充注释，明确 ruleset 缓存权威来源

**验证**:
- `cargo test --workspace --all-features`（实现报告内记录：✅ 2026-02-09）

### 已关闭 / Won't Fix

| 项目 | 决策 | 理由 |
|------|------|------|
| PX-007 Adapter 接口抽象 | **Won't Fix** | Rust 用 IR-based 架构替代 Go adapter.Router/RuleSet 接口，是合理的架构差异 |
| 6 项 TLS/WireGuard 限制 | **Accepted Limitation** | uTLS/REALITY/ECH/TLS fragment/WireGuard endpoint — rustls/平台库限制 |

---

## ✅ L2 关闭总结

**关闭日期**: 2026-02-08
**Parity 提升**: 88% (183/209) → 99.52% (208/209)
**新增测试**: +61 (1431 → 1492)

### L2 完成工作包

| Tier | 工作包 | 关键交付 |
|------|--------|---------|
| Tier 1 | L2.2 maxminddb | GeoIP 查询修复 |
| Tier 1 | L2.3 Config schema | Go configSchema 1:1 对齐 |
| Tier 1 | L2.4 Clash API 初步 | 基础端点 + GLOBAL 组注入 |
| Tier 1 | L2.5 CLI | `-c`/`-C`/`-D` 参数对齐 |
| Tier 1 | L2.1 审计 | 18 项偏差修复 (12 BREAK + 5 DEGRADE + 1 COSMETIC) |
| Tier 2 | L2.6 Selector 持久化 | OutboundGroup trait + CacheFile + as_group() fix |
| Tier 2 | L2.7 URLTest 历史 | URLTestHistoryStorage + tolerance 防抖 |
| Tier 2 | L2.8 ConnectionTracker | ConnTracker I/O 接入 + WS + 真实 close |
| Tier 2 | L2.9 Lifecycle 编排 | 拓扑排序 + 依赖验证 + default outbound + 回滚 |
| Tier 2 | L2.10 DNS 栈对齐 | exchange() + RDRC + FakeIP/Hosts + 规则动作 + 缓存 + ECS |

### L2 覆盖的 PX 项

PX-004 ✅, PX-005 ✅, PX-006 ✅, PX-008 ✅, PX-010 ✅, PX-012 ✅
PX-009 ◐ (核心功能完成，深度持久化移入 L3.4)
PX-007 Won't Fix (架构差异)

---

## 📝 重要决策记录

| 日期 | 决策 | 原因 |
|------|------|------|
| 2026-02-08 | **L2 关闭，创建 L3 scope** | Tier 1+2 全部完成，99% parity，GUI.for 兼容性目标达成；Tier 3 边缘服务移入 L3 |
| 2026-02-08 | PX-007 Won't Fix | Rust IR-based 架构是合理差异，非缺口 |
| 2026-02-08 | ConnMetadata chain/rule 延后至 L3.5 | 需 Router 层统一路由入口，不影响 GUI 显示 |
| 2026-02-08 | Cache File 深度对齐移入 L3.4 | 当前内存/简化持久化可工作，bbolt 级别是优化 |

<details>
<summary>L2 期间决策记录（已归档）</summary>

| 日期 | 决策 | 原因 |
|------|------|------|
| 2026-02-08 | L2.8 复用 sb-common::ConnTracker 而非 sb-api::ConnectionManager | ConnTracker 已有 DashMap + 原子计数 + register/unregister；ConnectionManager 从未被填充，是死代码 |
| 2026-02-08 | L2.8 handlers 直接调用 global_tracker() | 全局单例无需注入 ApiState，减少接线代码 |
| 2026-02-08 | L2.8 CancellationToken 替代 socket shutdown | tokio_util::CancellationToken 可从 API handler 触发，通过 select! 分支中断 I/O loop |
| 2026-02-08 | L2.8 copy_with_recording 添加 conn_counter 参数 | per-connection 原子计数器通过参数传入，每次 I/O 一次 fetch_add，性能影响可忽略 |
| 2026-02-08 | L2.9 拓扑排序提取为纯函数 validate_and_sort() | 同步、无 RwLock、可测试、两路径（Supervisor + legacy）直接复用 |
| 2026-02-08 | L2.9 OutboundManager 注册 DirectConnector 占位 | Bridge 用 adapter::OutboundConnector trait，OutboundManager 用 traits::OutboundConnector — 类型不兼容，注册占位即可满足 tag 跟踪需求 |
| 2026-02-08 | L2.9 populate_bridge_managers 改为 Result | 依赖验证（cycle detection）和 default 解析可能失败，需向调用方传播错误 |
| 2026-02-08 | L2.9 Startable impl 用轻量日志而非 try_read | tokio::sync::RwLock 无 try_read()，且 Startable::start() 是同步方法 |
| 2026-02-08 | L2.8 延后 chain/rule 字段填充 | 需要 Router 层统一路由入口，当前 inbound adapter 直连 outbound；L2.9 后自然填充 |
| 2026-02-08 | L2.7 URLTestHistoryStorage 用 DashMap | 已是 sb-core 依赖，无锁并发 map，与 Go sync.Map 语义一致 |
| 2026-02-08 | 每 tag 仅存最新一条历史 | Go 对齐：adapter.URLTestHistory 是单条而非数组 |
| 2026-02-08 | tolerance 使用 try_read() 读取 selected | 与 OutboundGroup::now() 同模式，非 async trait 约束 |
| 2026-02-08 | lookup_proxy_history 对 group 用 now() 作为 lookup key | Go 行为：group 的 history 实际是当前活跃成员的 history |
| 2026-02-08 | 默认值对齐 Go (180s/15s/https) | Go sing-box 默认: interval 3min, timeout=TCPTimeout=15s, URL https |
| 2026-02-08 | L2.6 使用 OutboundGroup trait 替代 downcast | downcast 依赖具体类型，跨 crate 时 as_any() 未转发导致静默失败；trait 方式更健壮 |
| 2026-02-08 | SelectorGroup 三阶段恢复 (cache → default → first) | 与 Go 对齐：CacheFile 优先，配置默认值次之，最后兜底第一个成员 |
| 2026-02-08 | OutboundGroup::now() 用 try_read() 而非 .await | OutboundGroup 是非 async trait，try_read() 在无竞争时总是成功，安全可用 |
| 2026-02-08 | 持久化写入在 SelectorGroup 内部完成 | 消除 handler 层重复调用 cache.set_selected() 的风险 |
| 2026-02-08 | WP-L2.1 Clash API 审计全部完成 | GUI.for 完全兼容保障 |
| 2026-02-08 | HTTP URL test 替代 TCP connect | Go 用 HTTP GET 测延迟，TCP connect 结果不等价 |
| 2026-02-08 | Config struct 与 Go configSchema 1:1 对齐 | GUI 直接读取 mode/allow-lan/tun 等字段 |
| 2026-02-08 | GLOBAL 虚拟 Fallback 组注入 | GUI tray 菜单硬依赖 proxies.GLOBAL |
| 2026-02-08 | Tier 2 规划重排 | 按 GUI 可感知度排序，CacheFile 并入 L2.6 |
| 2026-02-07 | B2: 共享契约放 sb-types | 最小依赖, 已有 Port traits 基础 |
| 2026-02-07 | AdapterIoBridge + connect_io() | 加密协议适配器返回 IoStream |

</details>

---

*最后更新：2026-02-10（L2.8 ConnMetadata 扩展 + L2 功能闭环关闭）*
