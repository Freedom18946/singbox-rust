# L5~L7 详细工作包规划

> 更新日期：2026-02-11
> 状态：✅ 已全部完成（22/22 工作包，4 批次）
> 输入来源：`labs/interop-lab/` 现有代码 + `agents-only/03-planning/07-L5-L11-INTEROP-LAB-PLAN.md` + Go 版本功能分析
> 关联：本文档为 L5-L7 执行级规划，替代此前 `07-L5-L11-INTEROP-LAB-PLAN.md` 中的概要描述

---

## Context

singbox-rust 项目已完成 L1(架构) + L2(功能对齐) + L4(治理)，parity 99.52%。`labs/interop-lab` 联测底座已入库（31 YAML case、6 upstream 模拟器、完整 CLI/orchestrator/diff 流水线）。本规划填补 L5-L7 的剩余缺口：**协议故障矩阵补全（L5）**、**仿真底座能力扩展（L6）**、**GUI 通信回放深化（L7）**。

约束：Go+GUI+TUN 基线不可动，Rust 仅并行对照。

---

## 总览：22 个工作包，4 批次

| 批次 | 工作包数 | 可并行 | 说明 |
|------|---------|--------|------|
| Batch 1 | 7 | 全并行 | 无依赖的基础设施+简单 case |
| Batch 2 | 8 | 大部分并行 | 依赖 Batch 1 的输出 |
| Batch 3 | 5 | 大部分并行 | 依赖 Batch 2 的 config/schema |
| Batch 4 | 2 | 串行 | 集成验证 capstone |

---

## L5: 契约冻结与用例建模（补全协议×故障矩阵）

### L5.1.1 — TCP 故障矩阵 (4 case)

- **目标**: TCP disconnect/delay/jitter/recovery
- **交付**:
  - `cases/p1_fault_disconnect_tcp_via_socks.yaml`
  - `cases/p1_fault_delay_tcp_via_socks.yaml`
  - `cases/p1_fault_jitter_tcp_via_socks.yaml`
  - `cases/p1_recovery_disconnect_reconnect_tcp_via_socks.yaml`
- **模式**: 复用 HTTP 故障 case 结构，upstream 改 `tcp_echo`，traffic 改 `tcp_round_trip`
- **验收**: disconnect → `traffic.*.success == false`；recovery → before=true/during=false/after=true
- **依赖**: L6.1.2（delay/jitter 子项需要 TCP echo 支持 delay 注入）
- **复杂度**: M

### L5.1.2 — UDP 故障矩阵 (4 case)

- **目标**: UDP disconnect/delay/jitter/recovery
- **交付**:
  - `cases/p1_fault_disconnect_udp_via_socks.yaml`
  - `cases/p1_fault_delay_udp_via_socks.yaml`
  - `cases/p1_fault_jitter_udp_via_socks.yaml`
  - `cases/p1_recovery_disconnect_reconnect_udp_via_socks.yaml`
- **验收**: 同 L5.1.1 模式；UDP echo 已支持 delay，无需代码改动
- **依赖**: 无
- **复杂度**: S

### L5.1.3 — DNS 故障矩阵补全 (2 case)

- **目标**: DNS delay + jitter（disconnect/recovery 已有）
- **交付**:
  - `cases/p1_fault_delay_dns_via_socks.yaml`
  - `cases/p1_fault_jitter_dns_via_socks.yaml`
- **验收**: 13s delay → dns_query timeout；jitter → 可变延迟可观测
- **依赖**: 无（DNS stub 已支持 delay）
- **复杂度**: S

### L5.1.4 — WS 故障矩阵 (4 case)

- **目标**: WS disconnect/delay/jitter/recovery
- **交付**:
  - `cases/p1_fault_disconnect_ws_upstream.yaml`
  - `cases/p1_fault_delay_ws_upstream.yaml`
  - `cases/p1_fault_jitter_ws_upstream.yaml`
  - `cases/p1_recovery_disconnect_reconnect_ws_upstream.yaml`
- **验收**: WS echo 已支持 delay；disconnect/reconnect 用 harness lifecycle
- **依赖**: L6.1.1（WsRoundTrip action，初期可用 Command 包装）
- **复杂度**: M

### L5.1.5 — TLS 故障矩阵 (4 case)

- **目标**: TLS disconnect/delay/jitter/recovery
- **交付**:
  - `cases/p1_fault_disconnect_tls_upstream.yaml`
  - `cases/p1_fault_delay_tls_upstream.yaml`
  - `cases/p1_fault_jitter_tls_upstream.yaml`
  - `cases/p1_recovery_disconnect_reconnect_tls_upstream.yaml`
- **验收**: disconnect/recovery 用 harness lifecycle（TcpRoundTrip 即可检测连通性）；delay/jitter 需 L6.1.2
- **依赖**: L6.1.2（TLS echo delay 注入）；L6.1.3（可选，proper TLS handshake）
- **复杂度**: M

### L5.1.6 — 文档更新

- **目标**: 更新 case_backlog.md + compat_matrix.md，将"planned"改为"implemented"
- **交付**: 更新 `labs/interop-lab/docs/case_backlog.md` 和 `compat_matrix.md`
- **依赖**: L5.1.1~L5.1.5 全部完成
- **复杂度**: S

### L5.2.1 — env_limited 失败归因增强

- **目标**: 对 env_limited case 的失败自动分类（rate_limit / network / tls / unknown）
- **交付**:
  - 新模块 `labs/interop-lab/src/attribution.rs`：`classify_env_limited_failure()` + `AttributionResult`
  - 更新 `diff_report.rs`：`DiffReport` 增加 `env_limited_attributions` 字段
  - 更新 `run_case_trend_gate.sh`：输出 env_limited 归因摘要行
- **分类规则**: HTTP 403/429/503 → rate_limit；connection refused/timeout → network；TLS handshake failure → tls；其他 → unknown
- **验收**: `cargo test -p interop-lab` 含归因分类单元测试；trend gate 输出归因摘要
- **依赖**: 无
- **复杂度**: M

---

## L6: 仿真底座能力扩展

### L6.1.1 — WsRoundTrip TrafficAction

- **目标**: 新增原生 WS 往返 traffic action，消除用 Command 包装的需要
- **交付**:
  - `case_spec.rs` 新增 `TrafficAction::WsRoundTrip { name, url, payload, proxy, timeout_ms }`
  - `upstream.rs` 实现：connect WS（可选 SOCKS5 代理）→ send payload → recv echo → 比对
- **实现**: 复用 `tokio-tungstenite`（gui_replay.rs 已引入）；SOCKS5 复用 `upstream.rs` 中已有的 SOCKS5 TCP 握手代码
- **验收**: 对 WsEcho upstream 往返成功；SOCKS5 代理模式工作；2+ 单元测试；现有 31 case 仍可 parse
- **关键文件**: `case_spec.rs:232`, `upstream.rs:425`
- **依赖**: 无
- **复杂度**: M

### L6.1.2 — TCP/TLS Echo Delay 注入

- **目标**: 让 TcpEcho + TlsEcho 支持 `service_delays_ms`，使 FaultJitter/Delay 对所有传输类型生效
- **交付**: 修改 `upstream.rs` 中 `tcp_echo`（~line 213）和 `tls_echo`（~line 379）handler
- **实现**: 将 `delays_ms: Arc<RwLock<BTreeMap<String, u64>>>` 和 `service_name` 传入 `start_single_upstream`，每次 echo 前调用 `service_delay()`（与 HttpEcho/UdpEcho/WsEcho 一致）
- **验收**: `FaultSpec::Delay { target: "local_tcp", ms: 13000 }` 让 TCP echo 每次响应延迟 13s；TLS 同理；现有 TCP/TLS case 不受影响
- **关键文件**: `upstream.rs:199-246`（TCP echo），`upstream.rs:348-413`（TLS echo）
- **依赖**: 无
- **复杂度**: S

### L6.1.3 — TlsRoundTrip TrafficAction（可选增强）

- **目标**: 新增 TLS 感知的往返 action（完成真正 TLS 握手 + echo，而非 raw TCP）
- **交付**:
  - `case_spec.rs` 新增 `TrafficAction::TlsRoundTrip { name, addr, payload, proxy, skip_verify, timeout_ms }`
  - `upstream.rs` 实现：tokio-rustls client + danger_accept_any_cert（自签名）
- **验收**: 对 TlsEcho 完成 TLS 握手 + payload echo；SOCKS5 可选
- **依赖**: 无
- **复杂度**: M

### L6.2.1 — 聚合趋势报告

- **目标**: trend gate 输出机器可读 JSON 摘要，含 per-case score、趋势方向、env_limited 归因
- **交付**:
  - 更新 `run_case_trend_gate.sh` 或新增 `aggregate_trend_report.sh`
  - 输出 `artifacts/trend_summary.json`：`{ cases: [{ id, scores: [], trend: "stable|improving|degrading", env_attributions: [] }] }`
- **验收**: 多 case 运行后产出 JSON；trend 字段正确反映分数走势
- **依赖**: L5.2.1（归因模块）
- **复杂度**: S

### L6.2.2 — CI Workflow 集成

- **目标**: GitHub Actions workflow 文件
- **交付**:
  - `.github/workflows/interop-lab-smoke.yml`：PR 触发，strict + P0/P1
  - `.github/workflows/interop-lab-nightly.yml`：定时触发，全 priority + 双 env_class + trend gate
- **实现**: build app + interop-lab → run cases → upload artifacts
- **验收**: workflow YAML 语法合法；smoke 可在 PR 中触发
- **依赖**: 无
- **复杂度**: M

---

## L7: GUI 通信回放深化

### L7.1.1 — WsParallel GuiStep

- **目标**: 新增 `GuiStep::WsParallel`，模拟 GUI 启动时 4 WS 流并行连接
- **交付**:
  - `case_spec.rs` 新增:
    ```rust
    WsParallel { name: String, streams: Vec<WsStreamSpec>, duration_ms: u64 }
    // WsStreamSpec { path: String, max_frames: usize, params: Option<String> }
    ```
  - `gui_replay.rs` 实现：用 `JoinSet` 并发启动所有 WS 连接，各自收集 frames，结果独立写入 snapshot
- **验收**: 4 WS 流并行收集 frame；任一流失败不阻塞其他；snapshot 含 4 个 WsFrameCapture
- **关键文件**: `case_spec.rs` GuiStep enum, `gui_replay.rs:run_gui_sequence()`
- **依赖**: 无
- **复杂度**: M

### L7.1.2 — GUI 完整启动回放 Case

- **目标**: 模拟真实 GUI.for 启动序列：4 WS 并行 + GET /configs + GET /proxies
- **交付**:
  - `cases/p1_gui_full_boot_replay.yaml`（strict，managed kernel）
  - `configs/rust_core_clash_api.json`（含 clash_api + socks inbound + direct outbound）
- **gui_sequence**: `ws_parallel`(4 streams) → `http GET /configs` → `http GET /proxies`
- **验收**: 4 WS 流各收到 ≥1 frame；/configs 200；/proxies 200 含 DIRECT；errors.count == 0
- **依赖**: L7.1.1, 新 config 文件
- **复杂度**: M

### L7.2.1 — Proxy 切换回放

- **目标**: 模拟 GUI 的 selector 切换操作 `PUT /proxies/:group`
- **交付**:
  - `cases/p1_gui_proxy_switch_replay.yaml`
  - `configs/rust_core_clash_api_selector.json`（含 selector group: direct + alt-direct）
- **gui_sequence**: GET /proxies(验证 now=direct) → PUT /proxies/my-group(切换) → GET /proxies(验证 now=alt-direct)
- **验收**: PUT 返回 204；切换后 GET 反映新 now 值
- **依赖**: 新 config
- **复杂度**: M

### L7.2.2 — Proxy Delay 测试回放

- **目标**: 模拟 `GET /proxies/:name/delay?url=...&timeout=5000`
- **交付**: `cases/p1_gui_proxy_delay_replay.yaml`
- **gui_sequence**: GET /proxies/DIRECT/delay?url=http://127.0.0.1:{echo_port}/&timeout=5000 → 200 + delay > 0
- **验收**: 返回 `{ "delay": <ms> }`，delay 合理（>0, <5000）
- **依赖**: L7.2.1 config 复用
- **复杂度**: S

### L7.2.3 — Group Delay 测试回放

- **目标**: 模拟 `GET /meta/group/:name/delay`
- **交付**: `cases/p1_gui_group_delay_replay.yaml`
- **gui_sequence**: GET /meta/group/my-group/delay?url=...&timeout=5000 → 200 + per-member delay
- **验收**: 每个 member 返回 delay 值；不存在的 group 返回 404
- **依赖**: L7.2.1 config 复用
- **复杂度**: S

### L7.3.1 — WS 重连行为测试 + CaseSpec 扩展

- **目标**: 测试 GUI 30s WS 重连行为；需新增 `post_traffic_gui_sequence` 字段
- **交付**:
  - `case_spec.rs` CaseSpec 新增 `post_traffic_gui_sequence: Option<Vec<GuiStep>>`
  - `orchestrator.rs` 在 traffic_plan 执行后、assertions 之前运行 post_traffic_gui_sequence
  - `cases/p1_gui_ws_reconnect_behavior.yaml`
- **流程**: gui_sequence(WS 连接) → traffic_plan(kernel_control restart) → post_traffic_gui_sequence(WS 重连 + 收集)
- **验收**: restart 前 WS 有 frame；restart 后重连成功并收到新 frame
- **依赖**: L7.1.1（WsParallel）, CaseSpec schema 扩展
- **复杂度**: L

### L7.3.2 — Connection Tracking 断言

- **目标**: 验证 /connections 返回的 chains/rule 元数据
- **交付**:
  - `orchestrator.rs` 扩展 `resolve_assertion_value()` 支持 `connections.count`、`connections.0.rule`、`connections.0.chains`
  - `cases/p1_gui_connections_tracking.yaml`
- **流程**: 启动 kernel → 生成 traffic → GET /connections → 断言 connections 非空 + rule/chains 已填充
- **验收**: `connections.count > 0`；每条连接有 rule 和 chains
- **依赖**: L7.2.1 config 复用, assertion key 扩展
- **复杂度**: M

### L7.4.1 — 完整用户会话端到端回放

- **目标**: 集成 capstone：启动 → 浏览 → 切换 proxy → 再浏览 → 验证连接 → 验证 WS 流
- **交付**:
  - `cases/p1_gui_full_session_replay.yaml`
  - `configs/rust_core_clash_api_full.json`
- **流程**: ws_parallel(4 streams) → GET /configs → GET /proxies → http_get via socks → GET /connections(验证 traffic) → PUT /proxies(切换) → http_get(再次) → post_traffic 验证 /traffic WS 有非零 counter
- **验收**: 全流程 errors.count == 0；proxy 切换反映在后续连接中
- **依赖**: L7.1.1, L7.2.1, L7.3.1, L7.3.2
- **复杂度**: L

### L7.4.2 — Strict 模式 P0 Clash API 契约 Case

- **目标**: 将现有 env_limited 的 `p0_clash_api_contract` 做一个 strict 版本（managed kernel）
- **交付**:
  - `cases/p0_clash_api_contract_strict.yaml`
  - 复用 L7.1.2 的 config
- **验收**: strict + kernel_mode: rust；所有 HTTP 端点返回预期状态码；4 WS 流有 frame；errors.count == 0
- **依赖**: Clash API config 文件
- **复杂度**: M

---

## 并行执行批次

### Batch 1（无依赖，立即启动，7 项全并行）

| ID | 标题 | 复杂度 | 产物类型 |
|----|------|--------|---------|
| **L5.1.2** | UDP 故障矩阵 | S | 4 YAML |
| **L5.1.3** | DNS 故障补全 | S | 2 YAML |
| **L5.2.1** | env_limited 归因 | M | Rust 模块 + 脚本 |
| **L6.1.1** | WsRoundTrip action | M | Rust 代码 |
| **L6.1.2** | TCP/TLS delay 注入 | S | Rust 代码 |
| **L6.2.2** | CI Workflow | M | YAML workflow |
| **L7.1.1** | WsParallel step | M | Rust 代码 |

### Batch 2（依赖 Batch 1，8 项）

| ID | 标题 | 依赖 | 复杂度 |
|----|------|------|--------|
| **L5.1.1** | TCP 故障矩阵 | L6.1.2 | M |
| **L5.1.4** | WS 故障矩阵 | L6.1.1 | M |
| **L5.1.5** | TLS 故障矩阵 | L6.1.2 | M |
| **L6.1.3** | TlsRoundTrip (可选) | — | M |
| **L6.2.1** | 聚合趋势报告 | L5.2.1 | S |
| **L7.1.2** | GUI 启动回放 | L7.1.1 | M |
| **L7.2.1** | Proxy 切换回放 | config | M |
| **L7.4.2** | Strict P0 契约 | config | M |

### Batch 3（依赖 Batch 2，5 项）

| ID | 标题 | 依赖 | 复杂度 |
|----|------|------|--------|
| **L5.1.6** | 文档更新 | L5.1.1~5 | S |
| **L7.2.2** | Proxy Delay 回放 | L7.2.1 | S |
| **L7.2.3** | Group Delay 回放 | L7.2.1 | S |
| **L7.3.1** | WS 重连 + schema 扩展 | L7.1.1 | L |
| **L7.3.2** | Connection Tracking | L7.2.1 | M |

### Batch 4（Capstone，2 项）

| ID | 标题 | 依赖 | 复杂度 |
|----|------|------|--------|
| **L7.4.1** | 完整用户会话 | L7.1~3 全部 | L |

---

## 依赖图

```
Batch 1 (并行):
  L5.1.2 ──┐
  L5.1.3 ──┤
  L5.2.1 ──┼──→ Batch 2
  L6.1.1 ──┤
  L6.1.2 ──┤
  L6.2.2 ──┘
  L7.1.1 ──┘

Batch 2 (大部分并行):
  L5.1.1 ←── L6.1.2
  L5.1.4 ←── L6.1.1
  L5.1.5 ←── L6.1.2
  L6.2.1 ←── L5.2.1
  L7.1.2 ←── L7.1.1 + config
  L7.2.1 ←── config
  L7.4.2 ←── config
  L6.1.3 ←── (standalone)

Batch 3:
  L5.1.6 ←── L5.1.1~5
  L7.2.2 ←── L7.2.1
  L7.2.3 ←── L7.2.1
  L7.3.1 ←── L7.1.1 + schema
  L7.3.2 ←── L7.2.1

Batch 4:
  L7.4.1 ←── L7.1.1 + L7.2.1 + L7.3.1 + L7.3.2
```

---

## 验证策略

1. **单 case 验证**: 每个新 YAML case 必须 `cargo run -p interop-lab -- case run <id>` 通过（errors=[]）
2. **回归门禁**: 每批次后跑全量 strict case：`cargo run -p interop-lab -- case run --kernel rust --env-class strict`
3. **Schema 兼容**: CaseSpec 变更后 `case list` 显示正确 case 数量（31 + 新增）
4. **单元测试**: `cargo test -p interop-lab` 全部通过
5. **趋势门禁**: `ITERATIONS=2 KERNEL=rust scripts/run_case_trend_gate.sh <case_id>`
6. **文档同步**: 每批次后更新 `case_backlog.md` + `compat_matrix.md`

---

## 关键文件清单

| 文件 | 改动类型 |
|------|---------|
| `labs/interop-lab/src/case_spec.rs` | 新增 WsRoundTrip/TlsRoundTrip/WsParallel/post_traffic_gui_sequence |
| `labs/interop-lab/src/upstream.rs` | TCP/TLS delay 注入 + WsRoundTrip/TlsRoundTrip 执行 |
| `labs/interop-lab/src/gui_replay.rs` | WsParallel step 实现 |
| `labs/interop-lab/src/orchestrator.rs` | post_traffic_gui_sequence 执行 + connections assertion keys |
| `labs/interop-lab/src/diff_report.rs` | env_limited_attributions 字段 |
| `labs/interop-lab/src/attribution.rs` | 新建：失败归因分类 |
| `labs/interop-lab/cases/*.yaml` | 新增 ~18 个 case 文件 |
| `labs/interop-lab/configs/*.json` | 新增 2-3 个 kernel config |
| `labs/interop-lab/docs/*.md` | 更新 case_backlog + compat_matrix |
| `.github/workflows/interop-lab-*.yml` | 新增 2 个 CI workflow |

---

## 实施建议

- **Batch 1 全部并行启动**：7 项无互相依赖，可用 7 个 parallel-task-executor 同时推进
- **Batch 2 分两组**：config 依赖组（L7.1.2/L7.2.1/L7.4.2 共用 config，先建 config 再并行写 case）+ 代码依赖组（L5.1.1/L5.1.4/L5.1.5 在 L6.1.1/L6.1.2 完成后即可启动）
- **Batch 3/4 按依赖顺序推进**
