# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护
> **优先级**：AI 启动时优先读取此文件

---

## 🔗 战略链接

**当前阶段**: **L18 认证替换实施中（认证优先 + 性能零回归并行）**（L1 ✅, L2 ✅, L5-L11 ✅, L12-L17 ✅）
**注**：历史 L3.1~L3.5 为服务补全/连接增强编号，现归并到 L2/M2.4；L3 仅指质量里程碑（M3.1~M3.3）。
**Parity（权威口径）**: 100%（209/209 closed, acceptance baseline），见 `agents-only/02-reference/GO_PARITY_MATRIX.md`（2026-02-24）
**Remaining**: 0（`PX-015` Linux runtime/system bus 实机验证已标记为 Accepted Limitation，不再追踪）
**Tests**: L17 快跑复验最新结果（2026-02-24 13:21，本机时区）为 `PASS_STRICT`（历史基线）；L18 起 `gui_smoke/canary` 为必过阻断，`docker` 在本机模式默认非阻断（`--require-docker 0`）。
**Interop-lab cases**: 83 total (72 strict, 10 env_limited, 1 smoke)；`cargo test -p interop-lab` 27 passed

### 🆕 L21 wave#10 推进快照（2026-03-05 17:43）

- 状态：`MIG-04 in_progress`（wave#10 已完成 app/tests inbound_http 去 core HTTP concrete + V7 断言升级）
- 本轮落地：
  1. `app/tests/inbound_http.rs` 迁移到 `sb_adapters::inbound::http::{serve_http,HttpProxyConfig}`，移除 `sb_core::inbound::http::{HttpInboundService,HttpConfig}` 依赖。
  2. `agents-only/06-scripts/l20-migration-allowlist.txt` 升级到 `l21.9-wave10-v1`（53 assertions），新增 W10-01~W10-03。
  3. 回流阻断证据：`reports/l21/artifacts/wave10_v7_regression_block.txt`（注入 `sb_core::inbound::http::HttpInboundService` 后 `--v7-only` 失败，`exit_code=1`）。
- 最小验证：
  - `cargo check -p sb-core`：PASS（`wave10_wp1_sb_core_check.txt`）
  - `cargo check -p app --test inbound_http`：PASS（`wave10_wp1_app_inbound_http_check.txt`）
  - `bash agents-only/06-scripts/check-boundaries.sh --strict`：PASS（`V7 PASS (53 assertions)`）
  - `cargo check -p app --tests`：当前 FAIL（`app/tests/selector_udp_test.rs` unresolved import/type inference，见 `wave10_wp1_app_tests_check.txt`）

### 🆕 L21 wave#11 推进快照（2026-03-05 17:55）

- 状态：`MIG-04 in_progress`（wave#11 已完成 examples 路径去 core HTTP inbound concrete + V7 断言升级）
- 本轮落地：
  1. `examples/code-examples/proxy/http_inbound_demo.rs` 迁移到 `sb_adapters::inbound::http::{serve_http,HttpProxyConfig}`，移除 `singbox_rust::inbound::http::{HttpInbound,DirectConnector}` 依赖。
  2. `agents-only/06-scripts/l20-migration-allowlist.txt` 升级到 `l21.10-wave11-v1`（56 assertions），新增 W11-01~W11-03。
  3. 回流阻断证据：`reports/l21/artifacts/wave11_v7_regression_block.txt`（注入 `singbox_rust::inbound::http::{HttpInbound, DirectConnector}` 后 `--v7-only` 失败，`exit_code=1`）。
- 最小验证：
  - `cargo check -p sb-core`：PASS（`wave11_wp1_sb_core_check.txt`）
  - `cargo check -p app --test inbound_http`：PASS（`wave11_wp1_app_inbound_http_check.txt`）
  - `bash agents-only/06-scripts/check-boundaries.sh --strict`：PASS（`V7 PASS (56 assertions)`）
  - `bash -n scripts/l18/gui_real_cert.sh`：PASS（`wave11_gui_static_syntax_check.txt`）

### 🆕 L21 wave#12 推进快照（2026-03-05 19:06）

- 状态：`MIG-06 in_progress`（wave#12 已完成 selector UDP 测试路径与统一 SelectorGroup 架构对齐 + V7 断言升级）
- 本轮落地：
  1. `app/tests/selector_udp_test.rs` 移除 `SelectorOutbound/UrlTestOutbound` 旧 concrete 依赖，统一改为 `SelectorGroup`。
  2. `agents-only/06-scripts/l20-migration-allowlist.txt` 升级到 `l21.11-wave12-v1`（59 assertions），新增 W12-01~W12-03。
  3. 回流阻断证据：`reports/l21/artifacts/wave12_v7_regression_block.txt`（注入 `sb_adapters::outbound::selector::SelectorOutbound` 后 `--v7-only` 失败，`exit_code=1`）。
- 最小验证：
  - `cargo check -p app --test selector_udp_test`：PASS（`wave12_wp1_selector_udp_check.txt`）
  - `cargo check -p app --tests`：PASS（`wave12_wp1_app_tests_check.txt`）
  - `bash agents-only/06-scripts/check-boundaries.sh --strict`：PASS（`V7 PASS (59 assertions)`）
  - `bash -n scripts/l18/gui_real_cert.sh`：PASS（`wave12_gui_static_syntax_check.txt`）

### 🆕 L21 wave#13 推进快照（2026-03-05 19:09）

- 状态：`MIG-06 in_progress`（wave#13 完成测试编译稳定性清理，门禁持续全绿）
- 本轮落地：
  1. `app/tests/protocol_chain_e2e.rs` 清理默认特性下无效告警：移除未使用顶层 `Arc`，并对 `is_constrained_dial_error_str` 添加 feature 条件编译。
  2. 复验通过：`cargo check -p app --tests`、`check-boundaries --strict`、`bash -n scripts/l18/gui_real_cert.sh`。
- 产物：
  - `reports/l21/artifacts/wave13_wp1_app_tests_check.txt`
  - `reports/l21/artifacts/wave13_strict_gate.txt`
  - `reports/l21/artifacts/wave13_gui_static_syntax_check.txt`

### 🆕 L21 wave#14 推进快照（2026-03-05 19:11）

- 状态：`MIG-06 in_progress`（wave#14 完成测试告警收敛，门禁持续全绿）
- 本轮落地：
  1. `app/src/analyze/registry.rs`：为 `supported_kinds/supported_async_kinds` 增加 `#[allow(dead_code)]`，清理 `app --tests` 既有 dead_code 告警。
  2. 复验通过：`cargo check -p app --tests`、`check-boundaries --strict`、`bash -n scripts/l18/gui_real_cert.sh`。
- 产物：
  - `reports/l21/artifacts/wave14_wp1_app_tests_check.txt`
  - `reports/l21/artifacts/wave14_strict_gate.txt`
  - `reports/l21/artifacts/wave14_gui_static_syntax_check.txt`

### 🆕 L21 wave#15 推进快照（2026-03-05 19:14）

- 状态：`MIG-06 closed`（wave#15 完成 selector 回流阻断收口）
- 本轮落地：
  1. `agents-only/06-scripts/l20-migration-allowlist.txt` 升级到 `l21.12-wave15-v1`（63 assertions），新增 W15-01~W15-04 防回流断言。
  2. 复验通过：`cargo check -p app --tests`、`check-boundaries --strict`、`bash -n scripts/l18/gui_real_cert.sh`。
  3. 回流阻断证据：`reports/l21/artifacts/wave15_v7_regression_block.txt`（注入 `struct SelectorOutbound` 后 `--v7-only` 失败，`exit_code=1`）。
- 产物：
  - `reports/l21/artifacts/wave15_wp1_app_tests_check.txt`
  - `reports/l21/artifacts/wave15_strict_gate.txt`
  - `reports/l21/artifacts/wave15_v7_regression_block.txt`
  - `reports/l21/artifacts/wave15_gui_static_syntax_check.txt`

### 🆕 L21 wave#16 推进快照（2026-03-05 19:21）

- 状态：`MIG-03 in_progress`（wave#16 完成 bootstrap selector/urltest 路径去 core Hysteria2 concrete）
- 本轮落地：
  1. `app/src/bootstrap.rs`：`to_adapter_connector(OutboundImpl::Hysteria2)` 不再构建 core `Hysteria2Outbound`，改为显式 `warn + None` 迁移提示。
  2. `agents-only/06-scripts/l20-migration-allowlist.txt` 升级到 `l21.13-wave16-v1`（65 assertions），新增 W16-01/W16-02。
  3. 回流阻断证据：`reports/l21/artifacts/wave16_v7_regression_block.txt`（注入 `sb_core::outbound::hysteria2::Hysteria2Outbound` 后 `--v7-only` 失败，`exit_code=1`）。
- 产物：
  - `reports/l21/artifacts/wave16_wp1_app_tests_check.txt`
  - `reports/l21/artifacts/wave16_wp1_sb_core_check.txt`
  - `reports/l21/artifacts/wave16_strict_gate.txt`
  - `reports/l21/artifacts/wave16_v7_regression_block.txt`
  - `reports/l21/artifacts/wave16_gui_static_syntax_check.txt`

### 🆕 L21 wave#17 推进快照（2026-03-05 19:26）

- 状态：`MIG-02 in_progress`（wave#17 完成 bootstrap selector/urltest 路径去 core SOCKS5 concrete）
- 本轮落地：
  1. `app/src/bootstrap.rs`：`to_adapter_connector(OutboundImpl::Socks5)` 不再构建 core `socks_upstream::SocksUp`，改为显式 `warn + None` 迁移提示。
  2. `agents-only/06-scripts/l20-migration-allowlist.txt` 升级到 `l21.14-wave17-v1`（67 assertions），新增 W17-01/W17-02。
  3. 回流阻断证据：`reports/l21/artifacts/wave17_v7_regression_block.txt`（注入 `socks_upstream::SocksUp` 后 `--v7-only` 失败，`exit_code=1`）。
- 产物：
  - `reports/l21/artifacts/wave17_wp1_app_tests_check.txt`
  - `reports/l21/artifacts/wave17_wp1_sb_core_check.txt`
  - `reports/l21/artifacts/wave17_strict_gate.txt`
  - `reports/l21/artifacts/wave17_v7_regression_block.txt`
  - `reports/l21/artifacts/wave17_gui_static_syntax_check.txt`

### 🆕 L21 wave#18 推进快照（2026-03-05 19:29）

- 状态：`MIG-02 in_progress`（wave#18 完成 bootstrap selector/urltest 路径去 core HTTP proxy concrete）
- 本轮落地：
  1. `app/src/bootstrap.rs`：`to_adapter_connector(OutboundImpl::HttpProxy)` 不再构建 core `http_upstream::HttpUp`，改为显式 `warn + None` 迁移提示。
  2. `agents-only/06-scripts/l20-migration-allowlist.txt` 升级到 `l21.15-wave18-v1`（69 assertions），新增 W18-01/W18-02。
  3. 回流阻断证据：`reports/l21/artifacts/wave18_v7_regression_block.txt`（注入 `http_upstream::HttpUp` 后 `--v7-only` 失败，`exit_code=1`）。
- 产物：
  - `reports/l21/artifacts/wave18_wp1_app_tests_check.txt`
  - `reports/l21/artifacts/wave18_wp1_sb_core_check.txt`
  - `reports/l21/artifacts/wave18_strict_gate.txt`
  - `reports/l21/artifacts/wave18_v7_regression_block.txt`
  - `reports/l21/artifacts/wave18_gui_static_syntax_check.txt`

### 🆕 L21 wave#19 推进快照（2026-03-05 19:32）

- 状态：`MIG-02 in_progress`（wave#19 完成 bootstrap selector/urltest 路径去 core TUIC concrete）
- 本轮落地：
  1. `app/src/bootstrap.rs`：`to_adapter_connector(OutboundImpl::Tuic)` 不再构建 core `outbound::tuic::TuicOutbound`，改为显式 `warn + None` 迁移提示。
  2. `agents-only/06-scripts/l20-migration-allowlist.txt` 升级到 `l21.16-wave19-v1`（71 assertions），新增 W19-01/W19-02。
  3. 回流阻断证据：`reports/l21/artifacts/wave19_v7_regression_block.txt`（注入 `outbound::tuic::TuicOutbound` 后 `--v7-only` 失败，`exit_code=1`）。
- 产物：
  - `reports/l21/artifacts/wave19_wp1_app_tests_check.txt`
  - `reports/l21/artifacts/wave19_wp1_sb_core_check.txt`
  - `reports/l21/artifacts/wave19_strict_gate.txt`
  - `reports/l21/artifacts/wave19_v7_regression_block.txt`
  - `reports/l21/artifacts/wave19_gui_static_syntax_check.txt`

### 🆕 L21 wave#20 推进快照（2026-03-05 19:36）

- 状态：`MIG-02 in_progress`（wave#20 完成 bootstrap selector/urltest 路径去 core VMess concrete）
- 本轮落地：
  1. `app/src/bootstrap.rs`：`to_adapter_connector(OutboundImpl::Vmess)` 不再构建 core `outbound::vmess::VmessOutbound`，改为显式 `warn + None` 迁移提示。
  2. `agents-only/06-scripts/l20-migration-allowlist.txt` 升级到 `l21.17-wave20-v1`（73 assertions），新增 W20-01/W20-02。
  3. 回流阻断证据：`reports/l21/artifacts/wave20_v7_regression_block.txt`（注入 `outbound::vmess::VmessOutbound` 后 `--v7-only` 失败，`exit_code=1`）。
- 产物：
  - `reports/l21/artifacts/wave20_wp1_app_tests_check.txt`
  - `reports/l21/artifacts/wave20_wp1_sb_core_check.txt`
  - `reports/l21/artifacts/wave20_strict_gate.txt`
  - `reports/l21/artifacts/wave20_v7_regression_block.txt`
  - `reports/l21/artifacts/wave20_gui_static_syntax_check.txt`

### 🆕 L21 wave#21 推进快照（2026-03-05 19:39）

- 状态：`MIG-02 in_progress`（wave#21 完成 bootstrap selector/urltest 路径去 core VLESS concrete）
- 本轮落地：
  1. `app/src/bootstrap.rs`：`to_adapter_connector(OutboundImpl::Vless)` 不再构建 core `outbound::vless::VlessOutbound`，改为显式 `warn + None` 迁移提示。
  2. `agents-only/06-scripts/l20-migration-allowlist.txt` 升级到 `l21.18-wave21-v1`（75 assertions），新增 W21-01/W21-02。
  3. 回流阻断证据：`reports/l21/artifacts/wave21_v7_regression_block.txt`（注入 `outbound::vless::VlessOutbound` 后 `--v7-only` 失败，`exit_code=1`）。
- 产物：
  - `reports/l21/artifacts/wave21_wp1_app_tests_check.txt`
  - `reports/l21/artifacts/wave21_wp1_sb_core_check.txt`
  - `reports/l21/artifacts/wave21_strict_gate.txt`
  - `reports/l21/artifacts/wave21_v7_regression_block.txt`
  - `reports/l21/artifacts/wave21_gui_static_syntax_check.txt`

### 🆕 L21 wave#22 推进快照（2026-03-05 19:43）

- 状态：`MIG-01 hardening`（wave#22 完成 bootstrap selector/urltest 路径去 core direct concrete）
- 本轮落地：
  1. `app/src/bootstrap.rs`：`to_adapter_connector(OutboundImpl::Direct)` 不再构建 core `direct_connector::DirectConnector`，改为本地 `BootstrapDirectAdapterConnector` 并委托 `sb_adapters::outbound::direct::DirectOutbound`。
  2. `agents-only/06-scripts/l20-migration-allowlist.txt` 升级到 `l21.19-wave22-v1`（77 assertions），新增 W22-01/W22-02。
  3. 回流阻断证据：`reports/l21/artifacts/wave22_v7_regression_block.txt`（注入 `direct_connector::DirectConnector` 后 `--v7-only` 失败，`exit_code=1`）。
- 产物：
  - `reports/l21/artifacts/wave22_wp1_app_tests_check.txt`
  - `reports/l21/artifacts/wave22_wp1_sb_core_check.txt`
  - `reports/l21/artifacts/wave22_strict_gate.txt`
  - `reports/l21/artifacts/wave22_v7_regression_block.txt`
  - `reports/l21/artifacts/wave22_gui_static_syntax_check.txt`

### 🆕 L21 wave#23 推进快照（2026-03-05 19:45）

- 状态：`MIG-02 hardening`（wave#23 完成 bootstrap selector/urltest Trojan 路径显式禁用提示补全）
- 本轮落地：
  1. `app/src/bootstrap.rs`：`to_adapter_connector(OutboundImpl::Trojan)` 从静默 `None` 改为显式 `warn + None`，提示迁移到 adapter bridge/supervisor 路径。
  2. `agents-only/06-scripts/l20-migration-allowlist.txt` 升级到 `l21.20-wave23-v1`（79 assertions），新增 W23-01/W23-02。
  3. 回流阻断证据：`reports/l21/artifacts/wave23_v7_regression_block.txt`（注入 `outbound::trojan::TrojanOutbound` 后 `--v7-only` 失败，`exit_code=1`）。
- 产物：
  - `reports/l21/artifacts/wave23_wp1_app_tests_check.txt`
  - `reports/l21/artifacts/wave23_wp1_sb_core_check.txt`
  - `reports/l21/artifacts/wave23_strict_gate.txt`
  - `reports/l21/artifacts/wave23_v7_regression_block.txt`
  - `reports/l21/artifacts/wave23_gui_static_syntax_check.txt`

### 🆕 L21 wave#24 推进快照（2026-03-05 20:01）

- 状态：`MIG-02 hardening`（wave#24 完成 bootstrap selector/urltest fallback 路径去静默回退）
- 本轮落地：
  1. `app/src/bootstrap.rs`：`to_adapter_connector` 末尾 fallback 从静默 `_ => None` 改为显式 `warn + None`，并提供统一迁移提示。
  2. `agents-only/06-scripts/l20-migration-allowlist.txt` 升级到 `l21.21-wave24-v1`（81 assertions），新增 W24-01/W24-02。
  3. 回流阻断证据：`reports/l21/artifacts/wave24_v7_regression_block.txt`（注入 `other => None` 后 `--v7-only` 失败，`exit_code=1`）。
- 产物：
  - `reports/l21/artifacts/wave24_wp1_app_tests_check.txt`
  - `reports/l21/artifacts/wave24_wp1_sb_core_check.txt`
  - `reports/l21/artifacts/wave24_strict_gate.txt`
  - `reports/l21/artifacts/wave24_v7_regression_block.txt`
  - `reports/l21/artifacts/wave24_gui_static_syntax_check.txt`

### 🆕 L21 wave#25 推进快照（2026-03-05 20:04）

- 状态：`MIG-02 hardening`（wave#25 完成 bootstrap selector/urltest 已知分支显式化）
- 本轮落地：
  1. `app/src/bootstrap.rs`：`to_adapter_connector` 新增 `Block`、`Connector`、`Naive(feature-gated)` 显式 `warn + None` 分支，收敛 fallback 命中面。
  2. `agents-only/06-scripts/l20-migration-allowlist.txt` 升级到 `l21.22-wave25-v1`（83 assertions），新增 W25-01/W25-02。
  3. 回流阻断证据：`reports/l21/artifacts/wave25_v7_regression_block.txt`（注入 `other => None` 后 `--v7-only` 失败，`exit_code=1`）。
- 产物：
  - `reports/l21/artifacts/wave25_wp1_app_tests_check.txt`
  - `reports/l21/artifacts/wave25_wp1_sb_core_check.txt`
  - `reports/l21/artifacts/wave25_strict_gate.txt`
  - `reports/l21/artifacts/wave25_v7_regression_block.txt`
  - `reports/l21/artifacts/wave25_gui_static_syntax_check.txt`

### 🆕 L21 wave#26 推进快照（2026-03-05 20:10）

- 状态：`MIG-02 hardening`（wave#26 完成 switchboard HTTP 路径去 core concrete）
- 本轮落地：
  1. `crates/sb-core/src/runtime/switchboard.rs`：`OutboundType::Http` 不再构建 core `outbound::http_upstream::HttpUp`，改为显式 `UnsupportedProtocol` 迁移提示。
  2. `agents-only/06-scripts/l20-migration-allowlist.txt` 升级到 `l21.23-wave26-v1`（85 assertions），新增 W26-01/W26-02。
  3. 回流阻断证据：`reports/l21/artifacts/wave26_v7_regression_block.txt`（注入 `outbound::http_upstream::HttpUp` 后 `--v7-only` 失败，`exit_code=1`）。
- 产物：
  - `reports/l21/artifacts/wave26_wp1_app_tests_check.txt`
  - `reports/l21/artifacts/wave26_wp1_sb_core_check.txt`
  - `reports/l21/artifacts/wave26_strict_gate.txt`
  - `reports/l21/artifacts/wave26_v7_regression_block.txt`
  - `reports/l21/artifacts/wave26_gui_static_syntax_check.txt`

### 🆕 L21 wave#27 推进快照（2026-03-05 20:14）

- 状态：`MIG-02 hardening`（wave#27 完成 core bridge HTTP/SOCKS 路径去 core concrete）
- 本轮落地：
  1. `crates/sb-core/src/adapter/mod.rs`：`Bridge::new_from_config` 的 `OutboundType::Http/Socks` 不再构建 `outbound::http_upstream::HttpUp`/`outbound::socks_upstream::SocksUp`，统一改为 `UnsupportedOutboundConnector` 并提示迁移到 `adapter::bridge::build_bridge`。
  2. `agents-only/06-scripts/l20-migration-allowlist.txt` 升级到 `l21.24-wave27-v1`（89 assertions），新增 W27-01~W27-04。
  3. 回流阻断证据：`reports/l21/artifacts/wave27_v7_regression_block.txt`（注入 `outbound::socks_upstream::SocksUp` 后 `--v7-only` 失败，`exit_code=1`）。
- 产物：
  - `reports/l21/artifacts/wave27_wp1_app_tests_check.txt`
  - `reports/l21/artifacts/wave27_wp1_sb_core_check.txt`
  - `reports/l21/artifacts/wave27_strict_gate.txt`
  - `reports/l21/artifacts/wave27_v7_regression_block.txt`
  - `reports/l21/artifacts/wave27_gui_static_syntax_check.txt`

### 🆕 L21 wave#28 推进快照（2026-03-05 20:17）

- 状态：`MIG-02 hardening`（wave#28 完成 core bridge outbound fallback 去静默 direct 回退）
- 本轮落地：
  1. `crates/sb-core/src/adapter/mod.rs`：`Bridge::new_from_config` 兜底分支由 `_ => direct_connector_fallback()` 调整为 `unsupported_outbound_connector(...)`，未知类型不再静默降级为 direct。
  2. `agents-only/06-scripts/l20-migration-allowlist.txt` 升级到 `l21.25-wave28-v1`（91 assertions），新增 W28-01/W28-02。
  3. 回流阻断证据：`reports/l21/artifacts/wave28_v7_regression_block.txt`（注入 `_ => direct_connector_fallback()` 后 `--v7-only` 失败，`exit_code=1`）。
- 产物：
  - `reports/l21/artifacts/wave28_wp1_app_tests_check.txt`
  - `reports/l21/artifacts/wave28_wp1_sb_core_check.txt`
  - `reports/l21/artifacts/wave28_strict_gate.txt`
  - `reports/l21/artifacts/wave28_v7_regression_block.txt`
  - `reports/l21/artifacts/wave28_gui_static_syntax_check.txt`

### 🆕 L21 wave#29 推进快照（2026-03-05 20:22）

- 状态：`MIG-02 hardening`（wave#29 完成 core bridge VLESS 分支去 direct fallback）
- 本轮落地：
  1. `crates/sb-core/src/adapter/mod.rs`：`Bridge::new_from_config` 的 `OutboundType::Vless` 由 `direct_connector_fallback()` 改为 `unsupported_outbound_connector(...)`，避免 VLESS 分支静默降级到 direct。
  2. `agents-only/06-scripts/l20-migration-allowlist.txt` 升级到 `l21.26-wave29-v1`（93 assertions），新增 W29-01/W29-02。
  3. 回流阻断证据：`reports/l21/artifacts/wave29_v7_regression_block.txt`（注入 `sb_config::ir::OutboundType::Vless => { direct_connector_fallback()` 后 `--v7-only` 失败，`exit_code=1`）。
- 产物：
  - `reports/l21/artifacts/wave29_wp1_app_tests_check.txt`
  - `reports/l21/artifacts/wave29_wp1_sb_core_check.txt`
  - `reports/l21/artifacts/wave29_strict_gate.txt`
  - `reports/l21/artifacts/wave29_v7_regression_block.txt`
  - `reports/l21/artifacts/wave29_gui_static_syntax_check.txt`

### 🆕 L21 wave#30 推进快照（2026-03-05 20:26）

- 状态：`MIG-02 hardening`（wave#30 完成 core bridge Shadowsocks 分支去 direct fallback）
- 本轮落地：
  1. `crates/sb-core/src/adapter/mod.rs`：`Bridge::new_from_config` 的 `OutboundType::Shadowsocks` 由 `direct_connector_fallback()` 改为 `unsupported_outbound_connector(...)`，避免 Shadowsocks 分支静默降级到 direct。
  2. `agents-only/06-scripts/l20-migration-allowlist.txt` 升级到 `l21.27-wave30-v1`（95 assertions），新增 W30-01/W30-02。
  3. 回流阻断证据：`reports/l21/artifacts/wave30_v7_regression_block.txt`（注入 `sb_config::ir::OutboundType::Shadowsocks => direct_connector_fallback()` 后 `--v7-only` 失败，`exit_code=1`）。
- 产物：
  - `reports/l21/artifacts/wave30_wp1_app_tests_check.txt`
  - `reports/l21/artifacts/wave30_wp1_sb_core_check.txt`
  - `reports/l21/artifacts/wave30_strict_gate.txt`
  - `reports/l21/artifacts/wave30_v7_regression_block.txt`
  - `reports/l21/artifacts/wave30_gui_static_syntax_check.txt`

### 🆕 L21 wave#31 推进快照（2026-03-05 20:29）

- 状态：`MIG-02 hardening`（wave#31 完成 core bridge URLTest 分支去 direct fallback）
- 本轮落地：
  1. `crates/sb-core/src/adapter/mod.rs`：`Bridge::new_from_config` 的 `OutboundType::UrlTest` 由 `direct_connector_fallback()` 改为 `unsupported_outbound_connector(...)`，避免 URLTest 分支静默降级到 direct。
  2. `agents-only/06-scripts/l20-migration-allowlist.txt` 升级到 `l21.28-wave31-v1`（97 assertions），新增 W31-01/W31-02。
  3. 回流阻断证据：`reports/l21/artifacts/wave31_v7_regression_block.txt`（注入 `sb_config::ir::OutboundType::UrlTest => direct_connector_fallback()` 后 `--v7-only` 失败，`exit_code=1`）。
- 产物：
  - `reports/l21/artifacts/wave31_wp1_app_tests_check.txt`
  - `reports/l21/artifacts/wave31_wp1_sb_core_check.txt`
  - `reports/l21/artifacts/wave31_strict_gate.txt`
  - `reports/l21/artifacts/wave31_v7_regression_block.txt`
  - `reports/l21/artifacts/wave31_gui_static_syntax_check.txt`

### 🆕 L21 wave#32 推进快照（2026-03-05 20:32）

- 状态：`MIG-02 hardening`（wave#32 完成 core bridge ShadowTLS 分支去 direct fallback）
- 本轮落地：
  1. `crates/sb-core/src/adapter/mod.rs`：`Bridge::new_from_config` 的 `OutboundType::Shadowtls` 由 `direct_connector_fallback()` 改为 `unsupported_outbound_connector(...)`，避免 ShadowTLS 分支静默降级到 direct。
  2. `agents-only/06-scripts/l20-migration-allowlist.txt` 升级到 `l21.29-wave32-v1`（99 assertions），新增 W32-01/W32-02。
  3. 回流阻断证据：`reports/l21/artifacts/wave32_v7_regression_block.txt`（注入 `sb_config::ir::OutboundType::Shadowtls => { direct_connector_fallback()` 后 `--v7-only` 失败，`exit_code=1`）。
- 产物：
  - `reports/l21/artifacts/wave32_wp1_app_tests_check.txt`
  - `reports/l21/artifacts/wave32_wp1_sb_core_check.txt`
  - `reports/l21/artifacts/wave32_strict_gate.txt`
  - `reports/l21/artifacts/wave32_v7_regression_block.txt`
  - `reports/l21/artifacts/wave32_gui_static_syntax_check.txt`

### 🆕 L21 wave#33 推进快照（2026-03-05 20:34）

- 状态：`MIG-02 hardening`（wave#33 完成 core bridge Hysteria2 分支去 direct fallback）
- 本轮落地：
  1. `crates/sb-core/src/adapter/mod.rs`：`Bridge::new_from_config` 的 `OutboundType::Hysteria2` 由 `direct_connector_fallback()` 改为 `unsupported_outbound_connector(...)`，避免 Hysteria2 分支静默降级到 direct。
  2. `agents-only/06-scripts/l20-migration-allowlist.txt` 升级到 `l21.30-wave33-v1`（101 assertions），新增 W33-01/W33-02。
  3. 回流阻断证据：`reports/l21/artifacts/wave33_v7_regression_block.txt`（注入 `sb_config::ir::OutboundType::Hysteria2 => { direct_connector_fallback()` 后 `--v7-only` 失败，`exit_code=1`）。
- 产物：
  - `reports/l21/artifacts/wave33_wp1_app_tests_check.txt`
  - `reports/l21/artifacts/wave33_wp1_sb_core_check.txt`
  - `reports/l21/artifacts/wave33_strict_gate.txt`
  - `reports/l21/artifacts/wave33_v7_regression_block.txt`
  - `reports/l21/artifacts/wave33_gui_static_syntax_check.txt`

### 🆕 L21 wave#34 推进快照（2026-03-05 20:37）

- 状态：`MIG-02 hardening`（wave#34 完成 core bridge TUIC 分支去 direct fallback）
- 本轮落地：
  1. `crates/sb-core/src/adapter/mod.rs`：`Bridge::new_from_config` 的 `OutboundType::Tuic` 由 `direct_connector_fallback()` 改为 `unsupported_outbound_connector(...)`，避免 TUIC 分支静默降级到 direct。
  2. `agents-only/06-scripts/l20-migration-allowlist.txt` 升级到 `l21.31-wave34-v1`（103 assertions），新增 W34-01/W34-02。
  3. 回流阻断证据：`reports/l21/artifacts/wave34_v7_regression_block.txt`（注入 `sb_config::ir::OutboundType::Tuic => { direct_connector_fallback()` 后 `--v7-only` 失败，`exit_code=1`）。
- 产物：
  - `reports/l21/artifacts/wave34_wp1_app_tests_check.txt`
  - `reports/l21/artifacts/wave34_wp1_sb_core_check.txt`
  - `reports/l21/artifacts/wave34_strict_gate.txt`
  - `reports/l21/artifacts/wave34_v7_regression_block.txt`
  - `reports/l21/artifacts/wave34_gui_static_syntax_check.txt`

### 🚨 P0 最高优先级（2026-03-04 18:14）

- **状态**：✅ 短路收口已全绿；`nightly 24h` 已重新发车并运行中
- 本轮已完成：
  1. `scripts/l18/run_capstone_fixed_profile.sh` 已使用批次私有冻结二进制（`runtime_bin/{run,app}`）驱动 capstone/dual，规避 `target/` 产物波动。
  2. 短路批次（`L18_CANARY_HOURS=0`）已完整收口：`reports/l18/batches/20260304T093912Z-l18-nightly-preflight`。
  3. `summary.tsv` + `l18_capstone_status.json` 完整生成，`overall=PASS`，`workspace/fmt/clippy/gui/canary/dual/perf` 全 `PASS`。
  4. 未复现 `clash_http_e2e::test_healthcheck_proxy_provider` 失败；`dual/perf` 未再出现 `target/release/run` 丢失。
  5. `precheck.txt` 固定环境记录已对齐冻结路径（`fixed_env.L18_RUST_BIN/L18_DUAL_RUST_BIN/L18_DUAL_RUST_APP_BIN`）。
- 关键证据：
  - 短路汇总：`reports/l18/batches/20260304T093912Z-l18-nightly-preflight/capstone_nightly_fixedcfg/summary.tsv`
  - 短路状态：`reports/l18/batches/20260304T093912Z-l18-nightly-preflight/capstone_nightly_fixedcfg/r1/l18_capstone_status.json`
  - capstone 标准输出：`reports/l18/batches/20260304T093912Z-l18-nightly-preflight/capstone_nightly_fixedcfg/r1/capstone.stdout.log`

### 🆕 当前执行主线（2026-03-04 18:14）

1. `nightly 24h` 已启动并在运行：
   - batch: `reports/l18/batches/20260304T101430Z-l18-nightly-24h`
   - 主进程: `pid=31072`（`run_capstone_fixed_profile.sh`）
   - 子进程: `pid=31170`（`l18_capstone.sh`）
   - 日志:
     - `reports/l18/batches/20260304T101430Z-l18-nightly-24h/capstone_nightly_fixedcfg/r1/capstone.stdout.log`
     - `reports/l18/batches/20260304T101430Z-l18-nightly-24h/capstone_nightly_fixedcfg/r1/capstone.stderr.log`
2. 进行中阶段快照（来自 `capstone.stdout.log`）：
   - `preflight=PASS`
   - `oracle=PASS`
   - `boundaries=PASS`
   - `parity=PASS`
   - `workspace_test=PASS`
   - `fmt=PASS`
   - `clippy=PASS`
   - `hot_reload=PASS`
   - `signal=PASS`
   - `gui_smoke=PASS`
   - `canary=RUNNING`
3. 下一动作：
   - 持续监控 `20260304T101430Z-l18-nightly-24h`，完成后回填 `summary.tsv` + `l18_capstone_status.json`
   - 若失败按日志修复并重跑短路，再次发车 24h
   - 24h 全绿后发车 `certify 7d`

### L18 nightly/certify 固定配置执行器（2026-02-26）

- 新增脚本：`scripts/l18/run_capstone_fixed_profile.sh`
  - 职责：配置冻结、前置校验、批次目录隔离、独立 canary runtime、固定 env 执行 `l18_capstone`
  - 固定基线：`L18_GUI_TIMEOUT_SEC=120`、`L18_RUST_BUILD_ENABLED=0`、`L18_GUI_GO_BUILD_ENABLED=0`、`L18_GUI_RUST_BUILD_ENABLED=0`、`L18_RUST_BIN=target/release/run`
  - 产物：`config.freeze.json`、`precheck.txt`、`r1/{preflight,oracle,gui,canary,dual_kernel,dual_kernel_artifacts,perf}`
- CI 固化：`.github/workflows/l18-certification-macos.yml`
  - 新增 parity 预构建步骤
  - capstone step 固定上述 env，避免 nightly/certify 配置漂移
- 运行入口：
  - 本地 nightly：`scripts/l18/run_capstone_fixed_profile.sh --profile nightly --gui-app <abs_gui_app> --require-docker 0`
  - CI certify：workflow dispatch `profile=certify`（保持 `L18_REQUIRE_DOCKER=1`）
- 会话结束前状态：
  - 24h `nightly` 尚未产出最终结论文件（需在下一会话持续执行并回填）
  - 关键端口已释放：`9090/19090/11810/11811/29090/12810` 全 free

### L18 短时高压 48x 预演（2026-02-27 14:07）

- 执行入口：
  - `scripts/l18/run_stress_short_48x.sh --duration-min 30 --gui-app /Users/bob/Desktop/Projects/ING/sing/singbox-rust/GUI_fork_source/GUI.for.SingBox-1.19.0/build/bin/GUI.for.SingBox.app --require-docker 0 --allow-existing-system-proxy 1 --allow-real-proxy-coexist 1`
- 批次根：
  - `reports/l18/batches/20260227T054642Z-l18-stress-48x`
- 结果：
  - `summary.tsv`: `r1 PASS PASS`
  - `stress_status.json`: `overall=PASS`，`elapsed_sec=1203`，`duration_min_target=30`，`composite_multiplier=48`
  - stage 全通过：`PREFLIGHT/GUI/ALL_CASES_RUST/SOAK_SHORT_WS/SOAK_SHORT_WS_DUAL_CORE/P2_ROUND_2/3/4/DUAL_NIGHTLY/PERF_3X`
- 证据：
  - canary：`stress_short_48x/r1/canary/canary_stress_30m.md`（`sample_count=80`，`health_200_count=80`，`pass=true`）
  - dual：`stress_short_48x/r1/dual_kernel/20260227T060009Z-nightly-7c1032bd/summary.json`（`run_fail_count=0`，`diff_fail_count=0`）
  - perf：`stress_short_48x/r1/perf/perf_gate.json`（`pass=true`）
  - gui：`reports/l18/gui_real_cert.json`（已复制到 `stress_short_48x/r1/gui/gui_real_cert.json`）
- 结论：
  - 短时高压预演已收口通过，可作为加速回归证据。
  - **不替代** L18 结项所需 `nightly 24h` 与 `certify 7d` 正式认证证据。

### L18 v7 同配置三连 PASS（2026-02-26 10:38）

- 基线 dual 差分复验：
  - 命令：`scripts/l18/run_dual_kernel_cert.sh --profile daily`
  - run_id：`20260226T015945Z-daily-dc0b3935`
  - 结果：`PASS`（`selected_case_count=5`，`run_fail_count=0`，`diff_fail_count=0`）
  - 证据：`reports/l18/dual_kernel/20260226T015945Z-daily-dc0b3935/{summary.json,diff_gate.json}`
- 同配置 3 轮 daily（复用 `timeout120 + parity 固定二进制`）：
  - 命令：`reports/l18/batches/20260225T134935Z-l18-daily-converge-v4/run_capstone_daily_v4.sh capstone_daily_convergence_v7_timeout120 3`
  - 汇总：`reports/l18/batches/20260225T134935Z-l18-daily-converge-v4/capstone_daily_convergence_v7_timeout120/summary.tsv`
  - 结果：`r1/r2/r3` 全部 `overall=PASS`，且 `gui/dual/perf` 全 `PASS`（`docker=WARN` 非阻断）
- 三轮 dual case 差分：
  - `r1` run_id=`20260226T021330Z-daily-db9d17f6`：`run_fail_count=0`，`diff_fail_count=0`
  - `r2` run_id=`20260226T022257Z-daily-a764c3c1`：`run_fail_count=0`，`diff_fail_count=0`
  - `r3` run_id=`20260226T023217Z-daily-d4d10514`：`run_fail_count=0`，`diff_fail_count=0`
- GUI 契约观测：三轮 `go=/proxies=200`、`rust=/proxies=200`，未复现偶发 startup 失败。
- 结论：已满足“连续至少 3 轮 capstone_daily 同配置 PASS（含 perf_gate=PASS）”目标。

### L18 v5/v6b 收敛更新（2026-02-25 22:55）

- 批次：`reports/l18/batches/20260225T134935Z-l18-daily-converge-v4`
- `capstone_daily_convergence_v5`（3 轮）结果：
  - `r1`: `PASS`
  - `r2`: `FAIL`（仅 `gui_smoke=FAIL`，其余 gate 全 `PASS`，`docker=WARN`）
  - `r3`: `FAIL`（仅 `gui_smoke=FAIL`，其余 gate 全 `PASS`，`docker=WARN`）
  - 失败特征一致：Rust GUI 核 `startup/load_config/connections` 失败，`/proxies=000000`（连接拒绝）。
- 隔离治理已完成并验证：
  - `scripts/l18/l18_capstone.sh` 新增稳定性报告目录派生修复：`SINGBOX_STABILITY_REPORT_DIR` 现在跟随每轮 `--canary-output-root`，不再污染根目录。
  - `scripts/bench_memory.sh` 去除对根目录 `reports/stability` 的隐式创建。
  - 当前稳定性产物落盘示例：`.../rN/canary/stability_reports/`。
- GUI 抖动缓解策略落地：
  - 在批次驱动脚本中将 `L18_GUI_TIMEOUT_SEC` 提升到 `120s`。
  - 追加验证轮：`capstone_daily_convergence_v6b_timeout120/r1`，当前结果 `PASS`（含 `gui_smoke=PASS`，`go/rust /proxies=200`）。
- 新阻塞已排除：
  - `perf_gate` 之前会重编 `target/release/run`（`acceptance`），导致后续 canary 二进制能力漂移；已在批次驱动脚本中固定为先构建 `parity` 且 `L18_RUST_BUILD_ENABLED=0`（避免被 perf 覆盖）。

### L18 认证批次更新（2026-02-25 19:45）

- 20 轮 GUI 稳定性批次已完成：`reports/l18/batches/20260225T105130Z-l18-stability/gui20/summary.json`
  - 结果：`overall_pass_rounds=20/20`，Go/Rust startup 均 `20/20 PASS`。
- `capstone_daily_r4` 与 `capstone_daily_r5` 已完成全链路实跑（目录级隔离）：
  - `r4` 状态：`reports/l18/batches/20260225T105130Z-l18-stability/capstone_daily_r4/l18_capstone_status.json`
  - `r5` 状态：`reports/l18/batches/20260225T105130Z-l18-stability/capstone_daily_r5/l18_capstone_status.json`
  - 共同结论：除 `perf_gate` 外全部门禁 `PASS`（`docker=WARN` 非阻断）。
- 双核差分在两轮 capstone 内均收敛：
  - `r4`: run_id=`20260225T112254Z-daily-39041b1c`，`run_fail_count=0`，`diff_fail_count=0`
  - `r5`: run_id=`20260225T113929Z-daily-15fa18f7`，`run_fail_count=0`，`diff_fail_count=0`
- Rust Clash API `/proxies` 契约在最新 GUI 实跑保持对齐：
  - `reports/l18/batches/20260225T105130Z-l18-stability/capstone_daily_r5/gui/gui_real_cert.json`
  - Go/Rust `load_config` 均 `PASS`（`/proxies=200`）。
- `perf_gate` 呈现延迟抖动（唯一阻塞）：
  - `r4`: `latency_p95` `+6.663%`（FAIL）
  - `r5`: `latency_p95` `+37.108%`（FAIL）
  - 复测：`perf_retries/retry_03_parity/perf_gate.json` 为 `PASS`（`latency_p95=-3.260%`）。
- 当前主线阻塞：**L18 `perf_gate` 稳定性不足（latency p95 抖动）**；非 `/proxies` 契约问题。

### L18 perf_gate 代码侧优化收口（2026-02-25 17:30）

- 目标：按 A 路线先收敛启动回归，优先代码侧优化（不依赖编译参数调参）。
- 关键代码优化：
  - `crates/sb-tls/src/global.rs`：TLS 全局配置改为惰性构建与缓存（`apply_extra_cas` 仅失效缓存，`get_effective` 首次使用时构建），移除启动期无条件加载系统根证书的固定开销。
  - `crates/sb-adapters/src/inbound/socks/mod.rs`：`ATYP=DOMAIN` 且 host 为字面 IP 时直转 `Endpoint::Ip`，避免无效 DNS 解析；并复用现有 tokio runtime 以降低入站启动开销。
  - `app/src/reqwest_http.rs`：全局 reqwest client 延迟到首次请求再初始化。
- 复测结果：
  - 命令：`scripts/l18/perf_gate.sh`
  - 报告：`reports/l18/perf_gate.json`（`generated_at=2026-02-25T09:30:54Z`）
  - 结论：`pass=true`
  - 指标：`startup` Rust 19ms vs Go 18ms（`+5.556%`，阈值 `+10%`，PASS）；`latency_p95` `-28.365%`（PASS）；`rss_peak` `-3.306%`（PASS）。
- 差分回归复验：
  - 命令：`scripts/l18/run_dual_kernel_cert.sh --profile daily`
  - run_id：`20260225T093234Z-daily-f0363206`
  - 结果：`PASS`（`run_fail_count=0`、`diff_fail_count=0`，`selected_case_count=5`）
  - 证据：`reports/l18/dual_kernel/20260225T093234Z-daily-f0363206/summary.json`、`diff_gate.json`
- 当前状态：代码侧优化已生效，但 capstone 批次内仍存在 `latency_p95` 抖动。
- 当前剩余主线阻塞：`perf_gate` 稳定性（p95 波动）待收敛。

### L18 GUI `/proxies` 契约对齐收口（2026-02-25 18:25）

- 根因定位：`gui_real_cert` 默认二进制可能不具备完整控制面能力（Go 未强制 `with_clash_api`、Rust 默认 `run` 二进制未确保 `parity` 特性），导致 `/proxies` 在 GUI 路径返回 `000/不可达`。
- 脚本收敛：`scripts/l18/gui_real_cert.sh`
  - 新增参数：`--go-build-enabled`、`--go-build-tags`、`--rust-build-enabled`、`--rust-build-features`。
  - 默认行为：Go 自动调用 `scripts/l18/build_go_oracle.sh --build-tags with_clash_api`；Rust 自动执行 `cargo build --release -p app --features parity --bin run`。
- GUI 实跑复验：
  - 命令：`scripts/l18/gui_real_cert.sh --gui-app /Users/bob/Desktop/Projects/ING/sing/singbox-rust/GUI_fork_source/GUI.for.SingBox-1.19.0/build/bin/GUI.for.SingBox.app --allow-existing-system-proxy 1 --allow-real-proxy-coexist 1`
  - 报告：`reports/l18/gui_real_cert.json`（`generated_at=2026-02-25T10:25:20Z`）
  - 结果：Go/Rust `load_config` 均为 `PASS`（`/proxies=200`），`overall=PASS`。
- case 级差分回归：
  - 命令：`scripts/l18/run_dual_kernel_cert.sh --profile daily`
  - run_id：`20260225T102551Z-daily-afa76157`
  - 结果：`PASS`（`run_fail_count=0`、`diff_fail_count=0`，5/5 clean）。

### L18 三产物重编 + startup 稳定性复验（2026-02-25 18:43）

- 按“编译产物 feature 不匹配可重编”策略，清理并重建 3 个关键产物：
  - `target/debug/app`（`cargo build -p app --features parity --bin app`）
  - `target/release/run`（`cargo build --release -p app --features parity --bin run`）
  - `go_fork_source/sing-box-1.12.14/sing-box`（`go build -tags with_clash_api`）
- 可用性探测：3 个产物分别启动后 `GET /proxies` 均返回 `200`。
- `startup` 稳定性多轮复验（禁用自动重编，避免混入构建抖动）：
  - 命令：`scripts/l18/gui_real_cert.sh --gui-app ... --allow-existing-system-proxy 1 --allow-real-proxy-coexist 1 --go-build-enabled 0 --rust-build-enabled 0`
  - 结果：连续 5 轮 `overall=PASS`，且 `go_startup=PASS`、`rust_startup=PASS`
  - 证据：`reports/l18/gui_real/startup_stability_20260225T103807Z.txt`、`reports/l18/gui_real/gui_real_cert.round{1..5}.json`
- 回归补充：
  - strict case：`p0_clash_api_contract_strict` 已执行通过（run_id=`20260225T103845Z-54090895-e508-40e0-8787-c3b87e47c306`）
  - daily 双核差分：run_id=`20260225T103843Z-daily-8e9cd9d7`，`PASS`（5/5 clean）

### L18 双核 daily 收敛 + perf_gate 固化快照（2026-02-24 19:28）

- 双核差分认证（daily）：
  - 执行：`scripts/l18/run_dual_kernel_cert.sh --profile daily`
  - 结果：`PASS`（`run_fail_count=0`，`diff_fail_count=0`）
  - 证据：`reports/l18/dual_kernel/20260224T111353Z-daily-a843bc48/summary.json`、`diff_gate.json`
  - 结论：5/5 case 全部 `clean=true`，`http/ws/subscription/traffic mismatch=0`，无 ignored 项。
- `perf_gate` 收口（先固化可重复配置与采样规模）：
  - 新增固定配置：`labs/interop-lab/configs/l18_perf_go.json`、`labs/interop-lab/configs/l18_perf_rust.json`
  - 脚本收敛：`scripts/l18/perf_gate.sh`（固定 `rust_build_features=acceptance`、startup 采样 `warmup=1/sample=7`、latency 采样 `warmup=20/sample=120`、输入 lock 文件、startup/latency sample_count 校验、bench_memory 端口对齐、`EPOCHREALTIME` 毫秒计时）
  - 配套修复：`scripts/bench_memory.sh`（支持 `RUST_PROXY_ADDR`/`GO_PROXY_ADDR`）
  - 输出：`reports/l18/perf/perf_gate.lock.json`、`reports/l18/perf_gate.json`
  - 当前门禁：`pass=false`；`latency_p95` 与 `rss_peak` 通过，`startup` 相对 Go 为 `+962.500%`（Rust 170ms vs Go 16ms，阈值 `+10%`）未过。

### L18 详细设计已落地为可执行资产（2026-02-24）

- `scripts/l18/preflight_macos.sh`：前置检查改为硬失败，并输出 `reports/l18/baseline.lock.json`。
- `scripts/l18/build_go_oracle.sh`：每轮从 `go_fork_source/sing-box-1.12.14` 现编译 Go Oracle，产出 `oracle_manifest.json`。
- `scripts/l18/run_dual_kernel_cert.sh`：按 `daily/nightly` 执行双核 run+diff，输出 `summary.json` 与 `diff_gate.json`。
- `scripts/l18/gui_real_cert.sh`：Go/Rust 双轨真实 GUI 核验（启动/加载配置/切换代理/连接面板/日志面板）并输出 `.md + .json` 对照报告。
- `scripts/l18/perf_gate.sh`：统一 p95/RSS/startup 三指标硬门禁，输出 `reports/l18/perf_gate.json`。
- `scripts/l18/l18_capstone.sh`：聚合 `boundaries/parity/workspace/fmt/clippy/hot_reload/signal/docker/gui_smoke/canary/dual_kernel_diff/perf_gate` 为必过门禁。
- `.github/workflows/l18-certification-macos.yml`：self-hosted macOS 认证流水线，支持 `profile=daily|nightly|certify` 并上传审计产物。
- `reports/L18_REPLACEMENT_CERTIFICATION.md`：L18 单一结项报告口径（默认无豁免）。
- `agents-only/03-planning/12-L18-REPLACEMENT-CERTIFICATION-WORKPACKAGES.md`：L18 专项规划（含沙盒不扰民约束与批次执行顺序）。

### L18 沙盒不扰民约束（2026-02-24）

- 二内核与 GUI 认证通信仅允许 loopback（`127.0.0.1/localhost/::1`）。
- GUI 在临时 sandbox HOME 运行，避免读写用户真实 GUI 配置目录。
- 认证配置禁止 `tun/tproxy/redirect` 入站，避免接管系统网络。
- 默认禁止与真实代理并存：检测到常见代理进程/端口即 FAIL。
- 认证前后执行 `scutil --proxy` 快照对比，若系统代理状态变化则 FAIL。
- run 结束后强制清理本次进程并校验关键端口释放，未释放则 FAIL。
- Docker 策略分层：本机替换验证默认非阻断；CI/certify 可开启 `--require-docker 1` 阻断。

### L18 daily fail-fast 首跑结果（2026-02-24）

- 执行：`scripts/l18/l18_capstone.sh --profile daily --fail-fast`
- 结果：`FAIL`（前置阻断，符合预期）
- 阻断点：`preflight` 检测 `docker_desktop_unavailable`
- 状态文件：`reports/l18/l18_capstone_status.json`
- 说明：本轮为“快速阻断探测”，`--fail-fast` 生效，后续门禁未执行（`NOT_RUN`）

### L18 daily fail-fast 二次首跑（docker 非阻断模式，2026-02-24）

- 执行：`scripts/l18/l18_capstone.sh --profile daily --fail-fast --require-docker 0`
- 结果：`FAIL`
- 通过门禁：`preflight/oracle/boundaries/parity/workspace_test/fmt/clippy/hot_reload/signal`
- Docker 门禁：`WARN`（`require_docker=0`，不阻断）
- 当前阻断点：`gui_smoke=FAIL`（未提供 `--gui-app`）
- 状态文件：`reports/l18/l18_capstone_status.json`（`generated_at=2026-02-24T06:23:54Z`）

### L18 本机源码直编与 GUI 联调现状（2026-02-24 15:10）

- Go Oracle 已按源码直编成功（`go_fork_source/sing-box-1.12.14`）并默认启用 `with_clash_api`：
  - 产物：`reports/l18/oracle/go/20260224T064419Z-62ad307b/sing-box`
  - 清单：`reports/l18/oracle/go/20260224T064419Z-62ad307b/oracle_manifest.json`
- L18 脚本增强已落地：
  - `scripts/l18/build_go_oracle.sh`：默认 `build_tags=with_clash_api`
  - `scripts/l18/gui_real_cert.sh`：Rust 启动命令双风格兼容、API 探测超时、`switch_proxy` 404 兼容、日志面板回退探测
- 当前 GUI 门禁阻塞事实：
  - Go 侧：`/proxies`、`/connections` 可达，`startup` 仍可能受 GUI 进程就绪判定影响（`gui_or_kernel_not_ready`）。
  - Rust 侧：当前 `run`/`app run` 路径未暴露 Clash API `/proxies`（返回 403 或不可达），导致 GUI 双轨认证未全绿。
- 最新报告：`reports/l18/gui_real_cert.json`（`pass=false`，sandbox pre/post 均通过，无系统代理扰动）。

### L18 下一步任务（按既定规划）

1. **P0 收口（最高优先级，先于 nightly/certify）**
   - 目标：清零 case 级断言失败与 `launch_kernel` 非预期失败，补齐 `case run` 严格退出语义。
   - 完成标准：83 case 最新快照 `assertion_fail=0`、`unexpected launch_kernel fail=0`，且存在失败时命令返回非 0。
2. **冻结 certify/nightly 配置（保持不漂移）**
   - 目标：`daily/nightly/certify` 全部对齐到同一稳定配置（`L18_GUI_TIMEOUT_SEC=120`、`L18_RUST_BUILD_ENABLED=0`、`L18_GUI_GO_BUILD_ENABLED=0`、`L18_GUI_RUST_BUILD_ENABLED=0`、parity `target/release/run`）。
   - 完成标准：执行参数与 `reports/L18_REPLACEMENT_CERTIFICATION.md` 的 fixed config 一致。
3. **nightly 24h 预演（P0 通过后执行）**
   - 目标：完成固定配置长跑并沉淀 `status + gui + canary + dual + perf` 全证据。
   - 完成标准：mandatory gate 全 `PASS` 且证据路径可追溯。
4. **certify 7d 正式跑（nightly 通过后执行）**
   - 目标：获取 L18 结项认证证据并回填结项文档。
   - 完成标准：`overall=PASS` 且 mandatory gate 证据完整。

### L17 发布就绪收口（2026-02-13）

- **L17.1.1 CI/CD Pipeline**: `.github/workflows/ci.yml` 已固定 5 门禁（fmt/clippy/test/parity/boundaries）。
- **L17.1.2 多平台构建**: `.github/workflows/release.yml` 保留 6 target matrix，新增 os/arch/archive 元数据并统一命名。
- **L17.1.3 Docker 正式化**: `deployments/docker/*` 已接线 non-root、`/services/health`、镜像 `<50MB` 校验链说明。
- **L17.1.4 CHANGELOG**: `CHANGELOG.md` 已补齐 L17 收口记录与贡献入口链接。
- **L17.2.1 Release 打包**: `scripts/package_release.sh` + `deployments/config-template.json` 已落地并完成本机打包验证。
- **L17.2.2 文档入口**: `docs/configuration.md`、`docs/migration-from-go.md`、`docs/troubleshooting.md` 已落地并互链。
- **L17.2.3 安全清单**: `deny.toml` 适配 cargo-deny 0.18；`reports/security_audit.md` 已转为实跑结论（HIGH/CRITICAL 阻断策略）。
- **L17.3.1 GUI 冒烟**: `scripts/gui_smoke_test.sh` 与 `reports/gui_integration_test.md` 已落地（半自动模板 + 证据位）。
- **L17.3.2 Canary 框架**: `scripts/canary_7day.sh` 与 `reports/stability/canary_summary.md` 已落地（JSONL + summary）。
- **L17.3.3 Capstone 状态**: `reports/stability/l17_capstone_status.json` 已更新为 2026-02-24 fast 实跑快照（`overall=PASS_STRICT`）。

### L17 当前状态（2026-02-24 fast 复验）

- `cargo fmt --all -- --check`：✅ PASS
- `cargo clippy --workspace --all-features --all-targets -- -D warnings`：✅ PASS
- `cargo test --workspace`：✅ PASS
- `cargo test -p app --test hot_reload_stability --features long_tests`（`SINGBOX_HOT_RELOAD_ITERATIONS=20`）：✅ PASS
- `cargo test -p app --test signal_reliability --features long_tests`（`SINGBOX_SIGNAL_ITERATIONS=5`）：✅ PASS
- Docker：`SKIP`（`docker_daemon_unavailable`）
- GUI smoke：`SKIP`（`gui_smoke_manual_step`）
- Canary：`SKIP`（`canary_api_unreachable`）
- 状态文件：`reports/stability/l17_capstone_status.json`（`generated_at=2026-02-24T05:21:01Z`）

### L16.2.x long_tests 稳定性补丁（2026-02-14）

- 修复文件：
  - `app/tests/hot_reload_stability.rs`
  - `app/tests/signal_reliability.rs`
- 修复内容：
  - readiness 超时/重试窗口增强（`SINGBOX_HEALTH_READY_TIMEOUT_SECS`，默认 30s）
  - 启动前端口可用性预检与端口占用诊断
  - 失败路径统一进程清理（TERM/kill）与 stderr/stdout tail 输出
  - 默认使用动态端口，降低并发/残留进程导致的 `/healthz` 假失败
  - 默认配置改为临时 `{}`（仍支持 `SINGBOX_CONFIG` 覆盖），默认二进制优先 `CARGO_BIN_EXE_*`
- 复验结果：
  - `cargo test -p app --test hot_reload_stability --features long_tests -- --nocapture` ✅
  - `cargo test -p app --test signal_reliability --features long_tests -- --nocapture` ✅
- 证据产物：
  - `reports/stability/hot_reload_100x.json`
  - `reports/stability/signal_reliability_10x.json`

### L16 基准与稳定性（2026-02-12 已完成）

- `feature-matrix` 全绿：`cargo run -p xtask -- feature-matrix` → 46/46（`reports/feature_matrix_report.txt`）。
- Benchmark 产物已落地：
  - `reports/benchmarks/baseline.json`（116 benchmark 键）
  - `reports/benchmarks/latency_percentiles.json`（socks5/shadowsocks/vmess/trojan 四项 p50/p95/p99/sample_size）
  - `reports/benchmarks/go_vs_rust_throughput.csv`（固定列，4 协议 × rust/go）
  - `reports/benchmarks/memory_comparison.json`（rust/go + idle/100/1000 + delta + status/reason）
- 长稳测试通过并落盘：
  - `cargo test -p app --test hot_reload_stability --features long_tests`
  - `cargo test -p app --test signal_reliability --features long_tests`
  - 报告：`reports/stability/hot_reload_100x.json`、`reports/stability/signal_reliability_10x.json`
- CI bench gate 收口：`scripts/bench_compare.sh` 产出 `reports/benchmarks/bench_regression_status.json`（`pass|warn|fail`）；`.github/workflows/bench-regression.yml` 已改为 warn/fail 告警且 non-blocking。
- L16.2.4 interop case 已可执行并有证据目录：
  - `cargo run -p interop-lab -- case run p2_bench_socks5_throughput`
  - `cargo run -p interop-lab -- case run p2_bench_shadowsocks_throughput`
  - artifacts: `labs/interop-lab/artifacts/p2_bench_*/<run_id>/rust.snapshot.json`

### 联测运行约束（2026-02-10 新增）

- Go 版本 sing-box + GUI + TUN 为网络基础，联测期间不得中断或替换。
- Rust 内核仅作并行对照，默认使用独立 API 端口，不接管现网路由。
- 每轮 Rust 联测后必须回收进程并确认端口释放，避免干扰用户侧网络。
- 实战场景清单见：`labs/interop-lab/docs/REALWORLD-TEST-PLAN.md`。

### 规划增量（2026-02-11 新增）

- 已导入并阅读 Go 版本功能分析资料：`agents-only/dump/go-version-analysis/2026-02-11-intake/sing-box-core-specs/`。
- 基于导入资料新增下一阶段工作包规划：`agents-only/03-planning/08-L12-L14-GO-SPECS-WORKPACKAGES.md`。
- 规划主轴：迁移兼容治理（L12）→ Services 安全与生命周期（L13）→ TLS/Endpoint 高级能力与趋势门禁 CI 化（L14）。

### L5~L7 详细工作包（2026-02-11 已完成）

- **规划文档**: `agents-only/03-planning/09-L5-L7-DETAILED-WORKPACKAGES.md`
- **总量**: 22 个工作包，4 批次 — **全部完成 ✅**
- **L5 补全**: 协议×故障矩阵（TCP/UDP/DNS/WS/TLS 的 disconnect/delay/jitter/recovery）+ env_limited 失败归因 — **✅ 全部 implemented**
- **L6 扩展**: WsRoundTrip/TlsRoundTrip traffic action、TCP/TLS delay 注入、聚合趋势报告、CI workflow — **✅ 全部 implemented**
- **L7 深化**: WsParallel step、GUI 启动/proxy 切换/delay/group delay 回放、WS 重连测试、connection tracking 断言、完整用户会话端到端回放、strict P0 契约 case — **✅ 全部 implemented**
- **最终状态**: 57 YAML case（31 → 57）、4 config 文件（1 → 4）、13 Rust 源文件（12 → 13）、2 脚本（1 → 2）、2 CI workflow、11 单元测试全部通过

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
| **L5-L7 联测仿真** | 2026-02-11 | 22 工作包全部完成，57 case，6×4 故障矩阵全覆盖，GUI 回放 7 case |
| **L8-L11 CI治理** | 2026-02-12 | 数据面/订阅/双核差分/CI准入全闭环，trend_history.jsonl 历史追踪 + 回归检测 |
| **L12 迁移兼容治理** | 2026-02-12 | WireGuard outbound→endpoint 迁移检测、V1→V2 字段重命名、flat conditions→when wrapper、default_outbound→route.default；3 interop-lab case |
| **L13 Services 安全与生命周期** | 2026-02-12 | Clash API auth middleware（Go parity）、SSMAPI auth middleware、non-localhost binding warning、ServiceStatus enum 服务故障隔离、Health API endpoint；2 interop-lab case |
| **L14 TLS/Endpoint 高级能力** | 2026-02-12 | TLS高级能力 + 证书管理 + 趋势门禁CI化 + interop-lab TLS case |
| **L15 CLI 完善与功能补全** | 2026-02-12 | generate uuid/rand/ech-keypair + AdGuard convert + Chrome cert store + format -w + 验收清单签署 + 4 interop-lab CLI case |
| **L16 质量验证与性能基线** | 2026-02-12 | Criterion baseline + Go/Rust throughput/memory 对比 + feature-matrix 46/46 + hot_reload/signal 长稳测试 + CI bench gate non-blocking + 2 interop bench case |

### L12 迁移兼容治理（2026-02-12 已完成）

- **WireGuard outbound → endpoint 迁移检测**: 识别 V1 风格 `type: "wireguard"` outbound 配置，输出迁移提示到 endpoint 模型。
- **V1→V2 字段重命名检测**: `tag`→`name`、`server_port`→`port`、`socks5`→`socks` 等字段自动识别 + deprecation 警告。
- **Flat conditions → when wrapper 检测**: 平铺路由条件迁移到 `when` 包装结构的检测与警告。
- **default_outbound → route.default 检测**: 顶层 `default_outbound` 迁移到 `route.default` 的检测与警告。
- **Non-localhost binding warning**: 非 localhost 绑定地址安全提示。
- **interop-lab case（3 个）**: `p1_deprecated_wireguard_outbound`、`p1_deprecated_v1_style_config`、`p1_deprecated_mixed_config`。

### L13 Services 安全与生命周期（2026-02-12 已完成）

- **Clash API auth middleware**: Bearer token 鉴权中间件，Go parity（`experimental.clash_api.secret` 配置项），覆盖 HTTP（`Authorization: Bearer`）和 WebSocket（`?token=`）路径。8 个单元测试。
- **SSMAPI auth middleware**: SSMAPI 服务独立 Bearer token 鉴权（`ServiceIR.auth_token`），与 Clash API 隔离。6 个单元测试。
- **Non-localhost binding warning**: 当 Clash API 或 SSMAPI 绑定非 localhost 地址且无认证时，输出 `IssueCode::InsecureBinding` 安全警告。6 个单元测试。
- **ServiceStatus enum 服务故障隔离**: `Starting`/`Running`/`Failed(String)`/`Stopped` 四态，`start_all()` 捕获单个服务启动失败但不阻塞其他服务。6 个单元测试。
- **Health API endpoint**: `GET /services/health` 返回服务健康状态聚合（当前为静态响应，ServiceManager 集成待后续架构管道打通）。
- **interop-lab case（2 个）**: `p1_clash_api_auth_enforcement`（Clash API 鉴权正/负测试：无 token→401、正确 Bearer→200、错误 Bearer→401）、`p1_service_failure_isolation`（单服务故障不阻塞 + Clash API 可达验证）。

### L14 TLS/Endpoint 高级能力与趋势门禁（2026-02-12 已完成）

- **证书存储模式（L14.1.1）**: `CertificateStoreMode` 枚举（System/Mozilla/None），System 模式通过 `rustls-native-certs` 加载 OS 证书库（Mozilla 回退），None 模式空池+仅自定义 CA，`certificate_directory_path` 递归加载 PEM 目录。`CertificateIR` 新增 `store`/`certificate_directory_path` 字段。5 个单元测试。
- **证书热重载（L14.1.2）**: `CertificateWatcher` 基于 `notify` crate 的文件监听，`CancellationToken` 优雅终止，`cert-watch` feature gate。4 个单元测试。
- **TLS fragment 配置→运行时接线验证（L14.1.3）**: `tls_fragment`/`tls_record_fragment`/`tls_fragment_fallback_delay` 加入 `allowed_route_keys()`，validator 不再误报 `UnknownField`。1 个单元测试。
- **TLS 能力矩阵验证（L14.1.4）**: `check_tls_capabilities()` 函数检测 uTLS/ECH/REALITY 配置并产生 info 级诊断（支持状态说明）。7 个单元测试。
- **Nightly 趋势门禁模板（L14.2.1）**: 五套阈值配置模板 — `strict`/`strict_default`（零容错）、`env_limited`/`env_limited_default`（适度容忍）、`development`（宽松），与 `run_case_trend_gate.sh` 集成。
- **interop-lab TLS case（4 个）**: `p1_tls_cert_store_mozilla`（mozilla 模式 TLS 验证）、`p1_tls_cert_store_none_custom_ca`（none 模式+自定义 CA）、`p1_tls_fragment_activation`（TLS fragment 激活验证）、`p1_tls_fragment_wiring`（TLS fragment 配置→运行时接线验证）。

### L15 CLI 完善与功能补全（2026-02-12 已完成）

- **generate uuid（L15.1.1）**: UUID v4 生成，`uuid` crate。1 个单元测试 + E2E 验证（36 字符，version=4，variant=8/9/a/b）。
- **generate rand（L15.1.2）**: 随机字节生成，支持 `--base64`（24 字符/16 bytes）和 `--hex`（32 字符/16 bytes）输出格式。3 个单元测试 + E2E 验证。
- **generate ech-keypair（L15.1.3）**: Go 兼容 ECH PEM 编码（`ECH CONFIGS` / `ECH KEYS` header），X25519 DHKEM + 3 cipher suites wire-format。`crates/sb-tls/src/ech_keygen.rs`（262 行，6 个单元测试）。E2E 验证含 `server_name` 参数。
- **rule-set convert --type adguard（L15.1.4）**: AdGuard DNS filter 解析器，`crates/sb-core/src/router/ruleset/adguard.rs`（723 行）。支持 `||domain^`/`@@||domain^`/`/regex/`/`$important`/hosts 格式/纯域名。20 个单元测试。
- **rule-set format --write/-w（L15.1.5）**: 原地写回格式化 JSON。3 个单元测试（写回验证、`--write`+`--output` 冲突检测、ConvertType 默认值）。
- **Chrome 证书存储模式（L15.1.6）**: `CertificateStoreMode::Chrome` 变体，使用 webpki-roots（与 Mozilla 模式共享根证书库）。4 个 Chrome 专属测试（大小写解析、非空验证、fingerprint）。
- **PX-015 CI 占位（L15.2.3）**: `.github/workflows/linux-resolved-validation.yml` 作为历史可选验证入口保留；PX-015 已转 Accepted Limitation，不再作为阻塞项。
- **验收清单签署（L15.2.1）**: `99-验收清单总表.md` 全部 33 项 A~I 节已 `[x]` 并附证据链。签署日期 2026-02-12。
- **interop-lab CLI case（4 个）**: `p1_cli_generate_uuid_format`（UUID v4 正则断言）、`p1_cli_generate_rand_base64`（24 字符长度断言）、`p1_cli_ruleset_convert_adguard`（domain_suffix 输出断言）、`p1_cli_ech_keypair_pem_format`（ECH PEM header 断言）。
- **测试修复**: `dns_integration.rs` 环境变量竞态修复（`set_var`→显式 config 传参，5 轮稳定）。
- **验证结果**: `cargo test --workspace` 1617 passed；`cargo test -p sb-tls` 93 passed；`cargo test -p sb-core --lib` 448 passed；全部 CLI 命令 E2E 通过。

### 关键参考

- **Clash API 审计报告**: `agents-only/05-analysis/CLASH-API-AUDIT.md`
- **L2 缺口分析**: `agents-only/05-analysis/L2-PARITY-GAP-ANALYSIS.md`
- **DNS 栈分析**: `agents-only/05-analysis/L2.10-DNS-STACK-ANALYSIS.md`
- **L4 开工前置分析**: `agents-only/05-analysis/L4-PREWORK-INFO.md`
- **L4 质量复验报告**: `reports/L4_QUALITY_RECHECK_2026-02-10.md`
- **PX-015 Linux 验证记录**: `reports/PX015_LINUX_VALIDATION_2026-02-10.md`
- **L5-L11 联测仿真计划（实施版）**: `agents-only/03-planning/07-L5-L11-INTEROP-LAB-PLAN.md`
- **L5~L7 详细工作包规划**: `agents-only/03-planning/09-L5-L7-DETAILED-WORKPACKAGES.md`
- **L15-L17 工作包规划**: `agents-only/03-planning/11-L15-L17-DETAILED-WORKPACKAGES.md`
- **Go Specs 验收清单（已签署）**: `agents-only/dump/go-version-analysis/2026-02-11-intake/sing-box-core-specs/99-验收清单总表.md`
- **历史 L3 Scope（服务补全）**: 见下方（已并入 M2.4）

---

## ✅ 最新完成：L16 质量验证与性能基线

**日期**: 2026-02-12

**完成项**:
- **L16.1.1 Criterion 基准正式化**: `scripts/run_benchmarks.sh` 统一落盘 `reports/benchmarks/`，`baseline.json` 汇总全 bench（116 键）。
- **L16.1.2 Go vs Rust 吞吐框架**: `scripts/bench_vs_go.sh` 固定 CSV schema，4 协议 rust/go 均有记录（`pass` 或 `env_limited`）。
- **L16.1.3 延迟百分位基线**: `latency_percentiles.json` 含 socks5/shadowsocks/vmess/trojan 的 `p50/p95/p99/sample_size`。
- **L16.1.4 Feature matrix**: `service_resolved` 依赖 `dns_udp` 修复，`cargo run -p xtask -- feature-matrix` 达成 46/46。
- **L16.2.1 内存对比基准**: `scripts/bench_memory.sh` 输出统一 JSON 结构（rust/go + idle/100/1000 + delta/status/reason）。
- **L16.2.2 热重载稳定性**: `app/tests/hot_reload_stability.rs` 增强健康检查/FD/RSS 阈值；产出 `hot_reload_100x.json`。
- **L16.2.3 信号与资源稳定性**: `app/tests/signal_reliability.rs` 增强 SIGTERM/端口回收/active task 趋势判定；产出 `signal_reliability_10x.json`。
- **L16.2.4 Interop 性能 case**: `p2_bench_socks5_throughput`、`p2_bench_shadowsocks_throughput` 可执行并可追溯归档。
- **L16.3.1 CI bench gate**: `bench_compare.sh` 产出 `pass|warn|fail` JSON，workflow 告警但不阻断合并。
- **L16.3.2 状态总线同步**: `CLAUDE.md`、`active_context.md`、`workpackage_latest.md` 口径对齐。

**关键文件变更**:
| 文件 | 改动 |
|------|------|
| `scripts/run_benchmarks.sh` | baseline + latency percentiles 聚合落盘 |
| `scripts/bench_vs_go.sh` | Go/Rust 吞吐对比 + 固定 CSV schema |
| `scripts/bench_memory.sh` | 内存对比统一结构输出 |
| `scripts/bench_compare.sh` | 机器可读 `pass/warn/fail` + 状态文件 |
| `.github/workflows/bench-regression.yml` | bench gate 告警化、non-blocking |
| `crates/sb-core/Cargo.toml` | `service_resolved = [\"dns_udp\"]` |
| `crates/sb-core/src/admin/http.rs` | `/metricsz` 增加 task monitor 计数字段 |
| `app/tests/hot_reload_stability.rs` | 100x 热重载稳定性断言与报告 |
| `app/tests/signal_reliability.rs` | 10x 信号稳定性/泄漏趋势断言与报告 |

**验证**: `cargo run -p xtask -- feature-matrix` 46/46；long_tests 2 项通过；interop-lab 83 cases

## ✅ 最新完成：L5-L7 联测仿真全量实施（22 工作包）

**日期**: 2026-02-11

**完成项**:
- **L5 协议×故障矩阵**：6 协议（HTTP/TCP/UDP/DNS/WS/TLS）× 4 故障类型（disconnect/delay/jitter/recovery）= 24 cell 全部 implemented，新增 18 个 YAML case
- **L5 env_limited 归因**：新增 `attribution.rs` 模块（classify_env_limited_failures + 5 单元测试），DiffReport 增加 env_limited_attributions 字段
- **L6 仿真底座扩展**：
  - `TrafficAction::WsRoundTrip` — 原生 WS 往返（含 SOCKS5 代理支持）
  - `TrafficAction::TlsRoundTrip` — 原生 TLS 往返（含 DangerousVerifier 自签名支持）
  - TCP/TLS echo delay 注入（与 HTTP/UDP/WS/DNS echo 一致的 service_delays_ms 模式）
  - `aggregate_trend_report.sh` — 趋势报告聚合（输出 trend_summary.json）
  - CI workflows：`interop-lab-smoke.yml`（PR 触发）+ `interop-lab-nightly.yml`（定时 + 全量）
- **L7 GUI 通信回放深化**：
  - `GuiStep::WsParallel` — 并行 WS 流采集（JoinSet 实现）
  - `post_traffic_gui_sequence` — CaseSpec 字段，traffic 后 GUI 序列
  - `connections.count` / `connections.N.rule` / `connections.N.chains` — 连接断言键
  - 7 个 GUI replay case（boot/switch/delay/group-delay/reconnect/connections/full-session）
  - `p0_clash_api_contract_strict` — env_limited P0 的 strict 版本
  - `p1_gui_full_session_replay` — E2E capstone（boot → browse → switch → browse → verify）
- **基础设施交付**：57 YAML case、4 kernel config、13 Rust 源文件、2 脚本、2 CI workflow
- **验证**：`cargo test -p interop-lab` 11/11 passed；`case list` 57 case；zero compilation errors

**关键文件变更**:
| 文件 | 改动 |
|------|------|
| `case_spec.rs` | +WsRoundTrip/TlsRoundTrip/WsParallel/WsStreamSpec/post_traffic_gui_sequence |
| `upstream.rs` | +TCP/TLS delay/ws_roundtrip/tls_roundtrip/socks5_connect/DangerousVerifier |
| `gui_replay.rs` | +WsParallel (run_ws_parallel with JoinSet) |
| `orchestrator.rs` | +post_traffic_gui_sequence execution/connections assertion keys |
| `attribution.rs` | 新建：失败归因分类 (5 tests) |
| `diff_report.rs` | +env_limited_attributions field |

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
- L4.4：`PX-015` Linux 双场景实机验证已转 Accepted Limitation（历史证据保留，不再要求 Linux 主机补证）

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
| L3.3 | Resolved 完整化 | PX-015 | 中 | 低 | ✅ 已完成（2026-02-09）：resolved 替代模型 + resolve1 Resolve* + UDP/TCP stub + `type:\"resolved\"` 接线 + transport 对齐；Linux runtime/system bus 实机补证已转 Accepted Limitation |
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

*最后更新：2026-02-12（L12 迁移兼容治理 + L13 Services 安全与生命周期 + L14 Go规格收敛 + L15 CLI完善与功能补全 + L16 质量验证与性能基线 全部完成）*
