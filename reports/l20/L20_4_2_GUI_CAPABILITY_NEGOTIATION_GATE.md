# L20.4.2 GUI 认证链路接入能力协商门禁

日期：2026-03-05  
范围：`L20.4.2`

## 变更摘要

1. `scripts/l18/gui_real_cert.sh`
   - 新增 capability negotiation gate 参数：
     - `--capabilities-gate-enabled 0|1`
     - `--go-capabilities-required 0|1`
     - `--rust-capabilities-required 0|1`
   - 新增环境变量：
     - `L20_CAPABILITIES_GATE_ENABLED`（默认 `1`）
     - `L20_CAPABILITIES_GATE_TIMEOUT_SEC`（默认 `5`）
     - `L20_CAPABILITIES_GO_REQUIRED`（默认 `0`）
     - `L20_CAPABILITIES_RUST_REQUIRED`（默认 `1`）
2. 新增 `check_capabilities_negotiation` 检查函数：
   - 在 core 启动后、GUI 步骤前访问 `GET /capabilities`。
   - 校验字段：`contract_version` / `required_by_gui` / `breaking_changes`。
   - 校验规则：
     - `contract_version >= required_by_gui.min_contract_version`
     - `required_by_gui.status == ok`
     - `breaking_changes` 为空
   - required core 不满足时 fail-fast，直接标记该 core 全步骤失败并退出该 core 流程。
3. 报告增强：
   - `gui_real_cert.json` 新增 `capability_negotiation` 段（`enabled/go/rust`）。
   - `gui_real_cert.md` 新增 `Capability Negotiation` 表格（required/status/pass/contract/reason）。

## 最小验证

1. `bash -n scripts/l18/gui_real_cert.sh`
2. 提取脚本内 4 个嵌入 Python block，逐个 `python3 -m py_compile`
3. `cargo test -p sb-api capabilities_contract_suite -- --nocapture`
4. `bash scripts/check_claims.sh`
5. `bash agents-only/06-scripts/check-boundaries.sh --strict`

结果：

- ✅ GUI cert 脚本语法与嵌入 Python 语法静态检查通过（4/4）
- ✅ `/capabilities` 契约套件通过（协商字段仍满足 v2）
- ✅ claim-guard / boundary strict 全绿

## 证据路径

1. `scripts/l18/gui_real_cert.sh`
2. `reports/l20/L20_4_2_GUI_CAPABILITY_NEGOTIATION_GATE.md`
3. `crates/sb-api/tests/capabilities_contract.rs`
