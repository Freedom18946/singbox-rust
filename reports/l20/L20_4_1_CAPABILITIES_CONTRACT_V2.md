# L20.4.1 `/capabilities` 契约 v2（协商字段）

日期：2026-03-05  
范围：`L20.4.1`

## 变更摘要

1. `crates/sb-api/src/clash/handlers.rs`
   - `/capabilities` 新增顶层协商字段：
     - `contract_version`
     - `required_by_gui`
     - `breaking_changes`
   - 增加语义化版本比较函数（`parse_semver_triplet` / `version_satisfies`）。
   - 新增 `required_by_gui` 派生逻辑：
     - `status=ok|blocked`
     - `min_contract_version`
     - `min_clash_api_compat_version`
     - `required_top_level_fields`
     - `blockers`（可选）
   - 当前 `contract_version=2.0.0`，`breaking_changes=[]`，`required_by_gui.status=ok`。
2. `crates/sb-api/tests/capabilities_contract.rs`
   - 契约测试新增 v2 字段校验。
   - 增加版本协商断言：`contract_version >= required_by_gui.min_contract_version`。
   - 校验 `breaking_changes` 为数组，且空数组时 `required_by_gui.status` 必须为 `ok`。
3. `crates/sb-api/tests/clash_http_e2e.rs`
   - `/capabilities` e2e 用例新增 `contract_version/required_by_gui/breaking_changes` 断言。
4. `docs/capabilities.md`
   - `/capabilities` 响应契约说明升级到 v2 协商字段。

## 最小验证

1. `cargo fmt -p sb-api`
2. `cargo test -p sb-api capabilities_provider_tests -- --nocapture`
3. `cargo test -p sb-api capabilities_contract_suite -- --nocapture`
4. `cargo test -p sb-api test_get_capabilities -- --nocapture`
5. `bash scripts/check_claims.sh`
6. `bash agents-only/06-scripts/check-boundaries.sh --strict`

结果：

- ✅ `capabilities_provider_tests` 通过（含版本协商/阻断单测）
- ✅ `capabilities_contract_suite` 通过（含 v2 字段 shape + negotiation 断言）
- ✅ `test_get_capabilities` 通过（含 v2 字段存在性断言）
- ✅ claim-guard / boundary strict 全绿

## 证据路径

1. `crates/sb-api/src/clash/handlers.rs`
2. `crates/sb-api/tests/capabilities_contract.rs`
3. `crates/sb-api/tests/clash_http_e2e.rs`
4. `docs/capabilities.md`
5. `reports/l20/L20_4_1_CAPABILITIES_CONTRACT_V2.md`
