# L20.2.1 ECH provider 决策外显化（配置 + API）

日期：2026-03-05  
范围：`L20.2.1`

## 变更摘要

1. `crates/sb-api/src/clash/handlers.rs`
   - `/capabilities` 增加顶层字段 `tls_provider`。
   - 从 `reports/capabilities.json` 的 `tls.ech.tcp` / `tls.ech.quic` runtime probe details 提取 provider 决策：
     - `requested`
     - `effective`
     - `source`
     - `install`
     - `fallback_reason`
   - 增加一致性判定：
     - `status=ok`（tcp/quic 一致）
     - `status=mismatch`（tcp/quic 决策分叉，附加错误）
     - `status=unavailable`（无可用 probe 细节）
2. `crates/sb-api/tests/capabilities_contract.rs`
   - 契约测试新增 `tls_provider` 字段及关键子字段校验。
3. `crates/sb-api/tests/clash_http_e2e.rs`
   - `/capabilities` e2e 用例新增 `tls_provider` 结构存在性断言。
4. `docs/capabilities.md`
   - 更新 `/capabilities` 响应契约说明，纳入 `tls_provider`。

## 最小验证

1. `cargo test -p sb-api capabilities_provider_tests -- --nocapture`
2. `cargo test -p sb-api capabilities_contract_suite -- --nocapture`
3. `cargo test -p sb-api test_get_capabilities -- --nocapture`
4. `bash scripts/check_claims.sh`
5. `bash agents-only/06-scripts/check-boundaries.sh --strict`

结果：

- ✅ provider 一致性单测通过（`ok` 与 `mismatch` 分支均覆盖）
- ✅ `/capabilities` 契约测试通过（含 `tls_provider`）
- ✅ `/capabilities` e2e 测试通过（`test_get_capabilities`）
- ✅ claim-guard / boundary strict 全绿

## 证据路径

1. `crates/sb-api/src/clash/handlers.rs`
2. `crates/sb-api/tests/capabilities_contract.rs`
3. `crates/sb-api/tests/clash_http_e2e.rs`
4. `docs/capabilities.md`
