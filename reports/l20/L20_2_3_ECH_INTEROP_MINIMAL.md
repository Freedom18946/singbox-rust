# L20.2.3 ECH 互操作最小证据链

日期：2026-03-05  
范围：`L20.2.3`

## 变更摘要

1. 新增脚本：`scripts/test/ech_interop_minimal.sh`
   - 构建 `app`（`schema-v2`）并执行 3 个最小互操作场景。
   - 输出统一报告：`reports/security/ech_interop_minimal.json`
   - 输出场景日志：`reports/security/ech_interop_minimal_logs/*.stdout.json|*.stderr.log`
2. 更新脚本索引：`scripts/test/README.md`
   - 新增 `ech_interop_minimal.sh` 与 `tls_fingerprint_baseline.sh` 入口说明。

## 场景定义

1. `tcp_ech_pass`（`tcp_ech`）
   - 配置 `trojan + tls.ech`
   - 预期：`pass_no_error`（error=0，可有 warning）
2. `quic_ech_reject_fail`（`quic_ech_reject`）
   - 配置 `tuic + tls.ech`，默认模式
   - 预期：`fail_with_error`（命中 QUIC+ECH reject）
3. `quic_ech_experimental_pass`（`quic_ech_experimental`）
   - 配置 `experimental.quic_ech_mode=experimental + tuic + tls.ech`
   - 预期：`pass_no_error`（error=0，允许 warning）

## 最小验证

1. `scripts/test/ech_interop_minimal.sh`
2. `python3 scripts/capabilities/generate.py --out reports/capabilities.json --probe-report reports/runtime/capability_probe.json`
3. `bash scripts/check_claims.sh`
4. `bash agents-only/06-scripts/check-boundaries.sh --strict`

结果：

- ✅ `reports/security/ech_interop_minimal.json`：`overall=PASS`，`case_count=3`
- ✅ 三个场景均 `expectation_met=true`
- ✅ claim-guard / boundary strict 全绿

## 证据路径

1. `reports/security/ech_interop_minimal.json`
2. `reports/security/ech_interop_minimal_logs/`
3. `scripts/test/ech_interop_minimal.sh`
4. `crates/sb-config/src/validator/v2.rs`
