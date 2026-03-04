# L20 Deep Alignment Capstone Report

日期：2026-03-05  
范围：`L20.1.1` ~ `L20.4.3`（Batch A~D）

## 结论

- `L20` 主线目标已收口：uTLS/ECH 证据化、重叠迁移 wave#1 + 回流阻断、`/capabilities` 契约 v2 协商、GUI 认证链路协商门禁接线。
- 执行边界保持与 `L18` 隔离并行：本轮未运行 `scripts/l18/*` 的运行器，只做脚本静态验证与接口契约校验。

## WP 回填（命令 + 产物 + 状态）

| WP | 状态 | 关键命令（最小验证） | 关键产物/证据 |
| --- | --- | --- | --- |
| `L20.1.1` | ✅ PASS | `scripts/test/tls_fingerprint_baseline.sh` | `scripts/test/tls_fingerprint_baseline.sh`；`reports/security/tls_fingerprint_baseline.json` |
| `L20.1.2` | ✅ PASS | `python3 scripts/capabilities/generate.py --out reports/capabilities.json`；`bash scripts/check_claims.sh` | `reports/l20/L20_1_2_UTLS_PROFILE_CAPABILITIES.md`；`reports/capabilities.json` |
| `L20.1.3` | ✅ PASS | `cargo test -p app capability_probe --features parity --lib`；`SB_CAPABILITY_PROBE_ONLY=1 ... cargo run -q -p app --features parity --bin run -- -c /tmp/l20_probe_utls_config.json` | `reports/l20/L20_1_3_UTLS_EFFECTIVE_PROFILE_PROBE.md`；`reports/runtime/capability_probe.json` |
| `L20.2.1` | ✅ PASS | `cargo test -p sb-api capabilities_provider_tests -- --nocapture`；`cargo test -p sb-api capabilities_contract_suite -- --nocapture` | `reports/l20/L20_2_1_ECH_PROVIDER_DECISION_EXPOSE.md`；`crates/sb-api/src/clash/handlers.rs` |
| `L20.2.2` | ✅ PASS | `cargo test -p sb-config tls_quic_ech -- --nocapture`；`cargo test -p sb-config test_parse_experimental_block -- --nocapture` | `reports/l20/L20_2_2_QUIC_ECH_MODE_SWITCH.md`；`crates/sb-config/src/validator/v2.rs` |
| `L20.2.3` | ✅ PASS | `scripts/test/ech_interop_minimal.sh` | `reports/l20/L20_2_3_ECH_INTEROP_MINIMAL.md`；`reports/security/ech_interop_minimal.json` |
| `L20.3.1` | ✅ PASS | `cargo check -p sb-adapters`；`cargo check -p sb-core --features dns_dot,tls_rustls`；`bash agents-only/06-scripts/check-boundaries.sh --strict` | `reports/l20/L20_3_1_WAVE1.md`；`agents-only/05-analysis/L19.3.3-SB-CORE-OVERLAP-MATRIX.md` |
| `L20.3.2` | ✅ PASS | `bash agents-only/06-scripts/check-boundaries.sh --strict` | `reports/l20/L20_3_2_STRICT_GATE_MIGRATION_ASSERTIONS.md`；`agents-only/06-scripts/l20-migration-allowlist.txt` |
| `L20.3.3` | ✅ PASS | `bash agents-only/06-scripts/check-boundaries.sh --strict`；`rg -n "## 3B\. L20\.3\.3|MIG-01|MIG-05" agents-only/05-analysis/L19.3.3-SB-CORE-OVERLAP-MATRIX.md` | `reports/l20/L20_3_3_MIGRATION_MATRIX_BACKFILL.md` |
| `L20.4.1` | ✅ PASS | `cargo test -p sb-api capabilities_provider_tests -- --nocapture`；`cargo test -p sb-api capabilities_contract_suite -- --nocapture`；`cargo test -p sb-api test_get_capabilities -- --nocapture` | `reports/l20/L20_4_1_CAPABILITIES_CONTRACT_V2.md`；`docs/capabilities.md` |
| `L20.4.2` | ✅ PASS | `bash -n scripts/l18/gui_real_cert.sh`；提取嵌入 Python 后逐块 `python3 -m py_compile`（4/4）；`cargo test -p sb-api capabilities_contract_suite -- --nocapture` | `reports/l20/L20_4_2_GUI_CAPABILITY_NEGOTIATION_GATE.md`；`scripts/l18/gui_real_cert.sh` |
| `L20.4.3` | ✅ PASS | `bash scripts/check_claims.sh`；`bash agents-only/06-scripts/check-boundaries.sh --strict` | `reports/L20_DEEP_ALIGNMENT.md`（本报告） |

## 关键统一门禁结果（本轮）

1. `bash scripts/check_claims.sh` -> `PASS (6 claims checked)`
2. `bash agents-only/06-scripts/check-boundaries.sh --strict` -> `PASS`（`V7 PASS (8 assertions)`）

## 残余风险

1. `tls.utls.*` 仍处于 `implemented_unverified`（已可观测/可追踪，但尚非大规模线上验证态）。
2. `tls.ech.quic` 仍依赖显式 `experimental` 模式，默认保持 `reject` 护栏。
3. `sb-core` 重叠迁移当前仅完成 wave#1，矩阵仍存在 `open/in_progress` 条目。

## 后续建议（L21 起步）

1. 对 `L20.3.x` 继续执行 wave#2（优先关闭 `MIG-01/MIG-05` 的 `in_progress`）。
2. 将 `gui_real_cert` negotiation gate 的失败样例纳入可复算 fixture（覆盖 `required_status!=ok` 与 `breaking_changes!=[]`）。
3. 以真实环境数据补足 `tls.utls.*` 的运行态验证证据，推动 `implemented_verified` 目标。
