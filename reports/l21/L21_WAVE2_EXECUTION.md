# L21 Wave#2 执行报告（起步）

日期：2026-03-05  
分支：`codex/l19-batch-a`  
执行边界：仅脚本/静态校验；未运行 `scripts/l18/*` 运行流程；未占用 `9090/19090/11810/11811`

## 结论

- `MIG-01 / MIG-05` wave#2 已落地并完成最小编译验证。
- strict gate 迁移断言 allowlist 已升级到下一版（`l21.1-wave2-v1`），并提供“回流会被阻断”的可复算失败证据。
- `gui_real_cert` capability negotiation gate 已补齐失败场景 fixture（`required_status!=ok`、`breaking_changes!=[]`）并完成静态复算。

## WP 回填（三元组）

| WP | 命令 | 产物 | 结果 |
| --- | --- | --- | --- |
| `L21-WP1` 迁移 wave#2（MIG-01/MIG-05） | `cargo check -p sb-core`；`cargo check -p app --bin diag` | `crates/sb-core/src/runtime/supervisor.rs`；`app/src/bin/diag.rs`；`agents-only/05-analysis/L19.3.3-SB-CORE-OVERLAP-MATRIX.md` | ✅ PASS（编译通过，矩阵已回填 `W2-01/W2-02`） |
| `L21-WP2` strict gate allowlist 升级 + 阻断证据 | `bash agents-only/06-scripts/check-boundaries.sh --strict`；`BOUNDARY_PROJECT_ROOT=<tmp> BOUNDARY_MIGRATION_ASSERT_FILE=... bash agents-only/06-scripts/check-boundaries.sh --v7-only` | `agents-only/06-scripts/l20-migration-allowlist.txt`；`agents-only/06-scripts/check-boundaries.sh`；`reports/l21/artifacts/v7_regression_block.txt` | ✅ PASS（strict 全绿 `V7 PASS (14 assertions)`；注入回流样例后 `--v7-only` 预期失败，`exit_code=1`） |
| `L21-WP3` GUI negotiation gate 失败样例可复算 | `bash -n scripts/l18/gui_real_cert.sh`；`python3 -m py_compile scripts/l18/capability_negotiation_eval.py`；`bash scripts/l18/capability_negotiation_fixture_check.sh` | `scripts/l18/capability_negotiation_eval.py`；`scripts/l18/capability_negotiation_fixture_check.sh`；`scripts/l18/fixtures/capability_negotiation/*.json`；`reports/l21/artifacts/gui_capability_negotiation/*.result.json` | ✅ PASS（两类失败样例均阻断，基线样例通过） |
| `L21-WP4` 本轮报告与状态同步 | `rg -n "L21 wave#2|l21.1-wave2-v1|W2-01|W2-02" agents-only/workpackage_latest.md agents-only/05-analysis/L19.3.3-SB-CORE-OVERLAP-MATRIX.md` | `reports/l21/L21_WAVE2_EXECUTION.md`；`agents-only/workpackage_latest.md` | ✅ PASS（状态页与矩阵已同步到 L21） |

## 关键改动清单

1. `crates/sb-core/src/runtime/supervisor.rs`
   - runtime outbound manager 改为注入 bridge 实际 connector（经 `ManagerConnectorBridge`），移除逐标签 `DirectConnector` 占位回流。
2. `app/src/bin/diag.rs`
   - TLS 诊断链路迁移为 `sb_transport::{TcpDialer,TlsDialer}`，保留显式 `sni_override`。
3. `agents-only/06-scripts/l20-migration-allowlist.txt`
   - 版本升级 `l21.1-wave2-v1`，新增 W2 migration 断言。
4. `agents-only/06-scripts/check-boundaries.sh`
   - 支持 `--v7-only` 与 `BOUNDARY_PROJECT_ROOT/BOUNDARY_MIGRATION_ASSERT_FILE` 覆盖，便于回流阻断复算。
5. `scripts/l18/gui_real_cert.sh`
   - capability negotiation gate 改为调用外部判定器 `scripts/l18/capability_negotiation_eval.py`。
6. `scripts/l18/capability_negotiation_eval.py` + fixtures + `scripts/l18/capability_negotiation_fixture_check.sh`
   - 新增 negotiation 失败样例静态复算链路。

## 残余风险

1. `MIG-01`
   - `sb-core` 内仍保留 `direct/block` fallback 连接器实现，尚未完全清空，当前状态维持 `in_progress`。
2. `MIG-05`
   - `sb-core/transport` 其余旧路径仍存在，当前仅完成 DoT + diag 子路径收敛，状态维持 `in_progress`。
3. 本机 Python 环境会打印 `hashlib blake2*` 错误日志（不影响脚本退出码与断言结果），后续建议在 CI Python 运行时统一环境。
