# L21 Wave#4 Execution Report (MIG-01 / MIG-05 Close-out)

日期：2026-03-05  
范围：`W4-01 ~ W4-03`（收口 `MIG-01/MIG-05`，不启动 `MIG-02/03/04/06`）

## 结论

- `W4-01`（MIG-01 runtime/switchboard Direct/Block 回流点清理）完成：不再依赖 core concrete connector fallback，缺失 connector 显式失败。
- `W4-02`（MIG-05 剩余非必要 `sb_core::transport` 引用清理）完成：`app` transport plan 日志口径统一到 `sb_transport`，CLI/API 行为保持兼容。
- `W4-03`（strict gate 升级 + 回流阻断）完成：allowlist 升级到 `l21.3-wave4-v1`，`--strict` 通过，负样例 `--v7-only` 阻断成功。
- 本轮遵守 L18 隔离约束：未运行 `scripts/l18/*` 运行流程；仅执行静态 `bash -n`。

## WP 回填（命令 + 产物 + 结果）

| WP | 命令 | 产物 | 结果 |
| --- | --- | --- | --- |
| `W4-01` | `cargo check -p sb-core` | `reports/l21/artifacts/wave4_wp1_sb_core_check.txt` | ✅ PASS（`switchboard` 移除 default direct fallback；`outbound manager` 移除 direct 自动注入） |
| `W4-02` | `cargo check -p app`；`cargo check -p sb-api` | `reports/l21/artifacts/wave4_wp2_app_check.txt`；`reports/l21/artifacts/wave4_wp2_sb_api_check.txt` | ✅ PASS（`app/src/run_engine.rs` transport target 改为 `sb_transport`，兼容性编译通过） |
| `W4-03` | `bash agents-only/06-scripts/check-boundaries.sh --strict`；`BOUNDARY_PROJECT_ROOT=<tmp> bash agents-only/06-scripts/check-boundaries.sh --v7-only`（注入回流样例） | `reports/l21/artifacts/wave4_strict_gate.txt`；`reports/l21/artifacts/wave4_v7_regression_block.txt` | ✅ PASS（严格门禁通过 `V7 PASS (29 assertions)`；负样例阻断 `exit_code=1`） |
| `W4-L18-static` | `bash -n scripts/l18/gui_real_cert.sh` | `reports/l21/artifacts/wave4_gui_static_syntax_check.txt` | ✅ PASS（仅语法检查，不触发 L18 运行流程） |

## 代码与门禁变更清单

- `crates/sb-core/src/runtime/switchboard.rs`
- `crates/sb-core/src/outbound/manager.rs`
- `crates/sb-core/src/runtime/supervisor.rs`
- `app/src/bootstrap.rs`
- `app/src/run_engine.rs`
- `agents-only/06-scripts/l20-migration-allowlist.txt`（`l21.3-wave4-v1`）
- `reports/l21/artifacts/wave4_v7_regression_block.txt`

## 风险与后续

1. `app/src/bootstrap.rs` 当前仅移除 fallback 注入，仍未在该路径统一接入 `outbound_manager.resolve_default()`；若后续要做 runtime default 行为完全一致化，建议单独开波次处理。
2. `MIG-02/03/04/06` 仍未启动，后续迁移时建议继续沿用 V7 forbid/require + 负样例阻断模式，避免回流。
