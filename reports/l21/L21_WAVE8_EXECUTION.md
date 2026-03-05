# L21 Wave#8 Execution Report (MIG-03 Runtime/Switchboard Path)

日期：2026-03-05  
范围：`W8-01 ~ W8-02`（启动 `MIG-03`，不启动 `MIG-04/06`）

## 结论

- `W8-01`（MIG-03 runtime/switchboard 去 core Hysteria2 concrete）完成：`OutboundType::Hysteria2` 不再构建 `outbound::hysteria2::Hysteria2Outbound`，改为显式 unsupported 诊断并通过 degraded 行为保持可诊断失败。
- `W8-02`（strict gate 升级 + 回流阻断）完成：allowlist 升级到 `l21.7-wave8-v1`，`--strict` 通过，负样例 `--v7-only` 阻断成功。
- 本轮保持 L18 隔离：未运行 `scripts/l18/*` 运行流程；仅执行静态 `bash -n`。

## WP 回填（命令 + 产物 + 结果）

| WP | 命令 | 产物 | 结果 |
| --- | --- | --- | --- |
| `W8-01` | `cargo check -p sb-core`；`cargo check -p app --tests` | `reports/l21/artifacts/wave8_wp1_sb_core_check.txt`；`reports/l21/artifacts/wave8_wp1_app_tests_check.txt` | ✅ PASS（switchboard Hysteria2 concrete 构建已移除，无编译回归） |
| `W8-02` | `bash agents-only/06-scripts/check-boundaries.sh --strict`；`BOUNDARY_PROJECT_ROOT=<tmp> bash agents-only/06-scripts/check-boundaries.sh --v7-only`（注入回流样例） | `reports/l21/artifacts/wave8_strict_gate.txt`；`reports/l21/artifacts/wave8_v7_regression_block.txt` | ✅ PASS（严格门禁通过 `V7 PASS (46 assertions)`；负样例阻断 `exit_code=1`） |
| `W8-L18-static` | `bash -n scripts/l18/gui_real_cert.sh` | `reports/l21/artifacts/wave8_gui_static_syntax_check.txt` | ✅ PASS（仅语法检查，不触发 L18 运行流程） |

## 代码与门禁变更清单

- `crates/sb-core/src/runtime/switchboard.rs`
- `agents-only/06-scripts/l20-migration-allowlist.txt`（`l21.7-wave8-v1`）
- `reports/l21/artifacts/wave8_v7_regression_block.txt`

## 风险与后续

1. `MIG-03` 当前为 `in_progress`：switchboard 侧已去 concrete，但完整 Hysteria2 单实现仍需继续向 adapters 路径聚合。
2. 下一波建议推进 `MIG-04`（HTTP/Mixed 入站）收口，并继续保持 V7 forbid/require + 负样例阻断模式。
