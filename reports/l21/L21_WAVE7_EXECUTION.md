# L21 Wave#7 Execution Report (MIG-02 Runtime/Switchboard Path)

日期：2026-03-05  
范围：`W7-01 ~ W7-02`（继续推进 `MIG-02`，不启动 `MIG-03/04/06`）

## 结论

- `W7-01`（MIG-02 runtime/switchboard 去 core SOCKS concrete）完成：`OutboundType::Socks` 不再构建 `socks_upstream::SocksUp`，改为显式 unsupported 诊断并走 degraded 行为。
- `W7-02`（strict gate 升级 + 回流阻断）完成：allowlist 升级到 `l21.6-wave7-v1`，`--strict` 通过，负样例 `--v7-only` 阻断成功。
- 本轮保持 L18 隔离：未运行 `scripts/l18/*` 运行流程；仅执行静态 `bash -n`。

## WP 回填（命令 + 产物 + 结果）

| WP | 命令 | 产物 | 结果 |
| --- | --- | --- | --- |
| `W7-01` | `cargo check -p sb-core`；`cargo check -p app --tests` | `reports/l21/artifacts/wave7_wp1_sb_core_check.txt`；`reports/l21/artifacts/wave7_wp1_app_tests_check.txt` | ✅ PASS（switchboard SOCKS concrete 构建已移除，无编译回归） |
| `W7-02` | `bash agents-only/06-scripts/check-boundaries.sh --strict`；`BOUNDARY_PROJECT_ROOT=<tmp> bash agents-only/06-scripts/check-boundaries.sh --v7-only`（注入回流样例） | `reports/l21/artifacts/wave7_strict_gate.txt`；`reports/l21/artifacts/wave7_v7_regression_block.txt` | ✅ PASS（严格门禁通过 `V7 PASS (44 assertions)`；负样例阻断 `exit_code=1`） |
| `W7-L18-static` | `bash -n scripts/l18/gui_real_cert.sh` | `reports/l21/artifacts/wave7_gui_static_syntax_check.txt` | ✅ PASS（仅语法检查，不触发 L18 运行流程） |

## 代码与门禁变更清单

- `crates/sb-core/src/runtime/switchboard.rs`
- `agents-only/06-scripts/l20-migration-allowlist.txt`（`l21.6-wave7-v1`）
- `reports/l21/artifacts/wave7_v7_regression_block.txt`

## 风险与后续

1. 当前 MIG-02 仍为 `in_progress`：runtime/switchboard 已去 core SOCKS concrete，但完整运行时出站单实现仍需继续收敛到 adapters 路径。
2. 下一波建议处理 `MIG-03`（Hysteria2）的同类回流点，并按 W7 模式新增 V7 forbid/require 与负样例证据。
