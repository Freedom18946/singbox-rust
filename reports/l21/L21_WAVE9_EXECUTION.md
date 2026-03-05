# L21 Wave#9 Execution Report (MIG-04 Bridge Inbound Path)

日期：2026-03-05  
范围：`W9-01 ~ W9-02`（启动 `MIG-04`，不启动 `MIG-06`）

## 结论

- `W9-01`（MIG-04 bridge 构建去 core HTTP/Mixed concrete）完成：`Bridge::new_from_config` 中 `InboundType::Http/Mixed` 不再实例化 core inbound 实现，改为显式 unsupported 指引到 adapter bridge。
- `W9-02`（strict gate 升级 + 回流阻断）完成：allowlist 升级到 `l21.8-wave9-v1`，`--strict` 通过，负样例 `--v7-only` 阻断成功。
- 本轮保持 L18 隔离：未运行 `scripts/l18/*` 运行流程；仅执行静态 `bash -n`。

## WP 回填（命令 + 产物 + 结果）

| WP | 命令 | 产物 | 结果 |
| --- | --- | --- | --- |
| `W9-01` | `cargo check -p sb-core`；`cargo check -p app --tests` | `reports/l21/artifacts/wave9_wp1_sb_core_check.txt`；`reports/l21/artifacts/wave9_wp1_app_tests_check.txt` | ✅ PASS（bridge 构建入口已去 core HTTP/Mixed inbound concrete，无编译回归） |
| `W9-02` | `bash agents-only/06-scripts/check-boundaries.sh --strict`；`BOUNDARY_PROJECT_ROOT=<tmp> bash agents-only/06-scripts/check-boundaries.sh --v7-only`（注入回流样例） | `reports/l21/artifacts/wave9_strict_gate.txt`；`reports/l21/artifacts/wave9_v7_regression_block.txt` | ✅ PASS（严格门禁通过 `V7 PASS (50 assertions)`；负样例阻断 `exit_code=1`） |
| `W9-L18-static` | `bash -n scripts/l18/gui_real_cert.sh` | `reports/l21/artifacts/wave9_gui_static_syntax_check.txt` | ✅ PASS（仅语法检查，不触发 L18 运行流程） |

## 代码与门禁变更清单

- `crates/sb-core/src/adapter/mod.rs`
- `agents-only/06-scripts/l20-migration-allowlist.txt`（`l21.8-wave9-v1`）
- `reports/l21/artifacts/wave9_v7_regression_block.txt`

## 风险与后续

1. `MIG-04` 当前为 `in_progress`：bridge 构建入口已禁用 core HTTP/Mixed concrete，但整体 inbound 单实现收口仍需继续（含运行时全链路验证）。
2. 下一波建议推进 `MIG-06`（Selector 职责收敛）或继续补 `MIG-04` 行为等价测试与 adapter-only 路径覆盖。
