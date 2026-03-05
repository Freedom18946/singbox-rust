# L21 Wave#6 Execution Report (MIG-02 App/Tests Path)

日期：2026-03-05  
范围：`W6-01 ~ W6-02`（继续推进 `MIG-02`，不启动 `MIG-03/04/06`）

## 结论

- `W6-01`（MIG-02 app/tests 路径去 `SwitchboardBuilder` 依赖）完成：5 个 app 集成测试改为 `OutboundSwitchboard::new()`，不再触发 switchboard concrete builder 路径。
- `W6-02`（strict gate 升级 + 回流阻断）完成：allowlist 升级到 `l21.5-wave6-v1`，`--strict` 通过，负样例 `--v7-only` 阻断成功。
- 本轮保持 L18 隔离：未运行 `scripts/l18/*` 运行流程；仅执行静态 `bash -n`。

## WP 回填（命令 + 产物 + 结果）

| WP | 命令 | 产物 | 结果 |
| --- | --- | --- | --- |
| `W6-01` | `cargo check -p app --tests` | `reports/l21/artifacts/wave6_wp1_app_tests_check.txt` | ✅ PASS（测试目标编译通过，迁移后的 5 个集成测试无编译回归） |
| `W6-02` | `bash agents-only/06-scripts/check-boundaries.sh --strict`；`BOUNDARY_PROJECT_ROOT=<tmp> bash agents-only/06-scripts/check-boundaries.sh --v7-only`（注入回流样例） | `reports/l21/artifacts/wave6_strict_gate.txt`；`reports/l21/artifacts/wave6_v7_regression_block.txt` | ✅ PASS（严格门禁通过 `V7 PASS (42 assertions)`；负样例阻断 `exit_code=1`） |
| `W6-L18-static` | `bash -n scripts/l18/gui_real_cert.sh` | `reports/l21/artifacts/wave6_gui_static_syntax_check.txt` | ✅ PASS（仅语法检查，不触发 L18 运行流程） |

## 代码与门禁变更清单

- `app/tests/http_connect_inbound.rs`
- `app/tests/socks_end2end.rs`
- `app/tests/socks_via_selector.rs`
- `app/tests/upstream_auth.rs`
- `app/tests/upstream_socks_http.rs`
- `agents-only/06-scripts/l20-migration-allowlist.txt`（`l21.5-wave6-v1`）
- `reports/l21/artifacts/wave6_v7_regression_block.txt`

## 风险与后续

1. 当前 MIG-02 仍处于 `in_progress`：测试与工具链路径已收口，但 `sb-core` 与 `sb-adapters` 在 SOCKS5 运行时实现层仍有双实现。
2. 下一波建议直接处理 `crates/sb-core/src/runtime/switchboard.rs` 的 SOCKS concrete connector，切到 adapter-first（或显式 unsupported），并补对应行为等价测试。
