# L21 Wave#5 Execution Report (MIG-02 Kickoff)

日期：2026-03-05  
范围：`W5-01 ~ W5-02`（启动 `MIG-02`，不启动 `MIG-03/04/06`）

## 结论

- `W5-01`（MIG-02 app/tool 路径先行去重叠）完成：`probe-outbound` 改为 adapter bridge 解析 outbound，不再依赖 `runtime::switchboard`。
- `W5-02`（strict gate 升级 + 回流阻断证据）完成：allowlist 升级到 `l21.4-wave5-v1`，`--strict` 通过，负样例 `--v7-only` 阻断成功。
- 本轮保持 L18 隔离：未运行 `scripts/l18/*` 运行流程；仅执行静态 `bash -n`。

## WP 回填（命令 + 产物 + 结果）

| WP | 命令 | 产物 | 结果 |
| --- | --- | --- | --- |
| `W5-01` | `cargo check -p app` | `reports/l21/artifacts/wave5_wp1_app_check.txt` | ✅ PASS（`probe-outbound` 完成 switchboard -> adapter bridge 迁移） |
| `W5-02` | `bash agents-only/06-scripts/check-boundaries.sh --strict`；`BOUNDARY_PROJECT_ROOT=<tmp> bash agents-only/06-scripts/check-boundaries.sh --v7-only`（注入回流样例） | `reports/l21/artifacts/wave5_strict_gate.txt`；`reports/l21/artifacts/wave5_v7_regression_block.txt` | ✅ PASS（严格门禁通过 `V7 PASS (32 assertions)`；负样例阻断 `exit_code=1`） |
| `W5-L18-static` | `bash -n scripts/l18/gui_real_cert.sh` | `reports/l21/artifacts/wave5_gui_static_syntax_check.txt` | ✅ PASS（仅语法检查，不触发 L18 运行流程） |

## 代码与门禁变更清单

- `app/src/bin/probe-outbound.rs`
- `agents-only/06-scripts/l20-migration-allowlist.txt`（`l21.4-wave5-v1`）
- `reports/l21/artifacts/wave5_v7_regression_block.txt`

## 风险与后续

1. 当前仅完成 app 工具链先行迁移，`sb-core` 与 `sb-adapters` 在 SOCKS5/Hysteria2 实现层仍存在双实现，`MIG-02` 仍需后续波次继续收口。
2. 下一波建议优先将 `runtime/switchboard` 的 SOCKS5 concrete connector 路径迁到 `sb-adapters`，并用 V7 断言锁定不回流。
