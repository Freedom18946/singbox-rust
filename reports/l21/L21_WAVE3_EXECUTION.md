# L21 Wave#3 Execution Report (MIG-01 / MIG-05)

日期：2026-03-05  
范围：`W3-01 ~ W3-03`（仅收口 `MIG-01/MIG-05`，不启动 `MIG-02/03/04/06`）

## 结论

- `W3-01`（MIG-01 非核心路径去 `DirectConnector` 依赖）完成并通过最小编译验证。
- `W3-02`（MIG-05 transport 引用继续收敛）完成并通过 `diag/tls_handshake` 编译验证。
- `W3-03`（V7 allowlist 升级 + 回流阻断证据）完成：`--strict` 通过、负样例 `--v7-only` 阻断成功。
- 本轮保持 L18 隔离：未运行 `scripts/l18/*` 运行流程；仅执行静态 `bash -n` 与 fixture 校验。

## WP 回填（命令 + 产物 + 结果）

| WP | 命令 | 产物 | 结果 |
| --- | --- | --- | --- |
| `W3-01` | `cargo check -p sb-api`；`cargo check -p sb-adapters --tests` | `reports/l21/artifacts/wave3_wp1_sb_api_check.txt`；`reports/l21/artifacts/wave3_wp1_sb_adapters_tests_check.txt` | ✅ PASS（`add_outbound` 改为复用 `direct` connector；TUN 测试不再依赖 `DirectConnector`） |
| `W3-02` | `cargo check -p app --bin diag`；`cargo check -p sb-core --example tls_handshake`；`rg -n "sb_transport::\\{Dialer as _, TcpDialer\\}|let dialer = TcpDialer" examples/code-examples/network/tcp_connect.rs` | `reports/l21/artifacts/wave3_wp2_app_diag_check.txt`；`reports/l21/artifacts/wave3_wp2_tls_handshake_check.txt`；`reports/l21/artifacts/wave3_wp2_tcp_connect_static.txt` | ✅ PASS（`diag tcp` 使用 `sb_transport::TcpDialer`，示例同步迁移） |
| `W3-03` | `bash agents-only/06-scripts/check-boundaries.sh --strict`；`BOUNDARY_PROJECT_ROOT=<tmp> bash agents-only/06-scripts/check-boundaries.sh --v7-only`（注入回流样例） | `reports/l21/artifacts/wave3_strict_gate.txt`；`reports/l21/artifacts/wave3_v7_regression_block.txt` | ✅ PASS（严格门禁通过 `V7 PASS (20 assertions)`；负样例阻断 `exit_code=1`） |
| `W3-L18-static` | `bash -n scripts/l18/gui_real_cert.sh`；`bash scripts/l18/capability_negotiation_fixture_check.sh` | `reports/l21/artifacts/wave3_gui_static_syntax_check.txt`；`reports/l21/artifacts/wave3_gui_negotiation_fixture_check.txt`；`reports/l21/artifacts/gui_capability_negotiation/` | ✅ PASS（失败样例 `required_status_not_ok` / `breaking_changes_non_empty` 均可复算阻断） |

## 代码与门禁变更清单

- `crates/sb-api/src/v2ray/services.rs`
- `crates/sb-adapters/src/inbound/tun_process_aware.rs`
- `crates/sb-adapters/tests/tun_process_integration.rs`
- `app/src/bin/diag.rs`
- `crates/sb-core/examples/tls_handshake.rs`
- `examples/code-examples/network/tcp_connect.rs`
- `agents-only/06-scripts/l20-migration-allowlist.txt`（`l21.2-wave3-v1`）
- `reports/l21/artifacts/wave3_v7_regression_block.txt`

## 风险与后续

1. `MIG-01` 仍为 `in_progress`：`runtime/switchboard` 的 Direct/Block 完整替换未纳入本轮。
2. `MIG-05` 仍为 `in_progress`：`sb-core/transport` 其余调用点尚未全部迁移。
3. `capability_negotiation_fixture_check.sh` 运行存在 Python `hashlib blake2*` 环境噪声日志，但脚本 exit=0 且判定结果正确；建议后续单独修复 Python 环境一致性。
