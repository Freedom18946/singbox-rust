# L18 GUI Real Certification

- Generated: 2026-03-07T10:06:50Z
- GUI App: `/Applications/GUI.for.SingBox.app`
- GUI Process: `GUI.for.SingBox`
- Sandbox Root: `/Users/bob/Desktop/Projects/ING/sing/singbox-rust/reports/l18/sandbox/gui_real_20260307T100646Z_6339`
- Sandbox: **PASS**
- Overall: **PASS**

## Capability Negotiation

- Enabled: `true`

| Core | Required | Status | Pass | Contract | Min Required | Reason |
|---|---|---|---|---|---|---|
| `go` | `false` | `optional-unavailable` | `true` | `-` | `-` | `http_error:404` |
| `rust` | `true` | `ok` | `true` | `2.0.0` | `2.0.0` | `-` |

## Sandbox Notes

- capabilities_negotiation_go_optional-unavailable:http_error:404
- capabilities_negotiation_rust_ok

| Step | Go | Rust |
|---|---|---|
| `startup` | PASS (gui_process_and_kernel_ready windows=0 ) | PASS (gui_process_and_kernel_ready windows=0 ) |
| `load_config` | PASS (/proxies=200 ) | PASS (/proxies=200 ) |
| `switch_proxy` | PASS (switched:my-group->direct ) | PASS (switched:my-group->direct ) |
| `connections_panel` | PASS (/connections=200 ) | PASS (/connections=200 ) |
| `logs_panel` | PASS (kernel_log_empty_connections_probe=200 ) | PASS (kernel_log_non_empty ) |
