<!-- tier: B -->
# Clash API Strict-Parity Closeout

Status: **CLOSED** (2026-07-23).

## Result

All eight scoped cases passed against live Rust and Go 1.13.13 kernels. Every final normalized
diff is clean with gate score zero:

| Case | Final run ID |
|---|---|
| `p0_clash_api_contract_strict` | `20260723T154420Z-31a2c920-90d0-44b1-a52a-9bc951f47ef9` |
| `p1_clash_mode_rule_switch_via_socks` | `20260723T154427Z-49583e44-310a-40f4-9126-5c570cab8c07` |
| `p1_dns_query_endpoint_contract` | `20260723T153123Z-0248021d-528e-42df-9f19-0b125db6383e` |
| `p1_fakeip_cache_flush_contract` | `20260723T154929Z-2f296d50-0b2e-4e9d-8eda-2c717fd05c32` |
| `p1_fakeip_dns_query_contract` | `20260723T153125Z-9983400b-f7f9-42af-ba07-635108c17678` |
| `p1_gui_connections_tracking` | `20260723T153126Z-6e4ea730-e9f2-4a5d-87d4-d7d2a6e3f052` |
| `p1_gui_proxy_switch_replay` | `20260723T153137Z-8ccf5c9b-1c43-4196-b031-fbc0ea721fe7` |
| `p2_connections_ws_soak_dual_core` | `20260723T153138Z-b0d43b43-06fa-451c-b3b2-811c93d4593e` |

Documented KEEP axes remain explicit: delay/log path ignores and non-Linux memory metric
incomparability. Linux retains the 2x peak-memory gate.

## Closeout Corrections

- Go proxy projection requires group-only `all`, including `GLOBAL: {"all":[]}`, and
  `GLOBAL.now` must follow configured final outbound rather than hash-map iteration.
- Rust/Go fixtures set lowercase `default_mode` to match GUI enum semantics. `/configs`
  derives the remaining mode-list from nested route and DNS `clash_mode` rules in Go order;
  strict replay now compares `["rule", "Global"]` in the mode-switch fixture.
- Persistent FakeIP fixtures now materialize per-run cache paths. Fresh Rust/Go runs both allocate
  `.2`, `.3`, then `.4` after flush, proving mappings clear without rewinding the cursor.
- Closed-connection capture uses a one-second settle window; four extra dual-kernel repeats passed.
- S3/S6 audit rejected the goal's speculative coverage increment. All eight cases were already
  strict `kernel_mode: both` and already credited. Authoritative metrics remain in
  `agents-only/active_context.md` and `labs/interop-lab/docs/dual_kernel_golden_spec.md`.

## DNS Flush Flake

`test_flush_dns_cache` uses a server-local injected `DnsResolver`; the handler does not read or
clear the process-global core resolver. Forty consecutive full `clash_http_e2e` binary runs with
`--test-threads=16` passed. Classification: accepted, non-reproduced test-infrastructure
observation; not a runtime Go/Rust divergence and not an S4 entry.

## Gates

- Acceptance app build with `acceptance,clash_api,adapters`: PASS.
- `sb-api`: 133 passed, 1 ignored.
- Focused `sb-core fakeip`: 30 passed; focused `sb-core dns`: 221 passed, 7 ignored.
- `interop-lab`: 49 passed.
- DNS-flush 16-thread stress: 40/40 full-binary rounds PASS.
- Boundaries: 430 assertions, zero violations.
- Repository-policy clippy (`--workspace --all-features`, no `--all-targets`): exit 0; existing
  warnings remain non-blocking by policy.
- Consistency, fmt, and diff-check: PASS.

An external `cargo clean` overlapped the first focused-core gate and removed the shared target
directory. Final builds and all required gates were rerun from isolated
`/private/tmp/singbox-rust-clash-api-closeout`; source state was unaffected.
