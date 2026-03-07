# WP-I1/I2/I3: GUI Replacement First Run Report

**Date**: 2026-03-07
**GUI**: GUI.for.SingBox.app (wails v2.11.0, /Applications/)
**Script**: `scripts/l18/gui_real_cert.sh`

---

## WP-I1: GUI Single-Core Rust Certification — PASS

All 5 required steps passed for Rust core:

| Step | Status | Note |
|------|--------|------|
| startup | PASS | gui_process_and_kernel_ready |
| load_config | PASS | /proxies=200 |
| switch_proxy | PASS | switched:my-group->direct |
| connections_panel | PASS | /connections=200 |
| logs_panel | PASS | kernel_log_non_empty |

Capability negotiation: Rust `ok` (contract v2.0.0)

## WP-I2: GUI Dual-Core Comparison — PASS

Both Go and Rust cores passed all 5 steps identically:

| Step | Go | Rust |
|------|-----|------|
| startup | PASS | PASS |
| load_config | PASS (/proxies=200) | PASS (/proxies=200) |
| switch_proxy | PASS (my-group->direct) | PASS (my-group->direct) |
| connections_panel | PASS (/connections=200) | PASS (/connections=200) |
| logs_panel | PASS (empty+connections_probe) | PASS (non_empty) |

Go capability negotiation: optional-unavailable (404) — expected, Go doesn't implement /capabilities.

**Behavioral difference**: Go logs_panel used empty+connections_probe fallback; Rust had non-empty logs directly. This is a known presentation difference, not a functional divergence.

## WP-I3: GUI Sandbox Isolation — PASS

| Check | Result |
|-------|--------|
| System proxy before/after identical | PASS (byte-level diff) |
| Sandbox HOME != user HOME | PASS |
| Sandbox HOME isolated | PASS (separate go/ and rust/ subdirs) |
| Ports released after shutdown | PASS (9090, 19090, 11810, 11811 all free) |
| No 0.0.0.0 listeners | PASS |
| Precheck | PASS |
| Postcheck | PASS |

Sandbox root: `reports/l18/sandbox/gui_real_20260307T100646Z_6339/`

---

## Overall Batch I Verdict: PASS

All 3 WPs complete. GUI replacement certification confirmed on MIG-02 post-baseline.
