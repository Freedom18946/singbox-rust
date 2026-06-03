<!-- tier: B -->
# MT-GUI-01 Scenario Matrix

> Structured per-scenario matrix for the MT-GUI-01 dual-kernel comparative acceptance.
> Companion document to [mt_gui_01_acceptance.md](./mt_gui_01_acceptance.md).
> Raw evidence in [mt_gui_01_evidence/](./mt_gui_01_evidence/).
>
> **Authoritative parity口径仍以** `labs/interop-lab/docs/dual_kernel_golden_spec.md` **为准**.

---

## Test environment

| Item | Value |
|------|-------|
| Date | 2026-04-10 |
| Host | macOS (darwin 25.4.0) |
| Rust binary | `target/release/app` (built with `--features parity`, MT-DEPLOY-01 baseline) |
| Go binary | `go_fork_source/sing-box-1.12.14/sing-box` (pre-built) |
| Rust config | `labs/interop-lab/configs/l18_gui_rust.json` |
| Go config | `labs/interop-lab/configs/l18_gui_go.json` |
| Rust Clash API | `127.0.0.1:19090` (Bearer `test-secret`) |
| Go Clash API | `127.0.0.1:9090` (Bearer `test-secret`) |
| Rust SOCKS5 | `127.0.0.1:11810` |
| Go SOCKS5 | `127.0.0.1:11811` |

---

## Scenario matrix

### Control plane (12 scenarios)

| # | Scenario | Method | Path / Action | Rust observed | Go observed | Status | Divergence class |
|---|----------|--------|---------------|---------------|-------------|--------|------------------|
| 1 | Startup readiness | GET | `/version` | 200 `{"meta":true,"premium":true,"version":"sing-box 0.1.0"}` | 200 `{"meta":true,"premium":true,"version":"sing-box unknown"}` | **PASS-STRICT** | none (version string differs but both are valid) |
| 2 | Read runtime config | GET | `/configs` | 200, `mode=rule`, `mode-list=[rule,global,direct]`, `socks-port=11810`, `tun={}` | 200, `mode=Rule`, `mode-list=[Rule]`, `socks-port=0`, `tun=null` | **PASS-STRICT** | already-known DIV-M-006 |
| 3 | List proxies | GET | `/proxies` | 200, keys=`[DIRECT, GLOBAL, REJECT, alt-direct, direct, my-group]` | 200, keys=`[GLOBAL, alt-direct, direct, my-group]` | **PASS-STRICT** | already-known DIV-M-007 (Rust synthetic entries) |
| 4 | Switch active proxy in selector | PUT | `/proxies/my-group` body `{"name":"alt-direct"}` | 204; subsequent `now=alt-direct` | 204; subsequent `now=alt-direct` | **PASS-STRICT** | none |
| 5 | Read connections snapshot | GET | `/connections` | 200, `connections=[]`, `downloadTotal=0`, `memory=17809408` | 200, `connections=[]`, `downloadTotal=0`, `memory=4530176` | **PASS-STRICT** | already-known DIV-M-008 (memory field shape) |
| 6 | Patch mode | PATCH | `/configs` body `{"mode":"rule"}` | 204 | 204 | **PASS-STRICT** | none |
| 7 | Auth enforcement (no token) | GET | `/configs` (no `Authorization` header) | 401 | 401 | **PASS-STRICT** | none |
| 8 | WS `/traffic` probe | WS | upgrade `/traffic` | data received | data received | **PASS-ENV-LIMITED** | curl best-effort, not real WS framing |
| 9 | WS `/memory` probe | WS | upgrade `/memory` | data received | data received | **PASS-ENV-LIMITED** | curl best-effort |
| 10 | WS `/connections` probe | WS | upgrade `/connections` | data received | data received | **PASS-ENV-LIMITED** | curl best-effort |
| 11 | WS `/logs` probe | WS | upgrade `/logs` | data received | data received | **PASS-ENV-LIMITED** | curl best-effort |
| 12 | Proxy delay test | GET | `/proxies/direct/delay?url=http%3A%2F%2F127.0.0.1%3A18899%2F&timeout=5000` | 200 `{"delay":4}` | 200 `{"delay":602}` | **PASS-STRICT** | already-known DIV-M-009 (timing-sensitive ms) |
| 13 | Graceful shutdown | SIG | SIGTERM to PID | clean exit | clean exit | **PASS-STRICT** | none |

### Data plane (2 scenarios)

| # | Scenario | Action | Rust observed | Go observed | Status | Divergence class |
|---|----------|--------|---------------|-------------|--------|------------------|
| 14 | SOCKS5 TCP CONNECT relay | `curl --socks5-hostname 127.0.0.1:11810 http://127.0.0.1:18899/` | exit 0, full HTTP body received | exit 0 (port 11811), full HTTP body received | **PASS-STRICT** | none |
| 15 | Cumulative `downloadTotal` after closed conn | `GET /connections` after curl finishes | `downloadTotal=0` | `downloadTotal=2454` | **NEW FINDING** | see §5 of acceptance doc — classification deferred |

---

## Status totals

| Status | Count | Scenarios |
|--------|-------|-----------|
| PASS-STRICT | 10 | 1, 2, 3, 4, 5, 6, 7, 12, 13, 14 |
| PASS-ENV-LIMITED | 4 | 8, 9, 10, 11 (all 4 WS probes via curl) |
| NEW FINDING | 1 | 15 (`downloadTotal` cumulative counter) |
| FAIL | 0 | — |

---

## Divergence reconciliation against golden spec

| Observed | Already in `dual_kernel_golden_spec.md` §S4? | DIV ID | Disposition |
|----------|----------------------------------------------|--------|-------------|
| `/configs` mode casing + exposed port fields | YES | DIV-M-006 | COSMETIC, oracle ignore at `ignore_http_paths: ["/configs"]` |
| `/proxies` synthetic Rust entries (`DIRECT`, `REJECT`) | YES | DIV-M-007 | COSMETIC, oracle ignore at `ignore_http_paths: ["/proxies"]` |
| `/connections` `memory` field magnitude | YES | DIV-M-008 | COSMETIC, oracle ignore at `ignore_http_paths: ["/connections"]` |
| `/proxies/{name}/delay` exact ms | YES | DIV-M-009 | COSMETIC, oracle ignore for delay path |
| `downloadTotal` post-close cumulative counter | NO (not the same as DIV-M-008) | — | NEW; classification deferred |

---

## Reproducibility

The exact commands that produced this matrix are committed at:

- `agents-only/mt_gui_01_evidence/control_plane_test.sh`
- `agents-only/mt_gui_01_evidence/data_plane_test.sh`

Raw output:

- `agents-only/mt_gui_01_evidence/control_plane.txt`
- `agents-only/mt_gui_01_evidence/data_plane.txt`

To re-run:

```bash
bash agents-only/mt_gui_01_evidence/control_plane_test.sh
bash agents-only/mt_gui_01_evidence/data_plane_test.sh
```

---

## What this matrix is NOT

- It is not a parity completion update.
- It is not a replacement for `dual_kernel_golden_spec.md` (which remains the authoritative parity口径).
- It is not a new dual-kernel interop case (those live in `labs/interop-lab/cases/`).
- It is not a regression test target — it is a one-shot acceptance evidence snapshot for MT-GUI-01.

If the §5 finding signal repeats in routine work, a future investigation card may decide whether
to escalate it into either a new DIV entry or a new `kernel_mode: both` interop case.
