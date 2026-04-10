<!-- tier: B -->
# MT-GUI-01: GUI-Driven Go/Rust Dual-Kernel Comparative Acceptance

**Date**: 2026-04-10
**HEAD**: post-7a5761c2 (on main, evidence captured against l18_gui_{rust,go}.json configs)
**Card type**: GUI-driven dual-kernel comparative acceptance / behavioral evidence work.
**NOT**: parity completion, internal refactor, or new maintenance line.

> **Authoritative parity口径仍以** `labs/interop-lab/docs/dual_kernel_golden_spec.md` **为准**.
> 本卡只产出实测证据和差异说明，不重写 parity 结论.

---

## 1. Scope

This card validates whether the project's local GUI integration path (GUI.for.SingBox 1.19.0 ↔
Clash API ↔ kernel) behaves consistently when driven against:

- **Go kernel** — `go_fork_source/sing-box-1.12.14/sing-box` (existing binary)
- **Rust kernel** — `target/release/app` (built with `--features parity`, MT-DEPLOY-01 baseline)

The test design intentionally exercises only what the GUI itself uses, by reading
[GUI_fork_source/GUI.for.SingBox-1.19.0/frontend/src/api/kernel.ts](../GUI_fork_source/GUI.for.SingBox-1.19.0/frontend/src/api/kernel.ts)
to enumerate the actual REST + WebSocket surface.

### Out of scope

- Building or running the GUI binary itself (Wails desktop, requires node/pnpm/wails)
- Real upstream proxy chains (no real proxy server in test sandbox)
- Recording new dual-kernel parity completion claims
- Restoring `.github/workflows/*`
- Public `RuntimePlan` / public `PlannedConfigIR` / generic query API

---

## 2. GUI Integration Surface (Verified by reading GUI source)

[frontend/src/api/kernel.ts](../GUI_fork_source/GUI.for.SingBox-1.19.0/frontend/src/api/kernel.ts) defines the complete GUI ↔ kernel contract:

### REST endpoints used by the GUI

| Method | Path | Used by |
|--------|------|---------|
| GET | `/configs` | settings panel reads runtime config |
| PATCH | `/configs` | mode switcher updates `mode` |
| GET | `/proxies` | proxy/group listing in main view |
| PUT | `/proxies/{group}` | manual proxy switch in selector |
| GET | `/proxies/{name}/delay?url=...&timeout=5000` | latency probe button |
| GET | `/connections` | connection list panel |
| DELETE | `/connections/{id}` | connection close button |

### WebSocket streams used by the GUI

| Path | Lifetime | Used by |
|------|----------|---------|
| `/memory` | long-lived | RSS chart |
| `/traffic` | long-lived | bandwidth chart |
| `/connections` | long-lived | live connection updates |
| `/logs?level=debug` | short-lived | log viewer panel |

### How the GUI discovers the kernel API

```ts
const controller = profile.experimental.clash_api.external_controller || '127.0.0.1:20123'
const [, port = 20123] = controller.split(':')
base = `${protocol}://127.0.0.1:${port}`
bearer = profile.experimental.clash_api.secret
```

The GUI reads `experimental.clash_api.external_controller` and `experimental.clash_api.secret`
from the active profile and uses them as the Bearer-authenticated base URL. Both kernels expose
this same key in their config schema, so the GUI binds to either kernel by simply pointing the
profile at the corresponding controller port.

---

## 3. Test Method

### Configs used (project-internal, GUI-shaped)

| File | Purpose |
|------|---------|
| `labs/interop-lab/configs/l18_gui_rust.json` | Rust GUI-shape config (Clash API on `127.0.0.1:19090`, SOCKS5 on 11810) |
| `labs/interop-lab/configs/l18_gui_go.json` | Go GUI-shape config (Clash API on `127.0.0.1:9090`, SOCKS5 on 11811) |

Both configs declare the same logical topology:
- one SOCKS5 inbound (only port differs)
- one `selector` outbound named `my-group` with `direct` and `alt-direct` members
- `route.final = my-group`
- `experimental.clash_api` with the same secret `test-secret`

This is the **smallest GUI-realistic shape**: a selector group + multiple direct outbounds is
exactly what GUI.for.SingBox profiles look like before the user adds real protocol nodes.

### Kernel commands

```bash
# Rust kernel
./target/release/app run -c labs/interop-lab/configs/l18_gui_rust.json

# Go kernel
go_fork_source/sing-box-1.12.14/sing-box run -c labs/interop-lab/configs/l18_gui_go.json
```

### Reproducible scripts

- `agents-only/mt_gui_01_evidence/control_plane_test.sh` — orchestrates 10 control-plane scenarios
- `agents-only/mt_gui_01_evidence/data_plane_test.sh` — verifies SOCKS5 data plane through both kernels
- `agents-only/mt_gui_01_evidence/control_plane.txt` — raw control-plane output captured 2026-04-10
- `agents-only/mt_gui_01_evidence/data_plane.txt` — raw data-plane output captured 2026-04-10

---

## 4. Scenario Results

The full per-scenario matrix is in [mt_gui_01_matrix.md](./mt_gui_01_matrix.md). Summary:

| # | Scenario | Result | Notes |
|---|----------|--------|-------|
| 1 | Startup + `GET /version` | **PASS-STRICT** | Both return valid version JSON |
| 2 | `GET /configs` | **PASS-STRICT** | Both 200; body shape diff = DIV-M-006 (mode casing, exposed port fields) |
| 3 | `GET /proxies` | **PASS-STRICT** | Both 200; Rust adds synthetic `DIRECT`/`REJECT` entries = DIV-M-007 |
| 4 | `PUT /proxies/my-group` (switch) | **PASS-STRICT** | Both 204; both reflect `now=alt-direct` after switch |
| 5 | `GET /connections` | **PASS-STRICT** | Both 200; body shape diff = DIV-M-008 (Rust includes large `memory` field) |
| 6 | `PATCH /configs` mode switch | **PASS-STRICT** | Both 204 |
| 7 | Auth enforcement (no token) | **PASS-STRICT** | Both 401 |
| 8 | WS streams `/traffic`, `/memory`, `/connections`, `/logs` | **PASS-ENV-LIMITED** | curl handshake gets data but not a real WS handshake; harness-side WS already covered by `p0_clash_api_contract*` |
| 9 | `GET /proxies/direct/delay` | **PASS-STRICT** | Both return `{"delay": ms}`; ms differs (Rust=4, Go=602) per DIV-M-009 |
| 10 | Graceful shutdown (SIGTERM) | **PASS-STRICT** | Both exit cleanly |
| 11 | SOCKS5 TCP CONNECT through inbound | **PASS-STRICT** | Both kernels relay HTTP 200 + body to upstream |
| 12 | `GET /connections.downloadTotal` after traffic | **NEW FINDING** | Go=2454, Rust=0 (see §5) |

**Verdict**: 10 PASS-STRICT, 1 PASS-ENV-LIMITED, 1 new finding requiring follow-up classification.

---

## 5. New Finding: `downloadTotal` cumulative counter divergence

### Observation

After running an HTTP GET via SOCKS5 through each kernel and then snapshotting `GET /connections`:

| Field | Rust | Go |
|-------|------|------|
| `connections` (active list) | `[]` | `[]` |
| `downloadTotal` | `0` | `2454` |
| `uploadTotal` | `0` | not asserted |

The HTTP request **succeeded on both kernels** (curl returned the upstream body 200 OK on both),
so the difference is not a data-plane failure — both data planes work. The divergence is in
**how each kernel exposes cumulative bytes after a connection has closed**.

### Tentative classification

Most likely categories (not yet definitively assigned):

1. **GUI integration difference** — Rust may scope traffic counters per-active-connection only
   and not maintain a global cumulative tally that survives connection close. Go cumulates.
2. **Already-known divergence** — close to but **not** identical to the existing entries:
   - DIV-M-008 covers `/connections.memory` shape (different concern)
   - The `p1_gui_connections_tracking` case uses live in-flight slow requests rather than
     post-close cumulative bytes, so this exact pattern may not be exercised today
3. **Real functional gap** — if the GUI relies on `downloadTotal` for its bandwidth chart,
   this could surface as "Rust shows 0 traffic" when the connection completes within one tick

### What this card does NOT claim

- It does NOT claim Rust traffic tracking is broken (the data plane works; live `/traffic` WS still emits)
- It does NOT promote this finding into a parity completion update
- It does NOT open a new maintenance card

### Recommended follow-up (not part of this card)

A future investigation card (if needed) should:
1. Check whether `crates/sb-core/src/services/clash_api.rs` (or equivalent) maintains a process-lifetime
   counter across connection-close events
2. Check whether the existing `p1_gui_connections_tracking` interop case asserts `downloadTotal != 0`
   under post-close conditions, and whether the strict-mode oracle flagged it
3. If a real gap exists, decide whether to track as a new DIV entry in `dual_kernel_golden_spec.md`
   or as a `kernel_mode: both` interop case promotion

This card explicitly leaves classification open and only records the observation.

---

## 6. Differences Categorized

### 6a. Already-documented divergences (NOT new)

All four below are already tracked in
[dual_kernel_golden_spec.md §S4](../labs/interop-lab/docs/dual_kernel_golden_spec.md):

| DIV ID | Concern | Observed in this run |
|--------|---------|----------------------|
| DIV-M-006 | `/configs` payload normalization (mode casing, exposed port fields) | Rust `mode=rule`, Go `mode=Rule`; Rust populates `socks-port=11810`, Go does not |
| DIV-M-007 | `/proxies` inventory includes synthetic Rust entries | Rust adds `DIRECT`, `GLOBAL`, `REJECT`; Go has only `GLOBAL` + user proxies |
| DIV-M-008 | `/connections` body includes runtime `memory` field | Rust=17809408, Go=4530176 (cosmetic shape diff already classified) |
| DIV-M-009 | `/proxies/{name}/delay` exact ms timing-sensitive across kernels | Rust=4ms, Go=602ms (both return well-formed JSON) |

### 6b. Already-handled environment limitations

| Concern | Reason |
|---------|--------|
| WS handshake via curl | curl `--http1.1` Upgrade probe gets data but is not a true RFC 6455 WS client; the harness-level coverage in `p0_clash_api_contract` and `p0_clash_api_contract_strict` already exercises real WS framing. Recorded here as PASS-ENV-LIMITED, not a regression. |
| Real proxy upstream (e.g. real shadowsocks server) | Sandbox has no real upstream; both kernels were tested against `direct` outbound + a local Python HTTP server. |
| GUI binary itself (Wails desktop) | Building requires node/pnpm/wails toolchain not provisioned; we instead validated GUI's exact API contract by reading `frontend/src/api/kernel.ts` and replaying the calls. |

### 6c. New observations (this card)

| # | Observation | Class | Action |
|---|-------------|-------|--------|
| 1 | `downloadTotal` after closed SOCKS5 conn: Go=2454, Rust=0 | Possible GUI-impacting divergence | Recorded only; classification deferred to a future investigation card if signal repeats |

### 6d. No new blockers

After the full dual-kernel run, **no new blocker is introduced**. Both kernels:
- start cleanly with the same-shape GUI config
- serve the full GUI REST contract
- accept GUI's auth model
- serve traffic through the SOCKS5 inbound
- shut down gracefully on SIGTERM

---

## 7. Reproduction

```bash
cd /Users/bob/Desktop/Projects/ING/sing/singbox-rust

# 1. Confirm both kernels exist
ls target/release/app
ls go_fork_source/sing-box-1.12.14/sing-box

# 2. Run control-plane comparison (10 scenarios)
bash agents-only/mt_gui_01_evidence/control_plane_test.sh

# 3. Run data-plane comparison (SOCKS5 + connection counter)
bash agents-only/mt_gui_01_evidence/data_plane_test.sh

# 4. Inspect raw evidence
cat agents-only/mt_gui_01_evidence/control_plane.txt
cat agents-only/mt_gui_01_evidence/data_plane.txt
```

---

## 8. Verdict

### Does the project's GUI-driven dual-kernel comparative path work?

**YES — with one new observation worth tracking.**

| Criterion | Status |
|-----------|--------|
| GUI ↔ kernel API contract reachable on Rust | **PASS-STRICT** |
| GUI ↔ kernel API contract reachable on Go | **PASS-STRICT** |
| Same-shape config drives both kernels | **PASS-STRICT** |
| Auth model honored on both kernels | **PASS-STRICT** |
| Selector switch round-trips on both kernels | **PASS-STRICT** |
| SOCKS5 data plane works on both kernels | **PASS-STRICT** |
| Graceful shutdown on both kernels | **PASS-STRICT** |
| WS streams (curl probe) | **PASS-ENV-LIMITED** |
| `downloadTotal` cumulative counter | **NEW FINDING** (see §5) |

### Categorical answer to the card's framing questions

- **Identical behavior on the GUI's exact REST contract**: yes, modulo the four already-documented
  DIV-M cosmetic/structural diffs (DIV-M-006, M-007, M-008, M-009).
- **GUI-integration adapter differences**: none new at the API surface; the cumulative counter
  finding in §5 is the only candidate and is left classification-pending.
- **Accepted limitations**: the four DIV-M entries above; WS handshake via curl is best-effort.
- **New blockers**: **none.**

This is a **deployment / acceptance / evidence** result, not a parity completion claim.
