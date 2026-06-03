<!-- tier: B -->
# MT-GUI-02 Scenario Matrix

> Structured per-scenario matrix for the MT-GUI-02 GUI-driven dual-kernel acceptance through a
> project-local mock public infrastructure.
> Companion document to [mt_gui_02_acceptance.md](./mt_gui_02_acceptance.md).
> Mock design spec: [mt_gui_02_mock_public_infra.md](./mt_gui_02_mock_public_infra.md).
> Raw evidence in [mt_gui_02_evidence/](./mt_gui_02_evidence/).
>
> **Authoritative parity口径仍以** `labs/interop-lab/docs/dual_kernel_golden_spec.md` **为准**.

---

## Test environment

| Item | Value |
|------|-------|
| Date | 2026-04-11 |
| HEAD | `b1f8238e` (post-MT-GUI-01 close, on `main`) |
| Host | macOS (darwin 25.4.0) |
| Rust binary | `target/release/app` (built with `--features parity`, MT-DEPLOY-01 baseline) |
| Go binary | `go_fork_source/sing-box-1.12.14/sing-box` |
| Rust config | `labs/interop-lab/configs/l18_gui_rust.json` |
| Go config | `labs/interop-lab/configs/l18_gui_go.json` |
| Rust Clash API | `127.0.0.1:19090` (Bearer `test-secret`) |
| Go Clash API | `127.0.0.1:9090` (Bearer `test-secret`) |
| Rust SOCKS5 | `127.0.0.1:11810` |
| Go SOCKS5 | `127.0.0.1:11811` |
| Mock HTTP | `127.0.0.1:18080` |
| Mock HTTPS | `127.0.0.1:18443` (self-signed, `SAN: mock-public.local / localhost / 127.0.0.1`) |
| Mock WS | `127.0.0.1:18081` |
| Mock TCP echo | `127.0.0.1:18083` |
| Dead port | `127.0.0.1:18499` (unbound) |
| Sub Bearer | `mt-gui-02-sub-bearer` |
| Sub ETag | `"34f2f416ae8fc084"` (sha256(body)[:16]) |

---

## Control plane — Clash API surface (14 scenarios)

| # | Scenario | Method | Path | Rust | Go | Status | Class |
|---|----------|--------|------|------|------|--------|-------|
| CP-01 | Startup readiness | GET | `/version` | 200 `{"version":"sing-box 0.1.0",…}` | 200 `{"version":"sing-box unknown",…}` | **PASS-STRICT** | none (version string differs, both valid) |
| CP-02 | Read runtime config | GET | `/configs` | 200, `mode=rule`, `mode-list=[rule,global,direct]`, `socks-port=11810` | 200, `mode=Rule`, `mode-list=[Rule]`, `socks-port=0` | **PASS-STRICT** | DIV-M-006 |
| CP-03 | List proxies | GET | `/proxies` | 200, keys=`[DIRECT,GLOBAL,REJECT,alt-direct,direct,my-group]` | 200, keys=`[GLOBAL,alt-direct,direct,my-group]` | **PASS-STRICT** | DIV-M-007 (Rust synthetic entries) |
| CP-04 | Switch selector | PUT | `/proxies/my-group` body `{"name":"alt-direct"}` | 204, then `now=alt-direct` | 204, then `now=alt-direct` | **PASS-STRICT** | none |
| CP-05 | Patch mode | PATCH | `/configs` body `{"mode":"rule"}` | 204 | 204 | **PASS-STRICT** | none |
| CP-06 | Auth enforcement | GET | `/configs` (no token + wrong token) | 401 / 401 | 401 / 401 | **PASS-STRICT** | none |
| CP-07 | Proxy delay to mock HTTP | GET | `/proxies/direct/delay?url=http%3A%2F%2F127.0.0.1%3A18080%2F&timeout=5000` | 200 `{"delay":1}` | 200 `{"delay":502}` | **PASS-STRICT** | DIV-M-009 |
| CP-08 | Connection snapshot baseline | GET | `/connections` | 200, `downloadTotal=0` | 200, `downloadTotal=0` | **PASS-STRICT** | DIV-M-008 (body shape diff) |
| CP-09 | Rules list | GET | `/rules` | 200, `rules_len=1` (wraps final MATCH) | 200, `rules=null` | **PASS-STRICT** | see §5 (shape diff, both 200) |
| CP-10 | Providers (proxies) | GET | `/providers/proxies` | 200 `{"providers":{}}` | 200 `{"providers":{}}` | **PASS-STRICT** | none |
| CP-11 | Providers (rules) | GET | `/providers/rules` | 200 `{"providers":{}}` | 200 `{"providers":[]}` | **PASS-STRICT** | see §5 (object vs array, cosmetic) |
| CP-12 | DNS query resolvable | GET | `/dns/query?name=example.com&type=A` | 200 (Clash-ish shape, `addresses=["198.18.1.30"]`) | 200 (Answer array, `data="198.18.1.30"`) | **PASS-STRICT** | DIV-M-005 (cosmetic) |
| CP-13 | **DNS query non-resolvable** | GET | `/dns/query?name=mock-public.local&type=A` | **500** + error text | **200** + fake answer `198.18.1.29` from internal resolver | **NEW FINDING** | §6 (status-code design divergence) |
| CP-14 | WS streams probe | GET (Upgrade) | `/traffic /memory /connections /logs` | all 4 got data | all 4 got data | **PASS-ENV-LIMITED** | curl best-effort; real WS covered by `p0_clash_api_contract*` |

### Control-plane totals

| Status | Count | Scenarios |
|--------|-------|-----------|
| PASS-STRICT | 12 | CP-01..CP-12 |
| PASS-ENV-LIMITED | 1 | CP-14 |
| NEW FINDING | 1 | CP-13 |
| FAIL | 0 | — |

---

## Data plane — through SOCKS5 → mock public (16 scenarios)

| # | Scenario | Action | Rust | Go | Status | Class |
|---|----------|--------|------|------|--------|-------|
| DP-01 | HTTP GET `/` banner | `curl --socks5-hostname …:11810 http://127.0.0.1:18080/` | body received | body received | **PASS-STRICT** | none |
| DP-02 | HTTP GET `/get` JSON echo | SOCKS5 → `/get` → parse `path` | `path=/get` | `path=/get` | **PASS-STRICT** | none |
| DP-03 | HTTP status 404 / 500 | SOCKS5 → `/status/404` + `/status/500` | 404 + 500 | 404 + 500 | **PASS-STRICT** | none |
| DP-04 | Redirect chain | SOCKS5 → `-L` follow `/redirect/3 → /get` | status 200, redirects=3 | status 200, redirects=3 | **PASS-STRICT** | none |
| DP-05 | Chunked transfer | SOCKS5 → `/chunked`, count `chunk-N` | `chunks=5` | `chunks=5` | **PASS-STRICT** | none |
| DP-06 | 1 MiB payload | SOCKS5 → `/large` | `bytes=1048576` | `bytes=1048576` | **PASS-STRICT** | none |
| DP-07 | Slow upstream 2 s | SOCKS5 → `/slow?ms=2000` | `total=2.003s status=200` | `total=2.008s status=200` | **PASS-STRICT** | none |
| DP-08 | SSE stream | SOCKS5 → `/sse`, count `event: tick` | `events=5` | `events=5` | **PASS-STRICT** | none |
| DP-09 | HTTPS `-k` through SOCKS5 | SOCKS5 → `https://…:18443/get` | `path=/get` | `path=/get` | **PASS-STRICT** | none |
| DP-10 | HTTPS strict (no `-k`) | SOCKS5 → `https://…:18443/get` | curl exit 60 | curl exit 60 | **PASS-STRICT** | both relay TCP; client rejects self-signed |
| DP-11 | Raw TCP echo through SOCKS5 | python SOCKS5 client → `:18083` → `hello-*` | `hello-rust-echo` echoed | `hello-go-echo` echoed | **PASS-STRICT** | none |
| DP-12 | **RFC 6455 WS through SOCKS5** | python client doing full handshake + echo through SOCKS5 | `101 Switching Protocols`, `hello-ws` + `mt-gui-02-ws` echo | same | **PASS-STRICT** | replaces CP-14 limitation with real WS coverage |
| DP-13 | Early-close (server shuts down mid-stream) | SOCKS5 → `/early-close` | curl exit 18 (partial) | curl exit 18 (partial) | **PASS-STRICT** | both kernels surface identically |
| DP-14 | RST (server shuts down with no reply) | SOCKS5 → `/reset` | curl exit 52 (empty reply) | curl exit 52 (empty reply) | **PASS-STRICT** | both kernels surface identically |
| DP-15 | Connection refused (dead port `18499`) | SOCKS5 → `:18499` | curl exit 97 (SOCKS5 refusal) | curl exit 97 (SOCKS5 refusal) | **PASS-STRICT** | both kernels surface identically |
| DP-16 | **Cumulative `downloadTotal` replay** | GET `/connections.downloadTotal` after all traffic | `delta=0` | `delta=1055034` | **CONFIRMED FINDING** | MT-GUI-01 §5 reproduces |

### Data-plane totals

| Status | Count | Scenarios |
|--------|-------|-----------|
| PASS-STRICT | 15 | DP-01..DP-15 |
| CONFIRMED FINDING | 1 | DP-16 (reproduces MT-GUI-01 §5) |
| FAIL | 0 | — |

---

## Subscription refresh — mock `/sub/clash.json` (5 scenarios)

| # | Scenario | Request | Rust kernel | Go kernel | Status |
|---|----------|---------|-------------|-----------|--------|
| SUB-01 | Public fetch | `GET /sub/clash.json` (no auth) | n/a (mock path) | n/a (mock path) | **PASS-STRICT** (200, 311 bytes) |
| SUB-02 | Wrong Bearer | `GET /sub/clash.json` with `Bearer wrong` | n/a | n/a | **PASS-STRICT** (401) |
| SUB-03 | Correct Bearer | `GET /sub/clash.json` with `Bearer mt-gui-02-sub-bearer` | n/a | n/a | **PASS-STRICT** (200 + ETag + `Cache-Control: max-age=60, public`) |
| SUB-04 | `If-None-Match` | `GET /sub/clash.json` with ETag | n/a | n/a | **PASS-STRICT** (304) |
| SUB-05 | `check` the downloaded body as config | GUI-style: fetch profile, feed to kernel `check` | `check exit=0` | `check exit=0` | **PASS-STRICT** (both kernels parse the fetched profile) |

### Subscription totals

5 / 5 PASS-STRICT. The Go `check` fix required a shallow-vs-deep-copy bug fix in the test
script's tag→name remap logic (commit message + acceptance doc §7 record this).

---

## Extra shape probe (raw body diffs)

Pretty-printed JSON of diverging endpoints captured in
[mt_gui_02_evidence/extra_shape_probe.txt](./mt_gui_02_evidence/extra_shape_probe.txt):

- `/rules` — Rust: `{"rules":[{MATCH,my-group,…}]}`, Go: `{"rules":null}`
- `/providers/proxies` — both `{"providers":{}}`
- `/providers/rules` — Rust: `{"providers":{}}`, Go: `{"providers":[]}` (object vs array)
- `/dns/query?name=mock-public.local&type=A` — Rust: 500 error, Go: 200 fake answer `198.18.1.29`
- `/dns/query?name=example.com&type=A` — Rust: Clash flat shape, Go: Answer-array shape (DIV-M-005)
- `/configs` — casing + port exposure diff (DIV-M-006)
- `/connections` — body shape diff (DIV-M-008) + DP-16 cumulative counter divergence

---

## Divergence reconciliation against golden spec

| Observed | In `dual_kernel_golden_spec.md` §S4? | DIV ID | Disposition |
|----------|--------------------------------------|--------|-------------|
| `/configs` mode casing + port field exposure | YES | DIV-M-006 | COSMETIC; oracle already ignores `/configs` |
| `/proxies` synthetic Rust entries | YES | DIV-M-007 | COSMETIC; oracle already ignores `/proxies` |
| `/connections.memory` field shape/magnitude | YES | DIV-M-008 | COSMETIC; oracle already ignores `/connections` |
| `/proxies/{name}/delay` ms timing | YES | DIV-M-009 | COSMETIC; timing-sensitive ignore rule |
| `/dns/query?name=example.com` body shape | YES | DIV-M-005 | COSMETIC; known Clash-shape vs Answer-array diff |
| `/rules` `{rules:[…]}` vs `{rules:null}` with same rule set | NO (shape diff within same route) | — | Cosmetic, both 200; Rust packages the final MATCH and Go does not |
| `/providers/rules` `{providers:{}}` vs `{providers:[]}` | NO | — | Cosmetic, both 200; object vs empty array for empty-provider case |
| **`/dns/query?name=mock-public.local`** status 500 vs 200 | **NO** (distinct from DIV-M-005) | — | **NEW FINDING** — see acceptance §6 |
| **Cumulative `downloadTotal` post-close counter** | NO (distinct from DIV-M-008) | — | **CONFIRMED FINDING** — reproduces MT-GUI-01 §5 |

The two entries at the bottom of the table are the only observations in this run that are not
already categorized by the golden spec. Both are attributed, not repaired; classification
remains deferred (see acceptance §6, §7).

---

## Reproducibility

```bash
cd /Users/bob/Desktop/Projects/ING/sing/singbox-rust
bash agents-only/mt_gui_02_evidence/run_acceptance.sh
```

The orchestrator:

1. Starts `mock_public_infra.py` in the background, waits for its ready JSON on stdout.
2. Starts both kernels with the GUI-shape configs, polls `/version` until 200.
3. Runs `control_plane_test.sh`, `data_plane_test.sh`, `subscription_refresh_test.sh`,
   `extra_shape_probe.sh` sequentially.
4. SIGTERMs both kernels and the mock; reports exit cleanliness.
5. Writes `run_acceptance.txt` + per-section `.txt` files + `rust_kernel.log` / `go_kernel.log`
   / `mock_public_infra.log` under `agents-only/mt_gui_02_evidence/`.

Run is idempotent: clean kill of any leftover PIDs on entry, `SO_REUSEADDR` on all mock
sockets, graceful shutdown on exit.

---

## What this matrix is NOT

- Not a parity completion update.
- Not a replacement for `dual_kernel_golden_spec.md`.
- Not a new dual-kernel interop case (those live in `labs/interop-lab/cases/`).
- Not a regression test target — it is a one-shot acceptance evidence snapshot for MT-GUI-02.
