<!-- tier: B -->
# A1 — Controlled Local REALITY Bidirectional Functional-Parity Fixture

Reproducible, self-validating fixture that exercises Go and Rust clients against
one local Go `vless+reality` server, then a Go uTLS client against the Rust
`vless+reality` server, with zero public-network dependency. It is the **local
deterministic gate** (merge-blocking tier) for REALITY functional parity.

## Scope (read before citing this)

- **What it proves:** functional REALITY handshake + Vision VLESS dataplane parity
  for the Rust client against the Go server, and empirical Go uTLS Vision client ↔
  Rust server interoperability. Every path fetches the same fixed HTTP token end-to-end.
- **What it does NOT prove:**
  - It does **not** validate ClientHello byte-level uTLS fingerprint parity or
    real-network anti-censorship camouflage — those remain open and belong to
    the *external healthy-cohort* pre-release observation tier.
  - It is **not** a `52/56` BHV behavior-parity increment. REALITY has no S3
    BHV-ID in that denominator.

See `labs/interop-lab/docs/dual_kernel_golden_spec.md` → `DEV-REALITY-01` for the
three-tier acceptance model this fixture anchors.

## Topology (all 127.0.0.1, no public node, no `openssl s_server`, no `socat`)

```
Go   client  (sing-box-utls, go_client.json, socks 11180) ─┐
Rust client  (app, rust_client.json, socks 11181)          ─┤
                                                            ▼
   18443  Go VLESS+REALITY server (sing-box -tags with_utls, go_server.json)
              │ handshake.server (TLS relay target) ──► 18444  in-repo concurrent Go tls.Listener (helper -mode tls-dest)
              │ VLESS forward ──►
              ▼
   18445  in-repo Go HTTP target (helper -mode http-target) → returns token "reality-fixture-ok"

Go Vision client (go_reverse_client.json, socks 11182)
              │
              ▼
   18446  Rust VLESS+REALITY+Vision server (vless_reality_server_fixture)
              │ VLESS forward ─────────────────────────────► 18445 HTTP target
```

The TLS dest and HTTP target are stdlib-only Go servers (`helper/main.go`): each
connection is handled in its own goroutine (no serial wedge), prints `READY ...`
on stdout (readiness), and is torn down via process-group SIGTERM.

## Single source of truth

`manifest.json` holds the **only** copy of the committed test parameters:
X25519 keypair (base64url *and* 64-hex, cross-checked), `short_id`, `uuid`, SNI,
flow, every port, the HTTP target path, the expected token, timeouts, and the
negative-case parameters. `render_configs.py` generates all seven kernel configs
from it; the Rust phase-probe env is derived from the rendered `rust_client.json`
via `scripts/tools/reality_vless_env_from_config.py`. **Do not hand-edit rendered
configs and do not duplicate any parameter** — change `manifest.json` and re-run.

## One-command reproduction

```bash
python3 labs/interop-lab/reality_local_fixture/run_fixture.py --runs 20
```

Or via the repo task runner (stable, discoverable entrypoint — optional merge-precheck):

```bash
make verify-reality-local
```

`make verify-reality-local` runs the exact command above with the default `--out`
(a git-ignored runtime dir under `labs/interop-lab/artifacts/`), so it never
overwrites the committed `evidence/` snapshot, and it exits non-zero on any
positive / negative / config-validation / readiness / teardown failure.

That single command: builds the Go kernel (`-tags with_utls`), the Go helper, the
Rust `app`, Rust server helper, and Rust phase probe → renders configs from the manifest →
validates them with the real kernels → brings up the local topology (readiness +
timeout + per-process log capture) → runs the full acceptance matrix → emits
evidence → tears everything down.

- Binaries are cached out-of-tree at `<repo>/target/reality_fixture_bin/`
  (so the evidence `--out` dir stays evidence-only). Re-run with `--skip-build`
  to reuse them.
- Evidence defaults to `labs/interop-lab/artifacts/reality_local_fixture/<run_id>/`;
  override with `--out <dir>`.

### Prerequisites

- Go toolchain (builds `go_fork_source/sing-box-1.13.13` with `-tags with_utls`;
  the prebuilt top-level binary lacks uTLS and will not work).
- Rust / cargo.
- `curl` and `python3` (stdlib only).

## Acceptance matrix

**Positive** (topology up):
- Go client: `--runs` consecutive end-to-end requests, every response token must equal `reality-fixture-ok`.
- Rust client (`app` SOCKS→VLESS+REALITY): `--runs` consecutive end-to-end token requests.
- Go Vision client → Rust VLESS+REALITY+Vision server: `--runs` consecutive
  end-to-end token requests; flow addon validation and bidirectional Vision
  framing are mandatory.
- Rust phase probe ×`--runs`, recording each of `direct_reality`,
  `transport_reality`, `vless_dial`, `vless_probe_io` (ok / class / error).

**Negative** (each proves a distinct, distinguishable failure mode):

| Case | Setup | Expectation |
|------|-------|-------------|
| `bad_public_key` | Rust client with a valid-format but unrelated X25519 pubkey | `direct_reality` fails (REALITY auth rejects); no phase falsely reports success |
| `bad_uuid` | correct keys, wrong VLESS uuid | REALITY phases pass; `vless_probe_io` fails (VLESS data-stage rejects) |
| `dead_dest` | server `handshake.server` points at a dead port | fails fast (`direct_reality` not ok), exits within timeout, no wedge |
| `occupied_port` | REALITY server port pre-occupied | server fails to bind with a diagnosable error |

## Evidence outputs (`--out` dir)

- `round-summary.json` — self-contained: `fixture_version`, `git_revision`,
  `go_build_tags`, `manifest_checksum`, `run_id`, `acceptance_model`, `topology`,
  `config_validation`, per-case + per-run rows (`case` / `kernel` / `run_index` /
  `phase_results` / `token_match` / `elapsed`), `teardown`, and the `verdict`.
- `per_run/*.json` — auto-emitted per-run rows (positive Go→Go, Rust→Go,
  Go→Rust, probe + negatives).
- `rendered/*.json` — the seven configs actually used this run.
- `logs/` — per-process stdout/stderr (positive top-level + a subdir per negative case).

`local_deterministic_gate` in the verdict is `PASS` iff all positive runs match
the token / all four phases ok, and all four negative cases meet their expectation.

A committed reference run lives in `evidence/` — **only** `round-summary.json` +
`per_run/` are tracked (point-in-time proof). `evidence/rendered/` and
`evidence/logs/` are git-ignored: rendered configs are reproduced deterministically
from `manifest.json`, and process logs carry per-line timestamp/ANSI churn. Refresh
the reference run with the one-command above plus
`--out labs/interop-lab/reality_local_fixture/evidence`.

## Files

| File | Role |
|------|------|
| `manifest.json` | single source of truth for all test parameters |
| `render_configs.py` | manifest → 7 kernel configs (b64↔hex cross-checked) |
| `run_fixture.py` | build → render → validate → topology → matrix → evidence → teardown |
| `crates/sb-adapters/examples/vless_reality_server_fixture.rs` | Rust reverse-lane server helper |
| `helper/main.go` | stdlib-only concurrent TLS dest + HTTP target servers |
| `helper/go.mod` | helper module |

## Known boundaries

Functional dataplane parity ≠ real-network camouflage. This fixture deliberately
uses a Go `crypto/tls` dest that does **no**
ClientHello inspection and accepts any relayed hello — the Go client's uTLS-Chrome
hello and the Rust client's plain `rustls` hello alike (the Rust client emits no
uTLS fingerprint). It therefore does not measure how a real censoring middlebox
would classify the Rust ClientHello. Fingerprint parity and real-network
camouflage stay in the external healthy-cohort observation tier and are out of
scope here.
