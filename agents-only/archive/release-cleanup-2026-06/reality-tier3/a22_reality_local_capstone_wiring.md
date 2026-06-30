<!-- tier: B -->
# A2.2 — REALITY Local Gate Wired into the L18 Capstone (checkpoint)

Checkpoint for A2.2 (implementation of the A2.1 Route-B recommendation). The REALITY
local deterministic gate (`make verify-reality-local`) is now an **L18 LOCAL capstone
gate** — **not** server-side merge enforcement (GitHub Actions is permanently disabled;
the repo has no required-check layer). Implemented by editing **only**
`scripts/l18/l18_capstone.sh`.

## Commit

- A2.2 implementation: **`71e51669`** (`build(interop-lab): wire REALITY local gate into
  the L18 capstone (A2.2)`), 1 file changed (+59), no Co-Authored-By.
- (Predecessor A2.1 evaluation: `c46fb60f`.)

## Insertion point

`run_gate_with_fail_fast "REALITY_LOCAL" run_reality_local_gate` is placed **after
`ORACLE`** (the Go-oracle build gate) and **before `BOUNDARIES`** — order
PREFLIGHT → ORACLE → **REALITY_LOCAL** → BOUNDARIES → … . Placing it after ORACLE means
a missing/broken Go toolchain fails at ORACLE first. Wiring mirrors the existing 14
gates: a `REALITY_LOCAL_STATUS` var (init `UNTESTED`), a `set_gate_status` case, and a
`"reality_local"` field in the `finalize_status` JSON `gates` object.

## Wrapper `run_reality_local_gate`

- **Required commands:** `go`, `cargo`, `python3`, `curl`, **`make`**. Missing any →
  reviewer-readable `[REALITY_LOCAL] missing required command(s): …` + `return 1`.
  **No `exit 77` skip** — when this gate is selected, a missing dependency FAILS.
- **Fixed-port preflight (lsof-independent):** the five fixed loopback ports
  **18443 / 18444 / 18445 / 11180 / 11181** are probed with a `python3`
  `socket.connect_ex` test (a connect succeeds iff something is listening). Any busy
  port → `[REALITY_LOCAL] fixed loopback port(s) already in use: …` +
  `refusing to start the fixture …` + `return 1`, **before** the fixture starts (so the
  port-by-port readiness check can never cross-contaminate).
- **lsof is best-effort only:** the extra `lsof -nP -iTCP:<port> -sTCP:LISTEN` dump is
  guarded by `if command -v lsof`, so a missing `lsof` never produces a
  `command not found` and never blocks the fail-fast.
- **Execution:** `make -C "$ROOT_DIR" verify-reality-local`; exit code propagated.
  Default gitignored `--out`; committed `evidence/` never overwritten; teardown handled
  by the fixture itself.

### `check_port_free` / `lsof` fact (recorded per A2.2a §1.3)

The file-global `check_port_free()` (used by the dual-kernel runtime helpers) **does
depend on `lsof`** (`lsof -nP -iTCP:<port> -sTCP:LISTEN`). It is **backed by an existing
global assumption**: the `PREFLIGHT` gate (`scripts/l18/preflight_macos.sh`) hard-fails
on a missing `lsof` (`check_cmd_required lsof`), so in a real capstone `lsof` is
guaranteed present. Per A2.2a it was **left untouched / not refactored**; the REALITY
wrapper deliberately uses its own `lsof`-independent probe instead of reusing
`check_port_free`, so the REALITY busy-port preflight stays correct even without `lsof`.

## Single-instance / serialized constraint

The fixture binds **fixed** loopback ports, so it is single-instance / serialized.
Concurrent standalone `make verify-reality-local` runs are unsupported and can fail via
cross-run port contamination (readiness probes by port, not by pid). This is an
**inherited fixed-port constraint, not silent corruption**; ports are released on
teardown either way. Parallel-runner support would need dynamic ports or an explicit
lock and is out of scope. The constraint is documented inline in the wrapper's header
comment.

## Verification results (this card)

- **Static:** `bash -n` OK; `git diff --check` clean; `REALITY_LOCAL` wired once after
  ORACLE; status var + case + JSON field present; no `exit 77`.
- **Standalone fixture (`make verify-reality-local`):** PASS — Go 20/20, Rust 20/20,
  phase probe 20/20, 4 negatives pass, teardown all `terminated`, five ports released,
  committed-evidence zero churn (warm wall ≈ 9–14 s).
- **Wrapper happy-path** (real function bytes, ports free): deps OK → ports free → runs
  the fixture → PASS (`WRAPPER_EXIT=0`; in-wrapper warm wall ≈ 9 s).
- **occupied-port fail-fast** (18443 occupied): `already in use: 18443` +
  `refusing to start the fixture` + `WRAPPER_EXIT=1`; fixture **not** started.
- **missing-make fail-fast** (PATH isolation, make hidden): `missing required
  command(s): make` + `WRAPPER_EXIT=1`; fixture **not** started; no artifacts.
- **missing-lsof busy-port** (PATH isolation, lsof hidden, 18443 occupied):
  `already in use: 18443` + `refusing to start the fixture` + `WRAPPER_EXIT=1`; **no
  `command not found`** (lsof guarded); fixture **not** started; ports freed on cleanup.
- **Regression:** strict boundaries `exit 0`; `cargo check --workspace --all-features`
  PASS; tracked change limited to `scripts/l18/l18_capstone.sh`.

## Deferred / scope

- **A2.3 (DEFERRED):** full-capstone **runtime** status-JSON verification — confirming
  `reality_local` renders `PROVEN`/`FAILED` after the gate runs in-sequence, and the
  in-place wall-time increment — is **only** to be done during the **next real L18
  capstone rehearsal** (no targeted/dry-run path exists; the `daily` profile triggers a
  long canary; no test-only machinery was added). Not claimed verified here.
- **No public network.** **tier-2** (external public fresh-cohort) remains **pre-release
  observation** only. **tier-3** (ClientHello byte-level fingerprint parity) remains
  **OPEN**.
- `agents-only/a0_reality_spike/` remains pre-existing untracked (untouched).

## Next card (not executed here)

**tier-3 ClientHello fingerprint scoping evaluation** (residual OPEN item; no public
network). A2.3 runtime confirmation rides along the next real capstone rehearsal.
