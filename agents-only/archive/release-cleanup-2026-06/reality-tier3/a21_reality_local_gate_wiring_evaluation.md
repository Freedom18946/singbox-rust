<!-- tier: B -->
# A2.1 — REALITY Local Deterministic Gate: Auto-Wiring Evaluation

Read-only investigation + design. Evaluates whether to promote
`make verify-reality-local` (the A1 REALITY local deterministic fixture) from an
**opt-in merge-precheck** to an automatically-executed gate. **No implementation:** this
card does not modify `.github/`, the L18 capstone, the `Makefile`, the fixture, Cargo,
or any source. Benchmarks and failure injections were run locally (authorized) with
zero tracked-workspace churn; the committed `evidence/` snapshot was never overwritten.

> **Recommendation up front: Route B — add the fixture as a low-invasive optional gate
> in the L18 capstone (`scripts/l18/l18_capstone.sh`), after the existing `ORACLE`
> (Go-build) gate, without touching the fast-test default path.** Unique recommendation.

---

## Calibration (2026-06-06, pre-commit review)

Four clarifications binding on this recommendation and on A2.2:

1. **Route B is an L18 *local capstone* gate, not server-side merge enforcement.**
   GitHub Actions is permanently disabled and the repo has **no required-check layer**;
   "the capstone overall FAILs" is a local/maintainer signal, not an automatic merge block.
2. **Capstone wall-time increment is an estimate, not a measured fact.** Measured here:
   standalone warm ≈ 9 s, cold ≈ 349 s. The "+~9 s once inserted after ORACLE" figure is a
   **pending estimate** until a real capstone run measures it in place.
3. **No `exit 77` skip for a missing toolchain by default.** When `REALITY_LOCAL` is
   selected to run, a missing required dependency must produce a reviewer-readable error
   and **FAIL** (not skip). `exit 77` would only be discussable if an existing profile
   semantic explicitly required a skippable environment capability; **not adopted this card.**
4. **Fixed-port concurrency cross-contamination is proven.** The L18 hook must declare a
   **single-instance / serialized** constraint and **check the five fixed ports
   (18443/18444/18445/11180/11181) are free before starting the fixture** (readiness probes
   by port, not pid, so a busy port silently cross-contaminates the topology).

---

## A. Decisive constraint (reframes the option space)

**GitHub Actions is permanently disabled in this repository** (`.github/README.md`,
verbatim: *"GitHub Actions is permanently disabled… Do not add or restore files under
`.github/workflows/`"*; `.github/workflows/` is empty). The repo's "CI" is **local
scripts** under `scripts/ci/` + `scripts/l18/`, invoked by a maintainer. Consequence:

- Options **C / D interpreted as GitHub-Actions jobs are forbidden by policy.**
- There is **no automated per-PR merge-gate mechanism at all** — so "blocking" (D) has
  no enforcement surface to attach to. "Blocking" can only mean "a gate inside a local
  aggregate a maintainer must pass," which is exactly what the **L18 capstone** already
  is.

## B. Current wiring surface

| Surface | What it is | Relevance |
|---|---|---|
| `Makefile: verify-reality-local` | `python3 …/run_fixture.py --runs 20` | the gate entry (Route A, current) |
| `.github/workflows/` | **empty**; Actions permanently disabled | C/D-as-Actions off the table |
| `scripts/ci/{local,accept,strict,warn-sweep}.sh` + `tasks/` | local CI suite; exit-code convention incl. **77 = skipped (deps absent)** | the repo's real "CI"; fast path = `local.sh` |
| `scripts/l18/l18_capstone.sh` | 14-gate orchestrator (PREFLIGHT, ORACLE, BOUNDARIES, PARITY, WORKSPACE_TEST, FMT, CLIPPY, HOT_RELOAD, SIGNAL, DOCKER, GUI, CANARY, DUAL_KERNEL_DIFF, PERF_GATE); profiles daily/nightly/certify | **the low-invasive hook target** |
| `scripts/l18/{preflight_macos,build_go_oracle,perf_gate,run_dual_kernel_cert}.sh` | capstone sub-gates | `ORACLE` already builds Go; `DUAL_KERNEL_DIFF` already uses fixed ports + `check_port_free` |

**L18 hook shape:** every gate is one line: `run_gate_with_fail_fast "KEY" <cmd>`
(plus a status var, a `set_gate_status` case, and a `finalize_status` JSON field). The
capstone already runs `BOUNDARIES` via the same `bash agents-only/06-scripts/check-boundaries.sh`
pattern — adding a `REALITY_LOCAL` gate is the **identical, additive, ~4-line** change,
and it does **not** touch `make check` / `scripts/ci/local.sh` (the fast path).

## C. Runner dependency inventory

- **Go toolchain** building `go_fork_source/sing-box-1.13.13` with **`-tags with_utls`**
  (the prebuilt top-level binary lacks uTLS). Verified locally: `go1.26.4 darwin/arm64`;
  `with_utls` builds fine on a general dev runner. Go is **already a capstone
  prerequisite** (`ORACLE` = `build_go_oracle.sh`).
- **Rust / cargo** (`app` with `acceptance,transport_reality`; probe example with
  `adapter-vless,tls_reality,sb-transport`). Already built by capstone gates.
- **python3** (stdlib only) and **curl**. No `jq` needed by the fixture itself.
- **Fixed loopback ports** (manifest.json, NOT ephemeral): `reality_server 18443`,
  `tls_dest 18444`, `http_target 18445`, `go_client_socks 11180`, `rust_client_socks 11181`.
- No Docker, no public network, no `openssl`/`socat`, no system-env mutation.

## D. Cold / warm benchmark (measured this session)

`/usr/bin/time -p make verify-reality-local`, fixture binary cache + runtime artifacts
cleaned for the cold run (workspace Cargo cache left intact per scope):

| Run | wall (`real`) | exit | verdict | go | rust | probe | neg | teardown | ports after | tracked churn |
|---|---|---|---|---|---|---|---|---|---|---|
| **cold** | **348.96 s** (~5m49s) | 0 | PASS | 20/20 | 20/20 | 20/20 | 4/4 | all `terminated` | all free | none |
| **warm 1** | **9.78 s** | 0 | PASS | 20/20 | 20/20 | 20/20 | 4/4 | all `terminated` | all free | none |
| **warm 2** | **8.73 s** | 0 | PASS | 20/20 | 20/20 | 20/20 | 4/4 | all `terminated` | all free | none |

- Cold cost is dominated by the from-scratch Go `with_utls` + Rust `app` + probe builds
  (`user` CPU ≈ 2018 s reflects parallel compile). A true empty-`target/` CI runner would
  be **higher** (full workspace dep compile) — flagged, not measured (scope kept the
  workspace cache warm).
- **Warm is ~9 s and stable** (validate + 20×3 positive + 4 negatives + teardown).
- Default `--out` = gitignored `labs/interop-lab/artifacts/reality_local_fixture/<run_id>/`;
  committed `evidence/` never overwritten; **zero tracked churn** across all runs.
- Diagnostics are rich and collectable: `round-summary.json` (self-contained verdict +
  per-run rows + teardown), `per_run/*.json`, `rendered/*.json`, `logs/` (per process).

## E. Failure-mode results

| Mode | Method | Result |
|---|---|---|
| **occupied_port** | built-in negative case (exercised ×3) | **fail-fast, diagnosable**: server exits non-zero with `address already in use`/`bind` line; case PASS |
| **missing Go** | PATH isolation (shim w/ python3+git, no `go`) | **hard FAIL, exit 1** with `FileNotFoundError: …'go'` traceback at the first build; **NOT** a graceful `exit 77` skip → a CI wrapper must preflight `command -v go` (in the capstone this is moot: `ORACLE` builds Go first) |
| **helper build failure** | code review (safe injection needs source edit) | same `sh([...]) → raise SystemExit("helper build failed:\n"+stderr)` pattern as the (injected) Go-build path → exit 1 + captured stderr |
| **teardown anomaly** | observed ×3 + code review | SIGTERM→wait 5 s→SIGKILL (`"killed"`), per-phase `ProcManager` in `finally`; observed all `terminated`, ports released even after the concurrent-FAIL path |
| **concurrency** | two parallel `make verify-reality-local` | **both FAIL, exit 2** (make-wrapped) |

## F. Concurrency finding (load-bearing for any wiring)

Two simultaneous runs **both report `readiness: all-True` yet both FAIL the positive
matrix and exit non-zero.** Cause: fixed ports + `wait_port` checks *whether a port is
listening*, not *whose process* — so run B sees run A's servers, both run against a
cross-contaminated topology, both fail token/handshake. Ports were released afterward
(all free). So it is **not silent corruption and not a wedge** — but it is a
**false-negative flaky risk**: parallel execution makes *both* jobs spuriously fail,
which a reviewer could misread as a regression. **Any wiring MUST declare
single-instance / serialized execution.** (The L18 capstone is already single-instance
and its `DUAL_KERNEL_DIFF` gate already assumes fixed-port exclusivity, so Route B
inherits this constraint rather than introducing it.)

## G. Answers to the wiring questions

- **CI workflow to mount a job on?** No (Actions disabled). The equivalent is the L18
  capstone local orchestrator.
- **Low-invasive L18 hook?** Yes — one `run_gate_with_fail_fast` line (+3 trivial edits),
  same pattern as the existing `BOUNDARIES` gate; fast path untouched.
- **Deps beyond Go/Rust/Python?** Only `curl`. (No jq/Docker/network.)
- **`with_utls` Go build on a general runner?** Yes (verified, go1.26.4).
- **Fixed ports?** Yes (5 fixed loopback ports). **Concurrent conflict?** Yes → serialize.
- **Teardown pollution of later jobs?** No — SIGTERM/SIGKILL + `finally`; ports freed even on failure.
- **Artifacts for diagnostics?** Yes — `round-summary.json` + `per_run/` + `logs/`.
- **Committed evidence overwrite risk?** No — default `--out` is gitignored; `evidence/` only if explicitly targeted.
- **Cold/warm cost?** ~349 s cold / ~9 s warm (this host, warm workspace cache).

## H. Option comparison

| Dimension | A — opt-in Make target (current) | **B — L18 capstone optional hook** | C — standalone local job, non-blocking | D — blocking CI job |
|---|---|---|---|---|
| Impl change surface | none | **~4 additive lines in `l18_capstone.sh`** | new `tasks/` script + wire into local.sh (more surface) | re-enable Actions (**policy violation**) or build a non-existent enforcement layer |
| Merge-blocking semantics | none (never auto-run) | runs at capstone cadence; FAILED → capstone overall FAILED | advisory; no display surface (no CI) | **unenforceable** (no CI in this repo) |
| Runtime cost | 349 s cold / 9 s warm | **+~9 s** (Go/Rust already warm post-ORACLE); negligible vs 1h–7d canary | ~9 s warm | n/a |
| Runner deps | Go(uTLS)+Rust+py+curl | **same; no NEW deps** (ORACLE already builds Go) | same | same |
| Concurrency risk | n/a (manual) | inherits capstone single-instance (already assumed) | dev pre-push, serial | high if ever parallel |
| Flaky risk | low | **low if single-instance** (warm ×2 deterministic) | low if serial | high |
| Log diagnosability | full | full + capstone status JSON field | full | full |
| Maintenance cost | zero | **low** (1 gate in existing 14-gate runner) | medium (parallel runner dup) | high |
| Rollback difficulty | n/a | **trivial** (delete the gate line) | easy | hard |
| Fits three-tier model | tier-1 stays opt-in but **under-exercised** | **tier-1 actually exercised at certify cadence; tier-2/3 untouched** | redundant with B | over-promotes tier-1 to a hard per-commit blocker (model says "not yet enforced") |

## I. Recommendation — **Route B** (unique)

Per the decision rule (§八.1): a low-invasive L18 optional hook exists **and** it does
not change the fast-test default path → recommend **B**, manually enabled at capstone
cadence. Reinforced by: **C/D-as-Actions are policy-forbidden** and there is no merge
gate to block on; **A under-delivers** because the normative merge-precheck tier is then
never exercised in the maintainer's certify flow despite costing only ~9 s warm; **C is
redundant** with the capstone's existing aggregation; the cost of B is negligible (rule
§八.4 does not apply — cost ≪ benefit).

Design of the (future, not-this-card) hook:

1. Add `run_gate_with_fail_fast "REALITY_LOCAL" make verify-reality-local` **after the
   `ORACLE` gate** (so a missing/old Go fails at `ORACLE` with its own diagnostic, and
   the REALITY gate's hard-crash-on-absent-Go never triggers); plus the matching status
   var, `set_gate_status` case, and `finalize_status` JSON field — mirroring `BOUNDARIES`.
2. Keep default `--out` (gitignored) → zero tracked churn; surface `round-summary.json`
   under the capstone's report dir for diagnosis.
3. Document **single-instance** execution (inherited capstone constraint).
4. Front it with a `command -v go cargo python3 curl` dependency check **and a free-port
   preflight on the five fixed ports** before starting the fixture; a missing dependency or
   a busy port **fails with a reviewer-readable diagnostic — NO `exit 77` skip by default**
   (Calibration §3/§4). In-capstone, `PREFLIGHT`/`ORACLE` already guarantee the toolchain,
   so the dep check is defense-in-depth.
5. Keep `make verify-reality-local` as the standalone opt-in entry (A and B coexist).

This makes tier-1 actually exercised in the certify flow without becoming a hard
per-commit blocker, consistent with the golden_spec three-tier model.

## J. Graduation conditions (C→D) — N/A

I recommend **B**, not **C**, so the C→D bar does not apply. For completeness:
**D-style hard enforcement is unreachable while GitHub Actions is policy-disabled** and
no other enforcement layer exists. If that policy were ever reversed, a graduation bar
would need: N consecutive clean runs on the CI runner, a cold/warm wall-time ceiling,
the single-instance/port-lock policy, teardown-reliability and artifact-collection
checks, and a declared runner-dependency manifest. **The repo has no existing numeric
CI flaky/N-run stability rubric** (only the capstone `daily/nightly/certify` cadence and
the 7-day `canary` notion); per the standing rule I do **not** invent N — **this bar is
flagged as needing human adjudication**, ideally reusing the `certify` 7-day-clean
posture as the reference.

## K. Disposition & next card

- A2.1 = evaluation only; **no implementation**. Recommendation: **B**.
- Suggested next card (do NOT execute here): **A2.2 — implement the Route B hook** (the
  ~4-line additive `REALITY_LOCAL` gate after `ORACLE` + optional exit-77 preflight),
  then run the capstone `daily` profile once to confirm the gate slots in. Strictly a
  `scripts/l18/l18_capstone.sh` edit; no Actions, no fast-path change, no fixture edit.
- After that, the standing roadmap resumes at the **tier-3 ClientHello fingerprint**
  project (the residual OPEN item; no public network in scope here).
