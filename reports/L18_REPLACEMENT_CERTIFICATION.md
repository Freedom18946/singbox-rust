# L18 Replacement Certification Report

## Scope

L18 objective is "replacement certification first, zero-regression performance in parallel" under macOS only.

- Topology: dual-kernel (Go + Rust) with GUI as the unified driver.
- Gate policy: `docker/gui/canary` are mandatory in L18.
- Go oracle source: `go_fork_source/sing-box-1.12.14` built locally for every run.

## Mandatory Gates

- `scripts/l18/preflight_macos.sh`
- `scripts/l18/build_go_oracle.sh`
- `scripts/l18/run_dual_kernel_cert.sh`
- `scripts/l18/gui_real_cert.sh`
- `scripts/l18/perf_gate.sh`
- `scripts/l18/l18_capstone.sh --profile daily|nightly|certify`
- `scripts/l18/run_capstone_fixed_profile.sh --profile daily|nightly|certify --gui-app <abs_path>`

Capstone gate set:

- `boundaries`
- `parity`
- `workspace_test`
- `fmt`
- `clippy`
- `hot_reload`
- `signal`
- `docker`
- `gui_smoke`
- `canary`
- `dual_kernel_diff`
- `perf_gate`

## Performance KPI

Relative to Go baseline:

- p95 latency <= +5%
- RSS peak <= +10%
- startup time <= +10%

## Artifacts Contract

- `reports/l18/baseline.lock.json`
- `reports/l18/oracle/go/<run_id>/oracle_manifest.json`
- `reports/l18/dual_kernel/<run_id>/summary.json`
- `reports/l18/dual_kernel/<run_id>/diff_gate.json`
- `reports/l18/gui_real_cert.json`
- `reports/l18/gui_real_cert.md`
- `reports/l18/perf_gate.json`
- `reports/l18/l18_capstone_status.json`

## Execution Profiles

- `daily`: P0/P1 dual-kernel diff + 1h canary
- `nightly`: full both-kernel diff + 24h canary
- `certify`: full both-kernel diff + 7d canary (required to close L18)

## Failure Attribution Policy

- Any missing precondition is `FAIL` and blocks certification.
- No `SKIP`/`BLOCKED` for L18 certification gates.
- External unstable subscriptions are excluded from blocking set.

## Exemption Policy

Default: no exemptions.

If an exemption is required, add a dated waiver entry with:

- explicit owner
- risk impact
- expiration date
- compensating controls

Without all four fields, waiver is invalid.

## Current Status

- Status: `IN_PROGRESS`
- Stage: Phase 3 nightly full PASS achieved; certify deferred pending global static review triage.
- Closure criteria pending:
  - at least one `certify` (7d canary) pass
  - all mandatory gate evidence uploaded from self-hosted macOS CI
- Local workspace note (2026-03-09):
  - to reduce package size for GPT static audit, bulky runtime artifacts (`target/`, most `reports/l18/batches/`, oracle/build caches) were pruned from the local workspace
  - batch ids below remain provenance references; referenced artifact files may not exist in this slimmed snapshot
- Phase 2 closure note (2026-03-08):
  - clean daily rerun `20260307T211512Z-l18-daily-preflight` reached `overall=PASS`
  - capstone gates: all PASS, `docker=WARN`
  - canary summary: 13/13 `health_code=200`, RSS `11024 KB -> 7168 KB`, no monotonic leak trend
  - perf gate: PASS (`latency_p95=-15.83%`, `rss_peak=-4.84%`, `startup=0.0%`)
  - baseline lock refreshed at `reports/l18/phase2_baseline.lock.json`
- Phase 3 nightly note (2026-03-09):
  - nightly `20260307T230356Z-l18-nightly-24h` reached `overall=PASS`
  - capstone gates: all PASS, `docker=WARN`
  - canary summary: 78/78 `health_code=200`, RSS `11744 KB -> 6736 KB`, no monotonic leak trend
  - dual gate: PASS (`run_fail_count=0`, `diff_fail_count=0`)
  - perf gate: PASS (`latency_p95=-5.30%`, `rss_peak=-8.18%`, `startup=0.0%`)
  - no valid `certify` conclusion has been recorded yet

## Latest Evidence (2026-03-09)

### 1) Phase 2 clean daily rerun

- Batch root:
  - `reports/l18/batches/20260307T211512Z-l18-daily-preflight`
- Status artifact:
  - `reports/l18/batches/20260307T211512Z-l18-daily-preflight/capstone_daily_fixedcfg/r1/l18_capstone_status.json`
- Result:
  - `overall=PASS`
  - gates: `preflight/oracle/boundaries/parity/workspace_test/fmt/clippy/hot_reload/signal/gui_smoke/canary/dual_kernel_diff/perf_gate=PASS`
  - `docker=WARN`

### 2) Phase 2 canary summary

- Artifact:
  - `reports/l18/batches/20260307T211512Z-l18-daily-preflight/capstone_daily_fixedcfg/r1/canary/canary_daily.md`
- Result:
  - samples: `13`
  - health 200 count: `13`
  - RSS: `11024 KB -> 7168 KB`
  - conclusion: no monotonic leak trend observed

### 3) Phase 2 perf gate

- Artifact:
  - `reports/l18/batches/20260307T211512Z-l18-daily-preflight/capstone_daily_fixedcfg/r1/perf/perf_gate.json`
- Result:
  - `latency_p95`: Rust `1.701 ms`, Go `2.021 ms`, regression `-15.83%`
  - `rss_peak`: Rust `1888 KB`, Go `1984 KB`, regression `-4.84%`
  - `startup`: Rust `18.0 ms`, Go `18.0 ms`, regression `0.0%`
  - verdict: `PASS`

### 4) Phase 3 nightly 24h full PASS

- Batch root:
  - `reports/l18/batches/20260307T230356Z-l18-nightly-24h`
- Status artifact:
  - `reports/l18/batches/20260307T230356Z-l18-nightly-24h/capstone_nightly_fixedcfg/r1/l18_capstone_status.json`
- Result:
  - `overall=PASS`
  - gates: `preflight/oracle/boundaries/parity/workspace_test/fmt/clippy/hot_reload/signal/gui_smoke/canary/dual_kernel_diff/perf_gate=PASS`
  - `docker=WARN`

### 5) Phase 3 nightly canary summary

- Artifact:
  - `reports/l18/batches/20260307T230356Z-l18-nightly-24h/capstone_nightly_fixedcfg/r1/canary/canary_nightly.md`
- Result:
  - samples: `78`
  - health 200 count: `78`
  - RSS: `11744 KB -> 6736 KB`
  - conclusion: no monotonic leak trend observed

### 6) Phase 3 nightly dual + perf evidence

- Dual artifact:
  - `reports/l18/batches/20260307T230356Z-l18-nightly-24h/capstone_nightly_fixedcfg/r1/dual_kernel/20260308T231830Z-nightly-34ebea7d/summary.json`
- Dual result:
  - selected cases: `6`
  - `run_fail_count=0`
  - `diff_fail_count=0`
  - verdict: `PASS`
- Perf artifact:
  - `reports/l18/batches/20260307T230356Z-l18-nightly-24h/capstone_nightly_fixedcfg/r1/perf/perf_gate.json`
- Perf result:
  - `latency_p95`: Rust `1.286 ms`, Go `1.358 ms`, regression `-5.30%`
  - `rss_peak`: Rust `1616 KB`, Go `1760 KB`, regression `-8.18%`
  - `startup`: Rust `111.0 ms`, Go `111.0 ms`, regression `0.0%`
  - verdict: `PASS`

### 7) Phase 3 certify status

- Status:
  - no active `certify` evidence is currently retained in the local slimmed workspace
- Note:
  - initial launch `20260309T004601Z-l18-certify-7d` was discarded because prior nightly perf runtimes still occupied `11810/11811`
  - follow-up launch `20260309T004649Z-l18-certify-7d` did not produce a retained final conclusion before the workflow shifted to global static review

## Historical Evidence (2026-02-26)

### 1) Dual-kernel baseline (daily)

- Command: `scripts/l18/run_dual_kernel_cert.sh --profile daily`
- Run ID: `20260226T015945Z-daily-dc0b3935`
- Result: `PASS`
- Gate data:
  - `selected_case_count=5`
  - `run_fail_count=0`
  - `diff_fail_count=0`
- Artifacts:
  - `reports/l18/dual_kernel/20260226T015945Z-daily-dc0b3935/summary.json`
  - `reports/l18/dual_kernel/20260226T015945Z-daily-dc0b3935/diff_gate.json`

### 2) Daily capstone convergence with fixed config (3 rounds)

- Command:
  - `reports/l18/batches/20260225T134935Z-l18-daily-converge-v4/run_capstone_daily_v4.sh capstone_daily_convergence_v7_timeout120 3`
- Fixed config (same for all rounds):
  - `L18_GUI_TIMEOUT_SEC=120`
  - `L18_RUST_BUILD_ENABLED=0`
  - `L18_GUI_GO_BUILD_ENABLED=0`
  - `L18_GUI_RUST_BUILD_ENABLED=0`
  - prebuilt Rust parity binary: `target/release/run`
- Batch root:
  - `reports/l18/batches/20260225T134935Z-l18-daily-converge-v4/capstone_daily_convergence_v7_timeout120`
- Summary:
  - `reports/l18/batches/20260225T134935Z-l18-daily-converge-v4/capstone_daily_convergence_v7_timeout120/summary.tsv`

Round outcomes:

- `r1`: `overall=PASS`, `gui_smoke=PASS`, `dual_kernel_diff=PASS`, `perf_gate=PASS`, `docker=WARN`
  - dual run_id: `20260226T021330Z-daily-db9d17f6`
  - dual stats: `selected_case_count=5`, `run_fail_count=0`, `diff_fail_count=0`
- `r2`: `overall=PASS`, `gui_smoke=PASS`, `dual_kernel_diff=PASS`, `perf_gate=PASS`, `docker=WARN`
  - dual run_id: `20260226T022257Z-daily-a764c3c1`
  - dual stats: `selected_case_count=5`, `run_fail_count=0`, `diff_fail_count=0`
- `r3`: `overall=PASS`, `gui_smoke=PASS`, `dual_kernel_diff=PASS`, `perf_gate=PASS`, `docker=WARN`
  - dual run_id: `20260226T023217Z-daily-d4d10514`
  - dual stats: `selected_case_count=5`, `run_fail_count=0`, `diff_fail_count=0`

GUI contract observation:

- all three rounds: `go=/proxies=200`, `rust=/proxies=200`
- no recurrence of `gui_or_kernel_not_ready` in this batch

### 3) Short high-pressure rehearsal (30min, 48x composite) - 2026-02-27

- Command:
  - `scripts/l18/run_stress_short_48x.sh --duration-min 30 --gui-app /Users/bob/Desktop/Projects/ING/sing/singbox-rust/GUI_fork_source/GUI.for.SingBox-1.19.0/build/bin/GUI.for.SingBox.app --require-docker 0 --allow-existing-system-proxy 1 --allow-real-proxy-coexist 1`
- Batch root:
  - `reports/l18/batches/20260227T054642Z-l18-stress-48x`
- Result:
  - `overall=PASS`
  - `elapsed_sec=1203` (within 30 min budget)
  - `pressure_model.composite_multiplier=48`
  - stages: all `PASS` (`PREFLIGHT/GUI/ALL_CASES_RUST/SOAK_SHORT_WS/SOAK_SHORT_WS_DUAL_CORE/P2_ROUND_2/3/4/DUAL_NIGHTLY/PERF_3X`)
- Artifacts:
  - status: `reports/l18/batches/20260227T054642Z-l18-stress-48x/stress_short_48x/r1/stress_status.json`
  - summary: `reports/l18/batches/20260227T054642Z-l18-stress-48x/stress_short_48x/summary.tsv`
  - gui: `reports/l18/batches/20260227T054642Z-l18-stress-48x/stress_short_48x/r1/gui/gui_real_cert.json`
  - canary: `reports/l18/batches/20260227T054642Z-l18-stress-48x/stress_short_48x/r1/canary/canary_stress_30m.md`
  - dual: `reports/l18/batches/20260227T054642Z-l18-stress-48x/stress_short_48x/r1/dual_kernel/20260227T060009Z-nightly-7c1032bd/summary.json`
  - perf: `reports/l18/batches/20260227T054642Z-l18-stress-48x/stress_short_48x/r1/perf/perf_gate.json`
- Note:
  - this rehearsal is supportive evidence only, and does not replace required closure evidence:
    - one full `nightly` (24h canary) pass
    - one full `certify` (7d canary) pass

## Next Execution Plan (as of 2026-02-26)

### Plan Goal

Complete L18 closure with certify-grade evidence while keeping the current stable config unchanged.

### Fixed Config Baseline (do not drift)

- `L18_GUI_TIMEOUT_SEC=120`
- `L18_RUST_BUILD_ENABLED=0`
- `L18_GUI_GO_BUILD_ENABLED=0`
- `L18_GUI_RUST_BUILD_ENABLED=0`
- Rust binary: prebuilt parity `target/release/run`

### Implemented Enforcements

- Local runner script `scripts/l18/run_capstone_fixed_profile.sh` now performs:
  - batch/run directory isolation
  - `config.freeze.json` + `precheck.txt` emission
  - dedicated canary runtime bootstrap (`127.0.0.1:29090`)
  - fixed env lock (`L18_GUI_TIMEOUT_SEC=120`, `L18_RUST_BUILD_ENABLED=0`, `L18_GUI_GO_BUILD_ENABLED=0`, `L18_GUI_RUST_BUILD_ENABLED=0`)
- CI workflow `.github/workflows/l18-certification-macos.yml` now enforces:
  - prebuild parity runtime (`cargo build --release -p app --features parity --bin run`)
  - fixed env lock in capstone step (`L18_RUST_BUILD_ENABLED=0`, `L18_RUST_BIN=.../target/release/run`, GUI build disabled, timeout=120)

### Sequence

1. `2026-02-26`: freeze certify/nightly parameter set
   - align `daily/nightly/certify` to the same fixed config baseline
   - keep output paths isolated per run root
2. `2026-02-26` to `2026-02-27`: run one `nightly` preflight rehearsal (24h canary)
   - expected mandatory gates: `gui_smoke/canary/dual_kernel_diff/perf_gate` all PASS
3. after nightly PASS: run one `certify` cycle (7d canary)
   - this is the required L18 closure run
4. fallback path (conditional only)
   - if GUI flake reappears (`gui_or_kernel_not_ready` or `/proxies=000000`), strengthen `gui_real_cert` Rust readiness diagnostics:
     - ready polling trace timeline
     - port-occupancy snapshots on failure paths
5. closure and publication
   - update this report to closure state after certify PASS
   - sync status docs (`docs/STATUS.md`, `agents-only` state bus)
