<!-- tier: S -->
# Active Context

> Purpose: high-frequency project navigation. S-tier: read every
> session.
> Discipline: keep only current-stage facts. This file must stay
> under 100 lines.

---

## Strategic State

Phase: MT-REAL-02 stage-2 closed (R45-R60); stage-3 path A active
on demand, gated by fresh sample intake. Parity 52/56 BHV (92.9%);
ARCH-LIMIT-REALITY label.

## MT-REAL-02 Stage-2 Closure Summary

Five latest non-all_ok candidates were falsified as noise. Full record
in `agents-only/archive/mt_real_02/round_45_60_evidence_framework.md`;
closure rationale + stage-3 paths in `archive/mt_real_02/closure_report.md`.

## Evidence Framework Capability

Per outbound: latest_health, latest_run_health_counts,
latest_divergence_phase_counts, latest_divergence_phase_dominance,
latest_divergence_run_ratio, is_bi_modal, dominant_phase_history,
is_phase_shifting.

Top level: latest_*_outbounds plus latest_phase_dominant_outbounds,
latest_phase_no_dominance_outbounds, latest_bi_modal_outbounds,
latest_phase_shifting_outbounds.

Planner filters: --latest-health, --latest-run-health,
--only-latest-run-health, --latest-phase-dominance, --latest-bi-modal,
--latest-phase-shifting.

## Current Build And Gate

- cargo check --workspace: PASS
- python3 -B -m unittest test_reality_probe_tools
  test_reality_clienthello_family test_dual_kernel_verification:
  **123 tests PASS** (Trojan structured-bridge refinement included).
- live_rollup.json/md unchanged: 18 rounds, 113 runs, 24 all_ok.

## Next Steps

- MT-TROJAN-FRESH-09 structured bridge-probe class refinement DONE
  (2026-05-07). Classification: **A — runner now emits a refined
  `bridge_diagnostic` and never surfaces `other` from a structured
  `bridge_probe` failure**. No live probe was authorized or run; only
  the runner's classifier was enriched. FRESH-08 evidence inspection
  showed structured bridge diagnostic was under-instrumented:
  `bridge_probe.error` / `bridge_probe.raw_connect_error` were never
  copied into evidence and the 180-char scrubbed stderr excerpt
  truncated before the actual `connect_io` failure text, so the real
  reason behind FRESH-08's `class=other` is not recoverable from
  preserved evidence. `scripts/tools/trojan_probe_live.py` now writes
  redacted `bridge_diagnostic` (`error_kind`, `error_sha256_12`,
  `raw_connect_error_sha256_12`, `scrubbed_excerpt`) for every
  structured failure, with scrubbing driven by the actual candidate
  config's server/password/TLS server_name set. The refined class set
  is `dns_error`, `network_unreachable`, `handshake_eof`, `tls_error`,
  `auth_failed`, `connection_refused`, `connection_reset`, `timeout`,
  `unexpected_response`, `unsupported_protocol`, and the explicit
  `unknown_probe_failure` fallback — `other` is no longer surfaced.
  Future live work still requires a new explicit authorization. Rust-
  only quality line; BHV 52/56 unchanged.
- MT-TROJAN-FRESH-08 normalized bounded live sanity DONE
  (2026-05-07). Classification A — first round with structured
  `bridge_probe` live signal (`probe_error=5`, `class_counts=other=5`,
  `node_contact_confirmed=true`); FRESH-09 then explained the `other`
  is connect/connect_io chain not yet preserved in evidence. Detail in
  `agents-only/mt_trojan_fresh_sample_intake.md`.
- R71 fresh sample intake gate DONE (2026-05-04). Classification:
  **A — intake gate ready, waiting for fresh config**. Operator guide:
  `agents-only/mt_real_02_fresh_sample_intake.md` (A-tier).
- R67-R70 HK closure + rollup audit detail archived; HK-A-BGP-2.0 off
  bi-modal/phase-shifting suspect list, fresh-signal gate verdict
  carried into R71. See archive for context.

## Still-Valid Constraints

- Do not return to a static ClientHello template.
- Do not hard-code precedence.
- Do not hard-code position-to-mode behavior.
- Round 12 seed-selected signature modes remain the stable sampler.
- Round 13 position hard coupling is falsified.
- Real node usability is not guaranteed; node outage is not sampler
  regression.
- The user pursues the highest goal, not a maintenance-only posture.
- MT-REAL-02 stage closure is not project closure.

## Historical Detail

- R33-R60 full record + early ClientHello/Vision/REALITY history:
  agents-only/mt_real_02_baseline.md
- L01-L25 project history: agents-only/archive/L*/
- Dual-kernel golden spec:
  labs/interop-lab/docs/dual_kernel_golden_spec.md
