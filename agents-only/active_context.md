<!-- tier: S -->
# Active Context

> Purpose: high-frequency project navigation. S-tier: read every
> session.
> Discipline: keep only current-stage facts. This file must stay
> under 100 lines.

---

## Strategic State

Phase: MT-REAL-02 stage-2 closed (R45-R60); stage-3 path A active on
demand, gated by fresh sample intake. Parity 52/56 BHV (92.9%);
ARCH-LIMIT-REALITY label.

## MT-REAL-02 Stage-2 Closure Summary

Five latest non-all_ok candidates falsified as noise. Full record in
`agents-only/archive/mt_real_02/round_45_60_evidence_framework.md`;
closure rationale + stage-3 paths in
`archive/mt_real_02/closure_report.md`.

## Evidence Framework Capability

Per outbound: latest_health, latest_run_health_counts,
latest_divergence_phase_counts, latest_divergence_phase_dominance,
latest_divergence_run_ratio, is_bi_modal, dominant_phase_history,
is_phase_shifting. Top level adds latest_*_outbounds (phase_dominant,
phase_no_dominance, bi_modal, phase_shifting). Planner filters:
--latest-health, --latest-run-health, --only-latest-run-health,
--latest-phase-dominance, --latest-bi-modal, --latest-phase-shifting.

## Current Build And Gate

- cargo check --workspace: PASS
- python3 -B -m unittest test_reality_probe_tools
  test_reality_clienthello_family test_dual_kernel_verification:
  **123 tests PASS**.
- live_rollup.json/md unchanged: 18 rounds, 113 runs, 24 all_ok.

## Next Steps

- MT-TROJAN-FRESH-10 refined bounded Trojan live reprobe DONE
  (2026-05-07). Classification **A — refined actionable live signal,
  no `tool_error`, no literal `other`**. Pre-gate: 5/5 validate-only
  passed, `no_network=true`. Live: same bounded plan,
  `executed_runs=5`, `failed_count=5`, `tool_error_count=0`,
  `class_counts=unsupported_protocol=5`, `node_contact_confirmed=true`.
  `bridge_diagnostic` exposes connect_io text `trojan dial failed:
  Other error: Invalid server address: invalid socket address syntax`
  — Rust dataplane blocker at `crates/sb-adapters/src/outbound/
  trojan.rs:363` calling `config.server.parse::<SocketAddr>()` on the
  `hostname:port` string from `register.rs:1007`. Recorded only;
  dataplane not modified per task scope. The label
  `unsupported_protocol` is the FRESH-09 refinement falling through
  to lowest-priority wrapper-rejection signal — table lacks an
  `Invalid server address` pattern. Next live not needed on same
  plan/dataplane (deterministic). Detail in
  `agents-only/mt_trojan_fresh_sample_intake.md`.
- MT-TROJAN-FRESH-09 structured bridge-probe class refinement DONE
  (2026-05-07). Classification A — runner emits redacted
  `bridge_diagnostic`; literal `other` is no longer surfaced. Refined
  classes: dns_error, network_unreachable, handshake_eof, tls_error,
  auth_failed, connection_refused, connection_reset, timeout,
  unexpected_response, unsupported_protocol, unknown_probe_failure.
- MT-TROJAN-FRESH-08 normalized bounded live sanity DONE
  (2026-05-07). Classification A — first structured `bridge_probe`
  live signal (`other=5`); FRESH-09 enriched diagnostics; FRESH-10
  identified the `Invalid server address` dataplane blocker.
- R71 fresh sample intake gate DONE (2026-05-04). Classification A —
  intake gate ready. Operator guide:
  `agents-only/mt_real_02_fresh_sample_intake.md` (A-tier).
- R67-R70 HK closure + rollup audit archived; HK-A-BGP-2.0 off
  bi-modal/phase-shifting suspect list.

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

- R33-R60 + early ClientHello/Vision/REALITY history:
  agents-only/mt_real_02_baseline.md
- L01-L25 project history: agents-only/archive/L*/
- Dual-kernel golden spec:
  labs/interop-lab/docs/dual_kernel_golden_spec.md
