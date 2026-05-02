<!-- tier: S -->
# Active Context

> Purpose: high-frequency project navigation. S-tier: read every
> session.
> Discipline: keep only current-stage facts. This file must stay
> under 100 lines.

---

## Strategic State

Current phase: MT-REAL-02 stage-2 evidence-driven loop is closed
through R45-R60.

Parity: 52/56 BHV (92.9%); ARCH-LIMIT-REALITY remains the accounting
label.

Current focus: stage-3 path selection. R62 framework abstraction is
closed; next is the R63 dual-kernel gap. Stage-3 Path A (expand sample
face) is on demand only.

## MT-REAL-02 Stage-2 Closure Summary

Five latest non-all_ok candidates were falsified as noise by tooling
and live evidence:

- Node-level dead buckets: JP-A-BGP-0.3, JP-A-BGP-1.0,
  UK-A-BGP-0.5, US-A-BGP-0.5.
- Bi-modal plus phase-shifting noise: HK-A-BGP-2.0.
- Recovered: TW-A-BGP-1.0, US-A-BGP-0.8.
- Latest all_ok baseline: 16 outbounds.

Evidence evolution and falsified hypotheses:
`agents-only/archive/mt_real_02/round_45_60_evidence_framework.md`

Stage-2 closure rationale and stage-3 options:
`agents-only/archive/mt_real_02/closure_report.md`

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
- python3 -B -m unittest scripts/tools/test_reality_probe_tools.py
  scripts/tools/test_reality_clienthello_family.py: 47 tests PASS
- live_rollup.json/md reflects 13 rounds, 90 executed runs, 21 all_ok
  runs.

## Next Steps

- v2 validator fixes (4553af1e + this commit): inbound type dispatch
  (fix-1 added shadowsocks/hysteria/hysteria2/tuic explicit arms) and
  shadowsocks field lowering (fix-2 wires method/password from JSON to
  IR). Cluster gap still open: vmess/vless/trojan/anytls/shadowtls/
  naive inbounds also have hardcoded-None fields - deferred to future
  v2-validator-completeness sweep WP.
- R68' (5e6aea0b) + R69 (677eafd6): pushed pre-validator-approval;
  retro-verified per RETRO-v3 + R68'-AUDIT. R68' deduplicated bilingual
  managers.rs docs (84 CJK lines paired with pre-existing English;
  semantics preserved, A3 spot-check 3/3). R69 added 2 e2e cases vs
  spec 1 (re-baselined clash_http_e2e to 49).
- Pre-existing baseline drifts (out of LC-003 scope, queued separate):
  sb-tls clippy V3.b @c9499a39; make boundaries 5 assert fails (V6);
  inbound.rs 8 CJK doc lines.
- LC-003 DAG: A/B/C done. Next: Sub-WP D RESUME-r2 (stash@{0}).

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

- R33-R60 full record: agents-only/mt_real_02_baseline.md
- Early ClientHello, Vision, and REALITY history:
  agents-only/mt_real_02_baseline.md
- L01-L25 project history: agents-only/archive/L*/
- Dual-kernel golden spec:
  labs/interop-lab/docs/dual_kernel_golden_spec.md
