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
and live evidence. Latest all_ok baseline: 16 outbounds. Full evidence
evolution and falsified hypotheses live in
`agents-only/archive/mt_real_02/round_45_60_evidence_framework.md`.
Stage-2 closure rationale and stage-3 options:
`agents-only/archive/mt_real_02/closure_report.md`.

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

- v2 validator fixes (4553af1e + 6e5c1a85 + this commit): inbound
  type dispatch (fix-1 added shadowsocks/hysteria/hysteria2/tuic
  arms), shadowsocks field lowering (fix-2 wires method/password
  from JSON to IR), and inbound tag lowering (fix-3 reads "tag"
  || "name" so post-migration JSON populates IR.tag). Cluster gap
  still open: vmess/vless/trojan/anytls/shadowtls/naive inbounds
  also have hardcoded-None fields - deferred to future
  v2-validator-completeness sweep WP.
- WP fix-managed-ssm-server-tag (this commit): root cause = V per
  audit -- compat::migrate_to_v2 renames inbound tag->name, but
  lower_inbounds read only "tag" so IR.tag was always None for any
  config flowing through migrate_to_v2. Fix reads "tag" then "name"
  fallback. Trace verification confirms register tag now matches
  configured "ss-in"; ssmapi services now resolve and bind. Unblocks
  LC-003 Sub-WP D ε retry.
- resolved-error-propagation filed in case_backlog.md as B-tier known
  issue (spawn-Ok start() pattern silently swallows bind failures).
- LC-003 DAG: A/B/C done. Sub-WP D RESUME-r2 6 files in stash@{0},
  ε retry now unblocked.

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
