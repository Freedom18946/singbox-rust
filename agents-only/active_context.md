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

- R66 BHV-SV-005/006/007 (DIV-H-005) parity-promotion audit COMPLETED
  (2026-05-04). Decision: **Class C — Go structural divergence**. Rust
  honest: provider routes wired to `provider_manager` (handlers.rs:
  1136-1264); `cargo test -p sb-api --test clash_http_e2e --
  test_get_proxy_providers_with_data test_get_rule_providers_with_data
  test_healthcheck_proxy_provider_with_data` → 3/3 PASS. Go fork
  (`experimental/clashapi/{provider,ruleprovider}.go`): hard-coded
  stubs (proxy `{providers: {}}` object, rule `{providers: []}` array
  — shape divergence); `findProviderByName` / `findRuleProviderByName`
  always 404 with `tunnel.{Proxy,Rule}Providers()` commented out;
  per-name actions all `render.NoContent` with bodies commented out;
  Go GET vs Rust POST on healthcheck. DIV-H-005,
  mt_gui_04_{capability_inventory,gap_list} updated. BHV unchanged
  (52/56). go_fork_source untouched.
- R65 BHV-LC-003 (DIV-H-006) audit (commit 833753dc, 2026-05-04):
  Class C — Rust honest broken-service fixture + live `/services/health`;
  Go fork has no route, no `ServiceStatus`, fail-fast `Manager.Start`.
- v2 validator inbound field-lowering sweep
  (vmess/vless/trojan/anytls/shadowtls/naive) remains B-tier deferred.
- resolved-error-propagation still on case_backlog.md as B-tier.

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
