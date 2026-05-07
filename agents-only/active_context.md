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
`archive/mt_real_02/round_45_60_evidence_framework.md`; closure +
stage-3 paths in `archive/mt_real_02/closure_report.md`.

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
  **142 tests PASS**.
- cargo test -p sb-adapters --features adapter-trojan --test
  trojan_integration: **17 PASS, 2 ignored**.
- live_rollup.json/md unchanged: 18 rounds, 113 runs, 24 all_ok.

## Next Steps

- MT-MIXED-FRESH-01 mixed fresh config intake + protocol split DONE
  (2026-05-07). A — no-live; redacted intake only. Candidate has
  32 outbounds (20 vless + 12 hys2). Three-line split: REALITY/VLESS
  (15, fresh_ready=15, ready_for_r73=true), VLESS+WS+TLS (5, audit
  only), Hysteria2 (12, ready=12, no live tool). WS audit: path +
  Host header plumbed; `max_early_data` and `early_data_header_name`
  silently dropped (5/5 nodes set 2048, effective loss to 0; header
  name length matches hardcoded default so no functional loss there).
  No xhttp/httpupgrade/grpc in batch. Dry-run plan only; no socket
  opened to any candidate. /tmp configs not committed. Doc:
  `agents-only/mt_mixed_fresh_intake.md`. Evidence:
  `agents-only/mt_mixed_fresh_evidence/`. BHV 52/56 unchanged.
- MT-TROJAN-FRESH-15 success-evidence cosmetic + line closure DONE
  (2026-05-07). MT-TROJAN-FRESH-14 post-TLS-fix bounded Trojan live
  reprobe DONE (2026-05-07): 5/5 ok, response_bytes 832-836, HTTP
  200 to example.com:80. MT-TROJAN-FRESH-13 root cause audit DONE
  (2026-05-07): `validator/v2/outbound.rs:872-877` dropped
  `tls.insecure`, fixed via fallback chain; Trojan SNI fallback uses
  `parse_server_endpoint`; 8 TLS subclasses added to runner.
  MT-TROJAN-FRESH-11/-12 hostname dataplane fix + first post-fix
  live DONE (2026-05-07). MT-TROJAN-FRESH line CLOSED.
- R71 fresh sample intake DONE (2026-05-04) A; R67-R70 HK closure
  archived.

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

- R33-R60 + early ClientHello/Vision/REALITY:
  agents-only/mt_real_02_baseline.md
- L01-L25: agents-only/archive/L*/
- Dual-kernel golden spec:
  labs/interop-lab/docs/dual_kernel_golden_spec.md
