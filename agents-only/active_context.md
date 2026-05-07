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

- MT-TROJAN-FRESH-15 success-evidence cosmetic + line closure DONE
  (2026-05-07). Classification **A — no-live; cosmetic fix + closure**.
  `trojan_probe_live.py` now sets `bridge_diagnostic=None` and emits
  no `error_kind` when `bridge_probe.ok=true`; redacted MD on success
  no longer renders `bridge_error_kind`/`bridge_fingerprint`/
  `bridge_excerpt`. Failure-path refined diagnostics
  (FRESH-09/-11/-13) preserved. +5 Python tests pin success hygiene
  + secret scrub + failure regression. MT-TROJAN-FRESH line CLOSED:
  same bounded plan reaches 5/5 ok end-to-end through FRESH-13 fix;
  no further live needed against this plan/dataplane. New live only
  under separate authorization for distinct work (UDP relay, ALPN,
  non-CONNECT targets, new sample).
- MT-TROJAN-FRESH-14 post-TLS-fix bounded Trojan live reprobe DONE
  (2026-05-07). A — TLS failure cleared; full end-to-end Trojan
  tunnel success. Pre-gate 5/5 no_network, plan identity confirmed.
  Live: executed_runs=5, ok_count=5, status_counts={ok:5},
  class_counts={}, node_contact_confirmed=true. Per-run
  connect_time_ms 159/241/264/523/567ms, response_bytes 832-836,
  HTTP/1.1 200 OK x5 to example.com:80. FRESH-12 `tls_error=5`
  cleared by FRESH-13 lowering fix.
- MT-TROJAN-FRESH-13 root cause audit DONE (2026-05-07). Lowering
  bug at `validator/v2/outbound.rs:872-877` dropped sing-box
  canonical `tls.insecure`; fixed via fallback chain. Trojan SNI
  fallback uses `parse_server_endpoint`. Eight TLS subclasses
  added to runner. FRESH-14 confirms fix.
- MT-TROJAN-FRESH-11/-12 hostname dataplane fix + first post-fix
  live DONE (2026-05-07). `parse_server_endpoint` + DNS deferred
  to transport; FRESH-12 surfaced TLS-handshake failure; FRESH-13
  traced root cause; FRESH-14 confirmed; FRESH-15 closed line.
- R71 fresh sample intake DONE (2026-05-04) A; R67-R70 HK closure
  archived; HK-A-BGP-2.0 off bi-modal suspect.

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
