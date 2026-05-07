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
  **126 tests PASS**.
- cargo test -p sb-adapters --features adapter-trojan --test
  trojan_integration: **15 PASS, 2 ignored**.
- live_rollup.json/md unchanged: 18 rounds, 113 runs, 24 all_ok.

## Next Steps

- MT-TROJAN-FRESH-12 post-fix bounded Trojan live reprobe DONE
  (2026-05-07). Classification **A — post-fix actionable live signal,
  no `invalid_server_address`**. Same bounded plan; pre-gate 5/5
  validate-only passed `no_network=true`. Live: `executed_runs=5`,
  `failed_count=5`, `tool_error_count=0`, `env_limited_count=0`,
  `class_counts=tls_error=5`, `node_contact_confirmed=true`.
  `connect_time_ms` 142–1245ms (vs 0–2ms pre-fix), confirming real
  DNS+TCP. `bridge_diagnostic.scrubbed_excerpt` shows `trojan dial
  failed: Other error: TLS handshake ...` — failure moved downstream
  to `perform_standard_tls_handshake`. Detail in
  `agents-only/mt_trojan_fresh_sample_intake.md`. Next live not
  needed on same plan/dataplane (deterministic).
- MT-TROJAN-FRESH-11 Trojan hostname server dataplane fix DONE
  (2026-05-07). Classification A — Rust dataplane blocker fixed.
  `parse_server_endpoint` in `crates/sb-adapters/src/outbound/
  trojan.rs` accepts `domain:port` / `IPv4:port` / `[IPv6]:port`. TCP
  `dial()` defers DNS to the transport layer; `udp_relay_dial` uses
  `tokio::net::lookup_host` with explicit `Network` error (UDP IPv6
  / round-robin pre-existing). `trojan_probe_live.py` classifier
  promotes `invalid_server_address` to top priority.
- MT-TROJAN-FRESH-09 structured bridge-probe class refinement
  (2026-05-07). Runner emits redacted `bridge_diagnostic`; no
  literal `other`. Classes (FRESH-11 priority):
  invalid_server_address, dns_error, network_unreachable,
  handshake_eof, tls_error, auth_failed, connection_refused,
  connection_reset, timeout, unexpected_response,
  unsupported_protocol, unknown_probe_failure.
- R71 fresh sample intake gate DONE (2026-05-04). Classification A.
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

- R33-R60 + early ClientHello/Vision/REALITY:
  agents-only/mt_real_02_baseline.md
- L01-L25: agents-only/archive/L*/
- Dual-kernel golden spec:
  labs/interop-lab/docs/dual_kernel_golden_spec.md
