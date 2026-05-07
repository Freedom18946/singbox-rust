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
  **137 tests PASS**.
- cargo test -p sb-adapters --features adapter-trojan --test
  trojan_integration: **17 PASS, 2 ignored**.
- live_rollup.json/md unchanged: 18 rounds, 113 runs, 24 all_ok.

## Next Steps

- MT-TROJAN-FRESH-13 Trojan TLS handshake no-live root cause audit
  DONE (2026-05-07). Classification **A — root cause located; two
  no-live dataplane / tooling fixes**. FRESH-12 evidence reread:
  identical TLS error fingerprint across 5 runs / 2 servers / 5 ports
  (not per-endpoint). Lowering audit found
  `crates/sb-config/src/validator/v2/outbound.rs:872-877` accepted
  `tls.skip_cert_verify` and `tls.allow_insecure` but **dropped**
  sing-box's canonical `tls.insecure`; all 90 candidates set
  `tls.insecure=true` so every TLS handshake hit `webpki-roots`
  verification. Fixed by adding `tls.insecure` to the fallback chain.
  Trojan SNI fallback rewritten to use `parse_server_endpoint`.
  `trojan_probe_live.py` adds eight TLS subclasses
  (`tls_cert_unknown_issuer`, `tls_name_mismatch`, `tls_cert_expired`,
  `tls_invalid_dns_name`, `tls_alert`, `tls_protocol_version`,
  `tls_handshake_failure`, `tls_error` fallback). New no-live tests:
  3 sb-config lowering regressions, 5 SNI fallback unit tests, 11
  Python TLS subclass tests, 2 localhost TLS loopback integration
  tests proving `skip_cert_verify` toggle works end-to-end. Future
  authorized live reprobe justified to confirm fix.
- MT-TROJAN-FRESH-12 post-fix bounded Trojan live reprobe DONE
  (2026-05-07). Classification A — `class_counts=tls_error=5`,
  `connect_time_ms` 142–1245ms confirms real DNS+TCP. FRESH-13
  identified the lowering bug behind the TLS error.
- MT-TROJAN-FRESH-11 Trojan hostname server dataplane fix DONE
  (2026-05-07). `parse_server_endpoint` accepts `domain:port` /
  `IPv4:port` / `[IPv6]:port`; TCP `dial()` defers DNS to transport;
  `udp_relay_dial` uses `tokio::net::lookup_host`.
- MT-TROJAN-FRESH-09 structured bridge-probe class refinement
  (2026-05-07). Redacted `bridge_diagnostic`; literal `other` gone.
- R71 fresh sample intake gate DONE (2026-05-04). Classification A.
- R67-R70 HK closure archived; HK-A-BGP-2.0 off bi-modal suspect.

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
