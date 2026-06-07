<!-- tier: S -->
# Active Context

> Purpose: high-frequency project navigation. S-tier: read every
> session.
> Discipline: keep only current-stage facts. This file must stay
> under 100 lines.
> **This file is the single source of truth for volatile state**
> (phase, parity-BHV, build/gate). Other docs point here, not copy.

---

## Resume (2026-06-07)

T3 ClientHello-parity harness committed (T3-1B, `052d4392`); T3-1C coordinated GREASE
selector next. REALITY local gate (A1/A2) + L18 wiring done; A4 projection CLOSED (A4.4).
Public fresh-cohort = external healthy-cohort observation (pre-release, non-gating).

## Strategic State

Phase: MT-REAL-02 stage-2 closed (R45-R60); public fresh-cohort rounds
are now pre-release observation (non-gating). Parity 52/56 BHV (92.9%)
unchanged. DEV-REALITY-01 = ARCH-LIMIT (residual): local client parity
validated, ClientHello fingerprint parity open (golden_spec S4).

## MT-REAL-02 Stage-2 + Evidence Framework

Stage-2 closed (5 non-all_ok falsified as noise); per-outbound rollup + planner
--latest-* filters. Detail: archive/mt_real_02/, live_rollup.json, mt_real_02_baseline.md.

## Current Build And Gate

- check/build/clippy (all-features,all-targets): **all PASS, 0 clippy warn**
  (lint relaxed 2026-06-03: warnings/dead_code deny→warn, safety kept deny).
- python3 unittest (reality_probe_tools / clienthello_family /
  dual_kernel_verification): **PASS**. trojan_integration: **17 PASS, 2 ign**.

## REALITY Acceptance (3-tier; golden_spec S4)

1. Local deterministic gate — opt-in merge-precheck
   `make verify-reality-local` (A1/A2 committed).
2. External healthy-cohort observation — pre-release, NON-gating (MT-REAL-02
   fresh-cohort; tri-state; no single node is a closure identity; outage ≠ regression).
3. ClientHello fingerprint parity — see T3 track (normalized + from-spec-JA4 parity;
   official-JA4 + GREASE randomization OPEN).

Retired non-goal: original cohort-C closure (was bound to fresh09).
History (mt_real_02_baseline.md): fresh13 per-rep closure R73+R90+R91;
fresh09 steady-state broken R85/R88.

## A4 Projection Track — CLOSED through A4.4 (2026-06-06)

- A4.1/A4.2A/A4.3 (route C, `a5b7a41f`) + A4.4 contract (`b042a683`) DONE. Inventory 34/34
  projected, 0 promotable, 31 PARTIAL, 3 UNSUPPORTED, candidate null. Route C: canonical
  STRICT; projection TERMINAL (universal-four + R80/82/83/84⊥R85-91); deferred G1/G2/G3.

## A2 REALITY-Gate Wiring — DONE (2026-06-06)

- A2.1 `c46fb60f` + A2.2 `71e51669` + checkpoint `e44c67d3`: L18 REALITY_LOCAL gate in
  l18_capstone.sh after ORACLE (go/cargo/python3/curl/make + lsof-independent 5-port
  preflight; no exit-77; single-instance). A2.3 runtime status-JSON DEFERRED. Detail: a22.

## T3 ClientHello Fingerprint Parity — T3-0/T3-1A/T3-1B DONE (2026-06-07)

- Rust is NOT naive rustls — patched-rustls Chrome shaping (handshake.rs, FIX-04/05): static
  fields + from-spec JA4 (`t13d1516h2_…`) + normalized digest match Go==Rust. No uTLS /
  uTLS-equivalent port. (t30/t31a/t31b reports + sanitized summaries.)
- T3-1B committed local harness `labs/interop-lab/reality_clienthello_parity/` (`052d4392`).
  Blocking: token-match, normalized-profile + required field-set parity, redaction guard.
  Advisory: from-spec JA4 (PENDING FoxIO; NOT official-JA4), GREASE entropy, ext-order, drift.
- GREASE: Go randomizes ALL slots/hello (invariants groups==key_share; 2 distinct ext-type);
  Rust pins values (advisory FIXED) → cipher-only INSUFFICIENT. T3-1C next: coordinated
  per-ClientHello GREASE selector (golden_spec amend deferred T3-2). L4 not a goal.
- agents-only/a0_reality_spike/ stays pre-existing untracked; do not commit/delete.

## Still-Valid Constraints

- Do not return to a static ClientHello template.
- Do not hard-code precedence or position-to-mode behavior.
- Round 12 seed-selected modes = stable sampler; Round 13 position coupling falsified.
- Real node usability is not guaranteed; node outage is not sampler
  regression.
- The user pursues the highest goal, not maintenance-only posture.
- MT-REAL-02 stage closure is not project closure.
- Any fresh-cohort live run must pass R81 subset-schema dry-run gate.
- closure scope is per-outbound + per-class; never extend A.1 to
  cohort-B group closure without the required same-class chain.
- A broken closure chain cannot be patched; restart needs a fresh
  consecutive sequence.
- Rotated-replacement per-rep closure is not original-cohort closure.
- Public-node (cohort C / fresh09) closure = external-healthy-cohort observation,
  not a merge gate; no single node mandatory; merge-precheck = local gate only.
- A single-node recheck of a broken rep is not a closure attempt;
  even a hypothetical clean recheck only opens a new chain at round 1.

## Historical Detail

- R33-R60 + early ClientHello/Vision/REALITY: `mt_real_02_baseline.md`.
  L01-L25: `archive/L*/`. Closed MT-* tracks: `archive/MT-*/`.
  Golden spec: `labs/interop-lab/docs/dual_kernel_golden_spec.md`.
