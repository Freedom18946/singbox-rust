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

T3 ClientHello parity: T3-1B harness (`052d4392`) + T3-1C per-ClientHello GREASE selector
(`6f8ae63a`, independent OsRng) committed; next T3-2 golden_spec governance. REALITY local
gate (A1/A2) + L18 wiring done; A4 projection CLOSED (A4.4). Public fresh-cohort = non-gating.

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

## T3 ClientHello Fingerprint Parity — T3-0/T3-1A/T3-1B/T3-1C DONE (2026-06-07)

- Rust is NOT naive rustls — patched-rustls Chrome shaping: static fields + from-spec JA4
  (`t13d1516h2_…`) + normalized digest match Go==Rust. No uTLS-equivalent port.
- T3-1B harness `labs/interop-lab/reality_clienthello_parity/` (`052d4392`): blocking =
  token-match + normalized-profile + field-set parity + redaction guard; advisory diagnostics.
- T3-1C (`6f8ae63a`): coordinated per-ClientHello GREASE selector — INDEPENDENT OsRng per slot
  (NOT the ext-order seed; T3-1C.1 audit: seed-derive collapsed to 16 affine profiles).
  groups==key_share + ext_head!=ext_tail enforced; harness blocking PASS; GREASE FIXED→RANDOMIZED.
- OPEN: official FoxIO JA4 PENDING; ext-order distribution + tier-2 camouflage OPEN. Next: T3-2
  golden_spec S4 governance update (no golden_spec edit yet).
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
