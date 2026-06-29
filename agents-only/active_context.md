<!-- tier: S -->
# Active Context

> Purpose: high-frequency project navigation. S-tier: read every
> session.
> Discipline: keep only current-stage facts. This file must stay
> under 300 lines.
> **This file is the single source of truth for volatile state**
> (phase, parity-BHV, build/gate). Other docs point here, not copy.

---

## Resume (2026-06-29) - PX-ACCEPT-01 local drop-in release rehearsal

- **PX-ACCEPT-01 DONE locally**: `gui_runtime` built the real `target/debug/app` binary and
  `agents-only/px_accept_01_release_rehearsal_probe.sh` completed the local drop-in rehearsal
  from the GUI 1.25.1 composite fixture.
- **Verification PASS**: see `agents-only/px_accept_01_release_rehearsal.md`. Probe summary:
  31 PASS / 0 FAIL / 1 WARN (valid `/connections` snapshot; best-effort active slow request not
  observed). Focused P1313 subset, app build, and probe passed on the final code.
- **Local blockers fixed in-line**: DNS CLI nested-runtime panic, Clash `/configs` stale reload
  snapshot, and CacheFile mode persistence flush. Mode switching remains the existing
  `PATCH /configs` GUI/strict contract; `PUT /configs` stays Go-compatible no-op.
- **Scope note**: release rehearsal pass only, not new dual-kernel BHV/parity movement. No Wails
  desktop click automation, root TUN, Linux resolved, official REALITY JA4/ext-order/camouflage,
  public fresh-cohort gate, workflow automation, or `agents-only/a0_reality_spike/` touch is
  claimed.

## Previous Resume (2026-06-29) - GO parity matrix refresh

- **GO_PARITY refreshed**: `agents-only/reference/GO_PARITY_MATRIX.md` now leads with the
  current post-FABLE/post1313 PX calibration and keeps old closure accounting only as a
  historical appendix.
- **Scope note**: no new dual-kernel BHV movement, GUI-ready/drop-in-ready claim, code change,
  workflow automation, or `agents-only/a0_reality_spike/` touch is implied by this docs pass.

## Previous Resume (2026-06-29) - fable5 report triage and cleanup

- **Fable5 report triage complete**: the 8 top-level
  `agents-only/fable5审计报告/*.md` audit reports were reviewed and kept in place as
  B-tier historical calibration input, with a stage-summary extract in the fable5
  audit directory.
- **Use with caution**: fable5 is a 2026-06-10 pre-closeout snapshot at HEAD `02d8d16e`.
  It seeded the post-FABLE packages (GUI P0s, reload/liveness P1 cluster, docs/lint/test
  hygiene), but raw fable5 P0/P1 findings must not be quoted as current blockers without
  checking the post-FABLE package map, `agents-only/post1313/`, and this file.

- **Cleanup complete**: ignored local run artifacts were removed; MT-GUI evidence directories
  moved under `agents-only/archive/MT-GUI/`; root `重构package相关/` moved under
  `agents-only/archive/MT-AUDIT/restructure_package_related/`.
- **Scope note**: `agents-only/a0_reality_spike/` remains untouched; no `.github/workflows/*`
  automation was added or restored.

## Previous Resume (2026-06-28) - P1313-12 GUI 1.25.1 low-priority contract

- **P1313-12 DONE locally**: GUI 1.25.1 generated-config shape is refreshed with a composite
  route/DNS/system-proxy fixture, Clash HTTP Bearer and lazy WebSocket `?token=` contracts are
  pinned, and a local GUI-style process/log contract probe is available.
- **Post1313 strict revalidation PASS**: see
  `agents-only/post1313/p1313_strict_revalidation_2026_06_28.md`. The revalidation repaired
  reload-aware admin `/explain`, refreshed runtime-capable reload integration tests, and unboxed the
  two stale `/connections` WebSocket snapshot quarantines.
- **Verification PASS**: see `agents-only/post1313/p1313_12_gui1251_low_priority_contract.md`.
  Targeted GUI fixture/API/runtime probes, `cargo check -p app --features parity`,
  `cargo check --workspace --all-features`, `make boundaries`, and consistency validation passed.
- **Scope note**: no Wails/desktop automation was resumed, no GitHub workflow automation was
  added, and no dual-kernel parity movement is claimed.

## Strategic State

Phase: MT-REAL-02 stage-2 closed; public fresh-cohort = pre-release observation
(non-gating). Parity **52/56 BHV (92.9%) unchanged** — REALITY has no S3 BHV-ID, not in the
S1/S6 denominator. DEV-REALITY-01 = ARCH-LIMIT: local profile parity CLOSED, official-JA4 + camouflage OPEN.

## Current Build And Gate

- check/build/clippy (all-features,all-targets): **all PASS, 0 clippy warn**
  (lint relaxed 2026-06-03: warnings/dead_code deny→warn, safety kept deny).
- cargo check --workspace --all-features: **PASS**. strict check-boundaries.sh: **exit 0**.
- python3 unittest (reality_probe_tools / clienthello_family /
  dual_kernel_verification): **PASS**. trojan_integration: **20 PASS, 0 ignored**.

## T3 ClientHello Fingerprint Parity — T3-0…T3-2 DONE (2026-06-08)

- CLOSED (local): functional dataplane, normalized-profile parity, required field-set parity,
  coordinated GREASE structure, and local from-spec JA4 Go==Rust diagnostic.
- OPEN: official FoxIO-tool JA4 crosscheck, extension-order statistical parity,
  `HelloChrome_Auto` drift, tier-2 camouflage. NON-GOAL: L4 byte identity.
- A2.3 runtime status-JSON rehearsal DEFERRED. Detail: t32 governance; T3-1B `052d4392`.
- agents-only/a0_reality_spike/ stays pre-existing untracked (do not commit/delete).

## REALITY Acceptance (3-tier; golden_spec S4)

1. Local deterministic gate — `make verify-reality-local` (A1/A2 committed; A2.3 deferred).
2. External healthy-cohort observation — pre-release, NON-gating (tri-state; no single node
   is a closure identity; outage ≠ regression).
3. ClientHello fingerprint parity — tier-3: local profile parity CLOSED (see T3 section);
   official-JA4 + ext-order distribution + camouflage OPEN.

## Closed Tracks (compressed; detail in archive)

- **A4 projection** CLOSED through A4.4 (`a5b7a41f`+`b042a683`, 2026-06-06): route C canonical
  STRICT, projection TERMINAL; 34/34 projected, 0 promotable; deferred G1/G2/G3.
- **A2 REALITY-gate wiring** DONE (`71e51669`+`e44c67d3`, 2026-06-06): L18 REALITY_LOCAL gate
  after ORACLE; A2.3 runtime status-JSON DEFERRED.
- **MT-REAL-02 stage-2** closed (R45-R60): per-outbound rollup + planner --latest-* filters.
  History (fresh13 per-rep R73/R90/R91; fresh09 broken R85/R88): mt_real_02_baseline.md.

## Still-Valid Constraints

- Do not return to a static ClientHello template; do not hard-code precedence or
  position-to-mode behavior. (R12 seed-modes = stable sampler; R13 position coupling falsified.)
- Real node usability is not guaranteed; node outage is not sampler regression.
- The user pursues the highest goal, not maintenance-only posture; stage closure ≠ project closure.
- Any fresh-cohort live run must pass R81 subset-schema dry-run gate.
- closure scope is per-outbound + per-class; never extend A.1 to cohort-B group closure
  without the required same-class chain.
- A broken closure chain cannot be patched; restart needs a fresh consecutive sequence.
  A single-node recheck of a broken rep only opens a new chain at round 1.
- Rotated-replacement per-rep closure is not original-cohort closure.
- Public-node (cohort C / fresh09) closure = external-healthy-cohort observation, not a merge
  gate; no single node mandatory; merge-precheck = local gate only.
- Retired non-goal: original cohort-C closure (was bound to fresh09).

## Historical Detail

- R33-R60 + early ClientHello/Vision/REALITY: `mt_real_02_baseline.md`; L01-L25: `archive/L*/`; closed MT-* tracks: `archive/MT-*/`; golden spec: `labs/interop-lab/docs/dual_kernel_golden_spec.md`.
