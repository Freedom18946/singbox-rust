<!-- tier: S -->
# Active Context

> Purpose: high-frequency project navigation. S-tier: read every
> session.
> Discipline: keep only current-stage facts. This file must stay
> under 300 lines.
> **This file is the single source of truth for volatile state**
> (phase, parity-BHV, build/gate). Other docs point here, not copy.

---

## Resume (2026-07-07) - agents-only doc compression + maintenance automation

- **agents-only top level compressed**: boxed MT-REAL-02 docs (baseline long report, 3 fresh
  intakes, a41/a42 spikes, mt_mixed_fresh_evidence) moved via `git mv` into
  `archive/mt_real_02/`; workflow notes moved to `memory/workflow_notes.md`. All repo references updated
  (incl. `trojan.rs` comment, golden spec, AGENTS.md). Nothing deleted.
- **NOT moved (hard constraints)**: `mt_real_01_evidence/` + `mt_real_02_evidence/` (paths
  hard-coded in `scripts/tools/*.py` regression tests); `fable5审计报告/` (2026-06-29 disposition:
  stays put, anchored by root README / docs / capabilities generator); `mig03/`, `post1313/` (active).
- **Maintenance automation upgraded**: `06-scripts/verify-consistency.sh` now enforces S-tier
  line caps (active_context ≤300, workpackage ≤120) and a top-level file whitelist as hard
  failures, plus stale-Resume / oversized-log advisories. `log.md` pre-2026-06 bulk rolled into
  `archive/logs/`.
- **Scope note**: documentation/process hygiene only. No code, parity/BHV, gate, or packaging
  movement is claimed.

## Resume (2026-07-06) - MIG-03 architecture de-dup migration PLANNED

- **MIG-03 planning complete, no code changed**: `agents-only/mig03/` now holds the full
  planning set (README index + overview + WP01-WP14, all `Status: PLANNED`) for the in-repo
  strangler-fig migration: trait unification, scaffold retirement, router-stack merge,
  control-plane/env convergence, feature slimming. User rejected the new-repo rewrite path.
- Baseline metrics snapshot lives in `mig03/mig03_00_overview.md` §1/§6 (sb-core 108k LOC /
  103 features / 161 SB_* env vars; register.rs 4,264 lines; ≥6 OutboundConnector defs).
- All optional technical choices pre-decided by user delegation (2026-07-06): see
  `mig03/mig03_01_decisions.md` D1-D18; user gates removed from packages (only D18 escalation
  remains). Entry points ready to claim: WP01 + WP04 (both doc-only); lane rules in README.
- **Scope note**: planning artifacts only. No behavior, parity/BHV, gate, or packaging
  movement is claimed.

## Resume (2026-07-03) - app helper-CLI audit cleanup batch (15 rounds, all DONE locally)

- **One batch, one pattern**: 15 consecutive audit-cleanup rounds hardened the `app` helper
  CLIs — every round replaced panic paths (`unwrap`/`expect`/nested `block_on`) or silent
  failure paths with structured errors, tightened the input/output contract, added focused
  unit + real-binary integration tests, and passed the same verification set (app fmt, focused
  tests, all-target/all-feature check, strict clippy, CLI smoke, `git diff --check`).
- **Covered surfaces**: `metrics-serve` (bind-before-READY), `merge` (inline-resource read
  errors, abort-before-write), `sb-bench` (invalid env targets; `SB_BENCH_PAR=0` fallback; CSV
  write errors), `bench io` (zero requests/concurrency; HTTP method validation), `coverage-http`
  (invalid `SB_COV_ADDR` non-zero exit), `prom` (async handlers off nested runtime; `--filter`
  regex validation), `tools synctime` (pre-UNIX clock), `sb-handshake slice` (fallible JSONL
  writes, `skipped_bad_lines`), metadata bins `version`/`sb-version`/`sb-rule-coverage` (JSON
  `Result` paths), `sb-explaind` (invalid `SB_DEBUG_ADDR`, port-query 400), `generate
  tls-keypair` (`--days` honored, `--days 0` rejected), `preflight` (missing/invalid config
  fails), `subs` (structured read/parse/write errors), `prefetch` (byte/duration totals; SOCKS
  UDP helper lint unblock in sb-adapters).
- **Scope note**: app helper-CLI hygiene only. No REALITY closure, dual-kernel BHV/parity
  movement, release packaging completion, or workflow automation is claimed. Full per-round
  details: git history 2026-07-03 (`029e48d8`, `71bb2026`, `5a97b46d`, …) + `log.md`.

## Strategic State

Phase: MT-REAL-02 stage-2 closed; public fresh-cohort = pre-release observation
(non-gating). Parity **52/56 BHV (92.9%) unchanged** — REALITY has no S3 BHV-ID, not in the
S1/S6 denominator. DEV-REALITY-01 = ARCH-LIMIT: local profile parity CLOSED, official-JA4 + camouflage OPEN.

## Current Build And Gate

- check/build/clippy (all-features,all-targets): **PASS** locally on 2026-06-30.
  Clippy exits 0 with existing warning-level lint reports (lint relaxed 2026-06-03:
  warnings/dead_code deny→warn, safety kept deny).
- cargo check --workspace --all-features: **PASS**. strict check-boundaries.sh: **exit 0**.
- python3 unittest (reality_probe_tools / clienthello_family /
  dual_kernel_verification): **PASS**. trojan_integration: **20 PASS, 0 ignored**.

## T3 ClientHello Fingerprint Parity — T3-0…T3-2 DONE (2026-06-08)

- CLOSED (local): functional dataplane, normalized-profile parity, required field-set parity,
  coordinated GREASE structure, and local from-spec JA4 Go==Rust diagnostic.
- OPEN: official FoxIO-tool JA4 crosscheck, extension-order statistical parity,
  `HelloChrome_Auto` drift, tier-2 camouflage. NON-GOAL: L4 byte identity.
- A2.3 runtime status-JSON rehearsal DEFERRED. Detail: t32 governance; T3-1B `052d4392`.

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
  History (fresh13 per-rep R73/R90/R91; fresh09 broken R85/R88):
  `archive/mt_real_02/mt_real_02_baseline.md`.

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

- R33-R60 + early ClientHello/Vision/REALITY: `archive/mt_real_02/mt_real_02_baseline.md`;
  L01-L25: `archive/l01_l25_summary.md`; closed MT-* tracks: `archive/mt_summary.md`;
  REALITY archive: `archive/reality_summary.md`; golden spec:
  `labs/interop-lab/docs/dual_kernel_golden_spec.md`.
