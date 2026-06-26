<!-- tier: S -->
# Active Context

> Purpose: high-frequency project navigation. S-tier: read every
> session.
> Discipline: keep only current-stage facts. This file must stay
> under 100 lines.
> **This file is the single source of truth for volatile state**
> (phase, parity-BHV, build/gate). Other docs point here, not copy.

---

## Resume (2026-06-27) - post004 WireGuard incoming TCP P6

- **post004 P6 DONE**: userspace WG endpoint now accepts incoming in-tunnel TCP on
  configured endpoint `listen_ports`. Flow: v2 `listen_ports` → EndpointIR →
  `WireGuardConfig` → smoltcp listener → `TcpAccept` → endpoint
  `ConnectionHandler::route_connection`; local WG destinations translate to loopback
  while preserving `origin_destination`.
- **04b harness extended PASS**: original Rust→Go→stub→Go→Rust curl remains green,
  and a new independent Go→Rust curl is green: Go mixed → `wg-go` → Rust smoltcp
  listener → route handler → direct stub. Evidence:
  `/tmp/pf04b-wg-live-p6/result.json` status=PASS, both curls 200, all stub/Go/Rust
  hit assertions true, cleanup=complete.
- **Audit result**: post004 Phase 1-5 claims match their sealed commits/evidence;
  the prior "No Phase 6 planned" note is superseded by this user-directed P6.
  Sealed commits: P1 `8f976824`, P2 `069c1e96`/`7964e5a6`, P3 `9dadcd10`,
  P4 `c0e11036`, P5 `9f0bf903`.
- **P7/P8 posture**: P7 `system:true` kernel WireGuard is planning-only; P8
  smoltcp→lwIP is deferred until performance/correctness evidence requires it.

## Resume (2026-06-20b) - post003 TUN UDP/IPv6 + proxy egress

- **post_fable_package03 DONE**: UDP NAT + IPv6 TCP/UDP reply packets; macOS EISCONN fix;
  TUN egress through proxy outbounds. Live root 03b TCP IPv4+IPv6 proof PASS at
  `/tmp/pf03b_post003_privileged2`; UDP pinned by unit test. Evidence: package03 note.

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
