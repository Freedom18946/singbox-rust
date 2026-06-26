<!-- tier: S -->
# Active Context

> Purpose: high-frequency project navigation. S-tier: read every
> session.
> Discipline: keep only current-stage facts. This file must stay
> under 100 lines.
> **This file is the single source of truth for volatile state**
> (phase, parity-BHV, build/gate). Other docs point here, not copy.

---

## Resume (2026-06-26e) - post004 WireGuard live proof (Phase 5)

- **post004 Phase 5 DONE**: live round-trip proof vs Go sing-box. 04b harness
  builds Go sing-box 1.13.13 (with_wireguard,with_gvisor) + Rust app, generates WG
  keypairs, starts both kernels on loopback, and proves HTTP round-trip through the
  WG tunnel: curl → Rust mixed → wg-rust (endpoint-as-outbound) → WG tunnel → Go
  gvisor netstack → http-out → stub → response back Go→Rust. Four assertions all
  green: curl 200 + body WG04B-OK + stub CONNECT + Go inbound + Rust outbound.
  `result.json` status=PASS, cleanup=complete.
- Honest limit: Go-initiated curl to Rust not possible (Rust smoltcp netstack has
  no incoming TCP forwarder, unlike Go gvisor). Round-trip response path already
  proves Go→Rust traversal. SOCKS5 proxy used (not HTTP) because Rust HTTP inbound
  hardcodes ip:None in RouteCtx, preventing ip_cidr matching.
- **post004 CLOSED**: Phase 1-5 complete. No Phase 6 planned.
- Verified: 04b harness PASS (`/tmp/pf04b-wg-live/result.json`); Go build PASS;
  Rust build PASS. Phase 1 `8f976824`, Phase 2 `069c1e96`, Phase 3 `9dadcd10`,
  Phase 4 `c0e11036` sealed.

## Resume (2026-06-26d) - post004 WireGuard MIG-02 (Phase 4)

- **post004 Phase 4 DONE**: loud disabled-feature outbound builder + islanded
  mtu/reserved/allowed_ips consumption. Disabled `adapter-wireguard-outbound` branch now
  returns `invalid_config_outbound` (loud) instead of silent `None`. `OutboundIR` +
  `RawOutboundIR` gained `wireguard_mtu` / `wireguard_reserved`; v2 validator extracts
  them; `WireGuardOutboundConfig::try_from` consumes `mtu` (unwrap_or 1420) + `reserved`
  (3-byte loud validation) + validates `allowed_ips` CIDRs loudly. Replaces hardcoded
  1420 / [0,0,0] / opaque-string allowed_ips.
- Verified: sb-config outbound 104, sb-config wireguard 16, compatibility_matrix 6,
  sb-adapters wireguard 12 (5+7), sb-adapters register 15 (incl disabled-loud),
  transport-wg 16, core endpoint 29, clippy 0 warn (sb-adapters+sb-config), fmt clean,
  all-features PASS. Phase 1 `8f976824`, Phase 2 `069c1e96`, Phase 3 `9dadcd10` sealed.
  Next: P5 live proof vs Go.

## Resume (2026-06-26c) - post004 WireGuard multi-socket concurrency (Phase 3)

- **post004 Phase 3 DONE**: multi-peer UDP socket routing (per-peer `HashMap` bucketing, no
  cross-peer socket reuse); `recv_from` Notify check-then-await race fixed via `tokio::sync::watch`;
  ephemeral port dedup + reclaim on socket reap; `pump_udp_recv` 64KB rxbuf hoisted to Driver scratch;
  `ensure_started` TOCTOU double-fill fixed (re-check under lock); `wireguard_udp_timeout` parsed
  (`humantime`) + per-peer idle reap; tailscale endpoint `tailscale_udp_timeout` aligned (was hardcoded
  300s); TCP concurrent-dial stress test added.
- Verified: transport-wg 16 (14 + port-collision + TCP concurrent-dial), adapters-wg 5, core endpoint
  29 (23 + 6 new: udp_timeout parse/invalid/none, multi-peer, idle reap, ensure_started concurrent),
  core registry 8, all-features PASS, fmt/clippy 0 warn. Phase 1 `8f976824`, Phase 2 `069c1e96` sealed.
  Next: P4 MIG-02 loud disabled builder + mtu/allowed_ips; P5 live proof vs Go.

## Resume (2026-06-26) - post004 WireGuard UDP-over-WG (Phase 2)

- **post004 Phase 2 DONE**: UDP now rides the same userspace WG netstack: `WgUdpSocket`
  wraps smoltcp `udp::Socket` with `send_to/recv_from`; transport + legacy outbound expose
  `connect_udp`; registry stores named UDP factories and routes connector detours through them;
  WireGuard endpoints expose endpoint-backed UDP outbound sessions. During test hardening, endpoint
  WG driver lifetime moved to a persistent runtime instead of a dropped temporary runtime.
- Verified: transport-wg 14 (13 + dual-stack accept stress), adapters-wg 5, core endpoint 23, core registry 8,
  all-features PASS, fmt/clippy clean. Acceptance re-run 2026-06-26 independently reproduced all claimed
  commands; added `udp_dual_stack_send_to_both_families_queues` to pin the v4+v6 happy path. Phase 1 was
  already `origin/main`-sealed (`8f976824`). Next: P3 multi-socket concurrency
  hardening; P4 MIG-02 loud disabled builder + mtu/allowed_ips; P5 live proof vs Go.

## Resume (2026-06-20b) - post003 TUN UDP/IPv6 + proxy egress

- **post_fable_package03 DONE**: Enhanced TUN datapath beyond TCP/IPv4 — UDP NAT + IPv6 TCP/UDP
  reply packets; macOS EISCONN fix; TUN egress through **proxy outbounds** (`connect_tcp_stream`
  + boxed-stream session relay; was direct-only).
- **Live root 03b proof PASS** (`/tmp/pf03b_post003_privileged2`): TCP IPv4+IPv6 through HTTP
  outbound — curl 200 + outbound_hit both stacks + cleanup; IPv6 fully round-tripped. UDP proven
  by unit test (single-host live UDP-through-utun infeasible: direct egress loops; documented).
  Limits: SOCKS5/Hyst2 UDP loud-Unsupported; no IP frag. Evidence: post_fable_package03 evidence note.

## Resume (2026-06-20) - P1313-03 DNS rule actions/cache
- **P1313-03 DONE**: DNS rule fields/logical rules, route-options/action options, answer cache semantics, ECS/predefined wire response, RDRC rejection, and FakeIP-safe reverse mapping are pinned. Evidence: `agents-only/post1313/p1313_03_dns_rule_actions_and_cache_semantics.md`.
- **P1313-01/02 DONE**: GUI fixture schema baseline and DNS transport manager remain closed; next is P1313-04 route rule engine/network strategy.

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

- CLOSED (local): functional dataplane (token-match + 4 phases + L18 REALITY_LOCAL gate);
  normalized-profile parity (committed harness `labs/interop-lab/reality_clienthello_parity/`,
  digest `bc002612a968fae0`); required field-set parity; coordinated GREASE structure
  (`6f8ae63a`, independent OsRng per ClientHello, FIXED→RANDOMIZED, 230,242/262,144 unique — sampled).
- LOCAL-DIAGNOSTIC: from-spec JA4 `t13d1516h2_…` Go==Rust observed locally.
- OPEN: official FoxIO-tool JA4 crosscheck **PENDING**; extension-order statistical parity;
  `HelloChrome_Auto` drift; tier-2 real-network camouflage. NON-GOAL: L4 byte identity.
- A2.3 full capstone runtime status-JSON rehearsal **DEFERRED**. No uTLS-equivalent port.
- Detail: t32_reality_tier3_governance_update.md; harness commit T3-1B `052d4392`.
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
