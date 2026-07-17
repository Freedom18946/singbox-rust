<!-- tier: S -->
# Active Context

> Purpose: high-frequency project navigation. S-tier: read every
> session.
> Discipline: keep only current-stage facts. This file must stay
> under 300 lines.
> **This file is the single source of truth for volatile state**
> (phase, parity-BHV, build/gate). Other docs point here, not copy.

---

## Resume (2026-07-17) - LNX-RT-01 Linux runtime closure DONE

- Pinned Debian Rust 1.92.0 / Go 1.24.7 amd64 lane: VMess multiplex 6/6, workspace
  all-feature test, all-target/all-feature check, repository-policy clippy, and fmt PASS.
- Rebuilt `with_clash_api` Go oracle and interop runner. Committed
  `p2_vmess_dual_dataplane_local` now has strict full assertions and passes `--kernel both`;
  evidence `20260717T142243Z-34b05275-47aa-41ff-bcfa-39220788da3d`.
- Linux dual-kernel result: **40 PASS / 1 DIV-COVERED / 0 ENV-LIMITED**. FakeIP keeps only
  its registered S4 coverage; VMess uses no S4 label. BHV denominator remains 52/56.
- Native arm64 best-effort image built with the same pins; focused VMess suite 6/6 PASS.
- Closed portability/isolation defects in custom-target binary discovery, Python helper,
  rate-limit env/accounting, Trojan router ownership/pooling, and test binary lookup.
- Track archived at `archive/lnx_rt_01/`; raw logs remain in `/private/tmp`.
- **Recommended next:** REALITY external research tail: tier-2 camouflage, active probing,
  healthy-cohort observation. GUI desktop stays paused unless explicitly reopened.

## Resume (2026-07-17) - canonical VMess (Go sing-vmess wire-compatible) DONE

- Replaced the non-canonical Rust-to-Rust VMess dialect with a faithful port of Go `sing-vmess`:
  MD5 cmdKey, nested HMAC-SHA256 KDF, AES-ECB AuthID+crc32, AEAD request/response headers
  (PortThenAddress, fnv1a), chunked AEAD body with SHAKE128 masked-length framing. New module
  `crates/sb-adapters/src/vmess/`; in/outbound rewired; client reads response lazily to match
  Go's lazy server write.
- Verified against REAL Go `sing-vmess` both directions (aes-128-gcm + chacha20, incl. 20 KB
  multi-chunk): Rust outbound → Go Service PASS; Go Client → Rust inbound PASS. Crypto locked to
  Go-generated vectors (cmdKey/KDF/AuthID). `multiplex_vmess_e2e` 6/6 (was 6 fail). Adapters suite,
  vmess/websocket/tls app tests, fmt, clippy, boundaries (W200-11 → injected-router like VLESS,
  +W200-11b forbid `rules_global::global`), consistency all PASS.
- Resolves the LNX-RT-01 VMess decision (`archive/lnx_rt_01/vmess_canonical_plan.md`): chose
  canonical Go interop over the bespoke patch / deferral. Linux strict closure is recorded above.
- Scope: VMess TCP AEAD dataplane only. Non-goals: legacy aes-128-cfb (alterId>0), canonical
  v1.mux.cool CommandMux (repo keeps yamux-outer), UDP/packet.

## Resume (2026-07-14) - Linux Rust 1.92 workspace build RESTORED

- Linux all-feature compile gaps closed across socket2, libc ABI, tun 0.8, zbus 3,
  routing feature gates, and app hardening.
- Added local Rust 1.92 Debian compile gate for x86_64 GNU + aarch64 GNU; no workflow
  automation. Both architecture checks, Linux adapter/unit regressions, TCP Fast Open
  socket-option tests, app bench-I/O contract, formatting, boundaries, and consistency pass.
- Scope: Linux portability/quality only; no dual-kernel parity or REALITY movement.

## Resume (2026-07-13) - local Docker skill startup hook DONE

- Root `AGENTS.md` and S-tier `init.md` now require startup loading of local
  `singbox-docker-lab`; all Docker work routes through it.
- Consistency gate locks both startup pointers. Skill readability/validation, Docker restart,
  arm64 Rust 1.92 smoke, and locked Cargo metadata pass; no product/parity movement claimed.

## Resume (2026-07-13) - VLESS multiplex E2E routing lifecycle FIXED

- Classified **B (portable logic bug)**, not macOS sandbox: mux and non-mux handshakes completed,
  then server ignored `cfg.router`, queried unset global routing, and closed before payload relay.
- VLESS inbound now routes through injected `RouterHandle::decide_with_meta` using canonical
  `RouteCtx`; boundary gate requires injected ownership and forbids `rules_global::global` reuse.
- Regression test explicitly keeps process-global routing unset. Exact five-case VLESS multiplex
  E2E passes with real assertions and zero skips; `sb-transport` tests, related clippy, fmt,
  strict boundaries, and consistency pass.
- Linux replay was blocked before tests by unrelated existing compile gaps (`socket2` TFO, libc
  pointer type, redirect/tproxy guards). Platform-neutral path evidence plus mux/non-mux identical
  closure and injected-router regression establish classification.

## Resume (2026-07-13) - REALITY Chrome-current drift + extension-order tail CLOSED locally

- Production profile now targets **full Chrome 150.0.7871.115**, not pinned uTLS
  `HelloChrome_Auto=Chrome133`: adds `trust_anchors` (`0xca34`, empty vector) and ML-DSA
  signature schemes `0x0904/05/06`; REALITY still removes X25519MLKEM768 group/key-share.
- Extension order now follows current BoringSSL semantics: independent `OsRng` u32 words,
  reverse Fisher-Yates over middle extensions; GREASE remains fixed at both ends. Shared u16
  order/ECH seed and empirical Go-order ranking tables removed. ECH bucket, order, GREASE,
  ECH payload/key bytes consume independent entropy.
- New sanitized full-browser canary: `labs/interop-lab/reality_chrome_canary/`. Harness split:
  Chrome-current Rust shape/JA4 = blocking; pinned Go/uTLS v1.8.4 = functional compatibility
  lane, profile differences advisory. Local 10-run Chrome lane PASS; tier-1 20/20 PASS.
- Remaining REALITY research tail: real-network camouflage, active probing, tier-2 cohort.
  No `52/56` BHV movement; REALITY has no S3 BHV-ID.

## Resume (2026-07-12) - MT-INTEROP-03 dual-kernel baseline cleanup DONE

- **MT-INTEROP-03 accepted:** its historical 103-case run replaced WP14's noisy baseline;
  LNX-RT-01 later superseded its VMess environment-limit classification.
- Four former `INTEROP_*` cases are self-managed. DNS TTL reference direction and cache bounds,
  WS memory warm-up, shutdown drain ordering, reload readiness debounce, Go group-delay route,
  FakeIP fixture/oracle, WireGuard compatibility fields, and isolated Rust/Go bootstrap are closed.
- VLESS local dual-kernel dataplane is strict PASS after fixing request version/address order.
  VMess canonical strict closure is recorded in the 2026-07-17 resume above.
- FakeIP cursor behavior is locked as S4 `DIV-M-012`; static S4 labels never suppress failures.
  Evidence: `archive/mt_interop_03/acceptance.md`.
- **Recommended next:** REALITY external research tail: tier-2 camouflage, active probing, and
  healthy-cohort observation. GUI desktop remains paused until
  explicitly reopened.

## Resume (2026-07-12) - MIG-03 WP14 final acceptance DONE

- **MIG-03 accepted and archived:** WP01-WP14 closed. Final D17 metrics meet every target;
  canonical contracts, adapter protocol ownership, single router stack, externalized Web/DERP
  services, frozen runtime options, duplicate cleanup, and feature slimming are closed.
- WP14 removed final `routing/` compatibility facade and locked non-return in boundary V8. Stable
  architecture docs, navigation, experience memory, phase map, and archived acceptance evidence
  now match source facts.
- Workspace all-feature fmt/check/clippy/test, five app profiles, Python tool suites, Trojan
  integration, strict boundaries, consistency, and diff-check pass. Interop full run: 87/103;
  all 16 failures classified as external-env, dual/Go oracle, non-promotable Rust diagnostic,
  harness assertion, or historical S4 baseline; no new unclassified difference. Exact evidence:
  `archive/mig03/mig03_wp14_final_acceptance_and_archive.md`.
- **Scope note:** architecture migration closure only. No parity/BHV/REALITY movement claimed.

## Resume (2026-07-11) - MIG-03 WP09/WP10/WP12 red-team acceptance DONE

- **WP09 accepted:** DERP moved to `sb-service-derp`; SSM/V2Ray API moved to `sb-api`;
  app owns concrete service registration. sb-core service tree has no axum/tonic and retains
  only non-Web kernel services.
- **WP10 accepted:** `sb_api::debug` is sole HTTP/auth/middleware owner. app keeps endpoint state
  plus route extension; all endpoints retained. Real HTTP tests lock 200/401/429, request-id,
  envelope, audit, and extension behavior.
- **WP12 accepted:** core selector/p3/udp-balancer and transport/tls/subscribe/config/socks5
  shadows retired or relocated per D15. WireGuard/Tailscale layer split is explicit; no D18 item.
- Red-team fixes closed default-profile metrics linkage, relocated test dependencies/feature gates,
  DERP header panic paths, and stale boundary assertions. Workspace all-features, focused crate/app
  tests, three app profiles, clippy, fmt, 427 boundaries, and diff-check pass.
- **Transition closed:** WP13 accepted; WP14 is next MIG-03 frontier.

## Resume (2026-07-11) - MIG-03 WP11 env/config convergence DONE

- 141 个 core-owned `SB_*` 全部由 app 组合根一次解析，注入 `CoreRuntimeOptions` 六域；
  core `SB_*` 字面量/直接读取/白名单均为 0，构造后冻结。
- DNS/router/net/service/debug/admin 消费链与测试已迁移；变量无废弃。登记权威：
  `agents-only/archive/mig03/mig03_wp11_env_registry.md`。
- 验收：workspace all-features check、clippy、sb-core/app full test、fmt、boundaries 429、
  diff-check 全绿。
- **Authorized transition:** WP14 已解锁；按 `workpackage_latest.md` 继续下一项 MIG-03 frontier。

## Resume (2026-07-11) - MIG-03 WP08 router stack merge DONE

- **WP08 accepted:** `router/` is sole implementation home. Its former 25-line `routing/`
  compatibility facade was removed by WP14; ConfigIR engine/explain/trace moved under router, duplicate toy matcher,
  IR, and reload router were deleted. Router-domain `pub struct Engine` count is one.
- ConfigIR and rule-set paths share label-aware suffix matching; DNS continues through canonical
  `RuleMatcher` with no local domain matcher. Explain JSON has an exact field-order/value lock;
  rule-hot-reload now atomically replaces canonical `Arc<RouterIndex>` built through config pipeline.
- Acceptance: workspace all-feature check/clippy, fmt, boundaries, diff-check, sb-core/app full and
  focused router/DNS/hot-reload tests, and 232 Python tool tests pass. Five route/DNS dual-kernel
  cases have `gate_score=0` and zero mismatches; no new S4 divergence.
- **Authorized transition:** WP11 is unblocked on serialized WP06 → WP08 → WP11 lane. Next step:
  inventory all sb-core `SB_*` reads, inject explicit runtime option structs from app composition root.
- **Scope note:** structural ownership/dedup plus acceptance-drift repairs only. No parity/BHV,
  packaging, or REALITY denominator movement is claimed.

## Resume (2026-07-11) - MIG-03 WP07 QUIC family relocation DONE

- **WP07 accepted:** Hysteria v1/v2 inbound/outbound, Naive H2, and shared QUIC protocol code now
  live in sb-adapters. sb-core has no hysteria*/quic/naive_h2 outbound module or protocol reference;
  Hysteria2 IR construction moved from switchboard into adapter registration.
- Hysteria2 canonical outbound retains TCP plus relocated UDP PacketConn behavior and full transport
  fields (Brutal, CA path/PEM, ALPN/SNI, 0-RTT, obfs/salamander). Opt-in app UDP loopback passes with
  a real authenticated QUIC association; Hysteria v1 E2E, integration tests, and Criterion bench pass.
- Acceptance: core+adapters tests, workspace all-feature check, strict workspace clippy, fmt,
  boundaries, diff-check, and focused feature-isolation checks pass. sb-core source drops 4,708 Rust
  lines. Remaining quinn/hyper users are DNS/DERP/dev or compatibility-feature paths assigned to
  WP09/WP13, not WP07 protocol ownership.
- **Authorized transition:** WP08 is next on the serialized WP06 → WP08 → WP11 lane; WP13 remains
  responsible for legacy feature/dependency edge retirement after its prerequisites.
- **Scope note:** structural ownership relocation plus preservation/verification of existing
  protocol behavior only. No parity/BHV, packaging, or REALITY denominator movement is claimed.

## Resume (2026-07-11) - MIG-03 WP06 scaffold retirement DONE

- **WP06 accepted:** bridge/runtime/switchboard now consume only canonical sb-adapters registry
  connectors. Registry rejection is a fatal startup error with tag/kind context; no scaffold,
  degraded, core direct/block, or implicit-direct protocol fallback remains.
- Scaffold feature/Cargo references and 16 core legacy files are gone. `OutboundImpl` has one
  Connector variant; inbound TCP helper ownership moved to adapters with DNS/keepalive/telemetry
  semantics preserved. Net diff is -5818 lines; final gui_runtime binary is 241,952 bytes smaller
  than the recorded pre-WP06 build.
- Acceptance: three-crate tests, registry fatal/no-READY test, workspace all-target/all-feature
  check, strict clippy, fmt, boundaries, diff-check, SS/Trojan net-e2e, release GUI mixed→direct
  traffic smoke all pass. Final strict interop is 87/95; every WP06-affected case is clean and
  remaining failures are pre-existing harness/config/S4 baselines documented in WP06.
- **Authorized transition:** WP07 is unblocked. Next step: relocate the full
  hysteria/hysteria2/naive/quic family from sb-core to sb-adapters, then run its protocol/bench/
  global acceptance set.
- **Scope note:** structural ownership/fallback retirement only. No parity/BHV, packaging, or
  REALITY denominator movement is claimed.

## Resume (2026-07-11) - MIG-03 WP05 adapter gap closure DONE

- **WP05 accepted:** `de25101d` moves active SOCKS UDP map/session/transport ownership into
  sb-adapters, closes product feature reachability, and preserves D14 env/default/wire-size
  behavior. SOCKS/mixed now share the legacy per-IP limiter; SOCKS reports active TCP and
  compatible UDP associate/packet/active metrics.
- WP04 matrix GAP count is now zero. Core SOCKS UDP scaffold tests moved to active adapter/product
  tests; exact adapter references to the four core UDP scaffold symbols are zero. Selector/urltest
  and generic balancer/group ownership remain WP12.
- Acceptance: adapter default/all-feature and core regression suites, three app product profiles,
  feature isolation, Python tool suites, global five gates, and SOCKS TCP/UDP + mixed dual-kernel
  runs all pass. No D18 item or behavior-expansion decision appeared.
- **Authorized transition:** WP06 is unblocked. Next step: remove bridge fallback/orphan scaffold
  implementations and stale `ADAPTER_FORCE` surface exactly per WP04 §11/WP06.
- **Scope note:** WP05 structural/compatibility closure only. No parity/BHV denominator,
  packaging, REALITY, WP06 deletion, or WP12 ownership movement is claimed.

## Resume (2026-07-11) - MIG-03 WP04 semantic audit DONE

- **WP04 accepted:** `archive/mig03/mig03_wp04_coverage_matrix.md` corrects stale scaffold
  assumptions, inventories all live construction paths, and records per-protocol eight-dimension
  coverage, D9/D10/D14 decisions, cross-dependencies, test disposition, and parity handoffs.
- Two WP05 GAP groups remain: SOCKS inbound Rust-only limiter/active-TCP/compatible metrics plus
  core UDP dependencies; SOCKS outbound product-profile UDP reachability plus core UDP helper
  migration. HTTP/mixed/direct/TUN/redirect/tproxy/block and registry-only protocols require no
  WP05 scaffold-semantic fill. Selector/urltest implementation ownership remains WP12.
- No D18 item remains. Next dependency step: execute WP05 exactly from matrix §11; WP06 stays
  blocked until WP05 acceptance.
- **Scope note:** documentation audit only. No production code, feature, test, packaging,
  parity/BHV, or REALITY denominator movement is claimed.

## Strategic State

Phase: LNX-RT-01 closed; MT-REAL-02 stage-2 closed; public fresh-cohort = pre-release observation
(non-gating). Parity **52/56 BHV (92.9%) unchanged** — REALITY has no S3 BHV-ID, not in the
S1/S6 denominator. DEV-REALITY-01 = ARCH-LIMIT: local Chrome-current profile, wide-entropy
BoringSSL order semantics, and official-JA4 algorithm cross-check CLOSED; real-network camouflage,
active probing, and tier-2 cohort remain OPEN.

## Current Build And Gate

- 2026-07-17 LNX-RT-01 final: pinned Linux amd64 workspace all-feature test/check,
  repository-policy clippy, fmt, focused VMess, and strict both-kernel replay PASS.
- Native arm64 focused VMess PASS. Repository closure gates: boundaries 430, consistency,
  diff-check, and post-archive pinned-Linux fmt/clippy PASS. Raw logs remain under
  `/private/tmp/singbox-rust-lnx-rt-01/`.

## T3 ClientHello Fingerprint Parity — Chrome-current refresh DONE (2026-07-13)

- CLOSED (local): functional dataplane; full-Chrome-150 sanitized canary shape; BoringSSL
  reverse-Fisher-Yates order semantics with wide independent entropy; coordinated GREASE;
  from-spec JA4 `t13d1517h2_8daaf6152771_cb7bf5808d99`; FoxIO algorithm vectors.
- Pinned Go/uTLS Chrome133 now compatibility-only, not current-browser authority.
- OPEN: tier-2 camouflage, active probing, external healthy-cohort observation.
  NON-GOAL: L4 byte identity; second-tool fingerprint of live captures.
- A2.3 runtime status-JSON rehearsal DEFERRED. Detail: t32 governance; T3-1B `052d4392`.

## REALITY Acceptance (3-tier; golden_spec S4)

1. Local deterministic gate — `make verify-reality-local` (A1/A2 committed; A2.3 deferred).
2. External healthy-cohort observation — pre-release, NON-gating (tri-state; no single node
   is a closure identity; outage ≠ regression).
3. ClientHello fingerprint parity — tier-3: Chrome-current local shape/order/JA4 CLOSED;
   pinned Go lane compatibility-only; real-network camouflage + active probing OPEN.

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
