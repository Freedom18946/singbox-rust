<!-- tier: S -->
# Active Context

> Purpose: high-frequency project navigation; S-tier, read every session. Keep under 300 lines.
> **This file is the single source of truth for volatile state** (phase, parity-BHV, build/gate).
> Other docs point here, not copy.

---
## Resume (2026-07-20) - REALITY production server deployment path DONE

- Red-team audit found reverse interop used an adapter example while production V2 rejected or
  discarded VLESS users and `tls.reality`; registry startup also panicked without a Tokio reactor.
- Added strict canonical `handshake`/`short_id` lowering (documented aliases retained), one-user
  VLESS validation, IR/bridge/starter wiring, base64+hex X25519 key support, runtime, and bind readiness.
- A1 now starts the Rust reverse lane through production `app run -c rust_server.json`.
  Full 20-run gate PASS: all three dataplanes and four-phase probe 20/20, four negatives PASS,
  five config checks PASS. Evidence: `archive/reality_production_server/acceptance.md`.
- Local production deployability is closed; no public deployment occurred. R94 remains
  `UPSTREAM_OBSERVABLE_MINIMUM_OBSERVED` / sufficiency `NOT_ASSESSED`; external blocker is a
  controlled publicly reachable Rust server and/or multi-vantage censor measurement.
- ServerHello borrowing stays ARCH-LIMIT. No `52/56` BHV movement.

## Resume (2026-07-20) - A2.3 L18 startup + status closure DONE

- Strict perf PASS (startup 17/17 ms); Cargo isolation and target-aware REALITY fixture closed.
- Terminal `PARTIAL`: all local gates PROVEN; Docker ADVISORY, GUI UNTESTED. Evidence:
  `archive/a2_3_runtime_status/acceptance.md`; no parity/BHV/external claim.

## Resume (2026-07-19) - R93 external healthy cohort PASS, BANKED

- User-supplied fresh subscription admitted 19 VLESS+REALITY plain-TCP Vision
  entries: 19 fresh-ready, production config parse PASS, R81 19/19 with zero violation.
- Discovery found 18/19 `all_ok`. An earlier public-source chain and the first user-source chain
  were discarded intact after timeouts/reset; no failed chain was patched. Alternate qualification
  then fixed three distinct healthy servers (`r93u_006/009/014`) before a new sequence started.
- Accepted fixed cohort: three consecutive rounds x three nodes x three runs; 27/27 matrices
  `all_ok`, 243/243 phase classes `ok`, zero divergence/same-failure/matrix error/timeout.
- Tier-2 external healthy-cohort observation is **PASS, banked at depth 3**, pre-release and
  non-gating. Evidence: `mt_real_02_evidence/round93_external_healthy_cohort.{json,md}`.
- No BHV movement or camouflage/ServerHello claim. R94 above records next-step external progress.

## Resume (2026-07-18) - S5/T4 dual-kernel SOCKS5 throughput DONE

- Closed the last S5/T4 pending case. `p2_bench_socks5_throughput` previously ran a Rust-only
  Criterion echo loop that never traversed either kernel; it now drives the same live 1 MiB TCP
  echo workload through fresh SOCKS5 connections on Rust and Go.
- New validated `tcp_throughput` action records per-sample rates and enforces a strict 10 MiB/s
  minimum. Both kernels passed with large local headroom; case is `kernel_mode: both`, `strict`.
- Coverage-neutral: BHV-PF-001 remains owned by the existing HTTP p95 both-case; parity denominator
  unchanged. Evidence: `archive/s5_t4_socks5_throughput/acceptance.md`.
- R93 subsequently banked the healthy-cohort tier. Current recommendation is in the top resume.

## Resume (2026-07-18) - R92 external probe flow parity FIXED; observation INCONCLUSIVE

- Fresh public REALITY/VLESS intake passed production config parsing and R81 subset-schema
  admission. A no-flow node exposed a repeatable harness-only false divergence: the env extractor
  omitted outbound `flow`, while the minimal phase probe hard-coded `xtls-rprx-vision`.
- Probe tooling now carries and validates exact flow (`none` / Vision / Direct). Same no-flow
  replay changed from two mismatches to zero; explicit Vision replay stayed at zero mismatches.
- Formal post-fix public observation: three nodes x three runs, 9/9 matrices completed, zero
  app/minimal mismatch. No all-phase healthy node: one uniform infrastructure-dead node, one
  post-dial EOF node, one no-flow VLESS-timeout node. Tier verdict **INCONCLUSIVE**, not banked;
  no Rust regression, tier-2 closure, real-network camouflage, or BHV movement claimed.
- Evidence: `mt_real_02_evidence/round92_external_public_observation.{json,md}`. Raw public
  credentials/endpoints were not committed.

## Resume (2026-07-18) - TLS global certificate-test isolation DONE

- Fixed a real concurrent-test race in `crates/sb-tls/src/global.rs`: store-mode tests mutated
  process-global mode, extra CA paths/PEMs, and certificate directories independently, allowing
  `test_none_mode_empty` to observe another test's roots. A process test lock plus RAII snapshot
  now serializes mutations and restores all global certificate state even on early failure.
- Evidence: four 16-thread stress rounds of the eight global tests PASS; sb-tls 199+5+1 PASS;
  focused all-feature/all-target clippy exit0 (only existing `redundant_pub_crate` warnings); fmt
  and diff-check clean.
- Scope: test determinism/quality only. No runtime behavior, parity-BHV, or REALITY movement.

## Resume (2026-07-18) - REALITY canonical server + inbound Vision interop DONE

- **active-probing tail closed (local, decidable).** Rewrote the REALITY server
  (`crates/sb-tls/src/reality/server.rs`) to Go-canonical: any non-authenticated input
  (plain TLS / wrong SNI / no keyshare / decrypt-fail / bad short_id / unparsable) is now
  transparently relayed to the real target instead of hard-erroring + dropping the socket —
  the old `0xFFCE` parse path dropped every real/prober connection. `RealityAcceptor::accept`
  no longer returns `Err` for a readable non-auth connection.
- **Canonical first-flight relay order closed locally.** Rust now dials target before reading
  client bytes, mirrors every partial read immediately, reuses that primed connection on auth
  failure/partial EOF, and commits fallback when target responds before ClientHello completion.
  The timing regression proves target accept + first-byte mirror + early response before a full
  TLS record; a backpressure unit test proves a ready target response cannot cancel an in-flight
  mirror write. Actual cross-network camouflage measurement remains external.
- **Canonical session_id auth.** New `handshake::open_reality_client_auth` (mirror of the client
  `seal`: AES-256-GCM, nonce=random[20:32], AAD=zeroed-sessionId ClientHello) replaces the
  non-canonical `0xFFCE` custom extension + SHA256 hash. `config::accepts_reality_short_id`
  matches Go (empty short_ids => only the zero short_id).
- **Vendored rustls patch** (`vendor/rustls`): opt-in `ServerConfig::reality_force_signature_scheme`
  (default None) forces the ed25519 CertVerify so the server interoperates with Chrome-fingerprint
  clients that don't advertise ed25519 — the exact rustls ARCH-LIMIT (Go forges handshake bytes);
  symmetric to the fork's existing client-side ed25519 tolerance. Backward-compatible (builder-only
  construction; default preserves RFC 8446 negotiation).
- **Decidable evidence:** `crates/sb-tls/tests/reality_active_probing.rs` (decoy + 5 cases,
  cert-DER equality vs direct-to-decoy; authenticated proxy receives distinct payload) + seal/open
  round-trip unit test. Rust-server↔Rust-client canonical interop now works (impossible under 0xFFCE).
- **Reverse Vision interop closed.** Rust VLESS inbound now validates canonical flow addons,
  unpads client Vision frames, and frames server payloads. A1 v3 promotes reverse Go uTLS
  `xtls-rprx-vision` client → Rust REALITY+VLESS+Vision server; reverse and both forward lanes pass
  the full repeated matrix. No compatibility passthrough is used as proof.
- **Server config hardening.** `max_time_difference` accepts Go duration syntax and enforces the
  absolute client clock window (`None`/zero disables); `enable_fallback=false` is rejected and the
  server relay path is unconditional, preserving active-probing resistance.
- **Gates all green:** sb-tls 199+5+1 PASS; sb-adapters PASS; boundaries 0; consistency exit0;
  diff-check clean; clippy exit0 (only non-blocking nursery/pedantic); fmt clean;
  **`make verify-reality-local` PASS** (20/20 each Go→Go, Rust→Go, Go Vision→Rust;
  20/20 four-phase probe; negative controls PASS).
- **No 52/56 movement** (REALITY has no S3 BHV-ID). Differential archived at
  `archive/reality_active_probing/`.
- Residual after R93: success-path ServerHello cipher/keyshare/record-framing borrow = rustls
  ARCH-LIMIT (prober can't reach), plus real-network camouflage measurement. Tier-2 healthy
  cohort is banked by R93.

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
- R93 subsequently banked the healthy-cohort tier; real-network camouflage remains external.

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
- Later rounds closed active probing locally and banked tier-2 cohort externally; real-network
  camouflage remains. No `52/56` BHV movement; REALITY has no S3 BHV-ID.

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
- Later rounds closed active probing locally and banked the healthy-cohort tier; real-network
  camouflage remains external. GUI desktop remains paused until explicitly reopened.

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

## Strategic State

Phase: LNX-RT-01 closed; MT-REAL-02 stage-2 closed; public fresh-cohort = pre-release observation
(non-gating). Parity **52/56 BHV (92.9%) unchanged** — REALITY has no S3 BHV-ID, not in the
S1/S6 denominator. DEV-REALITY-01 = ARCH-LIMIT: local Chrome-current profile, wide-entropy
BoringSSL order semantics, official-JA4 algorithm cross-check, **and active-probing relay
resistance + canonical first-flight ordering/mirroring + canonical session_id server auth +
inbound Vision framing + production-configured server + reverse Go-client empirical interop CLOSED**
(2026-07-20; see Resume); residual
success-path ServerHello framing-borrow stays rustls ARCH-LIMIT (unreachable by probers).
Tier-2 healthy cohort is PASS/banked by R93. R94 observed upstream's network-visible subset;
real-network camouflage sufficiency remains OPEN/external.

## Current Build And Gate
- 2026-07-20 REALITY A1: production-configured Rust server, three bidirectional dataplanes,
  phase probe, config checks, and negatives PASS; active-probing differential stays PASS.
- S5/T4 strict both-kernel throughput and LNX-RT-01 pinned Linux closure remain PASS; durable
  metrics/evidence live in their archives. Repository closure gates are rerun per task.

## T3 ClientHello Fingerprint Parity — Chrome-current refresh DONE (2026-07-13)

- CLOSED (local): functional dataplane; full-Chrome-150 sanitized canary shape; BoringSSL
  reverse-Fisher-Yates order semantics with wide independent entropy; coordinated GREASE;
  from-spec JA4 `t13d1517h2_8daaf6152771_cb7bf5808d99`; FoxIO algorithm vectors.
- Pinned Go/uTLS Chrome133 now compatibility-only, not current-browser authority.
- OPEN: real-network camouflage. External healthy-cohort observation PASS/banked in R93;
  active-probing relay resistance + canonical server auth closed 2026-07-18.
  NON-GOAL: L4 byte identity; second-tool fingerprint of live captures.

## REALITY Acceptance (3-tier; golden_spec S4)

1. Local deterministic gate — `make verify-reality-local` (A1/A2 committed; A2.3 rehearsed).
2. External healthy-cohort observation — pre-release, NON-gating (tri-state; no single node
   is a closure identity; outage ≠ regression); R93 PASS, banked at depth 3.
3. ClientHello fingerprint parity — tier-3: Chrome-current local shape/order/JA4 CLOSED;
   pinned Go lane compatibility-only; active-probing relay resistance + canonical first-flight
   ordering/mirroring + canonical server auth + inbound Vision framing + reverse Go-client
   empirical interop CLOSED (2026-07-18);
   real-network camouflage OPEN.

## Closed Tracks (compressed; detail in archive)

- **A4 projection** CLOSED through A4.4 (`a5b7a41f`+`b042a683`, 2026-06-06): route C canonical
  STRICT, projection TERMINAL; 34/34 projected, 0 promotable; deferred G1/G2/G3.
- **A2 REALITY-gate wiring** DONE (`71e51669`+`e44c67d3`, 2026-06-06): L18 REALITY_LOCAL gate
  after ORACLE; A2.3 runtime status-JSON rehearsal completed 2026-07-20.
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
