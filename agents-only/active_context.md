<!-- tier: S -->
# Active Context

> Purpose: high-frequency project navigation; S-tier, read every session. Keep under 300 lines.
> **This file is the single source of truth for volatile state** (phase, parity-BHV, build/gate).
> Other docs point here, not copy.

---
## Resume (2026-07-24) - VMESS-TLS-01 strict dual-kernel DONE; Linux/full closure active

- VMess raw TCP and WebSocket/HTTPUpgrade, with and without standard TLS, pass
  live Rust→Go and Go→production-Rust dataplanes. TLS is built once and owned by
  the physical chain: TCP → TLS → V2Ray transport → VMess.
- WS/HTTP Host stays independent from TLS SNI. HTTPUpgrade now matches Go's
  non-WebSocket handshake and preserves bytes buffered past upgrade headers;
  WebSocket byte-stream writes now flush instead of hanging.
- Project yamux remains an explicit non-Go outer layer:
  TCP → verified TLS → yamux → canonical VMess per substream. Four logical streams
  reuse one TLS connection; failure opens no plaintext fallback.
- Typed config rejects unsupported/multiple transports, malformed TLS material,
  invalid versions, and incomplete identities instead of falling back to TCP/plain.
- Raw TLS live coverage includes TLS 1.2/1.3, ALPN, SNI/CA/UUID/version negatives,
  repeated 32 KiB+ echo, startup readiness, and graceful shutdown.
- Replaced five ignored/fake TLS variants with nine real local E2E tests. Twenty
  16-thread rounds passed (180/0/0). Stress exposed and fixed cancellation of
  in-progress TLS accepts by heartbeat/task-reap select branches.
- New strict both case crosses production peers in both directions: Go client→Rust
  server and Rust client→Go server. Verified TLS 1.3/SNI/ALPN, 32 KiB hash-exact
  echo, UUID/SNI rejection, bounded readiness/teardown; 20/20 runs PASS and every
  normalized diff is clean with gate score zero.
- Current ledger: 127 cases, 66 both/strict; behavioral coverage remains 75/79
  (coverage-neutral VMess/TLS variant). Remaining: Linux proof/full gates, final
  archive/review/commit.
  Evidence: `archive/vmess_tls_01/acceptance.md`.

## Resume (2026-07-24) - dual-kernel strict ledger correction DONE

- Added a typed case-YAML + structured S3/S6 Markdown validator at
  `scripts/tools/validation/validate-dual-kernel-ledger.sh`, with eight drift/error regressions.
- Mechanical result at correction time: 126 cases, 65 both, all 65 both cases strict;
  79 active BHVs, 75 covered, and all 75 covered BHVs carry strict both-case evidence.
- Corrected S6 strict behavioral coverage from the mistakenly copied both-case count to
  **75/79 (94.9%)**. This is ledger-only: no case/BHV/denominator/implementation/gap movement.

## Resume (2026-07-23) - Clash API strict-wire parity CLOSED

- Eight scoped Clash API cases passed live `--kernel both`; all final normalized diffs are clean
  with gate score zero. Run IDs: `154420Z-31a2c920` (strict contract),
  `154427Z-49583e44` (mode), `153123Z-0248021d` (DNS), `154929Z-2f296d50`
  (FakeIP flush), `153125Z-9983400b` (FakeIP DNS), `153126Z-6e4ea730`
  (connections), `153137Z-8ccf5c9b` (selector), `153138Z-b0d43b43` (WS soak).
- Final strict corrections: group-only proxy `all` including empty GLOBAL list; configured
  GLOBAL `now`; config-derived mode-list with lowercase Rust/Go fixture default; per-run
  persistent FakeIP cache isolation; stable post-close connection capture; explicit non-Linux
  RSS/Go-heap oracle accounting.
- S3/S6 recalculation found no coverage increment: all eight cases were already strict/both and
  already credited. Parity remains **75/79 BHV (94.9%)**; inventory remains
  **65 both / 126 total**. Open gaps remain 3 SV.2 STRUCTURAL + LC-003.
- Closed DIV-M-001/004/005/006/007/011/012. KEEP DIV-M-002/003/008/009/010 remain explicit.
- `test_flush_dns_cache` is accepted as a non-reproduced test-infrastructure observation:
  server-local resolver wiring confirmed; 40 consecutive full-binary 16-thread rounds PASS.
- Gates: app build; sb-api 133/1; focused FakeIP 30/0; focused DNS 221/7; interop-lab 49/0;
  boundaries 430; repository-policy clippy, consistency, fmt, diff-check PASS.
- Evidence: `archive/clash_api_strict_parity/acceptance.md`. Clash strict line has no open action;
  project frontier returns to separate tracks/external real-network camouflage research.

## Resume (2026-07-23) - dual-kernel routing-action coverage batch 6 +4 BHV DONE

- Added strict both-kernel coverage for Go 1.13.13 nonterminal `direct` (BHV-DP-038), empty
  `bypass` continuation (BHV-DP-039), destination-rewriting `route-options` (BHV-DP-040), and
  default `resolve` feeding later destination-IP rules (BHV-DP-041).
- Red-team source/live comparison corrected Rust assumptions: `direct` is nonterminal in the
  current Go route loop; empty `bypass` continues without bypass support; `route-options` mutates
  ordered matching and the dial target; `resolve` populates destination addresses and resumes.
- Rust SOCKS/HTTP TCP routing now executes `resolve` asynchronously, retains route options across
  sniffing, updates effective destination matching and final dial target, and preserves inbound
  sniff priority.
- Evidence: `p1_{direct_rule_action,bypass_rule_action,route_options_override,resolve_rule_action}_via_socks`;
  final PASS run IDs `20260722T204419Z-8f796e28-f2ed-41b9-9568-2c654237fcd8`,
  `20260722T204542Z-d47bd3c4-e82f-4748-988b-3b683062d314`,
  `20260722T204641Z-8e87c9c6-02d1-49c5-8e23-1def894d09ce`, and
  `20260722T204744Z-6b7debce-4f1c-463f-abf8-cd6d9f620010`; all normalized diffs clean.
- Coverage moved **71/75 -> 75/79 (94.7% -> 94.9%)**; inventory is **65 both / 126 total**.
  The 4 open gaps (3 SV.2 STRUCTURAL + 1 LC-003) remain unchanged.
- Gates: `sb-core` 580 passed/8 ignored, focused route 12 passed, `sb-adapters --lib` 63 passed,
  interop-lab 47 passed, eight Go/Rust config checks, normal and isolated acceptance app builds,
  clippy, consistency, boundaries (430 assertions), fmt, and diff-check PASS.

## Resume (2026-07-20) - REALITY ServerHello target-profile borrowing DONE

- Authenticated Rust server now consumes the same decoy TLS 1.3 profile as Go uTLS REALITY:
  selected cipher suite, key-share group, and combined or split first-flight record lengths.
- Opt-in vendored-rustls support narrows provider choices, splits handshake messages when the
  target does, and applies RFC 8446 inner-plaintext zero padding to reproduce record lengths;
  normal rustls configs remain unchanged.
- Combined-flight and four-record regressions verify exact wire lengths plus AES-256-GCM/X25519
  selection. `sb-tls` all-feature/all-target suite PASS (202+7); local A1 20-run gate PASS.
- `DEV-REALITY-01` local implementation status is CLOSED. Remaining real-network camouflage
  sufficiency is external research/measurement, not a Rust architecture gap. Evidence:
  `archive/reality_serverhello_borrowing/acceptance.md`. No `52/56` BHV movement.

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
- ServerHello borrowing was subsequently closed locally above. No `52/56` BHV movement.

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
  clients that don't advertise ed25519 — the then-residual rustls architecture gap;
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
- Superseded 2026-07-20: success-path ServerHello cipher/keyshare/record-framing borrowing closed
  locally; only real-network camouflage measurement remains external. Tier-2 healthy cohort is
  banked by R93.

## Strategic State

Phase: LNX-RT-01 closed; MT-REAL-02 stage-2 closed; public fresh-cohort = pre-release observation
(non-gating). Parity **75/79 BHV (94.9%) current** — REALITY has no S3 BHV-ID, not in the
S1/S6 denominator. `DEV-REALITY-01` local implementation line is CLOSED: Chrome-current profile,
BoringSSL ordering, FoxIO JA4 cross-check, active-probing relay, canonical first-flight/session_id,
inbound Vision, production server, reverse Go-client interop, and success-path target ServerHello
cipher/keyshare/record-shape borrowing all have local evidence. Tier-2 healthy cohort is PASS/banked
by R93. R94 observed upstream's network-visible subset; real-network camouflage sufficiency remains
OPEN/external, but no longer represents a Rust architecture limit.

## Current Build And Gate
- 2026-07-20 REALITY: sb-tls all-feature/all-target clippy exit0 and suite 202+7 PASS;
  A1 production-configured server, three dataplanes, phase probe, config checks, negatives PASS;
  ServerHello target-profile regressions and active-probing differential PASS.
- S5/T4 strict both-kernel throughput and LNX-RT-01 pinned Linux closure remain PASS; durable
  metrics/evidence live in their archives. Repository closure gates are rerun per task.

## T3 ClientHello Fingerprint Parity — Chrome-current refresh DONE (2026-07-13)

- CLOSED (local): functional dataplane; full-Chrome-150 sanitized canary shape; BoringSSL
  reverse-Fisher-Yates order semantics with wide independent entropy; coordinated GREASE;
  from-spec JA4 `t13d1517h2_8daaf6152771_cb7bf5808d99`; FoxIO algorithm vectors.
- Pinned Go/uTLS Chrome133 now compatibility-only, not current-browser authority.
- OPEN: real-network camouflage. External healthy-cohort observation PASS/banked in R93.
- Active-probing relay + canonical server auth closed 2026-07-18; target ServerHello
  cipher/keyshare/record-shape borrowing closed 2026-07-20.
  NON-GOAL: L4 byte identity; second-tool fingerprint of live captures.

## REALITY Acceptance (3-tier; golden_spec S4)

1. Local deterministic gate — `make verify-reality-local` (A1/A2 committed; A2.3 rehearsed).
2. External healthy-cohort observation — pre-release, NON-gating (tri-state; no single node
   is a closure identity; outage ≠ regression); R93 PASS, banked at depth 3.
3. ClientHello fingerprint parity — tier-3: Chrome-current local shape/order/JA4 CLOSED;
   pinned Go lane compatibility-only; active-probing relay resistance + canonical first-flight
   ordering/mirroring + canonical server auth + inbound Vision framing + reverse Go-client
   empirical interop + target ServerHello profile borrowing CLOSED (2026-07-20);
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
