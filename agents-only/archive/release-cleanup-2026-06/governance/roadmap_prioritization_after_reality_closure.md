<!-- tier: B -->
# Roadmap Prioritization After REALITY Local-Mainline Closure

Read-only prioritization card (post T3-2). **Investigate + rank + recommend ONE next card
only. No implementation, no commit, no public network, no Go-fork change, no extension of
REALITY engineering to green open items.** HEAD = `44b3a5f8`; tracked tree clean; only
`agents-only/a0_reality_spike/` pre-existing untracked (untouched).

Method: direct read of the authoritative context + a 5-agent read-only discovery sweep
(golden_spec S1-S6 / labs+GO_PARITY_MATRIX backlog / crates tech-debt / agents-only
governance / build-gate health). Every candidate below is evidence-backed, not recalled.

## A. Authoritative context read

CLAUDE.md · active_context.md (85 lines, current) · workpackage_latest.md · t32 / t31c /
t31b governance+harness reports · a22 (L18 capstone wiring; A2.3 nature) ·
reality_local_fixture/README.md · reality_clienthello_parity/README.md · golden_spec
S1-S6 · a0_reality_spike/{README.md,spike_results.json} · reference/ index
(GO_PARITY_MATRIX, ACCEPTANCE-CRITERIA, ARCHITECTURE-SPEC, AGENT-DEVELOPMENT-GUIDELINES,
07-DEPENDENCY-AUDIT) · labs docs (case_backlog, compat_matrix, oracle_rules,
REALWORLD-TEST-PLAN) · crates/sb-core/src/services/dns_forwarder.rs · `git log -24` ·
`git status`. Confirmed: L1-L25 + all MT-* closed/archived; REALITY local mainline boxed.

## B. Complete unfinished-item inventory

**Decisive structural fact:** `52/56 BHV (92.9%)` is a **hard structural ceiling**. The 4
uncovered BHVs map 1:1 to Go-fork limits and have a complete, audited, passing Rust side:
- BHV-SV-005/006/007 (Provider API) — DIV-H-005 STRUCTURAL (Go `provider.go`/`ruleprovider.go`
  endpoints are commented-out stubs; `findProviderByName` always 404; GET-vs-POST method
  divergence on SV-007). Rust wired + 3 e2e PASS (R66).
- BHV-LC-003 (concurrent service init / fault isolation) — DIV-H-006 STRUCTURAL (Go has no
  `/services/health`, no service-status enum, fail-fast `Manager.Start`). Rust fixture +
  live `/services/health` audited (R65).
→ **No parity-number-moving work is available to Rust** without changing the Go reference
fork (out of scope/mandate). REALITY is not in the S1/S6 denominator.

**Non-REALITY code (crates/, excl. boxed reality + tests):** ZERO classic tech-debt markers
(no TODO/FIXME/HACK/`unimplemented!`/`todo!` in production). All apparent "incompleteness"
is benign: feature-gate `NotImplemented` plumbing; documented+adjudicated stubs
(WireGuard/Tailscale endpoints, Resolved/DERP/SSMAPI fallbacks); test scaffolding (≈90/95
`panic!` in `#[cfg(test)]`); defensive invariants (one prevalidated `unreachable!`, trait
defaults). One de-scoped item (`tailscale_dns` DERP send/recv) matches the matrix.

**GO_PARITY_MATRIX caliber:** `209/209` is the *acceptance* baseline (incl.
accepted-limitation / won't-fix / de-scoped / Rust-only). Behavior-aligned is self-disclosed
as ~183/209 (15 partial + 3 not-aligned). Residual partials are platform-bound
(tproxy/redirect/tun runtime, WireGuard userspace UDP-listen/reserved, Windows TLS-fragment
ACK, Tailscale de-scope) or library/fork-bound (uTLS, ECH server/QUIC, REALITY) — none
closeable by Rust without external OS/TUN env, upstream rustls, or Go-fork changes.

**Genuinely actionable Rust item (the only one):** `dns_forwarder` (`resolved` service)
bind-failure does NOT propagate to `ServiceStatus::Failed`. `start()` does
`tokio::spawn(run_server)` then unconditionally `Ok(())`
(`crates/sb-core/src/services/dns_forwarder.rs:208-217`); `run_server` on UDP bind error
only `tracing::error!` + `return` (`:43-50`). A bind-failed DNS forwarder reports healthy —
the opposite of the SSMAPI/DERP sync-bind-first pattern, and it weakens the very
fault-isolation honesty that `p1_service_failure_isolation` / `/services/health` (the
Rust-leads side of DIV-H-006) rely on. Live known-issue in `case_backlog.md` (2026-05-03).

**Governance / doc-drift (anti-drift discipline failures):**
- **D1 (auto-loaded, misleading):** CLAUDE.md §边界检查 still says the boundary gate is
  `exit 1` / "registered non-blocking drift" — but it is now `exit 0` (537 V7 assertions, 0
  violations). CLAUDE.md contradicts its own single-source-of-truth (active_context) and the
  live gate. Same stale exit-1 framing in `ACCEPTANCE-CRITERIA.md §2.1`,
  `07-DEPENDENCY-AUDIT.md`, `a0_reality_spike/README.md`, `a43 §L`.
- **D2 (broken mandatory gate):** `agents-only/06-scripts/verify-consistency.sh` —
  init.md Step-2's mandated startup consistency gate — **deterministically exits 1 on a
  clean tree** because it requires a `WP-NNN` id that the T3 regime retired
  (`workpackage_latest.md:69`), plus a `tail -1` date bug. An ownerless tooling rot that
  red-lights a consistent repo and trains agents to ignore the gate.
- **D3:** `ACCEPTANCE-CRITERIA §3.3/§6` still prescribes `clippy -- -D warnings` after the
  2026-06-03 lint relaxation (Makefile intentionally dropped it).
- **D4:** `README.md` + `workpackage_latest.md` still frame the frontier as "R91 dormant
  since 2026-06-03" — superseded by "T3-2 DONE / REALITY local mainline boxed".
- **D5:** golden_spec S6 "Projected Coverage by Tier" table uses a stale `/60` denominator
  (Current row `45/60`, 75.0%), contradicting the authoritative `52/56`. Pre-existing (NOT
  introduced by T3-2; T3-2 left S1/S5/S6 byte-identical).

**REALITY tail (registered OPEN/DEFERRED; do NOT extend to green):** FoxIO official-tool JA4
crosscheck (PENDING, offline-blocked); extension-order statistical-distribution equivalence
(OPEN); HelloChrome_Auto upstream drift (OPEN); tier-2 external healthy-cohort observation
(pre-release, needs public network, non-gating); A2.3 full L18-capstone runtime status-JSON
rehearsal (DEFERRED, ride-along).

**Hygiene:** `a0_reality_spike/` adjudication (below); no consolidated deferred-registry
(intentionally — a third copy of volatile numbers would violate single-source-of-truth).

## C. Risk / value ranking

| Item | Correctness risk if unfixed | User value | Regression risk | Impl cost | Governance value | Blocks release | Blocks merge | Needs net | Ready now | Status |
|------|------|------|------|------|------|------|------|------|------|------|
| **D1+D3+D4+D5 doc-drift sync** | none | low (high meta) | ~0 | low | **HIGH** | no | no | no | yes | **NOW** |
| **D2 verify-consistency.sh fix** | none (tooling) | med | low | low | **HIGH** | no | no | no | yes | **NOW** |
| **SVC-DNS-01 dns_forwarder bind propagation** | **med** (silent-healthy on bind fail) | low-med | low-med | low-med | med | no | no | no | yes | **NEXT** |
| reality_clienthello harness → enforced gate | none | low | low | med | med | no | no | no | yes | DEFER |
| p2_bench_socks5_throughput | none | low | low | med | low (coverage-neutral) | no | no | no | yes | DEFER |
| A2.3 capstone runtime rehearsal | none | low | low | med | med | no | no | no | only in real capstone | DEFER/OBSERVE |
| LC-003 / SV-005/006/007 promotion | none | low | n/a | n/a (Go-fork) | n/a | no | no | no | no | KEEP_OPEN |
| platform partials (tproxy/tun/WG/Tailscale) | low | med | high | high | low | no | no | no | no (need OS env) | DEFER |
| COSMETIC DIV-M-* format parity | none | ~0 | low | med | none | no | no | no | yes | DROP |
| FoxIO JA4 / ext-order / HelloChrome drift / tier-2 | none | low | n/a | high | low | no | no | mostly yes | no | KEEP_OPEN |
| a0_reality_spike/ | none | none | n/a | trivial | low | no | no | no | yes | DROP (or leave untracked) |

> Easy ≠ should-do-first: D1/D2 are ranked NOW not because they are cheap but because they
> are *active defects in the project's operating substrate* (an auto-loaded memory file that
> lies about gate health + a mandatory startup gate that fails on a clean tree). SVC-DNS-01
> is the higher-intrinsic-value *code* item and is a deliberate, close second.

## D. A2.3 adjudication — DEFER / OBSERVE (ride next real capstone)

Per a22: A2.3 (confirming `reality_local` renders PROVEN/FAILED in-sequence + the wall-time
increment) has **no dry-run / targeted path** — it can only be observed during a real L18
capstone (the `daily` profile triggers a long canary). It is **non-gating** and the REALITY
mainline is boxed. Do **not** spend a card spinning a full capstone just for A2.3; let it
ride the next genuine certify/nightly rehearsal. Status: DEFER, observe on next capstone.

## E. FoxIO offline official-tool JA4 crosscheck — KEEP_OPEN (register only)

The harness already classifies `from_spec_ja4` as advisory `DIAGNOSTIC_PENDING_FOXIO_REFERENCE`
that never changes exit code. Closing it needs an offline-vendored FoxIO tool environment;
ROI is low and it is non-gating. **Register as a low-priority verification item; do NOT
stand up a vendor env now, and do NOT claim official JA4 parity closed** on the strength of
the from-spec agreement. KEEP_OPEN.

## F. a0_reality_spike/ adjudication — DROP (fully superseded); adjudication only, untouched

The 2026-06-03 feasibility spike. Its own "正式夹具最小实现计划" is **fully delivered**: the
committed `labs/interop-lab/reality_local_fixture/` (A1) reproduces the forward path **and**
the negative controls — the fixture's `bad_public_key` ≡ spike NC1 and `bad_uuid` ≡ spike
NC2 (the exact two-layer REALITY-auth-vs-VLESS-data-stage discrimination), plus `dead_dest`
and `occupied_port`, over 20 runs with committed evidence. **Disagreement noted:** the
governance survey called the negative-control evidence "unique / not in the committed
harness" and suggested TIDY-AND-COMMIT — that is incorrect; cross-checking
`reality_local_fixture/README.md` shows those negative cases are already committed. The spike
also holds a throwaway X25519 **private** key + uuid and a now-stale `exit 1` boundary note.
→ **DROP (delete)** is the clean call (superseded; throwaway key material; stale notes). Do
**not** tidy-and-commit. Zero-effort fallback: leave it untracked (harmless — not in
history). It is forbidden to touch this card; this is a recommendation for a trivial future
hygiene action, NOT the next card.

## G. LC-003 adjudication — KEEP_OPEN (Go-fork structural; Rust side complete)

Rust side done + audited (R65: real broken-service fixture + live `/services/health`).
Promotion to `kernel_mode: both` is blocked solely by the Go fork (no `/services/health`,
no status enum, fail-fast `Manager.Start`) — DIV-H-006, listed Non-Promotable in S5. **No
Rust action closes it; it is not the next card.** (See SVC-DNS-01, which *strengthens the
Rust side's honesty* without trying to promote the BHV.)

## H. Highest-value non-REALITY gap

**`SVC-DNS-01` — propagate `dns_forwarder`/`resolved` bind failure to `ServiceStatus::Failed`.**
The single genuine Rust correctness/honesty item in the whole non-REALITY surface. Bounded,
Rust-only, no network, no Go-fork dependency; directly hardens the fault-isolation
observability that is the one place the Rust kernel leads the Go reference.

## I. Single recommended next card — **DRIFT-01: post-REALITY governance reconciliation**

- **Goal:** eliminate the stale-state drift accumulated while REALITY was the frontier, so
  the project's auto-loaded substrate tells the truth and the mandatory startup gate passes
  on a clean tree. (Closing the books after REALITY, before any new code work.)
- **Scope (in):**
  - Sync boundary-gate status to the live reality (`exit 0`, 537 assertions, 0 violations)
    in CLAUDE.md §边界检查, `ACCEPTANCE-CRITERIA.md §2.1`, `07-DEPENDENCY-AUDIT.md`
    (and strike the stale note in `a43 §L`). (D1)
  - Fix `agents-only/06-scripts/verify-consistency.sh` so it exits 0 on a clean tree: retire
    the obsolete `WP-NNN` requirement (make advisory) and the `tail -1` date bug. (D2)
  - Update `ACCEPTANCE-CRITERIA §3.3/§6` to match the 2026-06-03 lint relaxation (no
    `-D warnings` gate; safety lints still deny). (D3)
  - Refresh `README.md` + `workpackage_latest.md` frontier framing to point at
    active_context (REALITY local mainline boxed), not "R91 dormant". (D4)
  - Fix golden_spec S6 "Projected Coverage by Tier" stale `/60` table to the authoritative
    `52/56` basis (recompute or strike). (D5)
- **Explicitly NOT:** no business-source change; no Go-fork change; no REALITY engineering;
  no new parity numbers (52/56 stays); no `a0_reality_spike/` touch (separate hygiene); no
  public network; no new gate enforcement (harness-promotion is DEFER, separate).
- **Acceptance:** after the card — (1) no doc asserts the boundary gate is `exit 1`;
  (2) `verify-consistency.sh` exits 0 on the clean tree; (3) no doc prescribes
  `clippy -- -D warnings`; (4) README/workpackage point to active_context not a dormant
  phase; (5) golden_spec S6 carries no stale `/60` numbers; (6) strict boundaries `exit 0`,
  `cargo check --workspace --all-features` PASS; (7) tracked changes limited to the named
  docs + `verify-consistency.sh`; `a0_reality_spike/` untouched.
- **Why first (over SVC-DNS-01):** D1/D2 are active defects in the *decision substrate* — an
  always-loaded memory file that misreports gate health and a mandatory startup gate that
  fails on a clean repo. They tax and mislead every future card (including SVC-DNS-01), at
  ~zero regression risk and low cost. Repairing the substrate first, then doing code work
  from a trustworthy baseline, is correct sequencing — not easy-over-important.
  (If the user weights production-kernel correctness above substrate hygiene, swap #1 and #2.)

## J. Follow-up queue (after DRIFT-01)

1. **SVC-DNS-01** — dns_forwarder bind-failure → `ServiceStatus::Failed` (+ regression test).
   First substantive code card; do it from the clean post-DRIFT-01 baseline.
2. **(hygiene)** DROP `a0_reality_spike/` (or leave untracked) — trivial, bundle anytime.
3. **DEFER:** reality_clienthello harness → enforced gate; `p2_bench_socks5_throughput`;
   A2.3 (ride next real capstone).
4. **KEEP_OPEN / OBSERVE:** FoxIO JA4 crosscheck; extension-order distribution;
   HelloChrome_Auto drift; tier-2 cohort; LC-003 / SV-005/006/007 (Go-fork structural).
5. **DROP:** COSMETIC DIV-M-* format-parity chasing (accepted; some explicit non-goals).

## K. Disposition

Saved: this report. Recommend a one-line active_context Resume refresh (roadmap-prioritization
DONE → next = DRIFT-01; queue #2 = SVC-DNS-01). **No commit; stop at the proposal.**
`a0_reality_spike/` untouched untracked.
