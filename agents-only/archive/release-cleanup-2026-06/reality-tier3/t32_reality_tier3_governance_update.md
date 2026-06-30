<!-- tier: B -->
# T3-2 — REALITY tier-3 golden_spec governance update (checkpoint)

Governance-only card. **Modifies docs + this agents-only checkpoint only.** No public
network, no business-source / Cargo / fixture / Makefile / L18 / CI / `.github` change,
no new implementation card. Retires the stale REALITY arch-limit narrative in
`labs/interop-lab/docs/dual_kernel_golden_spec.md` (S4 DEV-REALITY-01 + the three-tier
model's tier 3) now that the T3-0…T3-1C evidence chain is committed.
`agents-only/a0_reality_spike/` stays pre-existing untracked — untouched.

## 1. DEV-REALITY-01 old vs new narrative

| Axis | OLD (stale) | NEW (this card) |
|------|-------------|-----------------|
| Rust TLS stack | "Rust `rustls` still lacks a `uTLS`-equivalent browser-TLS mimic" | Rust carries a **patched-rustls Chrome shaping layer** (`build_chrome_client_hello_fingerprint`, FIX-04/FIX-05 lineage); a uTLS-equivalent port is not required and not planned |
| Live handshake | "the live public-cohort handshake result historically remained `0/21`" | **retired** — predated the shaping layer; replaced by a layered closed/diagnostic/open taxonomy under tier 3 |
| Chrome shaping | implied absent ("lacks Chrome shaping") | **present and exercised**; normalized-profile + field-set + coordinated GREASE structure match Go `utls.HelloChrome_Auto` locally |
| ClientHello parity | "byte-level uTLS fingerprint parity … remain open" (single blanket open item) | **local profile parity validated by committed harness**; only official-JA4 (FoxIO tool) + ext-order distribution + camouflage remain open |
| Path forward | "until Rust gains a uTLS-equivalent library" | local main line is essentially boxed; no big uTLS port; remaining work is research/cross-check, not reimplementation |

Preserved verbatim (NOT a regression to re-state): "client-only / Rust-only functional
evidence — **NOT a `52/56` BHV behavior-parity increment** and **NOT** a claim of REALITY
*server* bidirectional interop." This is the numeric-discipline anchor and stays.

## 2. Evidence chain (T3-0 / T3-1A / T3-1B / T3-1C)

- **T3-0** (`3ada59f2`, scoping) — code-review + local capture + normalized diff. Found the
  golden_spec "0/21 / needs uTLS" framing **stale**; Rust already at JA4-equivalent (L2)
  parity with two residuals (pinned GREASE cipher; ext-order shuffle). Decision: config-level
  fix, **not** a uTLS-equivalent project.
- **T3-1A** (`5006a2d0`, measurement hardening) — (a) the T3-0 JA4-equivalent digest is
  **byte-identical to a from-spec FoxIO JA4 reimplementation** (Go==Rust), but the **FoxIO
  reference tool cross-check is BLOCKED** offline → "official JA4 parity" NOT declared.
  (b) "randomize only the cipher GREASE" is **insufficient**: Go randomizes all six GREASE
  slots under two hard correlations → the fix is a **coordinated GREASE selector**.
- **T3-1B** (`052d4392` harness + `50a74350` checkpoint) — committed local read-only harness
  `labs/interop-lab/reality_clienthello_parity/`. Blocking gates PASS: token-match,
  normalized-profile digest (Go==Rust==`bc002612a968fae0`), required field-set, redaction
  guard. `from_spec_ja4` is an advisory diagnostic (`DIAGNOSTIC_PENDING_FOXIO_REFERENCE`);
  Rust GREASE advisory = FIXED (the T3-1C target).
- **T3-1C** (`6f8ae63a` impl + `5d07b0f7` checkpoint) — coordinated per-ClientHello GREASE
  selector. Rejected the seed-derived design (GF(2)-linear → only 16 affine profiles) in
  favor of `ChromeGreaseProfile::random(&mut OsRng)` per handshake. Independent draws;
  `groups`GREASE==`key_share`GREASE; `ext_head!=ext_tail`. Sampled 262,144 draws →
  **230,242 unique profiles** (vs 16 before). Harness GREASE advisory flipped **FIXED →
  RANDOMIZED**; blocking parity stayed PASS (digest/field-set GREASE-as-category robust).

## 3. Closed (local)

- **Functional dataplane** — local REALITY client functional-parity fixture; Go/Rust
  token-match; `direct_reality`/`transport_reality`/`vless_dial`/`vless_probe_io` repeatable;
  L18 capstone wired to `REALITY_LOCAL` gate. Local gate, not server-side merge enforcement.
- **Normalized ClientHello profile** — committed harness; blocking = token-match +
  normalized-profile digest parity + required field-set parity + redaction guard.
- **Coordinated GREASE structure** — independent-OsRng per-ClientHello selector; correlations
  reproduced; advisory RANDOMIZED; 230,242/262,144 unique (sampled observation, not a full
  state-space proof); Go 256-sample shows the same structural constraints (not a
  full-distribution-equivalence proof).

## 4. Achieved but local-diagnostic (not closed)

- **from-spec JA4**: Go==Rust==`t13d1516h2_8daaf6152771_d8a2da3f94cd`; normalized digest
  Go==Rust==`bc002612a968fae0`. **Observed locally**; official FoxIO-tool cross-check
  **PENDING**. Not "official JA4 parity closed."

## 5. Still OPEN

1. FoxIO official-tool JA4 cross-check (offline-blocked).
2. extension-order statistical-distribution equivalence.
3. `HelloChrome_Auto` upstream profile drift.
4. real-network camouflage sufficiency.
5. active-probing resistance.
6. tier-2 external healthy-cohort observation (pre-release, non-gating).
7. A2.3 full L18-capstone runtime status-JSON rehearsal (deferred).

## 6. Non-goals

- L4 raw-byte identity / byte-for-byte ClientHello equality.
- forcing per-hello randomized fields into alignment.
- freezing `HelloChrome_Auto` via a historical snapshot.
- reinstating the retired `fresh09` fixed-node obligation.

## 7. S5 / S6 numbers: UNCHANGED — and why

**Mechanical review of the accounting rules before touching anything:**

- The 52/56 BHV figure is **S1 / S6**: `behaviors with ≥1 kernel_mode:both case / total
  behaviors`, denominator = the **S3 behavior registry** (CP+DP+LC+SV+PF) minus the 4 SV.1
  subscription BHVs reclassified as harness-only (2026-03-16). Numerator = S3 rows with a
  non-empty "Both Cases" column.
- **REALITY has no BHV-ID in S3.** It lives only in **S4** as the `DEV-REALITY-01`
  ARCH-LIMIT divergence entry. S4 entries do not feed the S1/S6 denominator or numerator.
- The S5 promotion roadmap moves a number only when a case is promoted to `kernel_mode:both`
  in S3. **T3-0…T3-2 added no S3 case** (the harness is a read-only labs tool, not a dual-
  kernel case YAML).
- The mechanical recompute entry is "recount S3 Both-Cases column" — there is **no REALITY
  row to recount**, so nothing changes.
- DEV-REALITY-01 itself states the evidence is "**NOT a `52/56` BHV behavior-parity
  increment**."

**Conclusion: numeric parity unchanged. 52/56 BHV (92.9%) holds; every S1/S5/S6 number is
left byte-for-byte intact.** The golden_spec edit is confined to narrative text in S4
(DEV-REALITY-01 scope + disposition) and the three-tier model's tier-3 prose. No S5/S6
formula mechanically supports an increment, so none was applied. (Per task §四 case 1.)

## 8. Why no uTLS-equivalent port

- L2 (JA4) / L3 (normalized-structure) parity is **already achieved** by the hand-rolled
  patched-rustls shaping layer (T3-0 route table: option C "already done", option D
  "rejected"). A fork/FFI/backend-replace uTLS port is **huge maintenance for marginal gain**.
- The remaining residuals (official-JA4 tool cross-check, ext-order distribution shape) are
  **research / cross-check** items, not capabilities a uTLS port would add — Go and Rust
  already produce the same from-spec JA4 and normalized digest.
- Standing constraint forbids regressing to a static ClientHello template; the per-hello
  GREASE + shuffle behavior is now structurally Chrome-like via independent OsRng.

## 9. A2.3 deferred / tier-2 status

- **A2.3** (full L18-capstone runtime status-JSON rehearsal) remains **DEFERRED** — the L18
  REALITY_LOCAL gate is wired (A2.1/A2.2) but the runtime status-JSON rehearsal is not part
  of this governance card.
- **tier-2** external healthy-cohort observation stays **pre-release, non-gating**: bound to
  no single node identity; node outage ≠ Rust regression; never a merge gate.

## 10. Next step recommendation

**Box the REALITY local main line.** The local functional + normalized-profile +
coordinated-GREASE work is closed and committed; the open items are external/research
(FoxIO tool, distribution statistics, real-network camouflage) that do **not** justify more
local REALITY implementation. Recommend returning to **roadmap prioritization** rather than
opening another REALITY implementation card. Do not auto-enter the next card.

## Verification (recorded at card close)

- `git diff --check`: clean.
- `bash agents-only/06-scripts/check-boundaries.sh`: strict **exit 0**.
- `cargo check --workspace --all-features`: **PASS** (exit 0).
- `python3 labs/interop-lab/reality_clienthello_parity/run_check.py --runs 20`:
  `EXIT=0`, `blocking_pass=true`, token Go 20/20 + Rust 20/20, normalized digest
  Go==Rust==`bc002612a968fae0`, required field-set parity PASS; from-spec JA4 consistent but
  diagnostic-pending-FoxIO; Rust GREASE advisory **RANDOMIZED**. No public network.
- Tracked changes limited to: `dual_kernel_golden_spec.md`, this report,
  `active_context.md`. Committed evidence zero churn. `a0_reality_spike/` untouched untracked.

## Disposition

Saved: this report + the golden_spec governance edit + the active_context snapshot. Two
commits (golden_spec; then this checkpoint + active_context). Stop at the T3-2 commits — do
not enter a new implementation card.
