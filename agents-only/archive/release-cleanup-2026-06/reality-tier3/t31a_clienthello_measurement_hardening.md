<!-- tier: B -->
# T3-1A — ClientHello Measurement-Caliber Hardening (evaluation)

Read-only follow-up to T3-0. **Local capture re-review + official-JA4 cross-check +
GREASE cross-field correlation + deterministic test-seam & formal-harness DESIGN only.**
No Rust/Go business-source change, no formal harness committed, no GREASE micro-fix, no
public network, no entry into T3-1B/T3-1C. Machine summary (sanitized):
`agents-only/archive/release-cleanup-2026-06/reality-tier3/t31a_clienthello_grease_correlation_summary.json`.

> **Two headline results:** (1) the T3-0 local JA4-equivalent digest is **byte-identical
> to a from-spec reimplementation of the official FoxIO JA4 algorithm**
> (`t13d1516h2_8daaf6152771_d8a2da3f94cd`, Go==Rust) — but the **FoxIO reference *tool*
> cross-check is BLOCKED** (no network/deps), so "official JA4 parity" is **not declared
> closed**. (2) The T3-0 "just randomize the cipher GREASE value" idea is **insufficient**:
> Go randomizes **all** GREASE slots per-hello under two hard correlations, so the real
> fix is a **coordinated GREASE selector**, not a one-field tweak.

## Terminology (calibrated)

- **official JA4** — output of the FoxIO reference implementation. NOT run here.
- **from-spec JA4** — my stdlib reimplementation of the published FoxIO JA4 algorithm.
- **JA4-equivalent digest** — the T3-0 approximation (turns out spec-faithful here).
- **normalized-profile digest** — project structural hash (GREASE as category) for local regression.
- **JA3** — auxiliary diagnostic only (unstable under Chrome shuffle).
- **JARM** — *server* fingerprinting; **out of scope** for ClientHello parity.

Until a FoxIO-tool cross-check exists, **do not write "official JA4 parity closed."**

## C / D. Official-JA4 cross-validation

| digest | go | rust | go==rust |
|---|---|---|---|
| from-spec JA4 | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | same | **yes** |
| T3-0 local JA4-equiv (actual) | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | same | **yes** |
| normalized-profile digest | `d298fdbe2430bd76` | same | **yes** |

- **Relationship:** the T3-0 JA4-equivalent digest **equals** the from-spec JA4 for this
  profile (both keep `signature_algorithms` in order). A sigalgs-sort sensitivity probe
  changes JA4_c to `…_9a55b862dad6`, confirming JA4_c is sigalgs-order-sensitive and the
  from-spec impl is correct. The earlier "structural approximation" caveat was
  conservative — for this input it was already spec-correct.
- **Where any difference would come from:** none observed between Go and Rust at JA4 or
  normalized-profile level — the inputs (cipher tail, sorted ciphers, extension set,
  sigalgs order) are identical, so it is a *profile-fact* match, not an
  algorithm-implementation artifact.
- **Blocker (recorded, not faked):** the FoxIO reference *tool* cannot be executed offline
  without a new dependency or fetching third-party code (no public network). Two
  same-author implementations agreeing is weak independent confirmation. **Open step:**
  a one-off FoxIO-tool cross-check (e.g. in an environment that already vendors it) before
  registering official-JA4 parity.

## E. Go GREASE cross-field correlation (utls.HelloChrome_Auto, 10 hellos)

- **4–5 distinct GREASE values per hello** (NOT a single reused value).
- All GREASE slots **randomize per-hello** (cipher VARIES(7), ext-types VARIES(10),
  supported_groups VARIES(6), supported_versions VARIES(7), key_share VARIES(6)).
- **Hard correlations (10/10):** `supported_groups` GREASE value **==** `key_share` GREASE
  group value (a structural TLS rule: the GREASE key_share group must be one of the
  offered GREASE groups); the **two extension-type GREASE slots (head/tail) are always
  distinct** (no duplicate extension type).
- cipher GREASE and supported_versions GREASE are **independent draws** (cipher∩groups
  overlap 0/10).
- ECH-GREASE (`0xfe0d`) payload length cycles {186, 218, 250, 282}.

## F. Rust GREASE cross-field correlation (current, 10 hellos)

- **Same STRUCTURE as Go**: 5 distinct GREASE values; `supported_groups`==`key_share`
  (10/10); two distinct ext-type GREASE (10/10); ECH buckets {186,218,250,282}.
- **But every GREASE VALUE is FIXED** (stable across all 10): cipher `0xfafa`,
  supported_groups `0x4a4a`, supported_versions `0x6a6a`, key_share `0x4a4a`,
  ext-head `0xcaca`, ext-tail `0xaaaa`. Go randomizes all of these per-hello; Rust does not.

## G. Is randomizing the cipher GREASE alone enough?

**No.** Go randomizes **all six** GREASE slots; pinning only the cipher value would leave
five fixed GREASE values (groups/versions/key_share/ext-head/ext-tail), still trivially
separable from Chrome by a GREASE-value-entropy analyzer. The T3-0 "config-level small
fix = randomize the cipher GREASE" was **incomplete**; the correct change is a
**coordinated per-hello GREASE selector** (answers to the 8 questions are in the summary
JSON `answers`).

## H. Deterministic test-seam design (for T3-1C; NOT implemented here)

Extract a `GreaseSelector` seam that produces, per ClientHello, a **coordinated** GREASE
set from an **injectable** RNG/sequence (so tests are deterministic, never probabilistic):

- `cipher`, `supported_versions`: independent GREASE draws.
- `group`: **one** value used for **both** supported_groups and key_share (reproduces the
  Go `groups==key_share` invariant).
- `ext_head`, `ext_tail`: **two distinct** GREASE draws (guards the duplicate-extension-type
  risk by construction / re-draw).

Deterministic tests (no flaky "run N× expect ≥2 values" gate):
1. **Domain:** every produced value ∈ RFC 8701 GREASE set {0x0a0a…0xfafa}.
2. **Disjointness:** no produced value equals any real cipher suite / named group used.
3. **No duplicate ext type:** `ext_head != ext_tail` for all injected sequences (incl. a
   sequence that *would* collide if unguarded → assert the selector still returns distinct).
4. **Changes under control:** seed/sequence A → values X; seed B → values Y; assert X≠Y
   (proves variability deterministically, no probability).
5. **Correlation reproduced:** the single `group` value appears in **both** supported_groups
   and key_share.

Production may **log** GREASE entropy as a **non-blocking diagnostic**; it must **not** use
a probabilistic sample as a hard gate.

## I. Formal local harness design (NOT implemented)

Proposed `labs/interop-lab/reality_clienthello_parity/`:

| file | role |
|---|---|
| `README.md` | scope, tiers, blocking vs diagnostic, sanitization rules |
| `capture_clienthello.py` | transparent recorder; raw first-record per kernel → **temp dir only, cleaned on exit** |
| `parse_clienthello.py` | stdlib parser → normalized profile (placeholders for random/key_share/session_id/GREASE-ECH payload) |
| `compare_profiles.py` | Go-ref vs Rust: from-spec JA4 + normalized-profile digest + required-field-set parity; emits **sanitized** summary only |
| `run_check.py` | orchestrate capture→parse→compare; exit 0/non-0 |
| `fixtures/` (or `test_vectors/`) | committed **sanitized** reference: expected JA4 + normalized-profile digest + field set (NO raw bytes) |

Constraints: default save sanitized normalized summary only; raw ClientHello exists only
in a temp dir and is cleaned post-run; summary excludes raw session_id / key_share /
REALITY auth / token / private key; **no L4 raw-byte equality**; no public network; never
overwrite committed evidence; **not** wired to Makefile/L18 in this design.

## J. Blocking vs non-blocking boundary

**Blocking (a real gate may enforce):**
1. functional request token-match (as tier-1);
2. **official JA4 parity** — *only once* FoxIO-tool-verified; until then a from-spec-JA4
   **diagnostic**, not blocking;
3. normalized-profile digest parity (Go-ref == Rust);
4. required field-set parity (cipher tail, supported_groups, sigalgs-in-order,
   supported_versions, ALPN, key_share groups, extension set).

**Non-blocking diagnostics (record, never fail on):**
- GREASE entropy / per-slot value distribution;
- extension-order shuffle distribution;
- HelloChrome_Auto **drift** hint (if the captured Go profile diverges from the committed
  reference, flag for refresh — do not fail Rust);
- L4 raw bytes (informational only).

## K. golden_spec DEV-REALITY-01 revision wording (proposed; NOT applied this card)

Suggested amendment for a later card:
- **Retire** "live result remained 0/21 … accepted until Rust gains a uTLS-equivalent
  library" — it is stale.
- **Functional local REALITY client parity: CLOSED** (tier-1 fixture; L18-wired).
- A **Rust patched-rustls Chrome shaping layer EXISTS** (`build_chrome_client_hello_fingerprint`).
- **normalized-profile parity (static TLS fields): achieved** (Go HelloChrome_Auto == Rust).
- **from-spec JA4 parity: achieved; official-JA4 (FoxIO-tool) cross-check: PENDING** — do
  not record "official JA4 parity" until cross-checked.
- **raw byte identity (L4): NOT a goal.**
- **OPEN:** GREASE-value randomization parity (Rust values fixed → coordinated selector,
  T3-1C); extension-order shuffle-distribution equivalence; real-network camouflage
  sufficiency (tier-2); HelloChrome_Auto upstream drift.

## Verification / disposition

- `git diff --check` clean · check-boundaries strict **exit 0** · `cargo check --workspace
  --all-features` **PASS** (recorded at card close).
- Saved (this card): this report + `t31a_clienthello_grease_correlation_summary.json`
  (sanitized; hygiene-scanned). Ephemeral recorder/parsers/raw bytes stay in a scratch dir
  — **not committed**. No business-source / fixture / L18 / Makefile / CI / Cargo / labs
  formal-dir change. `a0_reality_spike/` untouched untracked.

## Next-card split (NOT executed)

- **T3-1B** — implement the formal local capture + profile-digest harness (§I) as a
  committed read-only tool; optionally perform the FoxIO-tool JA4 cross-check in an
  environment that vendors it.
- **T3-1C** — the coordinated GREASE-selector micro-fix (§H) in
  `build_chrome_client_hello_fingerprint`, behind the deterministic seam + tests; then amend
  golden_spec (§K). No public network; no uTLS-equivalent port.
