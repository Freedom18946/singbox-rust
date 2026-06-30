<!-- tier: B -->
# T3-0 — REALITY ClientHello Fingerprint Parity Scoping (evaluation)

Read-only scoping for tier-3 of the REALITY acceptance model (ClientHello byte-level
fingerprint parity). **Code review + local controlled capture + normalized diff +
engineering decision only. No uTLS-equivalent implementation, no public network, no
business-source change, no T3-1.** Machine summary:
`agents-only/archive/release-cleanup-2026-06/reality-tier3/t30_clienthello_capture_summary.json` (sanitized: normalized/hashed only).

> **Headline:** the Rust REALITY client is **not** naive rustls — it carries a
> hand-rolled uTLS-Chrome emulation (the FIX-04/FIX-05 work) that **already achieves
> JA4-equivalent (L2) classifier parity** with the Go `utls.HelloChrome_Auto` reference.
> Only **two minor residuals** remain. **Recommended decision: option 2 — a config-level
> small fix** (randomize the GREASE cipher value), with tier-3 acceptance defined at **L2
> (JA4)**; do **not** open a uTLS-equivalent project.

## A. Authoritative context read

CLAUDE.md · active_context.md · a22_reality_local_capstone_wiring.md ·
reality_local_fixture/{README.md,manifest.json} · dual_kernel_golden_spec.md (S4,
DEV-REALITY-01) · reference/reality_historical_projection_contract.md ·
`git log -18` (HEAD `e44c67d3` ✓) · `git status` (only `a0_reality_spike/` untracked ✓).
tier-1 closed + L18-wired; tier-2 pre-release only; tier-3 OPEN.

## B. Reference & candidate call chains (file:line)

**Go reference (uTLS):**
- `common/tls/utls_client.go:251-278` maps fingerprint `"chrome"` → **`utls.HelloChrome_Auto`**;
  `Client()` (`:61`) wraps the conn via `utls.UClient(conn, cfg, c.id)`.
- `common/tls/reality_client.go:112` `uConn := utls.UClient(conn, uConfig, e.uClient.id)`
  builds/sends the ClientHello; `:119-126` **filters `X25519MLKEM768`** out of
  SupportedCurves + KeyShares; REALITY auth is injected via the uTLS
  `SessionIDGenerator` (`utls_client.go:64`).

**Rust candidate (patched rustls + hand-rolled Chrome shaping):**
- `crates/sb-tls/src/reality/handshake.rs:528 build_client_config` builds a **patched**
  rustls `ClientConfig` with TLS1.3, a custom cert verifier, and:
  - `:543 config.session_id_generator = RealitySessionIdGenerator{...}` — REALITY auth in
    the session_id (`:1302 build_reality_plaintext_session_id`).
  - `:548 config.fingerprint = build_chrome_client_hello_fingerprint(...)` — the
    `ClientHelloFingerprint` spec (`:577-609`): GREASE head/tail, SCT, compress_certificate,
    ALPS h2, GREASE-ECH (`:814`), Chrome cipher tail, supported_versions/groups GREASE,
    8-entry sigalgs, key_share GREASE, and a **per-hello extension shuffle**
    (`:698 build_chrome_extension_order`, seed sampler with payload-len buckets).
  - `:549 config.alpn_protocols`; `:897 build_crypto_provider` (ring; optional `utls`
    feature maps cipher_suites/kx_groups).
- **direct_reality vs transport_reality** share this single `build_client_config` path
  (one REALITY connector; the phase probe exercises phases of one handshake) — confirmed
  by capture (both Rust runs produce the same normalized profile).
- **Why functional gate passes but parity was "open":** L0 (handshake + VLESS dataplane)
  only needs a working REALITY auth + TLS1.3, which both do; fingerprint parity is an
  independent, finer axis (L1–L4). The golden_spec's "rustls lacks uTLS-equivalent / 0/21"
  framing predates the FIX-04/FIX-05 shaping layer and is now **stale**.

## C. Reference profile

`utls.HelloChrome_Auto` (github.com/metacubex/utls) — the auto-latest Chrome profile,
with `X25519MLKEM768` filtered for REALITY. ALPN `h2,http/1.1`; TLS1.3; per-hello GREASE +
extension shuffle. (HelloChrome_Auto auto-updates → a drift axis, see §must-stay-open.)

## D. Local recorder topology

Transparent stdlib TCP recorder (ephemeral, not committed) in front of the local
fixture server; client configs repointed to the recorder via a /tmp rendered copy (the
committed manifest/evidence untouched):

```
client → recorder(:28443, captures 1st client→server TLS record) → reality_server(:18443)
         → tls_dest(:18444) → http_target(:18445)
```
Per connection: capture the full first TLS record (the ClientHello), then relay both
directions so the functional request still succeeds. Binaries reused from `target/`.

## E. Sampling matrix & success

| kernel | curl token-match | ClientHellos captured |
|---|---|---|
| Go (`utls.HelloChrome_Auto`) | **10/10** | **10** |
| Rust (`app`) | **10/10** | **10** |

direct/transport share one handshake path → no separate direct/transport split needed
(recorded as shared). Every run: functional OK, full first record captured, teardown
complete, five ports + recorder port released, committed evidence + tracked tree zero churn.

## F. Intra-kernel stability (10 samples each)

Both kernels: `legacy_version`, `session_id_len`(32), `compression_methods`([0]),
`supported_groups`, `signature_algorithms`, `alpn`, `supported_versions`,
`key_share_groups`, cipher-GREASE position, extension-GREASE position = **STABLE**;
`extension order` = **VARIES (10/10 distinct)** — per-hello shuffle (Chrome behaviour),
reproduced by Rust; `record_len` ladder = **{500,532,564,596}** (identical, the
GREASE-ECH payload buckets). **Difference:** Go cipher list VARIES (GREASE cipher value
randomizes per-hello); Rust cipher list STABLE (GREASE cipher pinned `0xfafa`).

## G. Normalization rules

Preserve existence / order / length / group type / GREASE position+category. Replace
with placeholders (never compared as raw): ClientHello `random`; `key_share` key bytes
(keep group + key_len); REALITY-auth `session_id` value (keep length + role); GREASE-ECH
payload (keep length). GREASE kept as a **category at its position**, not deleted. Output
= normalized JSON + (intentionally) no raw bytes.

## H. Go vs Rust normalized diff

**IDENTICAL (Go == Rust):** cipher tail (15 suites, in order), `supported_groups`
`[GREASE,x25519,secp256r1,secp384r1]`, `signature_algorithms` (8, in order), `alpn`
`[h2,http/1.1]`, `supported_versions` `[GREASE,1.3,1.2]`, `key_share_groups`
`[GREASE(1B),x25519(32B)]`, `compression` `[0]`, `session_id_len`(32), SNI name_len,
record-len ladder, **extension SET (16, incl ALPS `0x44cd`)**, cipher-GREASE position.

**DIFFERENCES (only two):**
1. **GREASE cipher value** (cipher index 0): Go randomizes per-hello (7 distinct in 10);
   Rust pinned `0xfafa`. Cipher tail identical. → `EXPECTED_RANDOMNESS` (Go) vs
   `PROFILE_STABLE_DIFFERENCE` (Rust). Normalized away by official JA3 (ignores GREASE)
   and the local JA4-equivalent digest; other passive/custom classifiers out of scope.
   **Trivially fixable.**
2. **Extension exact order**: both shuffle per-hello (set identical); sequences differ
   between implementations. → `REALITY_PROTOCOL_VARIABILITY`/`EXPECTED_RANDOMNESS`; the
   shuffle *distribution* equivalence is `UNKNOWN_REQUIRES_RESEARCH` (classifier-irrelevant
   at JA3/JA4 since both shuffle).

No `PROFILE_STABLE_DIFFERENCE` in any *static* profile field; no missing/extra extension;
no `CLASSIFIER_RELEVANT_DIFFERENCE` at JA4.

## I. JA3 / JA4-equivalent

- **JA3 (classic & GREASE-stripped): UNSTABLE for BOTH** — Chrome per-hello extension
  shuffle ⇒ 10 distinct JA3 per kernel (classic distinct = 10/10). JA3 is therefore **not
  a valid parity metric here** (its known limitation: order-sensitive, can't represent
  payloads).
- **JA4-equivalent: IDENTICAL** — Go == Rust == `t13d1516h2_8daaf6152771_d8a2da3f94cd`
  (structural approximation: sorted, GREASE-stripped; **not** the official ja4 tool — a
  regression digest only). At the modern GREASE-robust classifier level the Rust hello is
  **indistinguishable** from Go uTLS Chrome.

## J. Camouflage-relevant risk judgement

- The two residuals are **LOW** camouflage risk: GREASE-value entropy and exact
  extension order are normalized by official JA3 (ignores GREASE) and by the local
  JA4-equivalent digest; other passive/custom classifiers are out of scope. (JARM is a
  *server* fingerprint, not a ClientHello-parity criterion.) A non-GREASE-aware
  classifier could note Rust's constant `0xfafa`, but that is an unusually weak signal.
- **Functional interop ≠ camouflage sufficiency.** A passing local JA4 parity does NOT
  prove a real censor cannot distinguish via active probing or traffic analysis; that is
  tier-2 (public observation) territory and must not be conflated with byte parity.
- **Do not** claim L4 byte identity — random/key_share/session_id/GREASE-ECH/ext-order
  vary per-hello in BOTH (two real Chrome instances also differ byte-for-byte).

## K. Route comparison

| Route | Verdict |
|---|---|
| **A. status quo (functional closed, tier-3 OPEN, document)** | under-sells: L2 is actually achieved; leaves a free, near-zero-cost fix on the table |
| **B. Rust backend config-level tweak** | **fits**: randomize the GREASE cipher value (closes residual #1) using the existing `ClientHelloFingerprint` surface; no new TLS impl; minutes of work |
| **C. add a ClientHello shaping layer** | **already done** (FIX-04/FIX-05 `build_chrome_client_hello_fingerprint`); no new layer needed |
| **D. uTLS-equivalent big project (fork/FFI/replace backend)** | **rejected**: huge maintenance for marginal gain; L2 is already met by the hand-rolled emulation; residuals don't justify it |
| **E. drop parity → camouflage-sufficiency observation** | complementary (tier-2), not a substitute; L2 parity is essentially in hand |

## L. Project decision — **option 2 (config-level small fix)** (unique)

Adopt **option 2**. Rationale: L2 (JA4) parity is **already achieved**; the single
clearly-actionable, near-zero-cost improvement is to **randomize the Rust GREASE cipher
value** (residual #1) so it matches Chrome/uTLS GREASE behaviour. This is a localized edit
to `build_chrome_client_hello_fingerprint` (the `grease_ciphersuite` field), no new TLS
backend, no shaping layer, no fork. The extension-shuffle distribution (residual #2) stays
**OPEN/UNKNOWN** and must not be claimed closed. Reject option 4 (uTLS-equivalent) as
disproportionate. (T3-0 is scoping only — the edit itself is the next card.)

Answers to the decision questions:
- **Stable profile difference Go/Rust?** No static-field difference; the only stable
  difference is Rust's pinned GREASE cipher value (residual #1).
- **Classifier-only or camouflage-affecting?** Classifier-irrelevant at JA4; residuals are
  at most very-low camouflage relevance.
- **Low-cost fixable item?** Yes — randomize the GREASE cipher value.
- **Worth long-term maintenance for the remainder?** No — a uTLS-equivalent port is not
  justified for residual #2.
- **tier-3 acceptance kaliber?** **L2 (JA4-equivalent)** as the closeable bar, with an L3
  normalized-structure check as a stronger documented gate; L4 explicitly not a goal.
- **What must stay OPEN?** extension-shuffle distribution equivalence; real-network
  camouflage sufficiency (tier-2); HelloChrome_Auto version drift.

## M. Recommended tier-3 acceptance kaliber

- **Closeable bar = L2:** a committed local capture+JA4-equivalent check
  (Go-reference == Rust JA4 over N hellos) — promote the ephemeral harness used here into a
  committed read-only tool (a future card), analogous to the tier-1 fixture.
- **Stronger documented gate = L3:** normalized-structure equality (cipher tail, groups,
  sigalgs, versions, ALPN, key_share groups, extension set, record-len ladder) — already
  passing.
- **Not a goal = L4** (raw byte identity) — impossible for a randomized Chrome hello.
- **Permanently OPEN (must not be faked closed):** shuffle-distribution equivalence;
  camouflage sufficiency; Chrome-Auto drift.

## N. strict boundary / workspace build

- `git diff --check`: clean · check-boundaries strict: **exit 0** ·
  `cargo check --workspace --all-features`: **PASS**. (Recorded at card close.)

## O. git status --short

Tracked tree clean apart from the two new agents-only artifacts; `a0_reality_spike/`
untouched untracked. No business-source / Cargo / fixture / L18 / Makefile / CI / .github /
labs-schema change. (Live output at card close.)

## P. Disposition / next card

- **Saved (this card):** this report + `t30_clienthello_capture_summary.json` (sanitized).
  Ephemeral recorder/parser/configs/raw bytes stay in a scratch dir — **not committed**.
- **Next card (NOT executed): T3-1** — the option-2 config fix (randomize the GREASE
  cipher value in `build_chrome_client_hello_fingerprint`) + promote the capture+JA4
  harness to a committed read-only tier-3 acceptance check. Then update golden_spec
  DEV-REALITY-01 to reflect the achieved L2 parity (retire the stale "0/21 / needs uTLS").
  No public network; no uTLS-equivalent port.
