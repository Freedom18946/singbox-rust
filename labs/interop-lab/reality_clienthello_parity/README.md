<!-- tier: B -->
# REALITY ClientHello Parity Harness (local, read-only)

Formal local harness that compares the **Go reference client** (`utls.HelloChrome_Auto`)
against the **Rust candidate client** in the controlled local REALITY fixture, and checks
**relative ClientHello parity** — no public network, no business-source change.

It does **not** modify the Rust/Go clients, the patched rustls, the
`reality_local_fixture`, the `Makefile`, the L18 capstone, CI, or any canonical schema. It
reuses the fixture binaries and renders fixture configs into a **temporary** dir; raw
ClientHello records live only in a tempfile dir and are removed on exit.

## Three layers (what blocks vs what only informs)

**1. L2 blocking** (changes the exit code):
- live Go-vs-Rust **normalized-profile digest** parity;
- **required field-set** parity: cipher tail, supported_groups, signature_algorithms
  (order), supported_versions, ALPN, key_share groups+lengths, extension set, compression,
  session_id length+role, record-length buckets;
- functional **token-match** (both kernels);
- **redaction guard**: the emitted summary carries no raw auth/key material.

**2. Diagnostic** (recorded, never changes the exit code):
- **from-spec JA4** (`from_spec_ja4`) — the JA4 algorithm is cross-checked against FoxIO's
  OWN published reference values (`fixtures/foxio_reference_vectors/`, BSD-3 `LICENSE-JA4`),
  so its status is now `FOXIO_REFERENCE_VERIFIED`. The live go-vs-rust JA4 parity stays
  advisory in *this* run_check exit code; the authoritative blocking gate is the offline
  vendored-vector test `tests/test_foxio_reference_vectors.py`. Scope: algorithm/vector
  conformance, **not** a second-tool fingerprint of the live captures;
- **FoxIO reference cross-check** result (`foxio_reference.verify_against_vendored_vectors()`);
- **GREASE slot entropy** (fixed vs randomized) — the current Rust fixed values are
  **advisory only**;
- **extension-order distribution** (per-hello Chrome shuffle);
- **`fixtures/expected_profile_shape.json` drift** (Go reference vs committed snapshot) —
  advisory only; flags `HelloChrome_Auto` upstream drift; **never fails Rust**.

**3. Out of scope:** L4 raw byte equality; real-network camouflage sufficiency; active
probing resistance; tier-2 public cohort; permanently freezing the `HelloChrome_Auto`
browser fingerprint.

## Usage

```bash
python3 labs/interop-lab/reality_clienthello_parity/run_check.py --runs 10
```
Requires the fixture binaries (`make verify-reality-local` once builds them). Exit `0` iff
the **blocking** gates pass; advisory diagnostics never change the exit code. Output (a
**sanitized** `summary.json`) defaults to the gitignored
`labs/interop-lab/artifacts/reality_clienthello_parity/<run_id>/`; the committed
`reality_local_fixture/evidence/` is never touched.

`--debug-retain-raw` keeps raw ClientHello records on disk **with a loud warning** (they may
contain REALITY auth material). Default is off (tempfile, removed on exit).

## Files

| File | Role |
|------|------|
| `capture_clienthello.py` | transparent TCP recorder (raw record → tempfile, cleaned on exit) |
| `parse_clienthello.py` | stdlib parser → **redacted** normalized profile + `normalized_profile_digest` + `from_spec_ja4` |
| `compare_profiles.py` | blocking (token / field-set / digest / redaction) + advisory (JA4 / GREASE / order / drift) |
| `run_check.py` | orchestrate capture→parse→compare; exit 0/non-0; sanitized summary |
| `fixtures/expected_profile_shape.json` | **advisory-only** sanitized Go-reference shape snapshot |
| `fixtures/foxio_reference_vectors/` | vendored FoxIO BSD-3 JA4 reference vectors (`vectors.json` + `PROVENANCE.md` + `LICENSE-JA4`) |
| `foxio_reference.py` | FoxIO algorithm cross-check: from-spec JA4 == FoxIO published values (offline) |
| `tests/` | parser/compare/hygiene + FoxIO-vector unit tests (self-contained synthetic + FoxIO vectors) |

## Sanitization

The parser **never** emits: ClientHello random, raw session_id value, key_share key bytes,
GREASE-ECH payload, SNI hostname, the token, any private key, or raw ClientHello bytes.
GREASE **values** appear only in a clearly-separate `grease_markers` block (public RFC 8701
markers, advisory entropy only) and are **not** part of the digest / field-set parity.

## Snapshot caveat

`expected_profile_shape.json` is **advisory only**: `HelloChrome_Auto` drifts with upstream
Chrome, so the snapshot hash is **not** a permanent browser-fingerprint commitment. The
**blocking** gate is the **live Go-vs-Rust relative comparison**, not equality to the
snapshot.

## Status

T3-1B harness. `from_spec_ja4`'s algorithm is now cross-checked against FoxIO's OWN published
reference vectors (`fixtures/foxio_reference_vectors/`, BSD-3 `LICENSE-JA4`), enforced offline
by `tests/test_foxio_reference_vectors.py` — the official-JA4 cross-check is **CLOSED at the
algorithm level** (2026-07-12; scope: vector conformance, not a second-tool fingerprint of live
captures). The coordinated GREASE-selector fix (Rust randomizes GREASE like Chrome) is **T3-1C**;
golden_spec is amended in **T3-2** (`DEV-REALITY-01`).
