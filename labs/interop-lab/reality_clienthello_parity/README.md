<!-- tier: B -->
# REALITY ClientHello Parity Harness (local, read-only)

Formal local harness with two explicit lanes: Chrome-current camouflage checks Rust against
sanitized full-browser Chrome canary; pinned Go/uTLS checks functional compatibility. No public
network during gate execution.

It does **not** modify the Rust/Go clients, the patched rustls, the
`reality_local_fixture`, the `Makefile`, the L18 capstone, CI, or any canonical schema. It
reuses the fixture binaries and renders fixture configs into a **temporary** dir; raw
ClientHello records live only in a tempfile dir and are removed on exit.

## Three layers (what blocks vs what only informs)

**1. Blocking** (changes the exit code):
- Rust **Chrome-current REALITY shape** against
  `../reality_chrome_canary/fixtures/chrome_150_stable_mac_arm64.json`;
- Chrome-current JA4 and 32-byte record-length ladder;
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
- pinned Go/uTLS v1.8.4 vs Rust field-set/digest parity. Expected to differ after Chrome-current
  advances; this lane proves compatibility, not current-browser camouflage;
- **GREASE slot entropy**;
- **extension-order distribution** (per-hello Chrome shuffle);
- **`fixtures/expected_profile_shape.json` drift** for pinned Go reference.

**3. Out of scope:** L4 raw byte equality; real-network camouflage sufficiency; active probing
resistance; tier-2 public cohort.

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
| `compare_profiles.py` | blocking Chrome-current shape/JA4 + token/redaction; advisory Go-compat/profile diagnostics |
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

`expected_profile_shape.json` is advisory pinned-Go history. Browser-current authority lives in
`../reality_chrome_canary/`; product/version/provenance are explicit and refreshable.

## Status

Chrome-current lane targets full Chrome 150.0.7871.115: `trust_anchors`, ML-DSA signature schemes,
BoringSSL-style wide-entropy Fisher-Yates order, independently sampled ECH bucket/GREASE. Go
v1.8.4 `HelloChrome_133` remains compatibility-only. FoxIO JA4 algorithm remains verified by
vendored BSD-3 vectors.
