<!-- tier: B -->
# T3-1B — REALITY ClientHello Parity Harness (checkpoint)

Implements the formal, local, read-only, no-public-network ClientHello-parity harness
designed in T3-1A. Tracked code is confined to
`labs/interop-lab/reality_clienthello_parity/`; this report is the agents-only checkpoint.
**No Rust/Go business-source change, no `GreaseSelector` implementation, no patched-rustls
change, no Makefile/L18/CI change, no golden_spec change, no public network.**

## C. File listing

```
labs/interop-lab/reality_clienthello_parity/
  README.md                         3-layer doc (L2 blocking / diagnostic / out-of-scope)
  capture_clienthello.py            transparent TCP recorder (raw → tempfile, cleaned on exit)
  parse_clienthello.py              stdlib redacting parser → normalized profile + digest + from-spec JA4
  compare_profiles.py               blocking (token/field-set/digest/redaction) + advisory diagnostics
  run_check.py                      orchestrator; exit 0/non-0; sanitized summary
  fixtures/expected_profile_shape.json   advisory-only Go-reference shape snapshot
  tests/test_parse_clienthello.py        11 parser redaction/structure/malformed tests
  tests/test_compare_profiles.py         10 blocking/advisory boundary tests
  tests/vectors/sanitized_clienthello_shape.json   sanitized reference profile
```

## D. Harness topology

```
client → recorder(:configurable, default 28443) → reality_server(:18443)
         → tls_dest(:18444) → http_target(:18445)
```
`run_check.py` renders the fixture configs into a **temp** dir, repoints the client configs'
server port to the recorder (committed manifest untouched), brings up the fixture topology
(fixed ports unchanged), records the first client→server TLS record per connection into a
`tempfile.TemporaryDirectory` (removed on exit), runs Go + Rust clients N×, token-matches,
parses, compares, writes a sanitized `summary.json` to the gitignored
`labs/interop-lab/artifacts/reality_clienthello_parity/<run_id>/`. Binaries reused from
`target/`; no root / tcpdump / openssl / socat.

## E. Parser redaction strategy

Never emits: ClientHello `random` (→ `"<redacted>"`), session_id value (length + role
`reality-auth-redacted` only), key_share key bytes (group + length only), GREASE-ECH payload
(length only), SNI hostname (name length only), token, private key, raw ClientHello. GREASE
**values** appear ONLY in a separate `grease_markers` block (public RFC 8701 markers,
advisory entropy only) and are **not** in the digest / field-set parity (which use GREASE as
a category, so they stay stable across Go's per-hello randomization). Malformed / truncated
records raise `ValueError`.

## F. Blocking checks (affect exit code) — all PASS

| check | result |
|---|---|
| functional token-match (Go, Rust) | **PASS** (10/10 each) |
| normalized_profile_digest parity | **PASS** — Go == Rust == `bc002612a968fae0` (single value each) |
| required field-set parity | **PASS** — identical shape; record-length **ladder** parity (single residue mod 32, span 96 = 3×32) |
| redaction guard | **PASS** — no raw auth/key material in the emitted summary |

Record-length parity is the **32-spaced ladder** (residue + bounded span), **not** exact
bucket-set equality — the latter is per-run sampling-dependent (a 10-run sample may miss a
bucket) and would be flaky, so it is advisory.

## G. Advisory diagnostics (never change exit code)

- **from_spec_ja4**: Go == Rust == `t13d1516h2_8daaf6152771_d8a2da3f94cd`, status
  `DIAGNOSTIC_PENDING_FOXIO_REFERENCE` — **not** a blocking gate, **not** "official JA4 parity".
- **GREASE entropy**: Rust = **FIXED** across all slots (advisory, does **not** fail T3-1B);
  Go = RANDOMIZED. (This is exactly the T3-1C target.)
- **extension-order distribution**: both randomize per-hello (Chrome shuffle); advisory.
- **record-length exact bucket sets**: advisory (sampling-dependent).
- **snapshot drift**: `drift_detected=false` vs `expected_profile_shape.json`; advisory-only,
  never fails Rust.

## H. FoxIO reference cross-check status

**`FOXIO_REFERENCE_CROSSCHECK = DEFERRED`.** This card runs no public network, so the FoxIO
reference tool was not fetched/run; no third-party code copied, no dependency added. The
`from_spec_ja4` digest stays a **non-blocking diagnostic**; **official JA4 parity is NOT
claimed closed.** Promotion of `from_spec_ja4` to a blocking diagnostic is gated on a future
FoxIO-tool cross-check (in an environment that already vendors it).

## I. `run_check.py --runs 10` result

`EXIT=0`, `blocking_pass=true`, go=10 rust=10, token-match pass, digest parity pass
(`bc002612a968fae0`), field-set + ladder parity pass. Re-run with the snapshot present:
`snapshot_drift.drift_detected=false`. Ports released; raw temp records removed on exit;
committed evidence zero churn.

## J. Python tests

`python3 -m unittest discover -s labs/interop-lab/reality_clienthello_parity/tests` →
**21 tests OK** (11 parser: redaction of random/session_id/key_share/GREASE-ECH/hostname,
structure preserved, malformed/truncated/non-handshake rejected; 10 compare: identical PASS,
token/field/digest mismatch FAIL, snapshot-drift + Rust-fixed-GREASE + ext-order advisory,
raw-forbidden-material + session_id-value FAIL).

## K. Summary hygiene

Committed snapshot + vector + code scanned: **no** hostname / token / fixture credentials /
private key / absolute path / `/tmp` path / 32+hex blob (no raw session_id/key). Artifacts
summary (gitignored) likewise carries no hex blobs. `__pycache__/*.pyc` are gitignored and
removed.

## L. Known boundaries

- `from_spec_ja4` ≠ official FoxIO JA4 until cross-checked (DEFERRED).
- Rust GREASE values are fixed (advisory) — relative parity passes, but it is not yet
  Chrome-like per-hello GREASE randomization (T3-1C).
- record-length parity uses the ladder invariant, not exact bucket-set equality.
- snapshot is advisory-only (HelloChrome_Auto drifts).
- L4 raw-byte equality, real-network camouflage sufficiency, active-probing resistance, and
  tier-2 public cohort are **out of scope**.

## M. T3-1C preconditions

1. This harness committed (blocking parity gate available as a regression check).
2. Extract a deterministic `GreaseSelector` seam (injectable RNG) preserving the two
   invariants (supported_groups GREASE == key_share GREASE; two distinct ext-type GREASE),
   with the deterministic tests from T3-1A §H (domain / disjointness / no-dup-ext /
   changes-under-control / correlation-reproduced) — **no probabilistic gate**.
3. Wire it into `build_chrome_client_hello_fingerprint` (the only Rust change).
4. Re-run this harness: blocking parity stays PASS; the **GREASE-entropy advisory should flip
   Rust slots to RANDOMIZED**.
5. Amend golden_spec DEV-REALITY-01 in **T3-2** (not T3-1C).

## Disposition

Saved: this report. Harness code is staged-ready under
`labs/interop-lab/reality_clienthello_parity/` (uncommitted). Ephemeral recorder raw
records / temp configs are not committed. Stop at the T3-1B commit proposal; do not enter
T3-1C.
