<!-- tier: B -->
# FoxIO JA4 Reference Vectors — Provenance

These vectors are the **authoritative FoxIO-published** JA4 values used to independently
cross-check this harness's from-spec JA4 algorithm (`parse_clienthello._from_spec_ja4`).
Before this, the harness's JA4 was a from-spec reimplementation with **no** independent
confirmation (`DIAGNOSTIC_PENDING_FOXIO_REFERENCE`, "offline-blocked, from-spec agreement
is weak independent confirmation" — golden_spec `DEV-REALITY-01`). Vendoring FoxIO's own
published values closes that gap at the algorithm level, fully offline and reproducible.

## Source

- Repository: `FoxIO-LLC/ja4` — <https://github.com/FoxIO-LLC/ja4>
- Commit: `0e54bc8371de34df94a35f2442c05bda2e8b2034` (`main`, fetched 2026-07-12)
- File: `technical_details/JA4.md`

## License

JA4 (TLS client fingerprinting) is released under a **BSD-3-Clause** license, held in the
repo's separate `LICENSE-JA4` file (copied verbatim here as `./LICENSE-JA4`). This is
**distinct** from the FoxIO License 1.1 (`LICENSE` in that repo), which is non-commercial
and covers only the JA4+ suite (JA4S/JA4H/JA4L/JA4X/JA4T/…). We vendor **only** base JA4
material, so BSD-3-Clause applies and permits redistribution with attribution. The copyright
notice and conditions are retained in `./LICENSE-JA4`.

## What each vector is

### `ja4_vectors[0]` — `foxio_ja4md_canonical_chrome`
The canonical worked example from JA4.md's "Example" + "Raw Output" sections. Its
`cipher_list_original_order` and `ext_type_list_original_order` are taken verbatim from the
published `JA4_ro` string; `sig_alg_list_in_order` from the same. The expected full
fingerprint `t13d1516h2_8daaf6152771_e5627efa2ab1` and the pre-hash intermediate strings
(`expected_ja4_b_sorted_input`, `expected_ja4_c_input`) are FoxIO's published values. Our
parser must reproduce all three segments.

Note: JA4.md's table-of-contents line shows an older `..._b186095e22b6` triad; the fully
derived worked example (with input strings shown) is `..._e5627efa2ab1`, which is the value
used here.

### `alpn_segment_vectors[*]`
The ALPN `a`-segment mapping table published in JA4.md ("ALPN Extension Value"). Covers the
plain cases (`h2`, `http/1.1`) and the documented **non-alphanumeric → hex** rule with all
eight worked byte patterns (e.g. `0xAB 0xCD → "ad"`, `0x30 0xAB 0xCD 0x31 → "01"`). These
lock the ALPN-segment code path that mainstream `h2` traffic never exercises.

## How they are consumed

`foxio_reference.py::verify_against_vendored_vectors()` and
`tests/test_foxio_reference_vectors.py` load this file and assert that
`parse_clienthello.from_spec_ja4_from_fields(...)` reproduces every `expected_ja4` and every
ALPN-segment `expected`. All stdlib, no network, no external tool.

## Scope caveat

This closes the **algorithm-level** FoxIO cross-check (our JA4 computation == FoxIO's own
published JA4). It does **not** claim: extension-order statistical-distribution equivalence,
`HelloChrome_Auto` upstream drift tracking, real-network camouflage, or byte-level identity —
those REALITY tails remain OPEN (see golden_spec three-tier model).
