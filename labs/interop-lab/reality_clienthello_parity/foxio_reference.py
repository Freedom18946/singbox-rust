#!/usr/bin/env python3
"""FoxIO reference cross-check for the from-spec JA4 algorithm.

Loads FoxIO's OWN published JA4 vectors (`fixtures/foxio_reference_vectors/`, BSD-3
`LICENSE-JA4`) and confirms `parse_clienthello`'s from-spec JA4 computation reproduces
them. This is the independent authority that closes the official-JA4 cross-check at the
ALGORITHM level (golden_spec `DEV-REALITY-01`): previously the harness's JA4 was a
from-spec reimplementation with no independent confirmation. Fully offline, stdlib only,
no external tool (tshark / scapy / ja4 module NOT required).

Scope: this cross-checks the JA4 *computation* against FoxIO's authority. It does NOT
cover extension-order statistical distribution, `HelloChrome_Auto` drift, or real-network
camouflage — those REALITY tails stay OPEN.
"""
import json
import os

import parse_clienthello as P

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.join(HERE, "fixtures", "foxio_reference_vectors", "vectors.json")


def load_vectors(path=VECTORS):
    with open(path) as f:
        return json.load(f)


def _check_ja4_vector(vec):
    """Run the from-spec algorithm over one full FoxIO JA4 vector -> (got, expected)."""
    alpn = bytes.fromhex(vec.get("alpn_first_hex", "")).decode("latin1")
    got = P.from_spec_ja4_from_fields(
        transport=vec.get("transport", "t"),
        tls_version_2c=vec["tls_version_2c"],
        sni_present=vec["sni_present"],
        cipher_list=vec["cipher_list_original_order"],
        ext_type_list=vec["ext_type_list_original_order"],
        sig_alg_list=vec["sig_alg_list_in_order"],
        first_alpn=alpn,
    )["from_spec_ja4"]
    return got, vec["expected_ja4"]


def _check_alpn_vector(vec):
    """Run the ALPN a-segment rule over one FoxIO ALPN vector -> (got, expected)."""
    s = bytes.fromhex(vec.get("alpn_first_hex", "")).decode("latin1")
    return P._ja4_alpn_segment(s), vec["expected"]


def verify_against_vendored_vectors(path=VECTORS):
    """Return a sanitized cross-check result. status == 'FOXIO_REFERENCE_VERIFIED' iff every
    vendored FoxIO vector is reproduced by the from-spec algorithm; else lists mismatches."""
    data = load_vectors(path)
    meta = data.get("_meta", {})
    mismatches = []
    checked = 0
    for vec in data.get("ja4_vectors", []):
        got, exp = _check_ja4_vector(vec)
        checked += 1
        if got != exp:
            mismatches.append({"name": vec.get("name"), "kind": "ja4", "got": got, "expected": exp})
    for vec in data.get("alpn_segment_vectors", []):
        got, exp = _check_alpn_vector(vec)
        checked += 1
        if got != exp:
            mismatches.append({"name": vec.get("name"), "kind": "alpn_segment", "got": got, "expected": exp})
    return {
        "status": "FOXIO_REFERENCE_VERIFIED" if not mismatches else "FOXIO_REFERENCE_MISMATCH",
        "checked": checked,
        "mismatches": mismatches,
        "source": meta.get("source"),
        "source_commit": meta.get("source_commit"),
        "license": "BSD-3-Clause (LICENSE-JA4)",
        "_note": "algorithm-level cross-check: from-spec JA4 == FoxIO published values; offline, "
                 "stdlib only. Does NOT cover ext-order distribution / HelloChrome_Auto drift / "
                 "real-network camouflage (those REALITY tails stay OPEN).",
    }


if __name__ == "__main__":
    import sys
    r = verify_against_vendored_vectors()
    print(json.dumps(r, indent=2))
    sys.exit(0 if r["status"] == "FOXIO_REFERENCE_VERIFIED" else 1)
