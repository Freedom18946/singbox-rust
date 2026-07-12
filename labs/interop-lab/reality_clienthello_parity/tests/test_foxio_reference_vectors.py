#!/usr/bin/env python3
"""Blocking, offline cross-check: the from-spec JA4 algorithm MUST reproduce FoxIO's OWN
published reference vectors (fixtures/foxio_reference_vectors/, BSD-3 LICENSE-JA4). This is
the gate that closes the official-JA4 cross-check at the ALGORITHM level (golden_spec
DEV-REALITY-01). Self-contained, stdlib only, no capture / network / external tool.
Run: python3 -m unittest discover -s labs/interop-lab/reality_clienthello_parity/tests
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import foxio_reference as F  # noqa: E402
import parse_clienthello as P  # noqa: E402


class TestFoxioReferenceVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = F.load_vectors()

    def test_vendored_vectors_present(self):
        self.assertTrue(self.data.get("ja4_vectors"), "no FoxIO JA4 vectors vendored")
        self.assertTrue(self.data.get("alpn_segment_vectors"), "no FoxIO ALPN vectors vendored")
        self.assertTrue(self.data.get("_meta", {}).get("source_commit"), "provenance commit missing")

    def test_ja4_vectors_match_foxio(self):
        for vec in self.data["ja4_vectors"]:
            got, exp = F._check_ja4_vector(vec)
            self.assertEqual(got, exp, f"JA4 mismatch for {vec.get('name')}: {got} != {exp}")

    def test_alpn_segment_vectors_match_foxio(self):
        for vec in self.data["alpn_segment_vectors"]:
            got, exp = F._check_alpn_vector(vec)
            self.assertEqual(got, exp, f"ALPN mismatch for {vec.get('name')}: {got!r} != {exp!r}")

    def test_verify_reports_verified(self):
        r = F.verify_against_vendored_vectors()
        self.assertEqual(r["status"], "FOXIO_REFERENCE_VERIFIED", r["mismatches"])
        self.assertEqual(r["mismatches"], [])
        expected_checked = len(self.data["ja4_vectors"]) + len(self.data["alpn_segment_vectors"])
        self.assertEqual(r["checked"], expected_checked)

    def test_status_constant_reflects_verification(self):
        self.assertEqual(P.FROM_SPEC_JA4_STATUS, "FOXIO_REFERENCE_VERIFIED")


if __name__ == "__main__":
    unittest.main()
