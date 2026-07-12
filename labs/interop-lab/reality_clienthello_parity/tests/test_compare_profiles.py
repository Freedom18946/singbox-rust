#!/usr/bin/env python3
"""Unit tests for compare_profiles (blocking vs advisory boundaries).
Run: python3 -m unittest discover -s labs/interop-lab/reality_clienthello_parity/tests
"""
import copy
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import compare_profiles as C  # noqa: E402

BASE_SHAPE = {
    "cipher_tail_no_grease": ["0x1301", "0x1302", "0x1303"],
    "supported_groups": ["GREASE", "0x001d", "0x0017"],
    "signature_algorithms_in_order": ["0x0403", "0x0804"],
    "supported_versions": ["GREASE", "0x0304", "0x0303"],
    "alpn": ["h2", "http/1.1"],
    "key_share_groups": [{"group": "GREASE", "key_length": 1}, {"group": "0x001d", "key_length": 32}],
    "trust_anchors": {"list_length": 0, "payload_length": 2},
    "extension_set_sorted_grease_as_category": ["alpn", "key_share", "server_name", "supported_groups"],
    "compression_methods": [0],
    "session_id_length": 32, "session_id_role": "reality-auth-redacted",
}


def prof(digest="d0", shape=None, ja4="t13d1516h2_aa_bb", reclen=500, gm=None, order=None,
         random="<redacted>", sid=None):
    shape = shape if shape is not None else copy.deepcopy(BASE_SHAPE)
    gm = gm if gm is not None else {"cipher": ["0xfafa"], "extension_types": ["0xcaca", "0xaaaa"],
                                    "supported_groups": ["0x4a4a"], "supported_versions": ["0x6a6a"],
                                    "key_share_groups": ["0x4a4a"]}
    order = order if order is not None else ["GREASE", "server_name", "supported_groups", "key_share", "alpn", "GREASE"]
    return {
        "record": {"record_length": reclen},
        "client_hello": {"random": random, "session_id": (sid if sid is not None else {"length": 32, "role": "reality-auth-redacted"})},
        "extensions": {"ordered_categories": order, "key_share": [{"group": "0x001d", "key_length": 32}]},
        "grease_markers": gm,
        "derived": {"normalized_profile_digest": digest, "required_field_shape": shape, "from_spec_ja4": ja4},
    }


class TestCompare(unittest.TestCase):
    def test_identical_pass(self):
        go = [prof() for _ in range(3)]
        rust = [prof() for _ in range(3)]
        r = C.compare(go, rust, True, True)
        self.assertTrue(r["blocking_pass"])
        self.assertTrue(r["blocking"]["normalized_profile_digest_parity"]["pass"])
        self.assertTrue(r["blocking"]["required_field_set_parity"]["pass"])

    def test_token_fail_blocks(self):
        r = C.compare([prof()], [prof()], True, False)
        self.assertFalse(r["blocking_pass"])
        self.assertFalse(r["blocking"]["token_match"]["pass"])

    def test_missing_required_field_fails(self):
        bad = copy.deepcopy(BASE_SHAPE); del bad["alpn"]
        r = C.compare([prof()], [prof(shape=bad)], True, True)
        self.assertFalse(r["blocking_pass"])
        self.assertFalse(r["blocking"]["required_field_set_parity"]["pass"])

    def test_digest_mismatch_fails(self):
        r = C.compare([prof(digest="aaa")], [prof(digest="bbb")], True, True)
        self.assertFalse(r["blocking_pass"])
        self.assertFalse(r["blocking"]["normalized_profile_digest_parity"]["pass"])

    def test_record_bucket_mismatch_fails(self):
        r = C.compare([prof(reclen=500)], [prof(reclen=999)], True, True)
        self.assertFalse(r["blocking"]["required_field_set_parity"]["pass"])

    def test_snapshot_drift_advisory_only(self):
        snap = {"required_field_shape": copy.deepcopy(BASE_SHAPE),
                "normalized_profile_digest": "OLDDIGEST", "from_spec_ja4": "t99old"}
        r = C.compare([prof(digest="d0")], [prof(digest="d0")], True, True, snap)
        self.assertTrue(r["blocking_pass"])  # drift does NOT block
        self.assertTrue(r["advisory"]["snapshot_drift"]["drift_detected"])

    def test_chrome_current_lane_blocks_rust_drift_not_go_legacy_drift(self):
        current = {
            "provenance": {"version": "150.0.7871.115"},
            "reality_expected_shape": copy.deepcopy(BASE_SHAPE),
            "reality_record_length_ladder_spacing": 32,
            "reality_from_spec_ja4": "t13d1516h2_aa_bb",
        }
        old_go = copy.deepcopy(BASE_SHAPE)
        old_go["signature_algorithms_in_order"] = ["0x0403"]
        r = C.compare([prof(shape=old_go)], [prof()], True, True, chrome_current=current)
        self.assertTrue(r["blocking_pass"])
        self.assertTrue(r["blocking"]["chrome_current_reality_shape"]["pass"])
        self.assertFalse(r["advisory"]["go_compat_profile_parity"]["field_set"]["pass"])

    def test_chrome_current_lane_rejects_rust_shape_drift(self):
        current = {
            "provenance": {"version": "150.0.7871.115"},
            "reality_expected_shape": copy.deepcopy(BASE_SHAPE),
            "reality_record_length_ladder_spacing": 32,
            "reality_from_spec_ja4": "t13d1516h2_aa_bb",
        }
        bad = copy.deepcopy(BASE_SHAPE)
        bad["trust_anchors"] = None
        r = C.compare([prof()], [prof(shape=bad)], True, True, chrome_current=current)
        self.assertFalse(r["blocking_pass"])

    def test_rust_fixed_grease_advisory_only(self):
        # rust GREASE fixed (1 distinct), go randomized — advisory, must not block
        go = [prof(gm={"cipher": [hex(0x0a0a + i * 0x1010)], "extension_types": ["0xcaca", "0xaaaa"],
                       "supported_groups": ["0x4a4a"], "supported_versions": ["0x6a6a"],
                       "key_share_groups": ["0x4a4a"]}) for i in range(3)]
        rust = [prof() for _ in range(3)]
        r = C.compare(go, rust, True, True)
        self.assertTrue(r["blocking_pass"])
        self.assertEqual(r["advisory"]["grease_entropy"]["rust"]["cipher"]["state"], "FIXED")
        self.assertEqual(r["advisory"]["grease_entropy"]["go"]["cipher"]["state"], "RANDOMIZED")

    def test_ext_order_variation_advisory_only(self):
        go = [prof(order=["GREASE", "server_name", "alpn", "key_share", "supported_groups", "GREASE"]),
              prof(order=["GREASE", "alpn", "server_name", "key_share", "supported_groups", "GREASE"])]
        rust = [prof(), prof()]
        r = C.compare(go, rust, True, True)
        self.assertTrue(r["blocking_pass"])
        self.assertGreaterEqual(r["advisory"]["extension_order_distribution"]["go"]["distinct_permutations"], 2)

    def test_raw_forbidden_material_fails(self):
        leak = prof(random="aabbccddeeff00112233445566778899aabbccddeeff0011")  # 48-hex blob
        r = C.compare([leak], [prof()], True, True)
        self.assertFalse(r["blocking_pass"])
        self.assertFalse(r["blocking"]["redaction_guard"]["pass"])

    def test_session_id_value_present_fails(self):
        leak = prof(sid={"length": 32, "role": "x", "value": "deadbeef"})
        r = C.compare([prof()], [leak], True, True)
        self.assertFalse(r["blocking"]["redaction_guard"]["pass"])


if __name__ == "__main__":
    unittest.main()
