#!/usr/bin/env python3
"""Unit tests for parse_clienthello (redaction + structure + malformed rejection).
Self-contained: builds synthetic ClientHello byte vectors, no capture dependency.
Run: python3 -m unittest discover -s labs/interop-lab/reality_clienthello_parity/tests
"""
import json
import os
import struct
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import parse_clienthello as P  # noqa: E402

RANDOM_MARK = bytes([0x5A]) * 32  # marker for the ClientHello random
SID_MARK = bytes([0xC3]) * 32     # pretend REALITY-auth session_id
KEY_MARK = bytes([0x9E]) * 32     # pretend key_share key bytes
ECH_MARK = bytes([0xEE]) * 20     # pretend GREASE-ECH payload


def _ext(t, data):
    return struct.pack(">HH", t, len(data)) + data


def build_clienthello():
    legacy = b"\x03\x03"
    random = RANDOM_MARK
    sid = struct.pack(">B", len(SID_MARK)) + SID_MARK
    ciphers = struct.pack(">H", 0x1a1a) + struct.pack(">H", 0x1301) + struct.pack(">H", 0x1302)
    cs = struct.pack(">H", len(ciphers)) + ciphers
    comp = b"\x01\x00"
    # extensions
    sni_name = b"x" * 17
    sni = _ext(0x0000, struct.pack(">H", len(sni_name) + 3) + b"\x00" + struct.pack(">H", len(sni_name)) + sni_name)
    groups_body = struct.pack(">H", 0x0a0a) + struct.pack(">H", 0x001d)
    groups = _ext(0x000a, struct.pack(">H", len(groups_body)) + groups_body)
    sig_body = struct.pack(">H", 0x0403) + struct.pack(">H", 0x0804)
    sigs = _ext(0x000d, struct.pack(">H", len(sig_body)) + sig_body)
    alpn_body = b"\x02h2" + b"\x08http/1.1"
    alpn = _ext(0x0010, struct.pack(">H", len(alpn_body)) + alpn_body)
    sv_body = struct.pack(">H", 0x2a2a) + struct.pack(">H", 0x0304) + struct.pack(">H", 0x0303)
    sv = _ext(0x002b, struct.pack(">B", len(sv_body)) + sv_body)
    ks_entries = struct.pack(">HH", 0x3a3a, 1) + b"\x00" + struct.pack(">HH", 0x001d, len(KEY_MARK)) + KEY_MARK
    ks = _ext(0x0033, struct.pack(">H", len(ks_entries)) + ks_entries)
    ech = _ext(0xfe0d, ECH_MARK)
    ghead = _ext(0x4a4a, b"")
    gtail = _ext(0x5a5a, b"\x00")
    exts = ghead + sni + groups + sigs + alpn + sv + ks + ech + gtail
    ext_block = struct.pack(">H", len(exts)) + exts
    hs_body = legacy + random + sid + cs + comp + ext_block
    hs = b"\x01" + struct.pack(">I", len(hs_body))[1:] + hs_body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


class TestParse(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = build_clienthello()
        cls.p = P.parse_record(cls.raw)
        cls.blob = json.dumps(cls.p)

    def test_random_redacted(self):
        self.assertEqual(self.p["client_hello"]["random"], "<redacted>")
        self.assertNotIn(RANDOM_MARK.hex(), self.blob)

    def test_session_id_redacted(self):
        sid = self.p["client_hello"]["session_id"]
        self.assertEqual(sid["length"], 32)
        self.assertEqual(sid["role"], "reality-auth-redacted")
        self.assertNotIn("value", sid)
        self.assertNotIn(SID_MARK.hex(), self.blob)

    def test_key_share_redacted(self):
        ks = self.p["extensions"]["key_share"]
        self.assertEqual(ks[-1]["group"], "0x001d")
        self.assertEqual(ks[-1]["key_length"], 32)
        for entry in ks:
            self.assertNotIn("key", entry)
        self.assertNotIn(KEY_MARK.hex(), self.blob)

    def test_grease_ech_payload_redacted(self):
        self.assertEqual(self.p["extensions"]["grease_ech_payload_length"], len(ECH_MARK))
        self.assertNotIn(ECH_MARK.hex(), self.blob)

    def test_sni_hostname_redacted(self):
        self.assertEqual(self.p["extensions"]["sni_name_length"], 17)
        self.assertNotIn("xxxxx", self.blob)  # hostname bytes never emitted

    def test_structure_preserved(self):
        np = self.p["normalized_profile"]
        self.assertEqual(np["cipher_tail_no_grease"], ["0x1301", "0x1302"])
        self.assertEqual(np["supported_groups"], ["GREASE", "0x001d"])
        self.assertEqual(np["signature_algorithms_in_order"], ["0x0403", "0x0804"])
        self.assertEqual(np["supported_versions"], ["GREASE", "0x0304", "0x0303"])
        self.assertEqual(np["alpn"], ["h2", "http/1.1"])
        self.assertEqual([g["group"] for g in np["key_share_groups"]], ["GREASE", "0x001d"])
        self.assertIn("server_name", np["extension_set_sorted_grease_as_category"])

    def test_grease_markers_public_only(self):
        gm = self.p["grease_markers"]
        self.assertEqual(gm["cipher"], ["0x1a1a"])
        self.assertEqual(sorted(gm["extension_types"]), ["0x4a4a", "0x5a5a"])
        self.assertEqual(gm["supported_groups"], ["0x0a0a"])

    def test_derived_present(self):
        d = self.p["derived"]
        self.assertEqual(len(d["normalized_profile_digest"]), 16)
        self.assertTrue(d["from_spec_ja4"].startswith("t13d"))
        self.assertEqual(d["from_spec_ja4_status"], "DIAGNOSTIC_PENDING_FOXIO_REFERENCE")

    def test_reject_truncated_record(self):
        with self.assertRaises(ValueError):
            P.parse_record(self.raw[:10])

    def test_reject_truncated_extensions(self):
        with self.assertRaises(ValueError):
            P.parse_record(self.raw[:-5])

    def test_reject_non_handshake(self):
        with self.assertRaises(ValueError):
            P.parse_record(b"\x17\x03\x03\x00\x05hello")


if __name__ == "__main__":
    unittest.main()
