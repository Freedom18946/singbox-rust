#!/usr/bin/env python3
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import reality_clienthello_family as family


class Fe0dPositionBandTests(unittest.TestCase):
    def test_classify_fe0d_position_band_known_profiles(self):
        self.assertEqual(family.classify_fe0d_position_band(186, 2), "early")
        self.assertEqual(family.classify_fe0d_position_band(186, 8), "mid")
        self.assertEqual(family.classify_fe0d_position_band(186, 15), "late")

        self.assertEqual(family.classify_fe0d_position_band(218, 2), "early")
        self.assertEqual(family.classify_fe0d_position_band(218, 6), "mid")
        self.assertEqual(family.classify_fe0d_position_band(218, 16), "late")

        self.assertEqual(family.classify_fe0d_position_band(250, 2), "early")
        self.assertEqual(family.classify_fe0d_position_band(250, 11), "mid")
        self.assertEqual(family.classify_fe0d_position_band(250, 16), "late")

        self.assertEqual(family.classify_fe0d_position_band(282, 2), "early")
        self.assertEqual(family.classify_fe0d_position_band(282, 8), "mid")
        self.assertEqual(family.classify_fe0d_position_band(282, 16), "late")

    def test_classify_fe0d_position_band_unknown_profile(self):
        self.assertEqual(family.classify_fe0d_position_band(999, 5), "unknown")

    def test_build_key_signature_tracks_precedence_pairs(self):
        positions = {
            "0x0000": 2,
            "0x0012": 6,
            "0x0017": 7,
            "0x002b": 3,
            "0xfe0d": 5,
            "0xff01": 8,
        }
        self.assertEqual(
            family.build_key_signature(positions),
            (
                "0x0000<0x002b",
                "0xfe0d<0x0012",
                "0xfe0d<0x0017",
                "0x002b<0xfe0d",
                "0xfe0d<0xff01",
            ),
        )


if __name__ == "__main__":
    unittest.main()
