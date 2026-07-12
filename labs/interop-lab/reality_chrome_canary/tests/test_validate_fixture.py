#!/usr/bin/env python3
import copy
import json
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import validate_fixture as V  # noqa: E402


class TestFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads(V.DEFAULT_FIXTURE.read_text())

    def test_committed_fixture_passes(self):
        self.assertEqual(V.validate(self.fixture), [])

    def test_rejects_missing_reality_transform(self):
        bad = copy.deepcopy(self.fixture)
        bad["reality_expected_shape"]["supported_groups"].insert(1, "0x11ec")
        self.assertIn("removed supported group remains in REALITY shape", V.validate(bad))

    def test_rejects_headless_product_surface(self):
        bad = copy.deepcopy(self.fixture)
        bad["provenance"]["product"] = "headless-shell"
        self.assertIn("fixture must identify full-browser product surface", V.validate(bad))


if __name__ == "__main__":
    unittest.main()
