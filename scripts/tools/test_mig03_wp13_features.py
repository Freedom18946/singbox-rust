#!/usr/bin/env python3
"""Regression locks for MIG-03 WP13 feature slimming."""

from __future__ import annotations

import pathlib
import re
import tomllib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
CORE_MANIFEST = ROOT / "crates" / "sb-core" / "Cargo.toml"
CORE_SOURCE = ROOT / "crates" / "sb-core" / "src"

RETIRED_CORE_FEATURES = {
    "dev-cli",
    "legacy_protocols",
    "out_http",
    "out_hysteria",
    "out_hysteria2",
    "out_naive",
    "out_quic",
    "out_shadowtls",
    "out_socks",
    "out_ssh",
    "out_ss",
    "out_tailscale",
    "out_trojan",
    "out_tuic",
    "out_vless",
    "out_vmess",
    "out_wireguard",
    "router",
    "router_keyword",
    "routing",
    "suffix_trie",
}


class Mig03Wp13FeatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest_text = CORE_MANIFEST.read_text(encoding="utf-8")
        cls.manifest = tomllib.loads(cls.manifest_text)
        cls.source_text = "\n".join(
            path.read_text(encoding="utf-8") for path in CORE_SOURCE.rglob("*.rs")
        )
        cls.crate_rust_text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in CORE_MANIFEST.parent.rglob("*.rs")
        )

    def test_core_feature_budget_and_retired_names(self) -> None:
        features = self.manifest["features"]
        self.assertLessEqual(len(features), 72)
        self.assertTrue(RETIRED_CORE_FEATURES.isdisjoint(features))

    def test_core_cfg_budget_and_no_retired_feature_guards(self) -> None:
        cfg_count = sum(
            1
            for line in self.source_text.splitlines()
            if "#[cfg(" in line and "feature" in line
        )
        self.assertLessEqual(cfg_count, 807)
        cfg_lines = "\n".join(
            line for line in self.crate_rust_text.splitlines() if "#[cfg" in line
        )
        for feature in RETIRED_CORE_FEATURES:
            self.assertNotRegex(
                cfg_lines,
                rf'feature\s*=\s*"{re.escape(feature)}"',
                feature,
            )

    def test_retained_features_have_inline_purpose_comments(self) -> None:
        feature_lines = self.manifest_text.split("[features]", 1)[1].split("[[", 1)[0]
        declared = {
            match.group(1): line
            for line in feature_lines.splitlines()
            if (match := re.match(r"^([A-Za-z0-9_-]+)\s*=", line))
        }
        for feature, line in declared.items():
            if feature == "default":
                continue
            self.assertIn("#", line, f"{feature} lacks one-line purpose comment")

    def test_consumers_do_not_forward_retired_core_features(self) -> None:
        for path in ROOT.rglob("Cargo.toml"):
            if path == CORE_MANIFEST or "target" in path.parts:
                continue
            text = path.read_text(encoding="utf-8")
            for feature in RETIRED_CORE_FEATURES:
                self.assertNotIn(f"sb-core/{feature}", text, f"{path}: {feature}")


if __name__ == "__main__":
    unittest.main()
