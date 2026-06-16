#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "scripts/capabilities/generate.py"
STALE_VALIDATOR = "/".join(["crates", "sb-config", "src", "validator", "v2.rs"])
STALE_ANCHORS = [f"{STALE_VALIDATOR}:1", STALE_VALIDATOR]


def _capability(payload: dict, cap_id: str) -> dict:
    for item in payload.get("capabilities", []):
        if item.get("id") == cap_id:
            return item
    raise AssertionError(f"missing capability {cap_id!r}")


def _all_evidence(payload: dict) -> list[dict]:
    evidence: list[dict] = []
    evidence.extend(payload.get("acceptance_closure", {}).get("evidence", []))
    for capability in payload.get("capabilities", []):
        evidence.extend(capability.get("evidence", []))
    return evidence


class CapabilitiesGenerateTest(unittest.TestCase):
    def run_generator(self) -> tuple[dict, str]:
        with tempfile.TemporaryDirectory(prefix="capabilities-generate-") as tmp:
            out_path = Path(tmp) / "capabilities.json"
            subprocess.run(
                [sys.executable, str(GENERATOR), "--out", str(out_path)],
                cwd=ROOT,
                check=True,
            )
            raw = out_path.read_text(encoding="utf-8")
            return json.loads(raw), raw

    def test_generated_report_has_valid_evidence_anchors(self) -> None:
        payload, raw = self.run_generator()

        for stale in STALE_ANCHORS:
            self.assertNotIn(stale, raw)

        quic = _capability(payload, "tls.ech.quic")
        self.assertIn(
            "crates/sb-config/src/validator/v2/outbound.rs",
            [item.get("path") for item in quic.get("evidence", [])],
        )

        for item in _all_evidence(payload):
            rel_path = item.get("path")
            line = item.get("line")
            self.assertIsInstance(rel_path, str)
            self.assertIsInstance(line, int)
            evidence_path = ROOT / rel_path
            self.assertTrue(evidence_path.exists(), rel_path)
            line_count = len(evidence_path.read_text(encoding="utf-8").splitlines())
            self.assertGreaterEqual(line, 1, rel_path)
            self.assertLessEqual(line, line_count, rel_path)

        self.assertEqual(
            payload.get("staleness", {}).get("status"),
            "refreshed_docs_only_snapshot",
        )
        self.assertEqual(
            payload.get("staleness", {}).get("current_status_source"),
            "agents-only/active_context.md",
        )


if __name__ == "__main__":
    unittest.main()
