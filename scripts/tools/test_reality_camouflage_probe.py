#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import tempfile
import unittest


MODULE_PATH = pathlib.Path(__file__).with_name("reality_camouflage_probe.py")
SPEC = importlib.util.spec_from_file_location("reality_camouflage_probe", MODULE_PATH)
assert SPEC and SPEC.loader
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def gui_outbound(tag: str = "secret-tag") -> dict:
    return {
        "type": "vless",
        "tag": tag,
        "server": "203.0.113.9",
        "server_port": 443,
        "uuid": "11111111-2222-4333-8444-555555555555",
        "flow": "xtls-rprx-vision",
        "tls": {
            "enabled": True,
            "server_name": "target.example",
            "reality": {
                "enabled": True,
                "public_key": "SECRET_PUBLIC_KEY",
                "short_id": "SECRET_SHORT_ID",
            },
        },
    }


def side(
    *, tls: bool = True, h2: bool = True, disallowed_redirect: bool = False
) -> dict:
    return {
        "tls_ok": tls,
        "tls_version": "TLSv1.3" if tls else None,
        "cipher": "TLS_AES_256_GCM_SHA384" if tls else None,
        "alpn": "h2" if h2 else "http/1.1",
        "handshake_ms": 12.5 if tls else None,
        "http_ok": tls,
        "http_status": 302 if disallowed_redirect else 200,
        "http_redirect": disallowed_redirect,
        "disallowed_domain_redirect": disallowed_redirect,
    }


def pair(run: int, *, good: bool = True) -> dict:
    return {
        "node_id": "cam-001",
        "run": run,
        "proxy_fallback": side(disallowed_redirect=not good),
        "direct_sni_oracle": side(),
        "comparison": {
            "leaf_cert_equal": True,
            "tls_version_equal": True,
            "cipher_equal": True,
            "alpn_equal": True,
        },
    }


class ConfigTests(unittest.TestCase):
    def test_gui_array_load_and_selection(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp) / "config.json"
            path.write_text(json.dumps([gui_outbound()]))
            fingerprint, candidates = probe.load_candidates(path)
        selected = probe.select_candidates(candidates, ["secret-tag"], [], None)
        self.assertTrue(fingerprint.startswith("sha256:"))
        self.assertEqual(selected[0]["node_id"], "cam-001")
        self.assertEqual(selected[0]["ready_reason"], None)

    def test_rejects_non_plain_transport(self) -> None:
        outbound = gui_outbound()
        outbound["transport"] = {"type": "grpc"}
        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp) / "config.json"
            path.write_text(json.dumps({"outbounds": [outbound]}))
            _, candidates = probe.load_candidates(path)
        self.assertEqual(candidates[0]["ready_reason"], "not_plain_tcp")

    def test_rejects_duplicate_requested_names(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp) / "config.json"
            path.write_text(json.dumps([gui_outbound()]))
            _, candidates = probe.load_candidates(path)
        with self.assertRaisesRegex(ValueError, "must be unique"):
            probe.select_candidates(
                candidates, ["secret-tag", "secret-tag"], [], None
            )

    def test_rejects_ambiguous_source_names(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp) / "config.json"
            path.write_text(json.dumps([gui_outbound(), gui_outbound()]))
            _, candidates = probe.load_candidates(path)
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            probe.select_candidates(candidates, ["secret-tag"], [], None)

    def test_selects_by_one_based_source_index(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp) / "config.json"
            path.write_text(
                json.dumps([gui_outbound("first-secret"), gui_outbound("second-secret")])
            )
            _, candidates = probe.load_candidates(path)
        selected = probe.select_candidates(candidates, [], [2], None)
        self.assertEqual(selected[0]["index"], 1)
        self.assertEqual(selected[0]["node_id"], "cam-001")

    def test_rejects_duplicate_source_indexes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp) / "config.json"
            path.write_text(json.dumps([gui_outbound()]))
            _, candidates = probe.load_candidates(path)
        with self.assertRaisesRegex(ValueError, "indexes must be unique"):
            probe.select_candidates(candidates, [], [1, 1], None)

    def test_dry_run_never_emits_sensitive_values(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            config = root / "config.json"
            output = root / "output.json"
            config.write_text(json.dumps([gui_outbound()]))
            completed = subprocess.run(
                [
                    "python3",
                    str(MODULE_PATH),
                    "--config",
                    str(config),
                    "--outbound",
                    "secret-tag",
                    "--dry-run",
                    "--output-json",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            serialized = output.read_text()
        for secret in (
            "203.0.113.9",
            "target.example",
            "11111111-2222-4333-8444-555555555555",
            "SECRET_PUBLIC_KEY",
            "SECRET_SHORT_ID",
            "secret-tag",
        ):
            self.assertNotIn(secret, serialized)


class SummaryTests(unittest.TestCase):
    def test_observable_minimum_without_sufficiency_claim(self) -> None:
        node = probe.summarize_node("cam-001", [pair(1), pair(2), pair(3)])
        summary = probe.summarize([node])
        self.assertEqual(node["upstream_observable_minimum_observed_runs"], 3)
        self.assertEqual(
            summary["observation"], "UPSTREAM_OBSERVABLE_MINIMUM_OBSERVED"
        )
        self.assertEqual(summary["camouflage_sufficiency_verdict"], "NOT_ASSESSED")

    def test_disallowed_redirect_prevents_full_minimum_observation(self) -> None:
        node = probe.summarize_node("cam-001", [pair(1), pair(2, good=False)])
        summary = probe.summarize([node])
        self.assertEqual(node["upstream_observable_minimum_observed_runs"], 1)
        self.assertEqual(
            summary["observation"],
            "UPSTREAM_OBSERVABLE_MINIMUM_NOT_FULLY_OBSERVED",
        )

    def test_no_complete_tls_pair_is_inconclusive(self) -> None:
        run = pair(1)
        run["proxy_fallback"] = side(tls=False)
        node = probe.summarize_node("cam-001", [run])
        summary = probe.summarize([node])
        self.assertEqual(summary["observation"], "INCONCLUSIVE")

    def test_errors_are_class_only(self) -> None:
        self.assertEqual(probe._error_class(socket_timeout()), "timeout")
        self.assertEqual(probe._error_class(ValueError("secret host")), "protocol_error")

    def test_domain_redirect_scope_allows_main_www_only(self) -> None:
        self.assertFalse(probe._disallowed_domain_redirect("example.com", None))
        self.assertFalse(probe._disallowed_domain_redirect("example.com", "/login"))
        self.assertFalse(
            probe._disallowed_domain_redirect("example.com", "https://www.example.com/")
        )
        self.assertFalse(
            probe._disallowed_domain_redirect("www.example.com", "https://example.com/")
        )
        self.assertTrue(
            probe._disallowed_domain_redirect("example.com", "https://other.example/")
        )


def socket_timeout() -> TimeoutError:
    return TimeoutError("secret endpoint timed out")


if __name__ == "__main__":
    unittest.main()
