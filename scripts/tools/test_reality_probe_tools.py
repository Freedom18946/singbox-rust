#!/usr/bin/env python3
import argparse
import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import reality_probe_compare as compare
import reality_vless_probe_batch as batch
import reality_vless_probe_evidence as evidence
import reality_vless_env_from_config as envtool


class RealityVlessEnvFromConfigTests(unittest.TestCase):
    def sample_config(self):
        return {
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {
                    "type": "vless",
                    "tag": "node-a",
                    "server": "203.0.113.7",
                    "server_port": 443,
                    "uuid": "550e8400-e29b-41d4-a716-446655440000",
                    "flow": "xtls-rprx-vision",
                    "tls": {
                        "enabled": True,
                        "server_name": "www.example.com",
                        "alpn": ["h2", "http/1.1"],
                        "reality": {
                            "enabled": True,
                            "public_key": "PUB",
                            "short_id": "abcd",
                        },
                        "utls": {"enabled": True, "fingerprint": "chrome"},
                    },
                },
            ]
        }

    def test_extracts_raw_singbox_reality_env(self):
        env = envtool.extract_env(
            self.sample_config(),
            "node-a",
            "example.com:80",
            12000,
            15000,
        )
        self.assertEqual(env["SB_VLESS_SERVER"], "203.0.113.7")
        self.assertEqual(env["SB_VLESS_PORT"], "443")
        self.assertEqual(env["SB_VLESS_SERVER_NAME"], "www.example.com")
        self.assertEqual(env["SB_VLESS_REALITY_PUBLIC_KEY"], "PUB")
        self.assertEqual(env["SB_VLESS_REALITY_SHORT_ID"], "abcd")
        self.assertEqual(env["SB_VLESS_FINGERPRINT"], "chrome")
        self.assertEqual(env["SB_VLESS_TARGET_HOST"], "example.com")
        self.assertEqual(env["SB_VLESS_TARGET_PORT"], "80")
        self.assertEqual(env["SB_VLESS_ALPN"], "h2,http/1.1")
        self.assertEqual(env["SB_VLESS_PHASE_TIMEOUT_MS"], "12000")
        self.assertEqual(env["SB_VLESS_PROBE_IO_TIMEOUT_MS"], "15000")

    def test_extracts_ir_like_reality_env(self):
        config = {
            "outbounds": [
                {
                    "type": "vless",
                    "name": "node-b",
                    "server": "198.51.100.9",
                    "port": 8443,
                    "uuid": "550e8400-e29b-41d4-a716-446655440000",
                    "reality_public_key": "PUB2",
                    "reality_short_id": "beef",
                    "tls_sni": "cdn.example",
                    "utls_fingerprint": "firefox",
                    "tls_alpn": "h2, http/1.1",
                }
            ]
        }
        env = envtool.extract_env(config, "node-b", "example.org:443", None, None)
        self.assertEqual(env["SB_VLESS_PORT"], "8443")
        self.assertEqual(env["SB_VLESS_SERVER_NAME"], "cdn.example")
        self.assertEqual(env["SB_VLESS_FINGERPRINT"], "firefox")
        self.assertEqual(env["SB_VLESS_ALPN"], "h2,http/1.1")
        self.assertNotIn("SB_VLESS_PHASE_TIMEOUT_MS", env)

    def test_load_config_reads_json_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "config.json"
            path.write_text(json.dumps(self.sample_config()), encoding="utf-8")
            loaded = envtool.load_config(path)
        self.assertEqual(loaded["outbounds"][1]["tag"], "node-a")

    def test_lists_ready_and_skipped_vless_reality_outbounds(self):
        config = self.sample_config()
        config["outbounds"].append(
            {
                "type": "vless",
                "tag": "ws-node",
                "server": "203.0.113.8",
                "server_port": 443,
                "uuid": "550e8400-e29b-41d4-a716-446655440000",
                "transport": {"type": "ws"},
                "tls": {"reality": {"public_key": "PUB"}},
            }
        )
        items = envtool.list_reality_vless_outbounds(config)
        by_name = {item["name"]: item for item in items}
        self.assertTrue(by_name["node-a"]["ready"])
        self.assertFalse(by_name["ws-node"]["ready"])
        self.assertEqual(by_name["ws-node"]["skip_reason"], "non_tcp_transport")


class RealityProbeCompareTests(unittest.TestCase):
    def test_report_marks_stable_ok_matrix(self):
        app = {
            "tool": "probe-outbound",
            "outbound": "node-a",
            "target": "example.com:80",
            "pre_bridge": {
                "direct_reality": {"ok": True, "status": "ok"},
                "direct_vless_dial": {"ok": True, "status": "ok"},
            },
            "post_bridge": {
                "direct_reality": {"ok": True, "status": "ok"},
                "direct_vless_dial": {"ok": True, "status": "ok"},
            },
            "bridge_probe": {"ok": True},
        }
        phase = {
            "server": "203.0.113.7",
            "target": "example.com:80",
            "direct_reality": {"ok": True},
            "transport_reality": {"ok": True},
            "vless_dial": {"ok": True},
            "vless_probe_io": {"ok": True},
        }
        report = compare.build_report(app, phase)
        self.assertEqual(report["summary"]["mismatches"], 0)
        self.assertIn("all_ok", report["summary"]["labels"])

    def test_report_flags_app_minimal_and_bridge_divergence(self):
        app = {
            "pre_bridge": {
                "direct_reality": {"ok": True, "status": "ok"},
                "direct_vless_dial": {"ok": True, "status": "ok"},
            },
            "post_bridge": {
                "direct_reality": {"ok": True, "status": "ok"},
                "direct_vless_dial": {"ok": False, "status": "err", "class": "timeout"},
            },
            "bridge_probe": {"ok": False, "class": "post_dial_eof"},
        }
        phase = {
            "direct_reality": {"ok": False, "class": "reality_dial_eof"},
            "transport_reality": {"ok": False, "class": "reality_dial_eof"},
            "vless_dial": {"ok": True},
            "vless_probe_io": {"ok": False, "class": "timeout"},
        }
        report = compare.build_report(app, phase)
        self.assertGreater(report["summary"]["mismatches"], 0)
        self.assertIn("app_minimal_diverged", report["summary"]["labels"])
        self.assertIn("bridge_io_diverged", report["summary"]["labels"])
        classes = report["classes"]
        self.assertEqual(classes["minimal.direct_reality"], "reality_dial_eof")
        self.assertEqual(classes["app.bridge"], "post_dial_eof")

    def test_report_labels_all_reality_same_failure(self):
        app = {
            "pre_bridge": {"direct_reality": {"ok": False, "class": "timeout"}},
            "post_bridge": {"direct_reality": {"ok": False, "class": "timeout"}},
        }
        phase = {
            "direct_reality": {"ok": False, "class": "timeout"},
            "transport_reality": {"ok": False, "class": "timeout"},
        }
        report = compare.build_report(app, phase)
        self.assertIn("reality_all_timeout", report["summary"]["labels"])


class RealityProbeBatchTests(unittest.TestCase):
    def test_safe_slug_keeps_paths_predictable(self):
        self.assertEqual(batch.safe_slug("HK A/B:1.0倍率"), "HK_A_B_1.0")
        self.assertEqual(batch.safe_slug("///"), "outbound")

    def test_select_outbounds_filters_ready_names_and_limit(self):
        items = [
            {"name": "a", "ready": True},
            {"name": "b-live", "ready": True},
            {"name": "c-live", "ready": False},
        ]
        selected = batch.select_outbounds(items, [], "live", None, False, None)
        self.assertEqual([item["name"] for item in selected], ["b-live"])
        selected = batch.select_outbounds(items, [], "live", None, True, 2)
        self.assertEqual([item["name"] for item in selected], ["b-live", "c-live"])
        selected = batch.select_outbounds(items, ["a"], None, None, False, None)
        self.assertEqual([item["name"] for item in selected], ["a"])
        selected = batch.select_outbounds(items, [], None, None, True, 0)
        self.assertEqual(selected, [])

    def test_summarize_results_counts_labels_and_classes(self):
        results = [
            {
                "name": "a",
                "run_index": 1,
                "status": "completed",
                "compare": {
                    "summary": {"labels": ["all_ok"]},
                    "classes": {"app.bridge": "ok", "minimal.vless_probe_io": "ok"},
                },
            },
            {
                "name": "a",
                "run_index": 2,
                "status": "completed",
                "compare": {
                    "summary": {"labels": ["bridge_io_diverged"]},
                    "classes": {"app.bridge": "post_dial_eof"},
                },
            },
            {"name": "b", "run_index": None, "status": "skipped", "compare": None},
        ]
        summary = batch.summarize_results(results)
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["executed_runs"], 2)
        self.assertEqual(summary["status_counts"]["completed"], 2)
        self.assertEqual(summary["label_counts"]["all_ok"], 1)
        self.assertEqual(summary["class_counts"]["ok"], 2)
        self.assertEqual(summary["by_outbound"]["a"]["status_counts"]["completed"], 2)
        self.assertEqual(summary["by_outbound"]["b"]["status_counts"]["skipped"], 1)

    def test_sample_dir_for_repeat_runs(self):
        output_dir = pathlib.Path("/tmp/reality-batch")
        self.assertEqual(
            batch.sample_dir_for(output_dir, 1, "node/a", 1, 1),
            pathlib.Path("/tmp/reality-batch/001-node_a"),
        )
        self.assertEqual(
            batch.sample_dir_for(output_dir, 1, "node/a", 2, 2),
            pathlib.Path("/tmp/reality-batch/001-node_a/run-002"),
        )

    def test_integer_arg_parsers_reject_invalid_values(self):
        self.assertEqual(batch.non_negative_int("0"), 0)
        self.assertEqual(batch.positive_int("1"), 1)
        with self.assertRaises(argparse.ArgumentTypeError):
            batch.non_negative_int("-1")
        with self.assertRaises(argparse.ArgumentTypeError):
            batch.positive_int("0")


class RealityProbeEvidenceTests(unittest.TestCase):
    def sample_payload(self):
        return {
            "plan": {
                "config": "config.json",
                "target": "example.com:80",
                "runs": 2,
                "selected_count": 2,
            },
            "summary": {
                "total": 3,
                "executed_runs": 3,
                "status_counts": {"completed": 3},
                "label_counts": {"all_ok": 2, "reality_all_timeout": 1},
                "class_counts": {"ok": 18, "timeout": 9},
                "by_outbound": {
                    "HK-A-BGP-0.3倍率": {
                        "status_counts": {"completed": 2},
                        "label_counts": {"all_ok": 2},
                        "class_counts": {"ok": 18},
                    },
                    "JP-A-BGP-1.0倍率": {
                        "status_counts": {"completed": 1},
                        "label_counts": {"reality_all_timeout": 1},
                        "class_counts": {"timeout": 9},
                    },
                },
            },
            "results": [
                {
                    "ordinal": 1,
                    "name": "HK-A-BGP-0.3倍率",
                    "run_index": 1,
                    "status": "completed",
                    "compare": {
                        "summary": {"labels": ["all_ok"]},
                        "classes": {"app.bridge": "ok", "minimal.vless_probe_io": "ok"},
                    },
                },
                {
                    "ordinal": 2,
                    "name": "JP-A-BGP-1.0倍率",
                    "run_index": 1,
                    "status": "completed",
                    "compare": {
                        "summary": {"labels": ["reality_all_timeout"]},
                        "classes": {"app.bridge": "timeout"},
                    },
                },
            ],
        }

    def test_build_evidence_sanitizes_outbound_names_and_counts_health(self):
        built = evidence.build_evidence(
            self.sample_payload(),
            "43",
            "2026-04-26",
            "sample",
            "cmd",
            "/tmp/summary.json",
            ["classification first"],
        )
        self.assertEqual(built["selection"]["selected_count"], 2)
        self.assertEqual(built["summary"]["executed_runs"], 3)
        self.assertFalse(built["matrix_health"]["has_divergence"])
        self.assertEqual(built["matrix_health"]["all_ok_runs"], 2)
        self.assertEqual(
            built["matrix_health"]["uniform_failure_labels"],
            {"reality_all_timeout": 1},
        )
        self.assertIn("HK-A-BGP-0.3", built["by_outbound"])
        self.assertIn("JP-A-BGP-1.0", built["by_outbound"])
        self.assertEqual(built["runs"][0]["outbound"], "HK-A-BGP-0.3")
        self.assertEqual(built["runs"][0]["class_counts"], {"ok": 2})

    def test_evidence_cli_writes_ascii_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            summary = tmp_path / "summary.json"
            output = tmp_path / "evidence.json"
            summary.write_text(json.dumps(self.sample_payload()), encoding="utf-8")
            evidence.write_json(
                output,
                evidence.build_evidence(
                    evidence.load_json(summary),
                    "43",
                    "2026-04-26",
                    "sample",
                    None,
                    str(summary),
                    [],
                ),
            )
            text = output.read_text(encoding="utf-8")
            self.assertNotRegex(text, r"[^\x00-\x7f]")
            loaded = json.loads(text)
            self.assertEqual(loaded["round"], "43")


if __name__ == "__main__":
    unittest.main()
