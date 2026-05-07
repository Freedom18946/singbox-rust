#!/usr/bin/env python3
import argparse
import contextlib
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import reality_probe_compare as compare
import reality_vless_evidence_rollup as rollup
import reality_vless_probe_batch as batch
import reality_vless_probe_evidence as evidence
import reality_vless_probe_plan as plan
import reality_vless_env_from_config as envtool
import reality_vless_sample_intake as intake
import trojan_config_normalize as trojan_normalize
import trojan_sample_intake as trojan_intake
import trojan_probe_live as trojan_live
import trojan_probe_plan as trojan_plan


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

    def test_report_labels_same_probe_io_failure_without_divergence(self):
        app = {
            "pre_bridge": {
                "direct_reality": {"ok": True},
                "direct_vless_dial": {"ok": True},
            },
            "post_bridge": {
                "direct_reality": {"ok": True},
                "direct_vless_dial": {"ok": True},
            },
            "bridge_probe": {"ok": False, "class": "post_dial_eof"},
        }
        phase = {
            "direct_reality": {"ok": True},
            "transport_reality": {"ok": True},
            "vless_dial": {"ok": True},
            "vless_probe_io": {"ok": False, "class": "post_dial_eof"},
        }
        report = compare.build_report(app, phase)
        self.assertEqual(report["summary"]["mismatches"], 0)
        self.assertIn("probe_io_all_post_dial_eof", report["summary"]["labels"])


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
        selected = batch.select_outbounds(items, ["b-live", "a"], None, None, False, None)
        self.assertEqual([item["name"] for item in selected], ["b-live", "a"])
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

    def test_load_plan_names_and_ordered_unique(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "plan.json"
            path.write_text(
                json.dumps(
                    {
                        "selected": [
                            {"name": "node-a"},
                            {"name": "node-b"},
                            {"key": "missing-name"},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(batch.load_plan_names(path), ["node-a", "node-b"])
        self.assertEqual(batch.ordered_unique(["a", "b", "a", "c", "b"]), ["a", "b", "c"])

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

    def test_default_matrix_timeout_has_hard_floor_and_scales(self):
        self.assertEqual(batch.default_matrix_timeout_secs(1, 1000, 1000), 180)
        self.assertEqual(batch.default_matrix_timeout_secs(30, 30_000, 30_000), 510)

    def test_run_matrix_returns_timeout_status_for_wedged_script(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            script = tmp_path / "wedged-matrix.sh"
            script.write_text("#!/usr/bin/env bash\nsleep 10\n", encoding="utf-8")
            script.chmod(0o755)
            status = batch.run_matrix(
                script,
                tmp_path / "config.json",
                "node-a",
                "example.com:80",
                tmp_path / "out",
                1,
                1000,
                1000,
                1,
            )
        self.assertEqual(status, batch.MATRIX_TIMEOUT_STATUS)

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


class RealityEvidenceRollupTests(unittest.TestCase):
    def sample_evidence(self, round_name, labels, classes, by_outbound, runs=None):
        total = sum(labels.values())
        payload = {
            "round": round_name,
            "date": "2026-04-26",
            "description": f"round {round_name}",
            "summary": {
                "total": total,
                "executed_runs": total,
                "status_counts": {"completed": total},
                "label_counts": labels,
                "class_counts": classes,
            },
            "by_outbound": by_outbound,
        }
        if runs is not None:
            payload["runs"] = runs
        return payload

    def test_build_rollup_counts_rounds_labels_classes_and_outbounds(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            first = tmp_path / "round1.json"
            second = tmp_path / "round2.json"
            first.write_text(
                json.dumps(
                    self.sample_evidence(
                        "1",
                        {"all_ok": 2},
                        {"ok": 18},
                        {"HK-A": {"label_counts": {"all_ok": 2}, "class_counts": {"ok": 18}}},
                    )
                ),
                encoding="utf-8",
            )
            second.write_text(
                json.dumps(
                    self.sample_evidence(
                        "2",
                        {"reality_all_timeout": 1},
                        {"timeout": 9},
                        {
                            "JP-A": {
                                "label_counts": {"reality_all_timeout": 1},
                                "class_counts": {"timeout": 9},
                            }
                        },
                    )
                ),
                encoding="utf-8",
            )
            built = rollup.build_rollup([first, second])
        self.assertEqual(built["total_rounds"], 2)
        self.assertEqual(built["total_executed_runs"], 3)
        self.assertEqual(built["total_all_ok_runs"], 2)
        self.assertFalse(built["has_any_divergence"])
        self.assertEqual(built["label_counts"]["reality_all_timeout"], 1)
        self.assertEqual(built["by_outbound"]["JP-A"]["class_counts"]["timeout"], 9)
        self.assertEqual(built["by_outbound"]["JP-A"]["latest_round"], "2")
        self.assertTrue(built["by_outbound"]["JP-A"]["latest_has_non_all_ok"])
        self.assertEqual(built["by_outbound"]["JP-A"]["latest_health"], "latest_same_failure")
        self.assertEqual(built["latest_non_all_ok_outbounds"], ["JP-A"])
        self.assertEqual(built["latest_health_counts"]["latest_all_ok"], 1)
        self.assertEqual(built["latest_health_counts"]["latest_same_failure"], 1)

    def test_build_rollup_tracks_latest_recovered_outbound_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            first = tmp_path / "round7.json"
            second = tmp_path / "round8.json"
            first.write_text(
                json.dumps(
                    self.sample_evidence(
                        "7",
                        {"reality_all_timeout": 1},
                        {"timeout": 9},
                        {
                            "TW-A": {
                                "label_counts": {"reality_all_timeout": 1},
                                "class_counts": {"timeout": 9},
                            }
                        },
                    )
                ),
                encoding="utf-8",
            )
            second.write_text(
                json.dumps(
                    self.sample_evidence(
                        "8",
                        {"all_ok": 3},
                        {"ok": 27},
                        {"TW-A": {"label_counts": {"all_ok": 3}, "class_counts": {"ok": 27}}},
                    )
                ),
                encoding="utf-8",
            )
            built = rollup.build_rollup([second, first])
        outbound = built["by_outbound"]["TW-A"]
        self.assertEqual(outbound["rounds"], ["7", "8"])
        self.assertEqual(outbound["latest_round"], "8")
        self.assertFalse(outbound["latest_has_non_all_ok"])
        self.assertTrue(outbound["historical_has_non_all_ok"])
        self.assertEqual(outbound["latest_health"], "latest_all_ok")
        self.assertEqual(built["latest_non_all_ok_outbound_count"], 0)
        self.assertEqual(built["recovered_outbounds"], ["TW-A"])
        self.assertEqual(built["recovered_outbound_count"], 1)

    def test_build_rollup_tracks_latest_divergence_outbounds(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "round9.json"
            path.write_text(
                json.dumps(
                    self.sample_evidence(
                        "9",
                        {"app_pre_post_diverged": 1},
                        {"ok": 1, "timeout": 8},
                        {
                            "HK-A": {
                                "label_counts": {"app_pre_post_diverged": 1},
                                "class_counts": {"ok": 1, "timeout": 8},
                            }
                        },
                    )
                ),
                encoding="utf-8",
            )
            built = rollup.build_rollup([path])
        self.assertEqual(built["latest_divergence_outbounds"], ["HK-A"])
        self.assertEqual(built["latest_divergence_outbound_count"], 1)
        self.assertEqual(built["by_outbound"]["HK-A"]["latest_health"], "latest_divergence")

    def test_build_rollup_tracks_latest_run_health_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "round10.json"
            path.write_text(
                json.dumps(
                    self.sample_evidence(
                        "10",
                        {"app_pre_post_diverged": 1, "reality_all_timeout": 1},
                        {"ok": 1, "timeout": 17},
                        {
                            "HK-A": {
                                "label_counts": {
                                    "app_pre_post_diverged": 1,
                                    "reality_all_timeout": 1,
                                },
                                "class_counts": {"ok": 1, "timeout": 17},
                            }
                        },
                        runs=[
                            {
                                "outbound": "HK-A",
                                "run_index": 1,
                                "status": "completed",
                                "labels": ["app_pre_post_diverged"],
                                "class_counts": {"ok": 1, "timeout": 8},
                            },
                            {
                                "outbound": "HK-A",
                                "run_index": 2,
                                "status": "completed",
                                "labels": ["reality_all_timeout"],
                                "class_counts": {"timeout": 9},
                            },
                        ],
                    )
                ),
                encoding="utf-8",
            )
            built = rollup.build_rollup([path])
        outbound = built["by_outbound"]["HK-A"]
        self.assertEqual(
            outbound["latest_run_health_counts"],
            {"run_divergence": 1, "run_same_failure": 1},
        )
        self.assertEqual(outbound["history"][0]["runs"][0]["run_health"], "run_divergence")
        self.assertEqual(built["latest_run_health_counts"]["run_divergence"], 1)
        self.assertEqual(built["latest_run_health_counts"]["run_same_failure"], 1)
        self.assertEqual(built["latest_mixed_run_health_outbounds"], ["HK-A"])
        self.assertEqual(built["latest_stable_divergence_outbound_count"], 0)
        self.assertEqual(built["latest_stable_same_failure_outbound_count"], 0)

    def test_build_rollup_tracks_stable_latest_divergence_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "round11.json"
            path.write_text(
                json.dumps(
                    self.sample_evidence(
                        "11",
                        {"bridge_io_diverged": 2},
                        {"ok": 4, "timeout": 14},
                        {
                            "HK-A": {
                                "label_counts": {"bridge_io_diverged": 2},
                                "class_counts": {"ok": 4, "timeout": 14},
                            }
                        },
                        runs=[
                            {
                                "outbound": "HK-A",
                                "run_index": 1,
                                "status": "completed",
                                "labels": ["bridge_io_diverged"],
                                "class_counts": {"ok": 2, "timeout": 7},
                            },
                            {
                                "outbound": "HK-A",
                                "run_index": 2,
                                "status": "completed",
                                "labels": ["bridge_io_diverged"],
                                "class_counts": {"ok": 2, "timeout": 7},
                            },
                        ],
                    )
                ),
                encoding="utf-8",
            )
            built = rollup.build_rollup([path])
        self.assertEqual(built["latest_stable_divergence_outbounds"], ["HK-A"])
        self.assertEqual(built["latest_stable_divergence_outbound_count"], 1)
        self.assertEqual(built["latest_mixed_run_health_outbound_count"], 0)

    def test_build_rollup_tracks_stable_latest_same_failure_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "round12.json"
            path.write_text(
                json.dumps(
                    self.sample_evidence(
                        "12",
                        {"reality_all_timeout": 2},
                        {"timeout": 18},
                        {
                            "JP-A": {
                                "label_counts": {"reality_all_timeout": 2},
                                "class_counts": {"timeout": 18},
                            }
                        },
                        runs=[
                            {
                                "outbound": "JP-A",
                                "run_index": 1,
                                "status": "completed",
                                "labels": ["reality_all_timeout"],
                                "class_counts": {"timeout": 9},
                            },
                            {
                                "outbound": "JP-A",
                                "run_index": 2,
                                "status": "completed",
                                "labels": ["reality_all_timeout"],
                                "class_counts": {"timeout": 9},
                            },
                        ],
                    )
                ),
                encoding="utf-8",
            )
            built = rollup.build_rollup([path])
        self.assertEqual(built["latest_same_failure_outbounds"], ["JP-A"])
        self.assertEqual(built["latest_stable_same_failure_outbounds"], ["JP-A"])
        self.assertEqual(built["latest_stable_same_failure_outbound_count"], 1)

    def test_rollup_collects_divergence_phase_counts_per_outbound(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "round13.json"
            path.write_text(
                json.dumps(
                    self.sample_evidence(
                        "13",
                        {
                            "app_pre_post_diverged": 2,
                            "minimal_transport_diverged": 1,
                        },
                        {"ok": 3, "timeout": 15},
                        {
                            "HK-A": {
                                "label_counts": {
                                    "app_pre_post_diverged": 2,
                                    "minimal_transport_diverged": 1,
                                },
                                "class_counts": {"ok": 3, "timeout": 15},
                            }
                        },
                        runs=[
                            {
                                "outbound": "HK-A",
                                "run_index": 1,
                                "status": "completed",
                                "labels": [
                                    "app_pre_post_diverged",
                                    "minimal_transport_diverged",
                                ],
                                "class_counts": {"ok": 2, "timeout": 7},
                            },
                            {
                                "outbound": "HK-A",
                                "run_index": 2,
                                "status": "completed",
                                "labels": ["app_pre_post_diverged"],
                                "class_counts": {"ok": 1, "timeout": 8},
                            },
                        ],
                    )
                ),
                encoding="utf-8",
            )
            built = rollup.build_rollup([path])
        outbound = built["by_outbound"]["HK-A"]
        expected = {"app_pre_post_diverged": 2, "minimal_transport_diverged": 1}
        self.assertEqual(outbound["latest_divergence_phase_counts"], expected)
        self.assertEqual(outbound["divergence_phase_counts"], expected)

    def test_rollup_top_level_phase_summary_only_includes_latest_divergence_outbounds(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "round14.json"
            path.write_text(
                json.dumps(
                    self.sample_evidence(
                        "14",
                        {
                            "app_minimal_diverged": 1,
                            "app_pre_post_diverged": 1,
                            "reality_all_timeout": 1,
                        },
                        {"ok": 2, "timeout": 16},
                        {
                            "A": {
                                "label_counts": {
                                    "app_minimal_diverged": 1,
                                    "app_pre_post_diverged": 1,
                                },
                                "class_counts": {"ok": 2, "timeout": 7},
                            },
                            "B": {
                                "label_counts": {"reality_all_timeout": 1},
                                "class_counts": {"timeout": 9},
                            },
                        },
                        runs=[
                            {
                                "outbound": "A",
                                "run_index": 1,
                                "status": "completed",
                                "labels": [
                                    "app_minimal_diverged",
                                    "app_pre_post_diverged",
                                ],
                                "class_counts": {"ok": 2, "timeout": 7},
                            },
                            {
                                "outbound": "B",
                                "run_index": 1,
                                "status": "completed",
                                "labels": ["reality_all_timeout"],
                                "class_counts": {"timeout": 9},
                            },
                        ],
                    )
                ),
                encoding="utf-8",
            )
            built = rollup.build_rollup([path])
        self.assertEqual(
            built["latest_divergence_phase_summary"],
            {
                "app_pre_post_diverged": ["A"],
                "app_minimal_diverged": ["A"],
            },
        )
        self.assertEqual(
            built["latest_divergence_phase_total_counts"],
            {
                "app_pre_post_diverged": 1,
                "app_minimal_diverged": 1,
            },
        )
        for outbounds in built["latest_divergence_phase_summary"].values():
            self.assertNotIn("B", outbounds)

    def test_rollup_handles_outbound_without_any_divergence_label(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "round15.json"
            path.write_text(
                json.dumps(
                    self.sample_evidence(
                        "15",
                        {"reality_all_timeout": 2},
                        {"timeout": 18},
                        {
                            "JP-A": {
                                "label_counts": {"reality_all_timeout": 2},
                                "class_counts": {"timeout": 18},
                            }
                        },
                        runs=[
                            {
                                "outbound": "JP-A",
                                "run_index": 1,
                                "status": "completed",
                                "labels": ["reality_all_timeout"],
                                "class_counts": {"timeout": 9},
                            },
                            {
                                "outbound": "JP-A",
                                "run_index": 2,
                                "status": "completed",
                                "labels": ["reality_all_timeout"],
                                "class_counts": {"timeout": 9},
                            },
                        ],
                    )
                ),
                encoding="utf-8",
            )
            built = rollup.build_rollup([path])
        outbound = built["by_outbound"]["JP-A"]
        self.assertEqual(outbound["latest_divergence_phase_counts"], {})
        self.assertEqual(outbound["divergence_phase_counts"], {})
        self.assertEqual(built["latest_divergence_phase_summary"], {})

    def test_rollup_computes_phase_dominance_ratio(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "round16.json"
            path.write_text(
                json.dumps(
                    self.sample_evidence(
                        "16",
                        {"app_minimal_diverged": 3, "bridge_io_diverged": 1},
                        {"ok": 4, "timeout": 32},
                        {
                            "HK-A": {
                                "label_counts": {
                                    "app_minimal_diverged": 3,
                                    "bridge_io_diverged": 1,
                                },
                                "class_counts": {"ok": 4, "timeout": 32},
                            }
                        },
                        runs=[
                            {
                                "outbound": "HK-A",
                                "run_index": 1,
                                "status": "completed",
                                "labels": ["app_minimal_diverged"],
                                "class_counts": {"ok": 1, "timeout": 8},
                            },
                            {
                                "outbound": "HK-A",
                                "run_index": 2,
                                "status": "completed",
                                "labels": ["app_minimal_diverged"],
                                "class_counts": {"ok": 1, "timeout": 8},
                            },
                            {
                                "outbound": "HK-A",
                                "run_index": 3,
                                "status": "completed",
                                "labels": ["app_minimal_diverged"],
                                "class_counts": {"ok": 1, "timeout": 8},
                            },
                            {
                                "outbound": "HK-A",
                                "run_index": 4,
                                "status": "completed",
                                "labels": ["bridge_io_diverged"],
                                "class_counts": {"ok": 1, "timeout": 8},
                            },
                        ],
                    )
                ),
                encoding="utf-8",
            )
            built = rollup.build_rollup([path])
        outbound = built["by_outbound"]["HK-A"]
        dominance = outbound["latest_divergence_phase_dominance"]
        self.assertEqual(outbound["latest_divergence_run_count"], 4)
        self.assertEqual(dominance["dominant_phase"], "app_minimal_diverged")
        self.assertEqual(dominance["dominant_count"], 3)
        self.assertEqual(dominance["dominant_ratio"], 0.75)
        self.assertTrue(dominance["is_dominant"])
        self.assertFalse(dominance["is_no_dominance"])
        self.assertEqual(built["latest_phase_dominant_outbounds"], ["HK-A"])

    def test_rollup_marks_no_dominance_when_below_threshold(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "round17.json"
            labels = {
                "app_minimal_diverged": 1,
                "app_pre_post_diverged": 1,
                "bridge_io_diverged": 1,
                "minimal_transport_diverged": 1,
            }
            path.write_text(
                json.dumps(
                    self.sample_evidence(
                        "17",
                        labels,
                        {"ok": 4, "timeout": 32},
                        {"HK-A": {"label_counts": labels, "class_counts": {"ok": 4, "timeout": 32}}},
                        runs=[
                            {
                                "outbound": "HK-A",
                                "run_index": index,
                                "status": "completed",
                                "labels": [label],
                                "class_counts": {"ok": 1, "timeout": 8},
                            }
                            for index, label in enumerate(sorted(labels), start=1)
                        ],
                    )
                ),
                encoding="utf-8",
            )
            built = rollup.build_rollup([path])
        dominance = built["by_outbound"]["HK-A"]["latest_divergence_phase_dominance"]
        self.assertEqual(dominance["dominant_phase"], "app_minimal_diverged")
        self.assertEqual(dominance["dominant_count"], 1)
        self.assertEqual(dominance["dominant_ratio"], 0.25)
        self.assertFalse(dominance["is_dominant"])
        self.assertTrue(dominance["is_no_dominance"])
        self.assertEqual(built["latest_phase_no_dominance_outbounds"], ["HK-A"])

    def test_rollup_marks_bi_modal_when_divergence_ratio_in_band_with_enough_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "round18.json"
            runs = []
            for index in range(1, 7):
                runs.append(
                    {
                        "outbound": "A",
                        "run_index": index,
                        "status": "completed",
                        "labels": ["app_pre_post_diverged"],
                        "class_counts": {"ok": 1, "timeout": 8},
                    }
                )
            for index in range(7, 13):
                runs.append(
                    {
                        "outbound": "A",
                        "run_index": index,
                        "status": "completed",
                        "labels": ["reality_all_timeout"],
                        "class_counts": {"timeout": 9},
                    }
                )
            for index in range(1, 3):
                runs.append(
                    {
                        "outbound": "B",
                        "run_index": index,
                        "status": "completed",
                        "labels": ["app_pre_post_diverged"],
                        "class_counts": {"ok": 1, "timeout": 8},
                    }
                )
            for index in range(3, 5):
                runs.append(
                    {
                        "outbound": "B",
                        "run_index": index,
                        "status": "completed",
                        "labels": ["reality_all_timeout"],
                        "class_counts": {"timeout": 9},
                    }
                )
            path.write_text(
                json.dumps(
                    self.sample_evidence(
                        "18",
                        {"app_pre_post_diverged": 8, "reality_all_timeout": 8},
                        {"ok": 8, "timeout": 136},
                        {
                            "A": {
                                "label_counts": {
                                    "app_pre_post_diverged": 6,
                                    "reality_all_timeout": 6,
                                },
                                "class_counts": {"ok": 6, "timeout": 102},
                            },
                            "B": {
                                "label_counts": {
                                    "app_pre_post_diverged": 2,
                                    "reality_all_timeout": 2,
                                },
                                "class_counts": {"ok": 2, "timeout": 34},
                            },
                        },
                        runs=runs,
                    )
                ),
                encoding="utf-8",
            )
            built = rollup.build_rollup([path])
        outbound_a = built["by_outbound"]["A"]
        outbound_b = built["by_outbound"]["B"]
        self.assertEqual(outbound_a["latest_round_run_count"], 12)
        self.assertEqual(outbound_a["latest_divergence_run_count"], 6)
        self.assertEqual(outbound_a["latest_divergence_run_ratio"], 0.5)
        self.assertTrue(outbound_a["is_bi_modal"])
        self.assertTrue(outbound_a["latest_divergence_phase_dominance"]["is_bi_modal"])
        self.assertEqual(outbound_b["latest_round_run_count"], 4)
        self.assertEqual(outbound_b["latest_divergence_run_ratio"], 0.5)
        self.assertFalse(outbound_b["is_bi_modal"])
        self.assertEqual(built["latest_bi_modal_outbounds"], ["A"])

    def test_rollup_phase_shifting_detects_dominant_phase_change_over_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            rounds = [
                ("1", {"A": "app_minimal_diverged", "B": "app_minimal_diverged", "C": "app_minimal_diverged"}),
                ("2", {"A": "app_pre_post_diverged", "B": "app_minimal_diverged", "C": "app_pre_post_diverged"}),
                ("3", {"A": "minimal_transport_diverged", "B": "app_minimal_diverged"}),
            ]
            paths = []
            for round_name, phases in rounds:
                path = tmp_path / f"round{round_name}.json"
                by_outbound = {
                    outbound: {
                        "label_counts": {phase: 1},
                        "class_counts": {"ok": 1, "timeout": 8},
                    }
                    for outbound, phase in phases.items()
                }
                runs = [
                    {
                        "outbound": outbound,
                        "run_index": 1,
                        "status": "completed",
                        "labels": [phase],
                        "class_counts": {"ok": 1, "timeout": 8},
                    }
                    for outbound, phase in phases.items()
                ]
                path.write_text(
                    json.dumps(
                        self.sample_evidence(
                            round_name,
                            {phase: 1 for phase in phases.values()},
                            {"ok": len(phases), "timeout": len(phases) * 8},
                            by_outbound,
                            runs=runs,
                        )
                    ),
                    encoding="utf-8",
                )
                paths.append(path)
            built = rollup.build_rollup(paths)
        self.assertTrue(built["by_outbound"]["A"]["is_phase_shifting"])
        self.assertFalse(built["by_outbound"]["B"]["is_phase_shifting"])
        self.assertFalse(built["by_outbound"]["C"]["is_phase_shifting"])
        self.assertEqual(built["latest_phase_shifting_outbounds"], ["A"])

    def test_rollup_dominant_phase_history_includes_only_rounds_with_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            paths = []
            for round_name, outbound in [("1", "A"), ("2", "B"), ("3", "A"), ("4", "B"), ("5", "A")]:
                path = tmp_path / f"round{round_name}.json"
                phase = "app_minimal_diverged"
                path.write_text(
                    json.dumps(
                        self.sample_evidence(
                            round_name,
                            {phase: 1},
                            {"ok": 1, "timeout": 8},
                            {
                                outbound: {
                                    "label_counts": {phase: 1},
                                    "class_counts": {"ok": 1, "timeout": 8},
                                }
                            },
                            runs=[
                                {
                                    "outbound": outbound,
                                    "run_index": 1,
                                    "status": "completed",
                                    "labels": [phase],
                                    "class_counts": {"ok": 1, "timeout": 8},
                                }
                            ],
                        )
                    ),
                    encoding="utf-8",
                )
                paths.append(path)
            built = rollup.build_rollup(paths)
        history = built["by_outbound"]["A"]["dominant_phase_history"]
        self.assertEqual([item["round"] for item in history], ["1", "3", "5"])
        self.assertEqual(len(history), 3)

    def test_markdown_table_contains_round_rows(self):
        built = {
            "total_rounds": 1,
            "total_executed_runs": 1,
            "total_all_ok_runs": 1,
            "total_non_all_ok_runs": 0,
            "has_any_divergence": False,
            "label_counts": {"all_ok": 1},
            "class_counts": {"ok": 9},
            "latest_run_health_counts": {"run_all_ok": 1},
            "rounds": [
                {
                    "round": "1",
                    "executed_runs": 1,
                    "all_ok_runs": 1,
                    "label_counts": {"all_ok": 1},
                    "class_counts": {"ok": 9},
                    "has_divergence": False,
                }
            ],
        }
        text = rollup.markdown_table(built)
        self.assertIn("| 1 | 1 | 1 | all_ok=1 | ok=9 | false |", text)


class RealityProbePlanTests(unittest.TestCase):
    def sample_config(self):
        return {
            "outbounds": [
                {
                    "type": "vless",
                    "tag": "HK-A-BGP-0.3倍率",
                    "server": "203.0.113.1",
                    "server_port": 443,
                    "uuid": "550e8400-e29b-41d4-a716-446655440000",
                    "tls": {"reality": {"public_key": "PUB"}},
                },
                {
                    "type": "vless",
                    "tag": "JP-A-BGP-1.0倍率",
                    "server": "203.0.113.2",
                    "server_port": 443,
                    "uuid": "550e8400-e29b-41d4-a716-446655440000",
                    "tls": {"reality": {"public_key": "PUB"}},
                },
                {
                    "type": "vless",
                    "tag": "NEW-A-BGP-1.0倍率",
                    "server": "203.0.113.3",
                    "server_port": 443,
                    "uuid": "550e8400-e29b-41d4-a716-446655440000",
                    "tls": {"reality": {"public_key": "PUB"}},
                },
                {
                    "type": "vless",
                    "tag": "__phase3_invalid_vless",
                    "server": "127.0.0.1",
                    "server_port": 9,
                    "uuid": "550e8400-e29b-41d4-a716-446655440000",
                    "tls": {"reality": {"public_key": "PUB"}},
                },
            ]
        }

    def sample_rollup(self):
        return {
            "total_rounds": 2,
            "total_executed_runs": 3,
            "by_outbound": {
                "HK-A-BGP-0.3": {
                    "latest_label_counts": {"all_ok": 2},
                    "label_counts": {"all_ok": 2},
                    "class_counts": {"ok": 18},
                    "latest_health": "latest_all_ok",
                    "latest_run_health_counts": {"run_all_ok": 2},
                },
                "JP-A-BGP-1.0": {
                    "latest_label_counts": {"reality_all_timeout": 1},
                    "label_counts": {"reality_all_timeout": 1},
                    "class_counts": {"timeout": 9},
                    "latest_health": "latest_same_failure",
                    "latest_run_health_counts": {"run_same_failure": 1},
                },
            },
        }

    def test_build_plan_prefers_uncovered_by_default(self):
        built = plan.build_plan(self.sample_config(), self.sample_rollup(), None, False, False, False)
        self.assertEqual(built["counts"]["uncovered"], 1)
        self.assertEqual(built["counts"]["prior_non_all_ok"], 1)
        self.assertEqual(built["counts"]["covered_all_ok"], 1)
        self.assertEqual([item["key"] for item in built["selected"]], ["NEW-A-BGP-1.0"])

    def test_build_plan_can_include_failure_rechecks_and_covered_nodes(self):
        built = plan.build_plan(self.sample_config(), self.sample_rollup(), 2, True, True, False)
        self.assertEqual([item["key"] for item in built["selected"]], ["NEW-A-BGP-1.0", "JP-A-BGP-1.0"])
        self.assertEqual(built["selected"][1]["reason"], "prior_non_all_ok")
        self.assertEqual(built["selected"][1]["latest_health"], "latest_same_failure")

    def test_build_plan_can_filter_by_latest_health(self):
        built = plan.build_plan(
            self.sample_config(),
            self.sample_rollup(),
            None,
            False,
            False,
            False,
            ["latest_same_failure"],
        )
        self.assertEqual(built["latest_health_filter"], ["latest_same_failure"])
        self.assertEqual(built["latest_health_counts"]["latest_all_ok"], 1)
        self.assertEqual(built["latest_health_counts"]["latest_same_failure"], 1)
        self.assertEqual([item["key"] for item in built["selected"]], ["JP-A-BGP-1.0"])

    def test_build_plan_can_filter_by_latest_run_health(self):
        built = plan.build_plan(
            self.sample_config(),
            self.sample_rollup(),
            None,
            False,
            False,
            False,
            None,
            ["run_same_failure"],
        )
        self.assertEqual(built["latest_run_health_filter"], ["run_same_failure"])
        self.assertEqual([item["key"] for item in built["selected"]], ["JP-A-BGP-1.0"])
        self.assertEqual(
            built["selected"][0]["latest_run_health_counts"],
            {"run_same_failure": 1},
        )

    def test_build_plan_can_require_only_latest_run_health(self):
        built = plan.build_plan(
            self.sample_config(),
            self.sample_rollup(),
            None,
            False,
            False,
            False,
            ["latest_same_failure"],
            None,
            ["run_same_failure"],
        )
        self.assertEqual(built["only_latest_run_health_filter"], ["run_same_failure"])
        self.assertEqual([item["key"] for item in built["selected"]], ["JP-A-BGP-1.0"])

    def test_build_plan_only_latest_run_health_excludes_mixed(self):
        rollup_data = self.sample_rollup()
        rollup_data["by_outbound"]["JP-A-BGP-1.0"]["latest_run_health_counts"] = {
            "run_divergence": 1,
            "run_same_failure": 1,
        }
        built = plan.build_plan(
            self.sample_config(),
            rollup_data,
            None,
            False,
            False,
            False,
            ["latest_same_failure"],
            None,
            ["run_same_failure"],
        )
        self.assertEqual(built["selected"], [])

    def test_build_plan_combines_latest_and_run_health_filters(self):
        built = plan.build_plan(
            self.sample_config(),
            self.sample_rollup(),
            None,
            False,
            False,
            False,
            ["latest_same_failure"],
            ["run_all_ok"],
        )
        self.assertEqual(built["selected"], [])

    def test_planner_filters_by_phase_dominance(self):
        rollup_data = {
            "total_rounds": 1,
            "total_executed_runs": 12,
            "by_outbound": {
                "HK-A-BGP-0.3": {
                    "latest_label_counts": {"app_minimal_diverged": 4},
                    "latest_health": "latest_divergence",
                    "latest_run_health_counts": {"run_divergence": 4},
                    "latest_divergence_phase_dominance": {
                        "dominant_phase": "app_minimal_diverged",
                        "dominant_count": 3,
                        "dominant_ratio": 0.75,
                        "is_dominant": True,
                        "is_no_dominance": False,
                    },
                },
                "JP-A-BGP-1.0": {
                    "latest_label_counts": {"app_minimal_diverged": 4},
                    "latest_health": "latest_divergence",
                    "latest_run_health_counts": {"run_divergence": 4},
                    "latest_divergence_phase_dominance": {
                        "dominant_phase": "app_minimal_diverged",
                        "dominant_count": 1,
                        "dominant_ratio": 0.25,
                        "is_dominant": False,
                        "is_no_dominance": True,
                    },
                },
                "NEW-A-BGP-1.0": {
                    "latest_label_counts": {"app_minimal_diverged": 5},
                    "latest_health": "latest_divergence",
                    "latest_run_health_counts": {"run_divergence": 5},
                    "latest_divergence_phase_dominance": {
                        "dominant_phase": "app_minimal_diverged",
                        "dominant_count": 3,
                        "dominant_ratio": 0.6,
                        "is_dominant": False,
                        "is_no_dominance": False,
                    },
                },
            },
        }
        no_dominance = plan.build_plan(
            self.sample_config(),
            rollup_data,
            None,
            False,
            False,
            False,
            None,
            None,
            None,
            ["no_dominance"],
        )
        self.assertEqual([item["key"] for item in no_dominance["selected"]], ["JP-A-BGP-1.0"])

        dominant_or_mid = plan.build_plan(
            self.sample_config(),
            rollup_data,
            None,
            False,
            False,
            False,
            None,
            None,
            None,
            ["dominant", "mid"],
        )
        self.assertEqual(
            [item["key"] for item in dominant_or_mid["selected"]],
            ["HK-A-BGP-0.3", "NEW-A-BGP-1.0"],
        )

    def test_planner_filters_by_phase_shifting_and_bi_modal(self):
        config = {
            "outbounds": [
                {
                    "type": "vless",
                    "tag": name,
                    "server": "203.0.113.10",
                    "server_port": 443,
                    "uuid": "550e8400-e29b-41d4-a716-446655440000",
                    "tls": {"reality": {"public_key": "PUB"}},
                }
                for name in ["A", "B", "C", "D"]
            ]
        }
        rollup_data = {
            "total_rounds": 1,
            "total_executed_runs": 16,
            "by_outbound": {
                "A": {
                    "latest_label_counts": {"app_minimal_diverged": 1},
                    "latest_health": "latest_divergence",
                    "latest_run_health_counts": {"run_divergence": 1},
                    "is_bi_modal": False,
                    "is_phase_shifting": True,
                },
                "B": {
                    "latest_label_counts": {"app_minimal_diverged": 1},
                    "latest_health": "latest_divergence",
                    "latest_run_health_counts": {"run_divergence": 1},
                    "is_bi_modal": True,
                    "is_phase_shifting": False,
                },
                "C": {
                    "latest_label_counts": {"app_minimal_diverged": 1},
                    "latest_health": "latest_divergence",
                    "latest_run_health_counts": {"run_divergence": 1},
                    "is_bi_modal": True,
                    "is_phase_shifting": True,
                },
                "D": {
                    "latest_label_counts": {"app_minimal_diverged": 1},
                    "latest_health": "latest_divergence",
                    "latest_run_health_counts": {"run_divergence": 1},
                    "is_bi_modal": False,
                    "is_phase_shifting": False,
                },
            },
        }
        bi_modal = plan.build_plan(
            config,
            rollup_data,
            None,
            False,
            False,
            False,
            latest_bi_modal_filter=True,
        )
        self.assertEqual([item["key"] for item in bi_modal["selected"]], ["B", "C"])

        phase_shifting = plan.build_plan(
            config,
            rollup_data,
            None,
            False,
            False,
            False,
            latest_phase_shifting_filter=True,
        )
        self.assertEqual([item["key"] for item in phase_shifting["selected"]], ["A", "C"])

        both = plan.build_plan(
            config,
            rollup_data,
            None,
            False,
            False,
            False,
            latest_bi_modal_filter=True,
            latest_phase_shifting_filter=True,
        )
        self.assertEqual([item["key"] for item in both["selected"]], ["C"])

    def test_build_plan_can_include_internal_sentinels_explicitly(self):
        built = plan.build_plan(self.sample_config(), self.sample_rollup(), None, False, False, True)
        self.assertEqual(
            [item["key"] for item in built["selected"]],
            ["NEW-A-BGP-1.0", "phase3_invalid_vless"],
        )

    def test_classify_item_marks_covered_all_ok(self):
        prior = {"label_counts": {"all_ok": 1}, "class_counts": {"ok": 9}}
        self.assertEqual(plan.classify_item("HK-A-BGP-0.3", prior), "covered_all_ok")
        self.assertEqual(
            plan.classify_item("JP-A-BGP-1.0", {"label_counts": {"reality_all_timeout": 1}}),
            "prior_non_all_ok",
        )
        self.assertEqual(
            plan.classify_item(
                "TW-A-BGP-1.0",
                {
                    "latest_label_counts": {"all_ok": 3},
                    "label_counts": {"all_ok": 3, "reality_all_timeout": 1},
                },
            ),
            "covered_all_ok",
        )
        self.assertEqual(plan.classify_item("NEW", None), "uncovered")


class RealityRoundSortKeyTests(unittest.TestCase):
    """R68: round_sort_key must place suffixed rounds between majors."""

    def test_pure_int_orders_by_value(self):
        keys = [rollup.round_sort_key(v) for v in ("58", "60", "61", "59")]
        self.assertEqual(sorted(keys), [
            rollup.round_sort_key("58"),
            rollup.round_sort_key("59"),
            rollup.round_sort_key("60"),
            rollup.round_sort_key("61"),
        ])

    def test_suffixed_round_sorts_between_majors(self):
        # Required ordering: 58 < 59 < 59-B < 60 < 61
        sample = ["60", "59-B", "58", "61", "59"]
        self.assertEqual(
            sorted(sample, key=rollup.round_sort_key),
            ["58", "59", "59-B", "60", "61"],
        )

    def test_suffixed_round_sorts_strictly_before_next_major(self):
        # 59-B must NOT trail 60 or 61 (the original bug).
        sample = ["59-B", "60", "61"]
        self.assertEqual(
            sorted(sample, key=rollup.round_sort_key),
            ["59-B", "60", "61"],
        )

    def test_unparseable_round_sorts_to_end_deterministically(self):
        sample = ["61", "weird", "60"]
        out = sorted(sample, key=rollup.round_sort_key)
        self.assertEqual(out[:2], ["60", "61"])
        self.assertEqual(out[-1], "weird")


class RealityEvidenceRollupOrderingTests(unittest.TestCase):
    """R68: rollup must compute latest-state by canonical round order, not argv order."""

    def _write_evidence(self, path, round_name, label_counts, by_outbound):
        total = sum(label_counts.values())
        path.write_text(
            json.dumps(
                {
                    "round": round_name,
                    "date": "2026-05-04",
                    "description": f"round {round_name}",
                    "summary": {
                        "total": total,
                        "executed_runs": total,
                        "status_counts": {"completed": total},
                        "label_counts": label_counts,
                        "class_counts": {"x": total * 9},
                    },
                    "by_outbound": by_outbound,
                }
            ),
            encoding="utf-8",
        )

    def test_latest_round_picks_higher_major_over_suffixed_lower(self):
        """Synthetic outbound: 59-B divergence + 61 same-failure.
        latest_round must be 61, latest_health latest_same_failure,
        and outbound must NOT show up in latest_divergence_outbounds.
        Reproduces the R67 HK-A-BGP-2.0 latest_round=='59-B' bug."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            r59b = tmp_path / "round59b_summary.json"
            r61 = tmp_path / "round61_summary.json"
            self._write_evidence(
                r59b,
                "59-B",
                {"app_pre_post_diverged": 4},
                {
                    "HK-A-BGP-2.0": {
                        "label_counts": {"app_pre_post_diverged": 4},
                        "class_counts": {"timeout": 36},
                    }
                },
            )
            self._write_evidence(
                r61,
                "61",
                {"reality_all_connection_reset": 4},
                {
                    "HK-A-BGP-2.0": {
                        "label_counts": {"reality_all_connection_reset": 4},
                        "class_counts": {"connection_reset": 36},
                    }
                },
            )
            # Pass paths in adversarial order (R61 first, R59-B last) to
            # exercise that build_rollup is order-independent.
            built = rollup.build_rollup([r61, r59b])
        outbound = built["by_outbound"]["HK-A-BGP-2.0"]
        self.assertEqual(outbound["latest_round"], "61")
        self.assertEqual(outbound["latest_health"], "latest_same_failure")
        self.assertNotIn("HK-A-BGP-2.0", built["latest_divergence_outbounds"])
        self.assertIn("HK-A-BGP-2.0", built["latest_same_failure_outbounds"])

    def test_same_round_multiple_evidence_files_are_deterministic(self):
        """Two evidence files share round='61'. latest_round / aggregate must
        not depend on argv order, and the within-round ordering must come
        from a stable secondary key (filename), not from the arg list."""
        def build(arg_order):
            with tempfile.TemporaryDirectory() as tmp:
                tmp_path = pathlib.Path(tmp)
                a = tmp_path / "round61_a_summary.json"
                b = tmp_path / "round61_b_summary.json"
                self._write_evidence(
                    a,
                    "61",
                    {"all_ok": 1},
                    {"NODE-X": {"label_counts": {"all_ok": 1}, "class_counts": {"ok": 9}}},
                )
                self._write_evidence(
                    b,
                    "61",
                    {"reality_all_connection_reset": 1},
                    {
                        "NODE-X": {
                            "label_counts": {"reality_all_connection_reset": 1},
                            "class_counts": {"connection_reset": 9},
                        }
                    },
                )
                paths = [a, b] if arg_order == "a-first" else [b, a]
                return rollup.build_rollup(paths)

        out_ab = build("a-first")["by_outbound"]["NODE-X"]
        out_ba = build("b-first")["by_outbound"]["NODE-X"]
        # Both invocations must produce identical latest-state.
        self.assertEqual(out_ab["latest_round"], out_ba["latest_round"])
        self.assertEqual(out_ab["latest_health"], out_ba["latest_health"])
        self.assertEqual(out_ab["latest_label_counts"], out_ba["latest_label_counts"])
        # Aggregate counters are commutative; assert they match too.
        self.assertEqual(out_ab["label_counts"], out_ba["label_counts"])


def _make_vless_outbound(
    tag: str,
    server: str,
    port: int,
    uuid: str,
    public_key: str,
    short_id: str,
    server_name: str = "www.example.com",
) -> dict:
    """Build a single fully-populated VLESS REALITY outbound dict."""
    return {
        "type": "vless",
        "tag": tag,
        "server": server,
        "server_port": port,
        "uuid": uuid,
        "flow": "xtls-rprx-vision",
        "tls": {
            "enabled": True,
            "server_name": server_name,
            "alpn": ["h2", "http/1.1"],
            "reality": {
                "enabled": True,
                "public_key": public_key,
                "short_id": short_id,
            },
            "utls": {"enabled": True, "fingerprint": "chrome"},
        },
    }


class RealityVlessSampleIntakeTests(unittest.TestCase):
    """R71 fresh sample intake gate."""

    def _baseline(self):
        return {
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                _make_vless_outbound(
                    "HK-A-BGP-2.0倍率",
                    "203.0.113.7",
                    10010,
                    "11111111-1111-1111-1111-111111111111",
                    "PUBKEY-HK",
                    "shorthk",
                ),
                _make_vless_outbound(
                    "JP-A-BGP-0.3倍率",
                    "203.0.113.8",
                    10020,
                    "22222222-2222-2222-2222-222222222222",
                    "PUBKEY-JP",
                    "shortjp",
                ),
            ]
        }

    def _rollup(self):
        return {
            "by_outbound": {
                "HK-A-BGP-2.0": {"latest_health": "latest_same_failure"},
                "JP-A-BGP-0.3": {"latest_health": "latest_same_failure"},
            }
        }

    def test_fresh_ready_outbound_is_identified(self):
        candidate = {
            "outbounds": [
                _make_vless_outbound(
                    "FRESH-NEW-1.0倍率",
                    "198.51.100.10",
                    11000,
                    "33333333-3333-3333-3333-333333333333",
                    "PUBKEY-FRESH",
                    "shortfresh",
                ),
            ]
        }
        result = intake.build_intake(candidate, self._baseline(), self._rollup())
        self.assertEqual(result["summary"]["counts"]["fresh_ready"], 1)
        self.assertEqual(result["summary"]["counts"]["duplicate"], 0)
        self.assertEqual(result["summary"]["counts"]["not_ready"], 0)
        self.assertEqual(result["summary"]["selected_count"], 1)
        self.assertTrue(result["summary"]["ready_for_r72"])
        self.assertEqual(result["fresh_ready"][0]["tag"], "FRESH-NEW-1.0倍率")
        self.assertEqual(result["fresh_ready"][0]["region"], "FRESH")

    def test_baseline_tag_collision_is_duplicate(self):
        candidate = {
            "outbounds": [
                _make_vless_outbound(
                    "HK-A-BGP-2.0倍率",  # tag exists in baseline
                    "9.9.9.9",  # different server
                    9999,
                    "44444444-4444-4444-4444-444444444444",
                    "PUBKEY-DIFFERENT",
                    "shortdifferent",
                ),
            ]
        }
        result = intake.build_intake(candidate, self._baseline(), self._rollup())
        self.assertEqual(result["summary"]["counts"]["duplicate"], 1)
        self.assertEqual(result["summary"]["counts"]["fresh_ready"], 0)
        self.assertEqual(result["duplicate"][0]["detail"]["duplicate_kind"], "tag")

    def test_fingerprint_collision_with_distinct_tag_is_duplicate(self):
        candidate = {
            "outbounds": [
                _make_vless_outbound(
                    "TOTALLY-NEW-NAME-3.3倍率",  # tag is fresh
                    "203.0.113.7",  # but server, port, pubkey, short_id match HK
                    10010,
                    "55555555-5555-5555-5555-555555555555",  # uuid differs
                    "PUBKEY-HK",
                    "shorthk",
                ),
            ]
        }
        result = intake.build_intake(candidate, self._baseline(), self._rollup())
        self.assertEqual(result["summary"]["counts"]["duplicate"], 1)
        self.assertEqual(result["summary"]["counts"]["fresh_ready"], 0)
        self.assertEqual(
            result["duplicate"][0]["detail"]["duplicate_kind"], "fingerprint"
        )
        self.assertIn(
            "HK-A-BGP-2.0倍率",
            result["duplicate"][0]["detail"]["duplicate_baseline_tags"],
        )

    def test_missing_reality_field_is_not_ready(self):
        # Three independent malformed candidates: missing public_key,
        # missing uuid, missing server_name -> all three must be not_ready.
        no_pubkey = _make_vless_outbound(
            "M1-1.0倍率",
            "198.51.100.20",
            12000,
            "66666666-6666-6666-6666-666666666666",
            "PUB-X",
            "shortx",
        )
        del no_pubkey["tls"]["reality"]["public_key"]
        no_uuid = _make_vless_outbound(
            "M2-1.0倍率",
            "198.51.100.21",
            12001,
            "77777777-7777-7777-7777-777777777777",
            "PUB-Y",
            "shorty",
        )
        del no_uuid["uuid"]
        # server_name fallback: when server_name is removed but raw server
        # is still present, env extractor falls back to the server. To
        # actually drive ready=False for "no server_name", drop the
        # server itself (which forces missing_server, also a not_ready
        # bucket result).
        no_server = _make_vless_outbound(
            "M3-1.0倍率",
            "198.51.100.22",
            12002,
            "88888888-8888-8888-8888-888888888888",
            "PUB-Z",
            "shortz",
        )
        del no_server["server"]

        candidate = {"outbounds": [no_pubkey, no_uuid, no_server]}
        result = intake.build_intake(candidate, self._baseline(), self._rollup())
        self.assertEqual(result["summary"]["counts"]["not_ready"], 3)
        self.assertEqual(result["summary"]["counts"]["fresh_ready"], 0)
        skip_reasons = sorted(item["skip_reason"] for item in result["not_ready"])
        self.assertEqual(
            skip_reasons,
            ["missing_reality_public_key", "missing_server", "missing_uuid"],
        )

    def test_redacted_output_contains_no_raw_secrets(self):
        candidate = {
            "outbounds": [
                _make_vless_outbound(
                    "FRESH-R-1.0倍率",
                    "198.51.100.30",
                    13000,
                    "deadbeef-dead-beef-dead-beefdeadbeef",
                    "RAWPUBKEYAAA",
                    "rawshortidBBB",
                ),
            ]
        }
        result = intake.build_intake(candidate, self._baseline(), self._rollup())
        rendered_json = json.dumps(result)
        rendered_md = intake.render_redacted_md(result)
        # The candidate's raw secrets must not appear anywhere in the
        # serialized output.
        for secret in (
            "deadbeef-dead-beef-dead-beefdeadbeef",
            "RAWPUBKEYAAA",
            "rawshortidBBB",
            "198.51.100.30",
        ):
            self.assertNotIn(secret, rendered_json)
            self.assertNotIn(secret, rendered_md)
        # Hashes are short prefixes (12 chars) and the entry must include them.
        fp = result["fresh_ready"][0]["fingerprint"]
        self.assertIsNotNone(fp["server_hash"])
        self.assertEqual(len(fp["server_hash"]), 12)
        self.assertIsNotNone(fp["public_key_hash"])
        self.assertEqual(len(fp["public_key_hash"]), 12)
        self.assertIsNotNone(fp["short_id_hash"])
        self.assertEqual(len(fp["short_id_hash"]), 12)

    def test_no_candidate_fresh_when_all_overlap(self):
        # Candidate is byte-identical to baseline tag/server -> fresh=0.
        candidate = {
            "outbounds": [
                _make_vless_outbound(
                    "HK-A-BGP-2.0倍率",
                    "203.0.113.7",
                    10010,
                    "11111111-1111-1111-1111-111111111111",
                    "PUBKEY-HK",
                    "shorthk",
                ),
                _make_vless_outbound(
                    "JP-A-BGP-0.3倍率",
                    "203.0.113.8",
                    10020,
                    "22222222-2222-2222-2222-222222222222",
                    "PUBKEY-JP",
                    "shortjp",
                ),
            ]
        }
        result = intake.build_intake(candidate, self._baseline(), self._rollup())
        self.assertEqual(result["summary"]["counts"]["fresh_ready"], 0)
        self.assertEqual(result["summary"]["selected_count"], 0)
        self.assertFalse(result["summary"]["ready_for_r72"])

    def test_covered_existing_marks_known_rollup_keys(self):
        # Candidate is a brand-new server (passes baseline-fingerprint),
        # but its tag — once stripped of the 倍率 suffix — already exists
        # as a rollup key. That demotes it from fresh_ready to
        # covered_existing. To synthesise this we must keep the candidate
        # tag distinct from baseline (so the duplicate-tag rule does not
        # fire), yet share the rollup-stripped key. We achieve that by
        # using a rollup that already contains a stripped key matching a
        # name not in the baseline, then handing the validator a
        # candidate with that exact tag plus a fresh fingerprint.
        baseline = {"outbounds": [{"type": "direct", "tag": "direct"}]}
        roll = {"by_outbound": {"NEW-COVERED-9.9": {"latest_health": "x"}}}
        candidate = {
            "outbounds": [
                _make_vless_outbound(
                    "NEW-COVERED-9.9倍率",
                    "198.51.100.99",
                    14999,
                    "99999999-9999-9999-9999-999999999999",
                    "PUBKEY-NEW",
                    "shortnew",
                ),
            ]
        }
        result = intake.build_intake(candidate, baseline, roll)
        self.assertEqual(result["summary"]["counts"]["covered_existing"], 1)
        self.assertEqual(result["summary"]["counts"]["fresh_ready"], 0)
        self.assertEqual(
            result["covered_existing"][0]["detail"]["rollup_key"], "NEW-COVERED-9.9"
        )


def _make_trojan_outbound(
    tag: str,
    server: str,
    port: int,
    password: str,
    server_name: str = "tls.example.invalid",
) -> dict:
    return {
        "type": "trojan",
        "tag": tag,
        "server": server,
        "server_port": port,
        "password": password,
        "tls": {
            "enabled": True,
            "server_name": server_name,
        },
    }


class TrojanSampleIntakeTests(unittest.TestCase):
    """MT-TROJAN-FRESH-01 fresh sample intake gate."""

    def test_ready_trojan_candidate_is_identified(self):
        candidate = {
            "outbounds": [
                _make_trojan_outbound(
                    "trojan-ready",
                    "ready.example.invalid",
                    443,
                    "ready-password",
                )
            ]
        }
        result = trojan_intake.classify_candidates(candidate)
        self.assertEqual(result["summary"]["counts"]["trojan_ready"], 1)
        self.assertEqual(result["summary"]["selected_count"], 1)
        self.assertTrue(result["summary"]["ready_for_trojan_sanity"])
        item = result["trojan_ready"][0]
        self.assertEqual(item["tag"], "trojan-ready")
        self.assertEqual(item["port"], 443)
        self.assertTrue(item["ready"])

    def test_missing_password_is_not_ready(self):
        outbound = _make_trojan_outbound(
            "missing-password",
            "nopass.example.invalid",
            443,
            "remove-me",
        )
        del outbound["password"]
        result = trojan_intake.classify_candidates({"outbounds": [outbound]})
        self.assertEqual(result["summary"]["counts"]["not_ready"], 1)
        self.assertEqual(result["not_ready"][0]["skip_reason"], "missing_password")

    def test_missing_server_is_not_ready(self):
        outbound = _make_trojan_outbound(
            "missing-server",
            "noserver.example.invalid",
            443,
            "server-test-password",
        )
        del outbound["server"]
        result = trojan_intake.classify_candidates({"outbounds": [outbound]})
        self.assertEqual(result["summary"]["counts"]["not_ready"], 1)
        self.assertEqual(result["not_ready"][0]["skip_reason"], "missing_server")

    def test_duplicate_tag_is_duplicate(self):
        candidate = {
            "outbounds": [
                _make_trojan_outbound("dup-tag", "first.example.invalid", 443, "pw-a"),
                _make_trojan_outbound("dup-tag", "second.example.invalid", 8443, "pw-b"),
            ]
        }
        result = trojan_intake.classify_candidates(candidate)
        self.assertEqual(result["summary"]["counts"]["trojan_ready"], 1)
        self.assertEqual(result["summary"]["counts"]["duplicate"], 1)
        self.assertEqual(result["duplicate"][0]["detail"]["duplicate_kind"], "tag")

    def test_duplicate_fingerprint_with_distinct_tag_is_duplicate(self):
        candidate = {
            "outbounds": [
                _make_trojan_outbound(
                    "fp-a",
                    "same.example.invalid",
                    443,
                    "same-password",
                    "same-sni.example.invalid",
                ),
                _make_trojan_outbound(
                    "fp-b",
                    "same.example.invalid",
                    443,
                    "same-password",
                    "same-sni.example.invalid",
                ),
            ]
        }
        result = trojan_intake.classify_candidates(candidate)
        self.assertEqual(result["summary"]["counts"]["trojan_ready"], 1)
        self.assertEqual(result["summary"]["counts"]["duplicate"], 1)
        self.assertEqual(result["duplicate"][0]["detail"]["duplicate_kind"], "fingerprint")

    def test_non_trojan_is_unsupported(self):
        candidate = {
            "outbounds": [
                {
                    "type": "vless",
                    "tag": "not-trojan",
                    "server": "unsupported.example.invalid",
                    "server_port": 443,
                }
            ]
        }
        result = trojan_intake.classify_candidates(candidate)
        self.assertEqual(result["summary"]["counts"]["unsupported"], 1)
        self.assertEqual(result["unsupported"][0]["skip_reason"], "not_trojan")

    def test_redacted_output_contains_no_raw_node_material(self):
        candidate = {
            "outbounds": [
                _make_trojan_outbound(
                    "redacted",
                    "raw-server.example.invalid",
                    443,
                    "raw-password-value",
                    "raw-sni.example.invalid",
                )
            ]
        }
        result = trojan_intake.classify_candidates(candidate)
        rendered_json = json.dumps(result)
        rendered_md = trojan_intake.render_redacted_md(result)
        for value in (
            "raw-server.example.invalid",
            "raw-password-value",
            "raw-sni.example.invalid",
        ):
            self.assertNotIn(value, rendered_json)
            self.assertNotIn(value, rendered_md)
        fp = result["trojan_ready"][0]["fingerprint"]
        self.assertEqual(len(fp["server_hash"]), 12)
        self.assertEqual(len(fp["password_hash"]), 12)
        self.assertEqual(len(fp["server_name_hash"]), 12)


class TrojanConfigNormalizeTests(unittest.TestCase):
    """MT-TROJAN-FRESH-07 no-dial config normalization gate."""

    def test_removes_id_in_gui_and_preserves_trojan_fields(self):
        outbound = _make_trojan_outbound(
            "normalize-one",
            "normalize-one.example.invalid",
            443,
            "normalize-password",
            "normalize-sni.example.invalid",
        )
        outbound["__id_in_gui"] = "gui-only-id"
        normalized, summary = trojan_normalize.normalize_config({"outbounds": [outbound]})

        clean = normalized["outbounds"][0]
        self.assertNotIn("__id_in_gui", clean)
        self.assertEqual(clean["type"], "trojan")
        self.assertEqual(clean["server"], "normalize-one.example.invalid")
        self.assertEqual(clean["server_port"], 443)
        self.assertEqual(clean["password"], "normalize-password")
        self.assertEqual(clean["tls"]["server_name"], "normalize-sni.example.invalid")
        self.assertEqual(summary["removed_field_counts"], {"__id_in_gui": 1})
        self.assertTrue(summary["ready_for_no_dial_preflight"])

    def test_removes_multiple_private_fields_recursively(self):
        outbound = _make_trojan_outbound(
            "normalize-many",
            "normalize-many.example.invalid",
            8443,
            "normalize-many-password",
            "normalize-many-sni.example.invalid",
        )
        outbound["__id_in_gui"] = "gui-id"
        outbound["__profile"] = "gui-profile"
        outbound["tls"]["__note"] = "gui-note"
        outbound["transport"] = {"type": "ws", "__gui_path_hint": "hint"}

        normalized, summary = trojan_normalize.normalize_config({"outbounds": [outbound]})
        rendered = json.dumps(normalized)

        for private_key in ("__id_in_gui", "__profile", "__note", "__gui_path_hint"):
            self.assertNotIn(private_key, rendered)
        self.assertEqual(
            summary["removed_field_counts"],
            {"__gui_path_hint": 1, "__id_in_gui": 1, "__note": 1, "__profile": 1},
        )
        self.assertEqual(summary["removed_total"], 4)

    def test_redacted_summary_contains_no_raw_node_material(self):
        outbound = _make_trojan_outbound(
            "normalize-redacted",
            "raw-normalize-server.example.invalid",
            443,
            "raw-normalize-password",
            "raw-normalize-sni.example.invalid",
        )
        outbound["__id_in_gui"] = "gui-id"
        _, summary = trojan_normalize.normalize_config({"outbounds": [outbound]})
        rendered_json = json.dumps(summary)
        rendered_md = trojan_normalize.render_redacted_md(summary)

        for value in (
            "raw-normalize-server.example.invalid",
            "raw-normalize-password",
            "raw-normalize-sni.example.invalid",
        ):
            self.assertNotIn(value, rendered_json)
            self.assertNotIn(value, rendered_md)
        self.assertIn("__id_in_gui", rendered_md)

    def test_validate_only_branch_precedes_probe_and_network_paths(self):
        repo = pathlib.Path(__file__).resolve().parents[2]
        source = (repo / "app/src/bin/probe-outbound.rs").read_text(encoding="utf-8")
        validate_pos = source.index("if args.validate_config_only")
        self.assertLess(validate_pos, source.index('maybe_probe_vless_direct("pre_bridge"'))
        self.assertLess(validate_pos, source.index("connector.connect(&host, port)"))
        self.assertLess(validate_pos, source.index("connector.connect_io(&host, port)"))

    def test_normalized_synthetic_fixture_passes_no_dial_preflight(self):
        repo = pathlib.Path(__file__).resolve().parents[2]
        outbound = _make_trojan_outbound(
            "synthetic-preflight",
            "127.0.0.1",
            443,
            "synthetic-password",
            "synthetic-sni.example.invalid",
        )
        outbound["__id_in_gui"] = "gui-id"
        normalized, _ = trojan_normalize.normalize_config({"outbounds": [outbound]})

        with tempfile.TemporaryDirectory() as tmp:
            config_path = pathlib.Path(tmp) / "normalized.json"
            config_path.write_text(json.dumps(normalized), encoding="utf-8")
            proc = subprocess.run(
                [
                    "cargo",
                    "run",
                    "--quiet",
                    "-p",
                    "app",
                    "--features",
                    "router,adapters",
                    "--bin",
                    "probe-outbound",
                    "--",
                    "--config",
                    str(config_path),
                    "--outbound",
                    "synthetic-preflight",
                    "--target",
                    "example.com:80",
                    "--timeout",
                    "8",
                    "--json",
                    "--validate-config-only",
                ],
                cwd=repo,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=240,
            )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        result = json.loads(proc.stdout)
        self.assertEqual(result["mode"], "validate_config_only")
        self.assertTrue(result["no_network"])
        self.assertTrue(result["selected_found"])
        self.assertTrue(result["bridge_member_found"])
        self.assertEqual(result["outbound_type"], "trojan")
        combined = proc.stdout + proc.stderr
        for value in (
            "127.0.0.1",
            "synthetic-password",
            "synthetic-sni.example.invalid",
        ):
            self.assertNotIn(value, combined)


class TrojanProbePlanTests(unittest.TestCase):
    """MT-TROJAN-FRESH-02 bounded dry-run planner."""

    def _candidate(self, count: int = 3) -> dict:
        return {
            "outbounds": [
                _make_trojan_outbound(
                    f"plan-{index}",
                    f"plan-{index}.example.invalid",
                    443 + index,
                    f"plan-password-{index}",
                    f"plan-sni-{index}.example.invalid",
                )
                for index in range(count)
            ]
        }

    def test_selects_bounded_trojan_ready_candidates(self):
        candidate = self._candidate(3)
        intake_result = trojan_intake.classify_candidates(candidate)
        plan_result = trojan_plan.build_plan(
            intake_result,
            candidate,
            "example.com:80",
            limit=2,
            runs=1,
            timeout=8,
        )
        self.assertEqual(plan_result["summary"]["selected_count"], 2)
        self.assertEqual(plan_result["summary"]["total_ready"], 3)
        self.assertEqual(
            [item["tag"] for item in plan_result["selected"]],
            ["plan-0", "plan-1"],
        )

    def test_runs_contribute_to_planned_runs(self):
        candidate = self._candidate(2)
        intake_result = trojan_intake.classify_candidates(candidate)
        plan_result = trojan_plan.build_plan(
            intake_result,
            candidate,
            "example.com:80",
            limit=2,
            runs=3,
            timeout=8,
        )
        self.assertEqual(plan_result["summary"]["selected_count"], 2)
        self.assertEqual(plan_result["summary"]["planned_runs"], 6)
        self.assertEqual(plan_result["selected"][0]["runs"], 3)

    def test_duplicate_candidates_are_not_selected(self):
        candidate = {
            "outbounds": [
                _make_trojan_outbound(
                    "unique",
                    "dup.example.invalid",
                    443,
                    "dup-password",
                    "dup-sni.example.invalid",
                ),
                _make_trojan_outbound(
                    "duplicate-fp",
                    "dup.example.invalid",
                    443,
                    "dup-password",
                    "dup-sni.example.invalid",
                ),
            ]
        }
        intake_result = trojan_intake.classify_candidates(candidate)
        plan_result = trojan_plan.build_plan(
            intake_result,
            candidate,
            "example.com:80",
            limit=5,
            runs=1,
            timeout=8,
        )
        self.assertEqual(plan_result["summary"]["selected_count"], 1)
        self.assertEqual(plan_result["summary"]["duplicate_count"], 1)
        self.assertEqual([item["tag"] for item in plan_result["selected"]], ["unique"])

    def test_empty_ready_disables_live_authorization(self):
        candidate = {
            "outbounds": [
                {
                    "type": "vless",
                    "tag": "unsupported",
                    "server": "unsupported.example.invalid",
                    "server_port": 443,
                }
            ]
        }
        intake_result = trojan_intake.classify_candidates(candidate)
        plan_result = trojan_plan.build_plan(
            intake_result,
            candidate,
            "example.com:80",
            limit=5,
            runs=1,
            timeout=8,
        )
        self.assertEqual(plan_result["summary"]["selected_count"], 0)
        self.assertEqual(plan_result["summary"]["planned_runs"], 0)
        self.assertFalse(plan_result["summary"]["ready_for_live_authorization"])

    def test_redacted_plan_contains_no_raw_node_material(self):
        candidate = {
            "outbounds": [
                _make_trojan_outbound(
                    "redacted-plan",
                    "raw-plan-server.example.invalid",
                    443,
                    "raw-plan-password",
                    "raw-plan-sni.example.invalid",
                )
            ]
        }
        intake_result = trojan_intake.classify_candidates(candidate)
        plan_result = trojan_plan.build_plan(
            intake_result,
            candidate,
            "example.com:80",
            limit=5,
            runs=1,
            timeout=8,
        )
        rendered_json = json.dumps(plan_result)
        rendered_md = trojan_plan.render_redacted_md(plan_result)
        for value in (
            "raw-plan-server.example.invalid",
            "raw-plan-password",
            "raw-plan-sni.example.invalid",
        ):
            self.assertNotIn(value, rendered_json)
            self.assertNotIn(value, rendered_md)
        selected = plan_result["selected"][0]
        self.assertEqual(len(selected["server_hash"]), 12)
        self.assertEqual(len(selected["password_hash"]), 12)
        self.assertEqual(len(selected["server_name_hash"]), 12)

    def test_cli_help_exits_zero(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            with self.assertRaises(SystemExit) as cm:
                trojan_plan.main(["--help"])
        self.assertEqual(cm.exception.code, 0)
        self.assertIn("--intake-json", stdout.getvalue())


class TrojanProbeLiveTests(unittest.TestCase):
    """MT-TROJAN-FRESH-04 bounded live evidence helpers."""

    def _plan(self) -> dict:
        candidate = {
            "outbounds": [
                _make_trojan_outbound(
                    "live-plan",
                    "live-plan.example.invalid",
                    443,
                    "live-plan-password",
                    "live-plan-sni.example.invalid",
                )
            ]
        }
        intake_result = trojan_intake.classify_candidates(candidate)
        return trojan_plan.build_plan(
            intake_result,
            candidate,
            "example.com:80",
            limit=1,
            runs=1,
            timeout=8,
        )

    def test_validate_plan_bounds_rejects_expansion(self):
        plan_result = self._plan()
        trojan_live.validate_plan_bounds(
            plan_result,
            expected_selected=1,
            expected_runs=1,
            expected_target="example.com:80",
            expected_timeout=8,
        )
        with self.assertRaises(SystemExit):
            trojan_live.validate_plan_bounds(
                plan_result,
                expected_selected=2,
                expected_runs=1,
                expected_target="example.com:80",
                expected_timeout=8,
            )

    def test_result_from_probe_keeps_only_redacted_fields(self):
        item = self._plan()["selected"][0]
        raw_detail = "raw detail should be scrubbed"
        stdout = json.dumps(
            {
                "bridge_probe": {
                    "ok": False,
                    "stream_mode": "connect_io",
                    "stage": "connect",
                    "class": "timeout",
                    "connect_time_ms": 8000,
                    "error": raw_detail,
                }
            }
        )
        result = trojan_live.result_from_probe(
            item,
            1,
            1,
            stdout,
            "",
            [raw_detail],
        )
        rendered = json.dumps(result)
        self.assertEqual(result["status"], "probe_error")
        self.assertEqual(result["class"], "timeout")
        self.assertNotIn(raw_detail, rendered)
        self.assertEqual(result["returncode"], 1)
        self.assertEqual(result["tool_diagnostic"]["stdout_kind"], "json_bridge_probe")
        self.assertEqual(len(result["server_hash"]), 12)
        self.assertEqual(len(result["password_hash"]), 12)
        self.assertEqual(len(result["server_name_hash"]), 12)
        self.assertEqual(result["bridge_diagnostic"]["error_kind"], "timeout")
        self.assertEqual(len(result["bridge_diagnostic"]["error_sha256_12"]), 12)
        self.assertIsNone(result["bridge_diagnostic"]["raw_connect_error_sha256_12"])
        self.assertIn("<redacted:", result["bridge_diagnostic"]["scrubbed_excerpt"])

    def test_stdout_non_json_gets_specific_tool_class(self):
        item = self._plan()["selected"][0]
        result = trojan_live.result_from_probe(
            item,
            1,
            2,
            "not-json",
            "",
        )
        self.assertEqual(result["status"], "tool_error")
        self.assertEqual(result["class"], "stdout_non_json")
        self.assertEqual(result["tool_diagnostic"]["stdout_kind"], "non_json")

    def test_json_without_bridge_probe_gets_specific_tool_class(self):
        item = self._plan()["selected"][0]
        result = trojan_live.result_from_probe(
            item,
            1,
            1,
            json.dumps({"tool": "probe-outbound", "bridge_probe": None}),
            "",
        )
        self.assertEqual(result["status"], "tool_error")
        self.assertEqual(result["class"], "stdout_missing_bridge_probe")
        self.assertEqual(
            result["tool_diagnostic"]["stdout_kind"],
            "json_missing_bridge_probe",
        )

    def test_stderr_raw_material_is_scrubbed_from_diagnostic(self):
        item = self._plan()["selected"][0]
        raw_server = "leaky-server.example.invalid"
        raw_password = "leaky-password"
        raw_sni = "leaky-sni.example.invalid"
        result = trojan_live.result_from_probe(
            item,
            1,
            2,
            "",
            f"failed {raw_server} {raw_password} {raw_sni}",
            [raw_server, raw_password, raw_sni],
        )
        diagnostic = result["tool_diagnostic"]
        rendered = json.dumps(result)
        for value in (raw_server, raw_password, raw_sni):
            self.assertNotIn(value, rendered)
        self.assertIn("<redacted:", diagnostic["scrubbed_excerpt"])

    def test_cli_usage_error_is_not_other(self):
        item = self._plan()["selected"][0]
        result = trojan_live.result_from_probe(
            item,
            1,
            2,
            "",
            "error: the following required arguments were not provided: --config\nUsage: probe-outbound --config <CONFIG>",
        )
        self.assertEqual(result["status"], "tool_error")
        self.assertEqual(result["class"], "cli_usage_error")

    def test_config_unknown_field_is_specific_tool_class(self):
        item = self._plan()["selected"][0]
        result = trojan_live.result_from_probe(
            item,
            1,
            1,
            "",
            "Error: load config: /tmp/candidate.json Caused by: config validation failed at /outbounds/0/__id_in_gui: unknown field",
        )
        self.assertEqual(result["status"], "tool_error")
        self.assertEqual(result["class"], "config_validation_unknown_field")

    def test_evidence_classification_distinguishes_env_limited_and_ok(self):
        plan_result = self._plan()
        env_result = {
            **plan_result["selected"][0],
            "run_index": 1,
            "status": "probe_error",
            "ok": False,
            "class": "timeout",
            "stage": "connect",
            "stream_mode": "connect_io",
            "connect_time_ms": 8000,
            "response_bytes": None,
        }
        env_evidence = trojan_live.build_evidence(plan_result, [env_result])
        self.assertEqual(env_evidence["classification"], "B")
        ok_result = {**env_result, "status": "ok", "ok": True, "class": None}
        ok_evidence = trojan_live.build_evidence(plan_result, [ok_result])
        self.assertEqual(ok_evidence["classification"], "A")

    def test_run_live_with_fake_probe_command(self):
        plan_result = self._plan()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            candidate_path = tmp_path / "candidate.json"
            candidate_path.write_text(json.dumps({"outbounds": []}), encoding="utf-8")
            fake = tmp_path / "fake_probe.py"
            fake.write_text(
                "import json\n"
                "print(json.dumps({'bridge_probe': {'ok': True, 'stream_mode': 'connect_io', 'connect_time_ms': 12, 'response_bytes': 128}}))\n",
                encoding="utf-8",
            )
            evidence = trojan_live.run_live(
                plan_result,
                candidate_path,
                [sys.executable, str(fake)],
            )
        self.assertEqual(evidence["summary"]["executed_runs"], 1)
        self.assertEqual(evidence["summary"]["probe_invocations"], 1)
        self.assertTrue(evidence["summary"]["node_contact_confirmed"])
        self.assertEqual(evidence["summary"]["ok_count"], 1)
        self.assertEqual(evidence["classification"], "A")

    def test_tool_error_does_not_confirm_node_contact(self):
        plan_result = self._plan()
        result = {
            **plan_result["selected"][0],
            "run_index": 1,
            "status": "tool_error",
            "ok": False,
            "class": "tool_unknown",
            "stage": None,
            "stream_mode": None,
            "connect_time_ms": None,
            "response_bytes": None,
        }
        evidence = trojan_live.build_evidence(plan_result, [result])
        self.assertEqual(evidence["classification"], "C")
        self.assertEqual(evidence["summary"]["probe_invocations"], 1)
        self.assertFalse(evidence["summary"]["node_contact_confirmed"])

    def test_rendered_live_evidence_contains_no_raw_node_material(self):
        plan_result = self._plan()
        result = {
            **plan_result["selected"][0],
            "run_index": 1,
            "status": "probe_error",
            "ok": False,
            "class": "timeout",
            "stage": "connect",
            "stream_mode": "connect_io",
            "connect_time_ms": 8000,
            "response_bytes": None,
        }
        evidence = trojan_live.build_evidence(plan_result, [result])
        rendered_json = json.dumps(evidence)
        rendered_md = trojan_live.render_redacted_md(evidence)
        for value in (
            "live-plan.example.invalid",
            "live-plan-password",
            "live-plan-sni.example.invalid",
        ):
            self.assertNotIn(value, rendered_json)
            self.assertNotIn(value, rendered_md)

    def _make_bridge_probe_stdout(
        self,
        *,
        original_class: str = "other",
        error: str | None = None,
        raw_connect_error: str | None = None,
        stream_mode: str = "connect_io",
        stage: str = "connect",
    ) -> str:
        bridge_probe: dict = {
            "ok": False,
            "stream_mode": stream_mode,
            "stage": stage,
            "class": original_class,
            "connect_time_ms": 0,
        }
        if error is not None:
            bridge_probe["error"] = error
        if raw_connect_error is not None:
            bridge_probe["raw_connect_error"] = raw_connect_error
        return json.dumps({"bridge_probe": bridge_probe})

    def test_refine_keeps_specific_class_when_no_stronger_signal(self):
        # `timeout` already conveys actionable meaning; do not overwrite it.
        self.assertEqual(
            trojan_live.refine_bridge_class("timeout", "irrelevant text", None),
            "timeout",
        )
        self.assertEqual(
            trojan_live.refine_bridge_class("post_dial_eof", "", None),
            "post_dial_eof",
        )

    def test_refine_other_with_empty_text_yields_unknown_probe_failure(self):
        self.assertEqual(
            trojan_live.refine_bridge_class("other", None, None),
            "unknown_probe_failure",
        )
        self.assertEqual(
            trojan_live.refine_bridge_class("other", "   ", "   "),
            "unknown_probe_failure",
        )

    def test_refine_unsupported_protocol_from_encrypted_stream_message(self):
        item = self._plan()["selected"][0]
        stdout = self._make_bridge_probe_stdout(
            error=(
                "dial outbound via connect_io after connect error: "
                "trojan adapter uses encrypted stream for example.com:80; "
                "use connect_io() instead: trojan dial failed: misc"
            ),
            raw_connect_error="trojan adapter uses encrypted stream for example.com:80; use connect_io() instead",
        )
        result = trojan_live.result_from_probe(item, 1, 1, stdout, "")
        self.assertEqual(result["status"], "probe_error")
        self.assertEqual(result["class"], "unsupported_protocol")
        self.assertEqual(
            result["bridge_diagnostic"]["error_kind"], "unsupported_protocol"
        )
        self.assertEqual(len(result["bridge_diagnostic"]["error_sha256_12"]), 12)
        self.assertEqual(
            len(result["bridge_diagnostic"]["raw_connect_error_sha256_12"]),
            12,
        )

    def test_refine_dns_error_from_no_such_host(self):
        item = self._plan()["selected"][0]
        stdout = self._make_bridge_probe_stdout(
            error="dial tcp: lookup ns.example.invalid: no such host",
        )
        result = trojan_live.result_from_probe(item, 1, 1, stdout, "")
        self.assertEqual(result["class"], "dns_error")

    def test_refine_tls_error_from_certificate_message(self):
        item = self._plan()["selected"][0]
        stdout = self._make_bridge_probe_stdout(
            error="tls: certificate signed by unknown authority",
        )
        result = trojan_live.result_from_probe(item, 1, 1, stdout, "")
        self.assertEqual(result["class"], "tls_error")

    def test_refine_handshake_eof(self):
        item = self._plan()["selected"][0]
        stdout = self._make_bridge_probe_stdout(
            error="trojan dial failed: tls handshake eof while reading server hello",
        )
        result = trojan_live.result_from_probe(item, 1, 1, stdout, "")
        self.assertEqual(result["class"], "handshake_eof")

    def test_refine_connection_refused(self):
        item = self._plan()["selected"][0]
        stdout = self._make_bridge_probe_stdout(
            error="trojan dial failed: connection refused (os error 61)",
        )
        result = trojan_live.result_from_probe(item, 1, 1, stdout, "")
        self.assertEqual(result["class"], "connection_refused")

    def test_refine_connection_reset(self):
        item = self._plan()["selected"][0]
        stdout = self._make_bridge_probe_stdout(
            error="trojan dial failed: connection reset by peer",
        )
        result = trojan_live.result_from_probe(item, 1, 1, stdout, "")
        self.assertEqual(result["class"], "connection_reset")

    def test_refine_network_unreachable(self):
        item = self._plan()["selected"][0]
        stdout = self._make_bridge_probe_stdout(
            error="trojan dial failed: network is unreachable (os error 51)",
        )
        result = trojan_live.result_from_probe(item, 1, 1, stdout, "")
        self.assertEqual(result["class"], "network_unreachable")

    def test_refine_timeout_text(self):
        item = self._plan()["selected"][0]
        stdout = self._make_bridge_probe_stdout(
            error="trojan dial failed: operation timed out",
        )
        result = trojan_live.result_from_probe(item, 1, 1, stdout, "")
        self.assertEqual(result["class"], "timeout")

    def test_refine_auth_failed(self):
        item = self._plan()["selected"][0]
        stdout = self._make_bridge_probe_stdout(
            error="trojan dial failed: server returned 401 unauthorized",
        )
        result = trojan_live.result_from_probe(item, 1, 1, stdout, "")
        self.assertEqual(result["class"], "auth_failed")

    def test_refine_unexpected_response(self):
        item = self._plan()["selected"][0]
        stdout = self._make_bridge_probe_stdout(
            error="trojan dial failed: malformed response from upstream",
        )
        result = trojan_live.result_from_probe(item, 1, 1, stdout, "")
        self.assertEqual(result["class"], "unexpected_response")

    def test_refine_unknown_probe_failure_when_pattern_misses(self):
        item = self._plan()["selected"][0]
        stdout = self._make_bridge_probe_stdout(
            error="trojan dial failed: weird unspecified condition zzz",
        )
        result = trojan_live.result_from_probe(item, 1, 1, stdout, "")
        # Falls back to unknown_probe_failure so future runs do not silently
        # bucket back into `other`.
        self.assertEqual(result["class"], "unknown_probe_failure")
        self.assertNotEqual(result["class"], "other")

    def test_refine_does_not_emit_other(self):
        item = self._plan()["selected"][0]
        # Even when probe-outbound says class=other and the chain is empty,
        # the runner must not surface `other` to evidence; it must use
        # `unknown_probe_failure` as the explicit fallback.
        stdout = self._make_bridge_probe_stdout(original_class="other", error="")
        result = trojan_live.result_from_probe(item, 1, 1, stdout, "")
        self.assertNotEqual(result["class"], "other")
        self.assertEqual(result["class"], "unknown_probe_failure")

    def test_refine_invalid_server_address_from_socketaddr_parse(self):
        # FRESH-10/11: connect_io chain that surfaced the dataplane blocker.
        # The pre-fix Rust adapter emitted this exact suffix; even after the
        # fix lands, classifier must still recognize the message so historic
        # /tmp evidence stays interpretable.
        item = self._plan()["selected"][0]
        stdout = self._make_bridge_probe_stdout(
            error=(
                "dial outbound via connect_io after connect error: "
                "trojan adapter uses encrypted stream for example.com:80; "
                "use connect_io() instead: trojan dial failed: Other error: "
                "Invalid server address: invalid socket address syntax"
            ),
            raw_connect_error=(
                "trojan adapter uses encrypted stream for example.com:80; "
                "use connect_io() instead"
            ),
        )
        result = trojan_live.result_from_probe(item, 1, 1, stdout, "")
        self.assertEqual(result["class"], "invalid_server_address")
        self.assertEqual(
            result["bridge_diagnostic"]["error_kind"], "invalid_server_address"
        )

    def test_refine_invalid_server_address_outranks_unsupported_protocol(self):
        # When BOTH the wrapper-rejection prefix and the adapter signal are
        # present in the chain, the adapter signal is the actionable one and
        # must win. Verifies the priority of the FRESH-11 pattern.
        self.assertEqual(
            trojan_live.refine_bridge_class(
                "other",
                "trojan adapter uses encrypted stream for x:1; "
                "use connect_io() instead: trojan dial failed: Other error: "
                "Invalid server address: invalid socket address syntax",
                "trojan adapter uses encrypted stream for x:1; use connect_io() instead",
            ),
            "invalid_server_address",
        )

    def test_refine_invalid_server_address_from_raw_connect_error(self):
        # If the adapter signal lives only in raw_connect_error (not in
        # error), the refinement should still pick it up.
        self.assertEqual(
            trojan_live.refine_bridge_class(
                "other",
                None,
                "Invalid server address: invalid socket address syntax",
            ),
            "invalid_server_address",
        )

    def test_bridge_diagnostic_scrubs_raw_server_password_sni(self):
        item = self._plan()["selected"][0]
        raw_server = "leaky-bridge.example.invalid"
        raw_password = "leaky-bridge-password"
        raw_sni = "leaky-bridge-sni.example.invalid"
        stdout = self._make_bridge_probe_stdout(
            error=(
                f"trojan dial failed for {raw_server}:443 sni={raw_sni} "
                f"with password={raw_password}: connection refused"
            ),
            raw_connect_error=(
                f"trojan adapter uses encrypted stream for {raw_server}:443; "
                "use connect_io() instead"
            ),
        )
        result = trojan_live.result_from_probe(
            item,
            1,
            1,
            stdout,
            "",
            [raw_server, raw_password, raw_sni],
        )
        rendered = json.dumps(result)
        for raw in (raw_server, raw_password, raw_sni):
            self.assertNotIn(raw, rendered)
        # The refined class still wins over the raw_connect_error stream
        # mismatch because the connect_io error contains "connection refused".
        self.assertEqual(result["class"], "connection_refused")
        diagnostic = result["bridge_diagnostic"]
        self.assertIn("<redacted:", diagnostic["scrubbed_excerpt"])
        # SHA-256 prefixes still present so future runs can correlate.
        self.assertEqual(len(diagnostic["error_sha256_12"]), 12)
        self.assertEqual(len(diagnostic["raw_connect_error_sha256_12"]), 12)

    def test_redacted_md_does_not_leak_raw_bridge_error_text(self):
        item = self._plan()["selected"][0]
        plan_result = self._plan()
        raw_server = "md-leaky.example.invalid"
        stdout = self._make_bridge_probe_stdout(
            error=f"trojan dial failed for {raw_server}: connection refused",
            raw_connect_error=(
                f"trojan adapter uses encrypted stream for {raw_server}:443; "
                "use connect_io() instead"
            ),
        )
        result = trojan_live.result_from_probe(
            item,
            1,
            1,
            stdout,
            "",
            [raw_server],
        )
        evidence = trojan_live.build_evidence(plan_result, [result])
        rendered_md = trojan_live.render_redacted_md(evidence)
        rendered_json = json.dumps(evidence)
        self.assertNotIn(raw_server, rendered_md)
        self.assertNotIn(raw_server, rendered_json)
        # The bridge fingerprint and refined kind still surface in the md.
        self.assertIn("bridge_error_kind: connection_refused", rendered_md)
        self.assertIn("bridge_fingerprint:", rendered_md)

    def test_fake_structured_probe_success_keeps_classification_a(self):
        plan_result = self._plan()
        item = plan_result["selected"][0]
        stdout = json.dumps(
            {
                "bridge_probe": {
                    "ok": True,
                    "stream_mode": "connect_io",
                    "stage": None,
                    "connect_time_ms": 12,
                    "response_bytes": 128,
                }
            }
        )
        result = trojan_live.result_from_probe(item, 1, 1, stdout, "")
        evidence = trojan_live.build_evidence(plan_result, [result])
        self.assertEqual(evidence["classification"], "A")
        self.assertTrue(evidence["summary"]["node_contact_confirmed"])
        self.assertIsNone(result["bridge_diagnostic"]["error_kind"]) if result.get(
            "bridge_diagnostic"
        ) and result["bridge_diagnostic"].get("error_kind") is None else None
        # Successful bridge_probe leaves class=None per redacted-fields contract.
        self.assertIsNone(result["class"])

    def test_structured_env_limited_failure_remains_classification_b(self):
        plan_result = self._plan()
        item = plan_result["selected"][0]
        stdout = self._make_bridge_probe_stdout(
            original_class="connection_reset",
            error="trojan dial failed: connection reset by peer",
        )
        result = trojan_live.result_from_probe(item, 1, 1, stdout, "")
        evidence = trojan_live.build_evidence(plan_result, [result])
        self.assertEqual(result["class"], "connection_reset")
        self.assertEqual(evidence["classification"], "B")
        self.assertEqual(evidence["summary"]["env_limited_count"], 1)

    def test_tool_error_still_does_not_confirm_node_contact_after_refine(self):
        plan_result = self._plan()
        item = plan_result["selected"][0]
        # Tool-level failure: stdout has no JSON. result.class falls through
        # to classify_tool_failure, and bridge_diagnostic stays None.
        result = trojan_live.result_from_probe(item, 1, 1, "not-json", "")
        self.assertEqual(result["status"], "tool_error")
        self.assertIsNone(result["bridge_diagnostic"])
        evidence = trojan_live.build_evidence(plan_result, [result])
        self.assertEqual(evidence["classification"], "C")
        self.assertFalse(evidence["summary"]["node_contact_confirmed"])


if __name__ == "__main__":
    unittest.main()
