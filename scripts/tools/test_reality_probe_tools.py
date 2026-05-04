#!/usr/bin/env python3
import argparse
import json
import pathlib
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


if __name__ == "__main__":
    unittest.main()
