#!/usr/bin/env python3
"""Contract tests for L18 capstone gate wiring."""

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("l18_capstone.sh")
BENCH_MEMORY = SCRIPT.parents[1] / "bench_memory.sh"
DUAL_CERT = SCRIPT.with_name("run_dual_kernel_cert.sh")


class L18CapstoneContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SCRIPT.read_text(encoding="utf-8")

    def test_reality_gate_order_and_status_field(self):
        oracle = self.source.index('run_gate_with_fail_fast "ORACLE"')
        reality = self.source.index('run_gate_with_fail_fast "REALITY_LOCAL"')
        boundaries = self.source.index('run_gate_with_fail_fast "BOUNDARIES"')
        self.assertLess(oracle, reality)
        self.assertLess(reality, boundaries)
        self.assertIn('"reality_local": "${REALITY_LOCAL_STATUS}"', self.source)

    def test_clippy_gate_uses_repository_policy(self):
        match = re.search(
            r'^run_gate_with_fail_fast "CLIPPY" (?P<command>.+)$',
            self.source,
            flags=re.MULTILINE,
        )
        self.assertIsNotNone(match)
        command = match.group("command")
        self.assertEqual(command, 'make -C "${ROOT_DIR}" clippy')
        self.assertNotIn("-D warnings", command)

    def test_memory_bench_tracks_runtime_pid_directly(self):
        source = BENCH_MEMORY.read_text(encoding="utf-8")
        self.assertNotIn('eval "$start_cmd"', source)
        self.assertIn('"${cmd[@]}" >"${WORK_DIR}/${prefix}_bench.log" 2>&1 &', source)

    def test_dual_cert_retains_failed_case_output_and_run_dir(self):
        source = DUAL_CERT.read_text(encoding="utf-8")
        self.assertIn('CASE_LOG_DIR="${REPORT_DIR}/case_logs"', source)
        self.assertIn('run_output="$("${run_cmd[@]}" 2>&1)" || run_rc=$?', source)
        self.assertIn('printf \'%s\\n\' "$run_output" > "${CASE_LOG_DIR}/${case_id}.log"', source)
        self.assertIn('run_dir="$(extract_kv run_dir "$run_output")"', source)

        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            fake_bin = temp / "bin"
            fake_bin.mkdir()
            fake_run_dir = temp / "failed-run"
            fake_cargo = fake_bin / "cargo"
            fake_cargo.write_text(
                """#!/usr/bin/env bash
set -eu
if [[ \"$*\" == *\"case list\"* ]]; then
  printf '%s\\n' 'fake_case\tP0\tBoth\tStrict\ttest'
  exit 0
fi
mkdir -p \"$FAKE_RUN_DIR\"
printf '%s\\n' 'case=fake_case' 'outcome=FAIL' \"run_dir=$FAKE_RUN_DIR\"
exit 7
""",
                encoding="utf-8",
            )
            fake_cargo.chmod(0o755)
            cases_dir = temp / "cases"
            cases_dir.mkdir()
            report_root = temp / "report"
            artifacts_dir = temp / "artifacts"
            env = os.environ.copy()
            env.update(
                {
                    "PATH": f"{fake_bin}:{env['PATH']}",
                    "L18_CASES_DIR": str(cases_dir),
                    "L18_DUAL_REPORT_ROOT": str(report_root),
                    "L18_DUAL_ARTIFACTS_DIR": str(artifacts_dir),
                    "FAKE_RUN_DIR": str(fake_run_dir),
                }
            )
            result = subprocess.run(
                [str(DUAL_CERT), "--profile", "daily"],
                cwd=temp,
                env=env,
                text=True,
                capture_output=True,
                check=False,
                timeout=30,
            )
            self.assertNotEqual(result.returncode, 0)
            reports = sorted(report_root.glob("*/summary.json"))
            self.assertEqual(len(reports), 1)
            summary = json.loads(reports[0].read_text(encoding="utf-8"))
            self.assertEqual(summary["run_fail_count"], 1)
            self.assertEqual(summary["results"][0]["run_dir"], str(fake_run_dir))
            case_log = reports[0].parent / "case_logs" / "fake_case.log"
            self.assertIn("run_dir=" + str(fake_run_dir), case_log.read_text(encoding="utf-8"))

    def test_memory_bench_preserves_literal_binary_and_config_arguments(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            rust_binary = temp / "rust $(touch injected)"
            go_binary = temp / "go binary"
            rust_config = temp / "rust config.json"
            go_config = temp / "go config.json"

            fake_binary = """#!/usr/bin/env bash
printf '%s\\n' "$@" > "${0}.args"
trap 'exit 0' TERM INT
while :; do sleep 1; done
"""
            for binary in (rust_binary, go_binary):
                binary.write_text(fake_binary, encoding="utf-8")
                binary.chmod(0o755)
            rust_config.write_text("{}\n", encoding="utf-8")
            go_config.write_text("{}\n", encoding="utf-8")

            report = temp / "memory report.json"
            env = os.environ.copy()
            env.update(
                {
                    "SINGBOX_BINARY": str(rust_binary),
                    "SINGBOX_CONFIG": str(rust_config),
                    "GO_BINARY": str(go_binary),
                    "GO_CONFIG": str(go_config),
                    "RUST_PROXY_ADDR": "127.0.0.1:1",
                    "GO_PROXY_ADDR": "127.0.0.1:1",
                    "BENCH_MEMORY_REPORT_FILE": str(report),
                    "BENCH_MEMORY_WORK_DIR": str(temp / "work dir"),
                }
            )

            result = subprocess.run(
                [str(BENCH_MEMORY)],
                cwd=temp,
                env=env,
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((temp / "injected").exists())
            self.assertEqual(
                Path(f"{rust_binary}.args").read_text(encoding="utf-8").splitlines(),
                ["--config", str(rust_config)],
            )
            self.assertEqual(
                Path(f"{go_binary}.args").read_text(encoding="utf-8").splitlines(),
                ["run", "-c", str(go_config)],
            )
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(payload["rust"]["binary"], str(rust_binary))
            self.assertEqual(payload["go"]["binary"], str(go_binary))


if __name__ == "__main__":
    unittest.main()
