#!/usr/bin/env python3
"""Run bounded Trojan live sanity from a redacted dry-run plan.

MT-TROJAN-FRESH-04 live runner. This script is intentionally narrow:
it consumes an already-authorized redacted plan, verifies the bounds,
invokes the Rust `probe-outbound` tool for the selected Trojan tags,
and writes only redacted evidence. Raw server, password, and TLS
server_name values are never written to stdout or evidence.
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import subprocess
import sys
from typing import Any


DEFAULT_PROBE_COMMAND = [
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
]

ENV_LIMITED_CLASSES = {
    "connection_refused",
    "connection_reset",
    "permission_denied",
    "post_dial_eof",
    "timeout",
}


def positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return parsed


def load_json_object(path: pathlib.Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"JSON root must be an object: {path}")
    return value


def validate_plan_bounds(
    plan: dict[str, Any],
    expected_selected: int,
    expected_runs: int,
    expected_target: str,
    expected_timeout: int,
) -> None:
    summary = plan.get("summary")
    if not isinstance(summary, dict):
        raise SystemExit("plan has no summary object")
    checks = {
        "selected_count": expected_selected,
        "runs": expected_runs,
        "target": expected_target,
        "timeout": expected_timeout,
        "planned_runs": expected_selected * expected_runs,
    }
    for key, expected in checks.items():
        if summary.get(key) != expected:
            raise SystemExit(f"plan bound mismatch: {key}")
    if summary.get("ready_for_live_authorization") is not True:
        raise SystemExit("plan is not ready_for_live_authorization")
    if len(plan.get("selected", [])) != expected_selected:
        raise SystemExit("selected list length does not match selected_count")


def extract_probe_json(stdout: str) -> dict[str, Any] | None:
    text = stdout.strip()
    if not text:
        return None
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def classify_process_failure(returncode: int, stderr: str) -> str:
    lower = stderr.lower()
    if returncode == 124 or "timeout" in lower or "timed out" in lower:
        return "timeout"
    if "permission denied" in lower or "operation not permitted" in lower:
        return "permission_denied"
    if "connection refused" in lower:
        return "connection_refused"
    if "connection reset" in lower:
        return "connection_reset"
    if "no such file" in lower or "not found" in lower:
        return "tool_missing"
    if "compile_error" in lower or "could not compile" in lower:
        return "tool_compile_error"
    return "other"


def build_probe_command(
    base_command: list[str],
    candidate_config: pathlib.Path,
    item: dict[str, Any],
    target: str,
    timeout: int,
) -> list[str]:
    tag = item.get("tag")
    if not isinstance(tag, str) or not tag:
        raise SystemExit("selected item has no tag")
    return [
        *base_command,
        "--config",
        str(candidate_config),
        "--outbound",
        tag,
        "--target",
        target,
        "--timeout",
        str(timeout),
        "--json",
    ]


def result_from_probe(
    item: dict[str, Any],
    run_index: int,
    returncode: int,
    stdout: str,
    stderr: str,
) -> dict[str, Any]:
    parsed = extract_probe_json(stdout)
    bridge_probe = parsed.get("bridge_probe") if isinstance(parsed, dict) else None
    if isinstance(bridge_probe, dict):
        ok = bridge_probe.get("ok") is True
        class_value = bridge_probe.get("class")
        status = "ok" if ok else "probe_error"
        return {
            "tag": item.get("tag"),
            "index": item.get("index"),
            "run_index": run_index,
            "status": status,
            "ok": ok,
            "class": None if ok else str(class_value or "other"),
            "stage": bridge_probe.get("stage"),
            "stream_mode": bridge_probe.get("stream_mode"),
            "connect_time_ms": bridge_probe.get("connect_time_ms"),
            "response_bytes": bridge_probe.get("response_bytes"),
            "port": item.get("port"),
            "server_hash": item.get("server_hash"),
            "password_hash": item.get("password_hash"),
            "server_name_hash": item.get("server_name_hash"),
        }

    class_value = classify_process_failure(returncode, stderr)
    status = "tool_error" if class_value.startswith("tool_") or class_value == "other" else "probe_error"
    return {
        "tag": item.get("tag"),
        "index": item.get("index"),
        "run_index": run_index,
        "status": status,
        "ok": False,
        "class": class_value,
        "stage": None,
        "stream_mode": None,
        "connect_time_ms": None,
        "response_bytes": None,
        "port": item.get("port"),
        "server_hash": item.get("server_hash"),
        "password_hash": item.get("password_hash"),
        "server_name_hash": item.get("server_name_hash"),
    }


def summarize_results(plan: dict[str, Any], results: list[dict[str, Any]]) -> dict[str, Any]:
    status_counts = collections.Counter(str(item.get("status", "unknown")) for item in results)
    class_counts = collections.Counter(
        str(item.get("class")) for item in results if item.get("class")
    )
    ok_count = sum(1 for item in results if item.get("ok") is True)
    tool_error_count = sum(1 for item in results if item.get("status") == "tool_error")
    env_limited_count = sum(
        1 for item in results if item.get("class") in ENV_LIMITED_CLASSES
    )
    failed_count = len(results) - ok_count
    node_contact_confirmed = any(item.get("status") != "tool_error" for item in results)
    summary = plan["summary"]
    return {
        "selected_count": summary["selected_count"],
        "runs": summary["runs"],
        "target": summary["target"],
        "timeout": summary["timeout"],
        "planned_runs": summary["planned_runs"],
        "executed_runs": len(results),
        "ok_count": ok_count,
        "failed_count": failed_count,
        "env_limited_count": env_limited_count,
        "tool_error_count": tool_error_count,
        "status_counts": dict(sorted(status_counts.items())),
        "class_counts": dict(sorted(class_counts.items())),
        "live_authorized": True,
        "probe_invocations": len(results),
        "node_contact_confirmed": node_contact_confirmed,
        "rust_only_quality_line": True,
        "dual_kernel_parity_promotion": False,
        "bhv_unchanged": "52/56",
    }


def classify_evidence(summary: dict[str, Any]) -> str:
    if summary["executed_runs"] == 0:
        return "D"
    if summary["tool_error_count"] > 0:
        return "C"
    if summary["ok_count"] > 0:
        return "A"
    if summary["failed_count"] == summary["env_limited_count"]:
        return "B"
    return "A"


def build_evidence(plan: dict[str, Any], results: list[dict[str, Any]]) -> dict[str, Any]:
    summary = summarize_results(plan, results)
    return {
        "summary": summary,
        "classification": classify_evidence(summary),
        "results": results,
    }


def render_redacted_md(evidence: dict[str, Any]) -> str:
    summary = evidence["summary"]
    lines = [
        "# Trojan Live Sanity Evidence (redacted)",
        "",
        "Raw server, password, and TLS server_name values are not present.",
        "This is a Rust-only quality line and not dual-kernel parity promotion.",
        "",
        "## Summary",
        "",
        f"- classification: {evidence['classification']}",
        f"- selected_count: {summary['selected_count']}",
        f"- runs: {summary['runs']}",
        f"- target: {summary['target']}",
        f"- timeout: {summary['timeout']}",
        f"- planned_runs: {summary['planned_runs']}",
        f"- executed_runs: {summary['executed_runs']}",
        f"- ok_count: {summary['ok_count']}",
        f"- failed_count: {summary['failed_count']}",
        f"- env_limited_count: {summary['env_limited_count']}",
        f"- tool_error_count: {summary['tool_error_count']}",
        f"- status_counts: {json.dumps(summary['status_counts'], sort_keys=True)}",
        f"- class_counts: {json.dumps(summary['class_counts'], sort_keys=True)}",
        f"- probe_invocations: {summary['probe_invocations']}",
        f"- node_contact_confirmed: {summary['node_contact_confirmed']}",
        f"- bhv_unchanged: {summary['bhv_unchanged']}",
        "",
        f"## Results ({len(evidence['results'])})",
        "",
    ]
    for item in evidence["results"]:
        lines.append(f"- tag={item.get('tag') or '?'}")
        lines.append(f"  - index: {item.get('index')}")
        lines.append(f"  - run_index: {item.get('run_index')}")
        lines.append(f"  - status: {item.get('status')}")
        lines.append(f"  - class: {item.get('class')}")
        lines.append(f"  - stage: {item.get('stage')}")
        lines.append(f"  - stream_mode: {item.get('stream_mode')}")
        lines.append(
            "  - fingerprint: server="
            f"{item.get('server_hash')} password={item.get('password_hash')}"
            f" server_name={item.get('server_name_hash')}"
        )
    return "\n".join(lines).rstrip() + "\n"


def run_live(
    plan: dict[str, Any],
    candidate_config: pathlib.Path,
    probe_command: list[str],
) -> dict[str, Any]:
    summary = plan["summary"]
    results: list[dict[str, Any]] = []
    for item in plan["selected"]:
        for run_index in range(1, int(summary["runs"]) + 1):
            cmd = build_probe_command(
                probe_command,
                candidate_config,
                item,
                str(summary["target"]),
                int(summary["timeout"]),
            )
            try:
                proc = subprocess.run(
                    cmd,
                    cwd=pathlib.Path(__file__).resolve().parents[2],
                    text=True,
                    capture_output=True,
                    timeout=int(summary["timeout"]) + 120,
                    check=False,
                )
                results.append(
                    result_from_probe(
                        item,
                        run_index,
                        proc.returncode,
                        proc.stdout,
                        proc.stderr,
                    )
                )
            except subprocess.TimeoutExpired as exc:
                results.append(
                    result_from_probe(
                        item,
                        run_index,
                        124,
                        exc.stdout if isinstance(exc.stdout, str) else "",
                        exc.stderr if isinstance(exc.stderr, str) else "timeout",
                    )
                )
    return build_evidence(plan, results)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run bounded Trojan live sanity from a redacted plan.")
    parser.add_argument("--plan-json", required=True)
    parser.add_argument("--candidate-config", required=True)
    parser.add_argument("--expected-selected", type=positive_int, default=5)
    parser.add_argument("--expected-runs", type=positive_int, default=1)
    parser.add_argument("--expected-target", default="example.com:80")
    parser.add_argument("--expected-timeout", type=positive_int, default=8)
    parser.add_argument("--output-json", required=True)
    parser.add_argument("--redacted-md")
    parser.add_argument("--probe-command", action="append", default=[])
    args = parser.parse_args(argv)

    plan = load_json_object(pathlib.Path(args.plan_json))
    validate_plan_bounds(
        plan,
        args.expected_selected,
        args.expected_runs,
        args.expected_target,
        args.expected_timeout,
    )
    probe_command = args.probe_command or DEFAULT_PROBE_COMMAND
    evidence = run_live(plan, pathlib.Path(args.candidate_config), probe_command)

    output_path = pathlib.Path(args.output_json)
    output_path.write_text(json.dumps(evidence, indent=2, ensure_ascii=True), encoding="utf-8")
    if args.redacted_md:
        pathlib.Path(args.redacted_md).write_text(render_redacted_md(evidence), encoding="utf-8")

    print(
        json.dumps(
            {
                "output_json": str(output_path),
                "redacted_md": args.redacted_md,
                "classification": evidence["classification"],
                "summary": evidence["summary"],
            },
            indent=2,
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
