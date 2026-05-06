#!/usr/bin/env python3
"""Build a bounded Trojan realworld sanity plan without network I/O.

MT-TROJAN-FRESH-02 dry-run runner. This script consumes the redacted
Trojan intake output plus the original candidate config, verifies that
selected intake rows still match the candidate by redacted fingerprint,
and writes an auditable dry-run plan. It never connects to any Trojan
node and never writes raw server, password, or TLS server_name values.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import trojan_sample_intake as intake_tool  # noqa: E402


def positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return parsed


def non_negative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return parsed


def load_json_object(path: pathlib.Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"JSON root must be an object: {path}")
    return value


def outbounds_list(config: dict[str, Any]) -> list[dict[str, Any]]:
    outbounds = config.get("outbounds")
    if not isinstance(outbounds, list):
        raise SystemExit("candidate config has no outbounds list")
    return [item for item in outbounds if isinstance(item, dict)]


def fingerprint_subset_matches(actual: dict[str, Any], expected: dict[str, Any]) -> bool:
    keys = ("server_hash", "port", "password_hash", "server_name_hash")
    return all(actual.get(key) == expected.get(key) for key in keys)


def verified_plan_item(
    ready_item: dict[str, Any],
    candidate_outbounds: list[dict[str, Any]],
    target: str,
    timeout: int,
    runs: int,
) -> dict[str, Any]:
    index = ready_item.get("index")
    if not isinstance(index, int) or index < 0 or index >= len(candidate_outbounds):
        raise SystemExit("intake row has invalid candidate index")

    outbound = candidate_outbounds[index]
    actual_fp = intake_tool.fingerprint_for(outbound)
    expected_fp = ready_item.get("fingerprint")
    if not isinstance(expected_fp, dict) or not fingerprint_subset_matches(actual_fp, expected_fp):
        raise SystemExit(f"intake fingerprint mismatch at candidate index {index}")

    return {
        "tag": ready_item.get("tag"),
        "index": index,
        "port": actual_fp.get("port"),
        "server_hash": actual_fp.get("server_hash"),
        "password_hash": actual_fp.get("password_hash"),
        "server_name_hash": actual_fp.get("server_name_hash"),
        "target": target,
        "timeout": timeout,
        "runs": runs,
    }


def build_plan(
    intake: dict[str, Any],
    candidate_config: dict[str, Any],
    target: str,
    limit: int,
    runs: int,
    timeout: int,
) -> dict[str, Any]:
    summary = intake.get("summary")
    if not isinstance(summary, dict):
        raise SystemExit("intake has no summary object")
    counts = summary.get("counts")
    if not isinstance(counts, dict):
        raise SystemExit("intake summary has no counts object")
    ready_items = intake.get("trojan_ready")
    if not isinstance(ready_items, list):
        raise SystemExit("intake has no trojan_ready list")

    candidate_outbounds = outbounds_list(candidate_config)
    selected_source = [
        item for item in ready_items if isinstance(item, dict) and item.get("classification") == "trojan_ready"
    ][:limit]
    selected = [
        verified_plan_item(item, candidate_outbounds, target, timeout, runs)
        for item in selected_source
    ]
    duplicate_count = int(counts.get("duplicate", 0))
    total_ready = int(counts.get("trojan_ready", len(ready_items)))
    planned_runs = len(selected) * runs
    return {
        "summary": {
            "selected_count": len(selected),
            "total_ready": total_ready,
            "duplicate_count": duplicate_count,
            "planned_runs": planned_runs,
            "dry_run_only": True,
            "ready_for_live_authorization": planned_runs > 0,
            "target": target,
            "limit": limit,
            "runs": runs,
            "timeout": timeout,
        },
        "selected": selected,
    }


def render_redacted_md(plan: dict[str, Any]) -> str:
    summary = plan["summary"]
    lines: list[str] = [
        "# Trojan Probe Plan (redacted dry-run)",
        "",
        "No network connection is made by this plan. Raw server, password,",
        "and TLS server_name values are never written here.",
        "",
        "## Summary",
        "",
        f"- selected_count: {summary['selected_count']}",
        f"- total_ready: {summary['total_ready']}",
        f"- duplicate_count: {summary['duplicate_count']}",
        f"- planned_runs: {summary['planned_runs']}",
        f"- dry_run_only: {summary['dry_run_only']}",
        f"- ready_for_live_authorization: {summary['ready_for_live_authorization']}",
        f"- target: {summary['target']}",
        f"- limit: {summary['limit']}",
        f"- runs: {summary['runs']}",
        f"- timeout: {summary['timeout']}",
        "",
        f"## Selected ({len(plan['selected'])})",
        "",
    ]
    if not plan["selected"]:
        lines.append("_(none)_")
        return "\n".join(lines).rstrip() + "\n"
    for item in plan["selected"]:
        lines.append(f"- tag={item.get('tag') or '?'}")
        lines.append(f"  - index: {item['index']}")
        lines.append(f"  - port: {item['port']}")
        lines.append(
            "  - fingerprint: server="
            f"{item['server_hash']} password={item['password_hash']}"
            f" server_name={item['server_name_hash']}"
        )
        lines.append(f"  - target: {item['target']}")
        lines.append(f"  - timeout: {item['timeout']}")
        lines.append(f"  - runs: {item['runs']}")
    return "\n".join(lines).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a redacted Trojan dry-run probe plan.")
    parser.add_argument("--intake-json", required=True)
    parser.add_argument("--candidate-config", required=True)
    parser.add_argument("--target", default="example.com:80")
    parser.add_argument("--limit", type=non_negative_int, default=5)
    parser.add_argument("--runs", type=positive_int, default=1)
    parser.add_argument("--timeout", type=positive_int, default=8)
    parser.add_argument("--output-json", required=True)
    parser.add_argument("--redacted-md")
    args = parser.parse_args(argv)

    plan = build_plan(
        load_json_object(pathlib.Path(args.intake_json)),
        load_json_object(pathlib.Path(args.candidate_config)),
        args.target,
        args.limit,
        args.runs,
        args.timeout,
    )
    output_path = pathlib.Path(args.output_json)
    output_path.write_text(json.dumps(plan, indent=2, ensure_ascii=True), encoding="utf-8")
    if args.redacted_md:
        pathlib.Path(args.redacted_md).write_text(render_redacted_md(plan), encoding="utf-8")

    print(
        json.dumps(
            {
                "output_json": str(output_path),
                "redacted_md": args.redacted_md,
                "summary": plan["summary"],
            },
            indent=2,
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
