#!/usr/bin/env python3
"""Normalize Trojan candidate configs for offline probe preflight.

MT-TROJAN-FRESH-07 config gate. This tool removes GUI/private metadata
fields whose names start with ``__`` and writes a probe-loadable config
copy. It emits only type-level and field-name summaries; raw server,
password, and TLS server_name values are never written to stdout or
redacted outputs.
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
from typing import Any


def load_json_object(path: pathlib.Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit("candidate config root must be an object")
    return value


def normalize_value(value: Any, removed: collections.Counter[str]) -> Any:
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, child in value.items():
            if key.startswith("__"):
                removed[key] += 1
                continue
            normalized[key] = normalize_value(child, removed)
        return normalized
    if isinstance(value, list):
        return [normalize_value(item, removed) for item in value]
    return value


def outbounds_count(config: dict[str, Any]) -> int:
    outbounds = config.get("outbounds")
    return len(outbounds) if isinstance(outbounds, list) else 0


def normalize_config(config: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    removed: collections.Counter[str] = collections.Counter()
    normalized = normalize_value(config, removed)
    if not isinstance(normalized, dict):
        raise SystemExit("normalized config root must be an object")
    summary = {
        "outbounds_count": outbounds_count(normalized),
        "removed_field_counts": dict(sorted(removed.items())),
        "removed_field_names": sorted(removed),
        "removed_total": sum(removed.values()),
        "ready_for_no_dial_preflight": isinstance(normalized.get("outbounds"), list),
    }
    return normalized, summary


def render_redacted_md(summary: dict[str, Any]) -> str:
    lines = [
        "# Trojan Config Normalization (redacted)",
        "",
        "This summary contains only counts and removed field names.",
        "Raw server, password, and TLS server_name values are never written here.",
        "",
        "## Summary",
        "",
        f"- outbounds_count: {summary['outbounds_count']}",
        f"- removed_total: {summary['removed_total']}",
        f"- ready_for_no_dial_preflight: {summary['ready_for_no_dial_preflight']}",
        "",
        "## Removed Fields",
        "",
    ]
    counts = summary.get("removed_field_counts", {})
    if not counts:
        lines.append("_(none)_")
    else:
        for name, count in sorted(counts.items()):
            lines.append(f"- {name}: {count}")
    return "\n".join(lines).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Remove GUI/private metadata from Trojan candidate configs."
    )
    parser.add_argument("--candidate-config", required=True)
    parser.add_argument("--output-config", required=True)
    parser.add_argument("--summary-json", required=True)
    parser.add_argument("--redacted-md")
    args = parser.parse_args(argv)

    normalized, summary = normalize_config(load_json_object(pathlib.Path(args.candidate_config)))
    pathlib.Path(args.output_config).write_text(
        json.dumps(normalized, indent=2, ensure_ascii=True),
        encoding="utf-8",
    )
    pathlib.Path(args.summary_json).write_text(
        json.dumps(summary, indent=2, ensure_ascii=True),
        encoding="utf-8",
    )
    if args.redacted_md:
        pathlib.Path(args.redacted_md).write_text(render_redacted_md(summary), encoding="utf-8")

    print(
        json.dumps(
            {
                "outbounds_count": summary["outbounds_count"],
                "removed_field_counts": summary["removed_field_counts"],
                "removed_field_names": summary["removed_field_names"],
                "ready_for_no_dial_preflight": summary["ready_for_no_dial_preflight"],
            },
            indent=2,
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
