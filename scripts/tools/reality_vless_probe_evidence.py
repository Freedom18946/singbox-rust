#!/usr/bin/env python3
"""Build sanitized evidence JSON from a VLESS REALITY probe batch summary."""

import argparse
import datetime
import json
import pathlib
import sys
from typing import Any

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import reality_vless_probe_batch as batch  # noqa: E402


def load_json(path: pathlib.Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise SystemExit(f"JSON root must be an object: {path}")
    return value


def list_strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def counter_value(summary: dict[str, Any], key: str) -> dict[str, int]:
    value = summary.get(key)
    if not isinstance(value, dict):
        return {}
    output = {}
    for item_key, item_value in value.items():
        if isinstance(item_key, str) and isinstance(item_value, int):
            output[item_key] = item_value
    return dict(sorted(output.items()))


def unique_key(base: str, used: set[str]) -> str:
    candidate = batch.safe_slug(base)
    if candidate not in used:
        used.add(candidate)
        return candidate
    index = 2
    while f"{candidate}-{index}" in used:
        index += 1
    value = f"{candidate}-{index}"
    used.add(value)
    return value


def compact_classes(classes: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in classes.values():
        key = str(value)
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def compact_run(result: dict[str, Any], key: str) -> dict[str, Any]:
    compare = result.get("compare")
    labels: list[str] = []
    classes: dict[str, int] = {}
    if isinstance(compare, dict):
        summary = compare.get("summary")
        if isinstance(summary, dict):
            labels = list_strings(summary.get("labels"))
        class_map = compare.get("classes")
        if isinstance(class_map, dict):
            classes = compact_classes(class_map)
    return {
        "outbound": key,
        "ordinal": result.get("ordinal"),
        "run_index": result.get("run_index"),
        "status": result.get("status"),
        "labels": labels,
        "class_counts": classes,
    }


def sanitized_by_outbound(summary: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    source = summary.get("by_outbound")
    if not isinstance(source, dict):
        return {}, {}
    used: set[str] = set()
    aliases: dict[str, str] = {}
    output: dict[str, Any] = {}
    for name, value in sorted(source.items()):
        if not isinstance(name, str) or not isinstance(value, dict):
            continue
        key = unique_key(name, used)
        aliases[name] = key
        output[key] = {
            "status_counts": counter_value(value, "status_counts"),
            "label_counts": counter_value(value, "label_counts"),
            "class_counts": counter_value(value, "class_counts"),
        }
    return output, aliases


def matrix_health(summary: dict[str, Any]) -> dict[str, Any]:
    labels = counter_value(summary, "label_counts")
    divergence = {
        key: value
        for key, value in labels.items()
        if key.endswith("_diverged") or "diverged" in key
    }
    uniform_failures = {
        key: value
        for key, value in labels.items()
        if key.startswith("reality_all_") or key.startswith("vless_all_")
    }
    return {
        "has_divergence": bool(divergence),
        "divergence_labels": divergence,
        "all_ok_runs": labels.get("all_ok", 0),
        "uniform_failure_labels": uniform_failures,
    }


def build_evidence(
    payload: dict[str, Any],
    round_name: str,
    date: str,
    description: str,
    command: str | None,
    source_summary: str | None,
    interpretations: list[str],
) -> dict[str, Any]:
    plan = payload.get("plan")
    summary = payload.get("summary")
    results = payload.get("results")
    if not isinstance(plan, dict):
        plan = {}
    if not isinstance(summary, dict):
        raise SystemExit("batch summary JSON is missing object field: summary")
    if not isinstance(results, list):
        results = []

    by_outbound, aliases = sanitized_by_outbound(summary)
    compact_runs = []
    for result in results:
        if not isinstance(result, dict):
            continue
        name = result.get("name")
        key = aliases.get(name, batch.safe_slug(str(name)))
        compact_runs.append(compact_run(result, key))

    evidence = {
        "round": round_name,
        "date": date,
        "description": description,
        "source_summary": source_summary,
        "command": command,
        "selection": {
            "config": plan.get("config"),
            "target": plan.get("target"),
            "runs": plan.get("runs"),
            "selected_count": plan.get("selected_count"),
        },
        "summary": {
            "total": summary.get("total"),
            "executed_runs": summary.get("executed_runs"),
            "status_counts": counter_value(summary, "status_counts"),
            "label_counts": counter_value(summary, "label_counts"),
            "class_counts": counter_value(summary, "class_counts"),
        },
        "matrix_health": matrix_health(summary),
        "by_outbound": by_outbound,
        "runs": compact_runs,
        "interpretation": interpretations,
    }
    return evidence


def write_json(path: pathlib.Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--summary-json", required=True)
    parser.add_argument("--output-json", required=True)
    parser.add_argument("--round", required=True)
    parser.add_argument("--date", default=datetime.date.today().isoformat())
    parser.add_argument("--description", required=True)
    parser.add_argument("--command")
    parser.add_argument("--interpretation", action="append", default=[])
    args = parser.parse_args()

    summary_path = pathlib.Path(args.summary_json)
    evidence = build_evidence(
        load_json(summary_path),
        args.round,
        args.date,
        args.description,
        args.command,
        str(summary_path),
        args.interpretation,
    )
    output_path = pathlib.Path(args.output_json)
    write_json(output_path, evidence)
    json.dump(
        {
            "output_json": str(output_path),
            "round": args.round,
            "summary_json": str(summary_path),
            "executed_runs": evidence["summary"]["executed_runs"],
            "has_divergence": evidence["matrix_health"]["has_divergence"],
        },
        sys.stdout,
        indent=2,
        ensure_ascii=True,
    )
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
