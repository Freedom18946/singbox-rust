#!/usr/bin/env python3
"""Roll up sanitized VLESS REALITY live evidence files."""

import argparse
import collections
import json
import pathlib
import sys
from typing import Any

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import reality_vless_probe_evidence as evidence_tool  # noqa: E402


def load_json(path: pathlib.Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise SystemExit(f"JSON root must be an object: {path}")
    return value


def merge_counts(target: collections.Counter[str], value: Any) -> None:
    if not isinstance(value, dict):
        return
    for key, count in value.items():
        if isinstance(key, str) and isinstance(count, int):
            target[key] += count


def round_summary(path: pathlib.Path, payload: dict[str, Any]) -> dict[str, Any]:
    summary = payload.get("summary")
    if not isinstance(summary, dict):
        summary = {}
    health = payload.get("matrix_health")
    if not isinstance(health, dict):
        health = evidence_tool.matrix_health(summary)
    label_counts = evidence_tool.counter_value(summary, "label_counts")
    class_counts = evidence_tool.counter_value(summary, "class_counts")
    status_counts = evidence_tool.counter_value(summary, "status_counts")
    return {
        "round": str(payload.get("round", path.stem)),
        "date": payload.get("date"),
        "path": str(path),
        "description": payload.get("description"),
        "total": summary.get("total"),
        "executed_runs": summary.get("executed_runs"),
        "all_ok_runs": health.get("all_ok_runs", label_counts.get("all_ok", 0)),
        "has_divergence": bool(health.get("has_divergence")),
        "uniform_failure_labels": health.get("uniform_failure_labels", {}),
        "status_counts": status_counts,
        "label_counts": label_counts,
        "class_counts": class_counts,
    }


def outbound_summaries(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    source = payload.get("by_outbound")
    if not isinstance(source, dict):
        return {}
    output = {}
    for name, value in source.items():
        if not isinstance(name, str) or not isinstance(value, dict):
            continue
        output[name] = {
            "status_counts": evidence_tool.counter_value(value, "status_counts"),
            "label_counts": evidence_tool.counter_value(value, "label_counts"),
            "class_counts": evidence_tool.counter_value(value, "class_counts"),
        }
    return output


def build_rollup(paths: list[pathlib.Path]) -> dict[str, Any]:
    rounds = []
    labels: collections.Counter[str] = collections.Counter()
    classes: collections.Counter[str] = collections.Counter()
    statuses: collections.Counter[str] = collections.Counter()
    by_outbound: dict[str, dict[str, Any]] = {}

    for path in paths:
        payload = load_json(path)
        item = round_summary(path, payload)
        rounds.append(item)
        merge_counts(labels, item["label_counts"])
        merge_counts(classes, item["class_counts"])
        merge_counts(statuses, item["status_counts"])
        for outbound, summary in outbound_summaries(payload).items():
            entry = by_outbound.setdefault(
                outbound,
                {
                    "rounds": [],
                    "status_counts": collections.Counter(),
                    "label_counts": collections.Counter(),
                    "class_counts": collections.Counter(),
                },
            )
            entry["rounds"].append(item["round"])
            merge_counts(entry["status_counts"], summary.get("status_counts"))
            merge_counts(entry["label_counts"], summary.get("label_counts"))
            merge_counts(entry["class_counts"], summary.get("class_counts"))

    total_runs = sum(item.get("executed_runs") or 0 for item in rounds)
    all_ok_runs = sum(item.get("all_ok_runs") or 0 for item in rounds)
    by_outbound_json = {
        name: {
            "rounds": values["rounds"],
            "status_counts": dict(sorted(values["status_counts"].items())),
            "label_counts": dict(sorted(values["label_counts"].items())),
            "class_counts": dict(sorted(values["class_counts"].items())),
        }
        for name, values in sorted(by_outbound.items())
    }
    return {
        "total_rounds": len(rounds),
        "total_executed_runs": total_runs,
        "total_all_ok_runs": all_ok_runs,
        "total_non_all_ok_runs": total_runs - all_ok_runs,
        "has_any_divergence": any(item["has_divergence"] for item in rounds),
        "status_counts": dict(sorted(statuses.items())),
        "label_counts": dict(sorted(labels.items())),
        "class_counts": dict(sorted(classes.items())),
        "rounds": sorted(rounds, key=lambda item: item["round"]),
        "by_outbound": by_outbound_json,
    }


def markdown_table(rollup: dict[str, Any]) -> str:
    lines = [
        "# MT-REAL-02 REALITY Live Evidence Rollup",
        "",
        f"- rounds: {rollup['total_rounds']}",
        f"- executed runs: {rollup['total_executed_runs']}",
        f"- all_ok runs: {rollup['total_all_ok_runs']}",
        f"- non-all_ok runs: {rollup['total_non_all_ok_runs']}",
        f"- has divergence: {str(rollup['has_any_divergence']).lower()}",
        "",
        "## Rounds",
        "",
        "| Round | Runs | all_ok | Labels | Classes | Divergence |",
        "| --- | ---: | ---: | --- | --- | --- |",
    ]
    for item in rollup["rounds"]:
        labels = ", ".join(f"{key}={value}" for key, value in item["label_counts"].items()) or "-"
        classes = ", ".join(f"{key}={value}" for key, value in item["class_counts"].items()) or "-"
        lines.append(
            "| {round} | {runs} | {ok} | {labels} | {classes} | {divergence} |".format(
                round=item["round"],
                runs=item.get("executed_runs") or 0,
                ok=item.get("all_ok_runs") or 0,
                labels=labels,
                classes=classes,
                divergence=str(item.get("has_divergence", False)).lower(),
            )
        )
    lines.extend(
        [
            "",
            "## Aggregates",
            "",
            f"- labels: {json.dumps(rollup['label_counts'], sort_keys=True)}",
            f"- classes: {json.dumps(rollup['class_counts'], sort_keys=True)}",
            "",
        ]
    )
    return "\n".join(lines)


def write_json(path: pathlib.Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", nargs="+", required=True)
    parser.add_argument("--output-json")
    parser.add_argument("--output-md")
    args = parser.parse_args()

    paths = [pathlib.Path(value) for value in args.evidence]
    rollup = build_rollup(paths)
    if args.output_json:
        write_json(pathlib.Path(args.output_json), rollup)
    if args.output_md:
        output_md = pathlib.Path(args.output_md)
        output_md.parent.mkdir(parents=True, exist_ok=True)
        output_md.write_text(markdown_table(rollup), encoding="utf-8")
    json.dump(
        {
            "total_rounds": rollup["total_rounds"],
            "total_executed_runs": rollup["total_executed_runs"],
            "total_all_ok_runs": rollup["total_all_ok_runs"],
            "has_any_divergence": rollup["has_any_divergence"],
        },
        sys.stdout,
        indent=2,
        ensure_ascii=True,
    )
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
