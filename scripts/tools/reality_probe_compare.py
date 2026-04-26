#!/usr/bin/env python3
"""Compare app probe JSON with minimal VLESS REALITY phase-probe JSON."""

import argparse
import json
import sys
from typing import Any


def load_json(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise SystemExit(f"JSON root must be an object: {path}")
    return value


def get_path(root: dict[str, Any], dotted: str) -> Any:
    cursor: Any = root
    for part in dotted.split("."):
        if not isinstance(cursor, dict) or part not in cursor:
            return None
        cursor = cursor[part]
    return cursor


def phase_label(phase: Any) -> str:
    if not isinstance(phase, dict):
        return "missing"
    status = phase.get("status")
    if status == "skip":
        reason = phase.get("reason")
        return f"skip:{reason}" if reason else "skip"
    if phase.get("ok") is True:
        return "ok"
    phase_class = phase.get("class")
    if isinstance(phase_class, str) and phase_class:
        return phase_class
    if status:
        return str(status)
    return "unknown"


def collect_classes(app: dict[str, Any], phase: dict[str, Any]) -> dict[str, str]:
    paths = {
        "app.pre.direct_reality": (app, "pre_bridge.direct_reality"),
        "app.pre.direct_vless_dial": (app, "pre_bridge.direct_vless_dial"),
        "app.post.direct_reality": (app, "post_bridge.direct_reality"),
        "app.post.direct_vless_dial": (app, "post_bridge.direct_vless_dial"),
        "app.bridge": (app, "bridge_probe"),
        "minimal.direct_reality": (phase, "direct_reality"),
        "minimal.transport_reality": (phase, "transport_reality"),
        "minimal.vless_dial": (phase, "vless_dial"),
        "minimal.vless_probe_io": (phase, "vless_probe_io"),
    }
    return {name: phase_label(get_path(root, path)) for name, (root, path) in paths.items()}


def compare_pair(classes: dict[str, str], name: str, left: str, right: str) -> dict[str, Any]:
    left_value = classes.get(left, "missing")
    right_value = classes.get(right, "missing")
    return {
        "name": name,
        "left": left,
        "right": right,
        "left_class": left_value,
        "right_class": right_value,
        "match": left_value == right_value,
    }


def build_report(app: dict[str, Any], phase: dict[str, Any]) -> dict[str, Any]:
    classes = collect_classes(app, phase)
    comparisons = [
        compare_pair(
            classes,
            "app_pre_post_direct_reality",
            "app.pre.direct_reality",
            "app.post.direct_reality",
        ),
        compare_pair(
            classes,
            "app_pre_post_vless_dial",
            "app.pre.direct_vless_dial",
            "app.post.direct_vless_dial",
        ),
        compare_pair(
            classes,
            "minimal_direct_vs_transport_reality",
            "minimal.direct_reality",
            "minimal.transport_reality",
        ),
        compare_pair(
            classes,
            "app_post_vs_minimal_direct_reality",
            "app.post.direct_reality",
            "minimal.direct_reality",
        ),
        compare_pair(
            classes,
            "app_post_vs_minimal_vless_dial",
            "app.post.direct_vless_dial",
            "minimal.vless_dial",
        ),
        compare_pair(
            classes,
            "app_bridge_vs_minimal_probe_io",
            "app.bridge",
            "minimal.vless_probe_io",
        ),
    ]
    labels = []
    for comparison in comparisons:
        if comparison["match"]:
            continue
        if comparison["name"].startswith("app_pre_post"):
            labels.append("app_pre_post_diverged")
        elif comparison["name"].startswith("minimal_direct"):
            labels.append("minimal_transport_diverged")
        elif comparison["name"].startswith("app_bridge"):
            labels.append("bridge_io_diverged")
        else:
            labels.append("app_minimal_diverged")
    non_missing = [value for value in classes.values() if value != "missing"]
    if non_missing and all(value == "ok" for value in non_missing):
        labels.append("all_ok")
    reality_values = [
        classes["app.pre.direct_reality"],
        classes["app.post.direct_reality"],
        classes["minimal.direct_reality"],
        classes["minimal.transport_reality"],
    ]
    if len(set(reality_values)) == 1 and reality_values[0] not in {"ok", "missing"}:
        labels.append(f"reality_all_{reality_values[0]}")
    probe_io_values = [
        classes["app.bridge"],
        classes["minimal.vless_probe_io"],
    ]
    if len(set(probe_io_values)) == 1 and probe_io_values[0] not in {"ok", "missing"}:
        labels.append(f"probe_io_all_{probe_io_values[0]}")

    labels = sorted(set(labels))
    return {
        "app": {
            "tool": app.get("tool"),
            "outbound": app.get("outbound"),
            "target": app.get("target"),
        },
        "minimal": {
            "server": phase.get("server"),
            "target": phase.get("target"),
        },
        "classes": classes,
        "comparisons": comparisons,
        "summary": {
            "total_comparisons": len(comparisons),
            "mismatches": sum(1 for comparison in comparisons if not comparison["match"]),
            "labels": labels,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app-json", required=True)
    parser.add_argument("--phase-json", required=True)
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()

    report = build_report(load_json(args.app_json), load_json(args.phase_json))
    json.dump(report, sys.stdout, indent=2, ensure_ascii=True)
    sys.stdout.write("\n")
    if args.strict and report["summary"]["mismatches"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
