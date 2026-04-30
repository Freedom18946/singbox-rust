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

DIVERGENCE_PHASE_LABEL_ORDER = [
    "app_pre_post_diverged",
    "app_minimal_diverged",
    "minimal_transport_diverged",
    "bridge_io_diverged",
]
DIVERGENCE_PHASE_LABELS = frozenset(DIVERGENCE_PHASE_LABEL_ORDER)
DIVERGENCE_LABELS = DIVERGENCE_PHASE_LABELS
RUN_HEALTH_VALUES = [
    "run_all_ok",
    "run_same_failure",
    "run_divergence",
    "run_unknown",
]


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


def round_sort_key(value: Any) -> tuple[int, int | str]:
    text = str(value)
    try:
        return (0, int(text))
    except ValueError:
        return (1, text)


def has_non_all_ok_labels(labels: dict[str, int]) -> bool:
    return any(key != "all_ok" and value > 0 for key, value in labels.items())


def has_divergence_labels(labels: dict[str, int]) -> bool:
    return any(key in DIVERGENCE_LABELS and value > 0 for key, value in labels.items())


def latest_health(labels: dict[str, int]) -> str:
    if not labels:
        return "latest_unknown"
    if not has_non_all_ok_labels(labels):
        return "latest_all_ok"
    if has_divergence_labels(labels):
        return "latest_divergence"
    return "latest_same_failure"


def run_health(labels: list[str]) -> str:
    counts = {label: 1 for label in labels}
    if not labels:
        return "run_unknown"
    if not has_non_all_ok_labels(counts):
        return "run_all_ok"
    if has_divergence_labels(counts):
        return "run_divergence"
    return "run_same_failure"


def divergence_phase_counts(runs: list[dict[str, Any]]) -> collections.Counter[str]:
    counts: collections.Counter[str] = collections.Counter()
    for run in runs:
        if not isinstance(run, dict):
            continue
        labels = run.get("labels")
        if not isinstance(labels, list):
            continue
        for label in DIVERGENCE_PHASE_LABEL_ORDER:
            if label in labels:
                counts[label] += 1
    return counts


def compact_runs_by_outbound(payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    source = payload.get("runs")
    if not isinstance(source, list):
        return {}
    output: dict[str, list[dict[str, Any]]] = {}
    for item in source:
        if not isinstance(item, dict):
            continue
        outbound = item.get("outbound")
        if not isinstance(outbound, str):
            continue
        labels = item.get("labels")
        if not isinstance(labels, list):
            labels = []
        label_list = [label for label in labels if isinstance(label, str)]
        run = {
            "ordinal": item.get("ordinal"),
            "run_index": item.get("run_index"),
            "status": item.get("status"),
            "labels": label_list,
            "run_health": run_health(label_list),
            "class_counts": evidence_tool.counter_value(item, "class_counts"),
        }
        output.setdefault(outbound, []).append(run)
    return output


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
    runs_by_outbound = compact_runs_by_outbound(payload)
    for name, value in source.items():
        if not isinstance(name, str) or not isinstance(value, dict):
            continue
        output[name] = {
            "status_counts": evidence_tool.counter_value(value, "status_counts"),
            "label_counts": evidence_tool.counter_value(value, "label_counts"),
            "class_counts": evidence_tool.counter_value(value, "class_counts"),
            "runs": runs_by_outbound.get(name, []),
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
                    "history": [],
                    "status_counts": collections.Counter(),
                    "label_counts": collections.Counter(),
                    "class_counts": collections.Counter(),
                    "run_health_counts": collections.Counter(),
                    "divergence_phase_counts": collections.Counter(),
                },
            )
            entry["rounds"].append(item["round"])
            merge_counts(entry["status_counts"], summary.get("status_counts"))
            merge_counts(entry["label_counts"], summary.get("label_counts"))
            merge_counts(entry["class_counts"], summary.get("class_counts"))
            phase_counts = divergence_phase_counts(summary.get("runs", []))
            run_health_counts = collections.Counter(
                run.get("run_health")
                for run in summary.get("runs", [])
                if isinstance(run, dict) and isinstance(run.get("run_health"), str)
            )
            merge_counts(entry["run_health_counts"], run_health_counts)
            merge_counts(entry["divergence_phase_counts"], phase_counts)
            entry["history"].append(
                {
                    "round": item["round"],
                    "path": item["path"],
                    "status_counts": summary.get("status_counts", {}),
                    "label_counts": summary.get("label_counts", {}),
                    "class_counts": summary.get("class_counts", {}),
                    "run_health_counts": dict(sorted(run_health_counts.items())),
                    "divergence_phase_counts": dict(sorted(phase_counts.items())),
                    "runs": summary.get("runs", []),
                }
            )

    total_runs = sum(item.get("executed_runs") or 0 for item in rounds)
    all_ok_runs = sum(item.get("all_ok_runs") or 0 for item in rounds)
    by_outbound_json = {}
    latest_non_all_ok = []
    latest_divergence = []
    latest_same_failure = []
    latest_stable_divergence = []
    latest_mixed_run_health = []
    recovered = []
    latest_stable_same_failure = []
    latest_health_counts: collections.Counter[str] = collections.Counter()
    latest_run_health_counts: collections.Counter[str] = collections.Counter()
    latest_divergence_phase_total_counts: collections.Counter[str] = collections.Counter()
    latest_divergence_phase_outbounds: dict[str, set[str]] = {
        label: set() for label in DIVERGENCE_PHASE_LABEL_ORDER
    }
    for name, values in sorted(by_outbound.items()):
        history = sorted(values["history"], key=lambda item: round_sort_key(item["round"]))
        latest = history[-1] if history else {}
        latest_labels = evidence_tool.counter_value(latest, "label_counts")
        latest_classes = evidence_tool.counter_value(latest, "class_counts")
        latest_statuses = evidence_tool.counter_value(latest, "status_counts")
        latest_run_counts = evidence_tool.counter_value(latest, "run_health_counts")
        latest_phase_counts = evidence_tool.counter_value(latest, "divergence_phase_counts")
        latest_has_non_all_ok = has_non_all_ok_labels(latest_labels)
        latest_state = latest_health(latest_labels)
        historical_has_non_all_ok = has_non_all_ok_labels(dict(sorted(values["label_counts"].items())))
        latest_health_counts[latest_state] += 1
        merge_counts(latest_run_health_counts, latest_run_counts)
        latest_run_health_kinds = [
            key
            for key in RUN_HEALTH_VALUES
            if latest_run_counts.get(key, 0) > 0
        ]
        if latest_has_non_all_ok:
            latest_non_all_ok.append(name)
        if latest_state == "latest_divergence":
            latest_divergence.append(name)
            merge_counts(latest_divergence_phase_total_counts, latest_phase_counts)
            for label in DIVERGENCE_PHASE_LABEL_ORDER:
                if latest_phase_counts.get(label, 0) > 0:
                    latest_divergence_phase_outbounds[label].add(name)
            if latest_run_counts.get("run_divergence", 0) > 0 and len(latest_run_health_kinds) == 1:
                latest_stable_divergence.append(name)
            elif len(latest_run_health_kinds) > 1:
                latest_mixed_run_health.append(name)
        elif latest_state == "latest_same_failure":
            latest_same_failure.append(name)
            if latest_run_counts.get("run_same_failure", 0) > 0 and len(latest_run_health_kinds) == 1:
                latest_stable_same_failure.append(name)
            elif len(latest_run_health_kinds) > 1:
                latest_mixed_run_health.append(name)
        elif latest_state == "latest_all_ok" and historical_has_non_all_ok:
            recovered.append(name)
        by_outbound_json[name] = {
            "rounds": sorted(values["rounds"], key=round_sort_key),
            "status_counts": dict(sorted(values["status_counts"].items())),
            "label_counts": dict(sorted(values["label_counts"].items())),
            "class_counts": dict(sorted(values["class_counts"].items())),
            "run_health_counts": dict(sorted(values["run_health_counts"].items())),
            "divergence_phase_counts": dict(sorted(values["divergence_phase_counts"].items())),
            "history": history,
            "latest_round": latest.get("round"),
            "latest_status_counts": latest_statuses,
            "latest_label_counts": latest_labels,
            "latest_class_counts": latest_classes,
            "latest_run_health_counts": latest_run_counts,
            "latest_divergence_phase_counts": latest_phase_counts,
            "latest_has_non_all_ok": latest_has_non_all_ok,
            "latest_health": latest_state,
            "historical_has_non_all_ok": historical_has_non_all_ok,
        }
    return {
        "total_rounds": len(rounds),
        "total_executed_runs": total_runs,
        "total_all_ok_runs": all_ok_runs,
        "total_non_all_ok_runs": total_runs - all_ok_runs,
        "has_any_divergence": any(item["has_divergence"] for item in rounds),
        "latest_non_all_ok_outbounds": latest_non_all_ok,
        "latest_non_all_ok_outbound_count": len(latest_non_all_ok),
        "latest_divergence_outbounds": latest_divergence,
        "latest_divergence_outbound_count": len(latest_divergence),
        "latest_stable_divergence_outbounds": latest_stable_divergence,
        "latest_stable_divergence_outbound_count": len(latest_stable_divergence),
        "latest_mixed_run_health_outbounds": latest_mixed_run_health,
        "latest_mixed_run_health_outbound_count": len(latest_mixed_run_health),
        "latest_same_failure_outbounds": latest_same_failure,
        "latest_same_failure_outbound_count": len(latest_same_failure),
        "latest_stable_same_failure_outbounds": latest_stable_same_failure,
        "latest_stable_same_failure_outbound_count": len(latest_stable_same_failure),
        "latest_divergence_phase_summary": {
            label: sorted(names)
            for label, names in latest_divergence_phase_outbounds.items()
            if names
        },
        "latest_divergence_phase_total_counts": {
            label: latest_divergence_phase_total_counts[label]
            for label in DIVERGENCE_PHASE_LABEL_ORDER
            if latest_divergence_phase_total_counts.get(label, 0) > 0
        },
        "recovered_outbounds": recovered,
        "recovered_outbound_count": len(recovered),
        "latest_health_counts": dict(sorted(latest_health_counts.items())),
        "latest_run_health_counts": dict(sorted(latest_run_health_counts.items())),
        "status_counts": dict(sorted(statuses.items())),
        "label_counts": dict(sorted(labels.items())),
        "class_counts": dict(sorted(classes.items())),
        "rounds": sorted(rounds, key=lambda item: round_sort_key(item["round"])),
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
        f"- latest non-all_ok outbounds: {rollup.get('latest_non_all_ok_outbound_count', 0)}",
        f"- latest divergence outbounds: {rollup.get('latest_divergence_outbound_count', 0)}",
        f"- latest stable divergence outbounds: {rollup.get('latest_stable_divergence_outbound_count', 0)}",
        f"- latest mixed run-health outbounds: {rollup.get('latest_mixed_run_health_outbound_count', 0)}",
        f"- latest stable same-failure outbounds: {rollup.get('latest_stable_same_failure_outbound_count', 0)}",
        f"- recovered outbounds: {rollup.get('recovered_outbound_count', 0)}",
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
            f"- latest health: {json.dumps(rollup.get('latest_health_counts', {}), sort_keys=True)}",
            f"- latest run health: {json.dumps(rollup.get('latest_run_health_counts', {}), sort_keys=True)}",
            "",
            "## Latest divergence phase composition",
            "",
        ]
    )
    phase_totals = rollup.get("latest_divergence_phase_total_counts", {})
    phase_summary = rollup.get("latest_divergence_phase_summary", {})
    if not phase_totals:
        lines.extend(["_(no latest divergence)_", ""])
    else:
        for label in DIVERGENCE_PHASE_LABEL_ORDER:
            count = phase_totals.get(label, 0) if isinstance(phase_totals, dict) else 0
            outbounds = phase_summary.get(label, []) if isinstance(phase_summary, dict) else []
            outbound_text = ", ".join(outbounds) if outbounds else "-"
            lines.append(f"- {label}: {count} ({outbound_text})")
        lines.append("")
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
