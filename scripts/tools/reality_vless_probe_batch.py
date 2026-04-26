#!/usr/bin/env python3
"""Batch app/minimal VLESS REALITY probe matrix samples."""

import argparse
import collections
import json
import pathlib
import re
import subprocess
import sys
from typing import Any

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent
sys.path.insert(0, str(SCRIPT_DIR))

import reality_vless_env_from_config as envtool  # noqa: E402


def safe_slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    slug = slug.strip("._-")
    return slug[:80] or "outbound"


def select_outbounds(
    items: list[dict[str, Any]],
    names: list[str],
    include: str | None,
    exclude: str | None,
    include_skipped: bool,
    limit: int | None,
) -> list[dict[str, Any]]:
    selected = []
    by_name = {}
    for item in items:
        name = item.get("name")
        if isinstance(name, str) and name not in by_name:
            by_name[name] = item
    if names:
        candidates = [by_name[name] for name in names if name in by_name]
    else:
        candidates = items
    for item in candidates:
        if limit is not None and len(selected) >= limit:
            break
        name = item.get("name")
        if not isinstance(name, str):
            continue
        if include and include not in name:
            continue
        if exclude and exclude in name:
            continue
        if not include_skipped and not item.get("ready"):
            continue
        selected.append(item)
    return selected


def load_compare(path: pathlib.Path) -> dict[str, Any] | None:
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (FileNotFoundError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def load_plan_names(path: pathlib.Path) -> list[str]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise SystemExit(f"plan root must be an object: {path}")
    selected = value.get("selected")
    if not isinstance(selected, list):
        raise SystemExit(f"plan has no selected list: {path}")
    names = []
    for item in selected:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            names.append(item["name"])
    return names


def ordered_unique(values: list[str]) -> list[str]:
    seen = set()
    output = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output


def summarize_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    labels = collections.Counter()
    classes = collections.Counter()
    statuses = collections.Counter()
    by_outbound: dict[str, dict[str, collections.Counter[str]]] = {}
    for result in results:
        name = str(result.get("name", "unknown"))
        status = str(result.get("status", "unknown"))
        statuses[status] += 1
        outbound = by_outbound.setdefault(
            name,
            {
                "status_counts": collections.Counter(),
                "label_counts": collections.Counter(),
                "class_counts": collections.Counter(),
            },
        )
        outbound["status_counts"][status] += 1
        compare = result.get("compare")
        if not isinstance(compare, dict):
            continue
        summary = compare.get("summary")
        if isinstance(summary, dict):
            for label in summary.get("labels", []):
                labels[str(label)] += 1
                outbound["label_counts"][str(label)] += 1
        class_map = compare.get("classes")
        if isinstance(class_map, dict):
            for value in class_map.values():
                classes[str(value)] += 1
                outbound["class_counts"][str(value)] += 1
    return {
        "total": len(results),
        "executed_runs": sum(1 for result in results if result.get("run_index") is not None),
        "status_counts": dict(sorted(statuses.items())),
        "label_counts": dict(sorted(labels.items())),
        "class_counts": dict(sorted(classes.items())),
        "by_outbound": {
            name: {
                key: dict(sorted(counter.items()))
                for key, counter in sorted(counters.items())
            }
            for name, counters in sorted(by_outbound.items())
        },
    }


def run_matrix(
    matrix_script: pathlib.Path,
    config: pathlib.Path,
    outbound: str,
    target: str,
    output_dir: pathlib.Path,
    timeout: int,
    phase_timeout_ms: int,
    probe_io_timeout_ms: int,
) -> int:
    cmd = [
        "bash",
        str(matrix_script),
        "--config",
        str(config),
        "--outbound",
        outbound,
        "--target",
        target,
        "--timeout",
        str(timeout),
        "--phase-timeout-ms",
        str(phase_timeout_ms),
        "--probe-io-timeout-ms",
        str(probe_io_timeout_ms),
        "--output-dir",
        str(output_dir),
    ]
    completed = subprocess.run(cmd, cwd=ROOT, check=False)
    return completed.returncode


def write_json(path: pathlib.Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def sample_dir_for(output_dir: pathlib.Path, ordinal: int, name: str, runs: int, run_index: int) -> pathlib.Path:
    base = output_dir / f"{ordinal:03d}-{safe_slug(name)}"
    if runs == 1:
        return base
    return base / f"run-{run_index:03d}"


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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--target", default="example.com:80")
    parser.add_argument("--output-dir")
    parser.add_argument("--outbound", action="append", default=[])
    parser.add_argument("--plan-json", action="append", default=[])
    parser.add_argument("--include")
    parser.add_argument("--exclude")
    parser.add_argument("--include-skipped", action="store_true")
    parser.add_argument("--limit", type=non_negative_int)
    parser.add_argument("--runs", type=positive_int, default=1)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--phase-timeout-ms", type=int, default=10_000)
    parser.add_argument("--probe-io-timeout-ms", type=int, default=10_000)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--matrix-script",
        default=str(SCRIPT_DIR / "reality_vless_probe_matrix.sh"),
    )
    args = parser.parse_args()

    config = pathlib.Path(args.config)
    output_dir = pathlib.Path(
        args.output_dir
        or pathlib.Path("/tmp") / f"reality-vless-probe-batch.{safe_slug(config.stem)}"
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    items = envtool.list_reality_vless_outbounds(envtool.load_config(config))
    plan_names = []
    for plan_path in args.plan_json:
        plan_names.extend(load_plan_names(pathlib.Path(plan_path)))
    names = ordered_unique(args.outbound + plan_names)
    selected = select_outbounds(
        items,
        names,
        args.include,
        args.exclude,
        args.include_skipped,
        args.limit,
    )
    plan = {
        "config": str(config),
        "target": args.target,
        "dry_run": args.dry_run,
        "runs": args.runs,
        "plan_json": args.plan_json,
        "selected_count": len(selected),
        "selected": selected,
    }
    write_json(output_dir / "plan.json", plan)

    results = []
    if not args.dry_run:
        matrix_script = pathlib.Path(args.matrix_script)
        results_jsonl = output_dir / "results.jsonl"
        results_jsonl.unlink(missing_ok=True)
        for ordinal, item in enumerate(selected, start=1):
            name = str(item["name"])
            if not item.get("ready"):
                sample_dir = output_dir / f"{ordinal:03d}-{safe_slug(name)}"
                sample_dir.mkdir(parents=True, exist_ok=True)
                result = {
                    "ordinal": ordinal,
                    "name": name,
                    "run_index": None,
                    "status": "skipped",
                    "skip_reason": item.get("skip_reason"),
                    "sample_dir": str(sample_dir),
                    "compare": None,
                }
                results.append(result)
                with results_jsonl.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(result, ensure_ascii=True) + "\n")
                continue
            for run_index in range(1, args.runs + 1):
                sample_dir = sample_dir_for(output_dir, ordinal, name, args.runs, run_index)
                sample_dir.mkdir(parents=True, exist_ok=True)
                status = run_matrix(
                    matrix_script,
                    config,
                    name,
                    args.target,
                    sample_dir,
                    args.timeout,
                    args.phase_timeout_ms,
                    args.probe_io_timeout_ms,
                )
                compare = load_compare(sample_dir / "compare.json")
                result = {
                    "ordinal": ordinal,
                    "name": name,
                    "run_index": run_index,
                    "status": "completed" if status == 0 else "matrix_error",
                    "matrix_status": status,
                    "sample_dir": str(sample_dir),
                    "compare": compare,
                }
                results.append(result)
                with results_jsonl.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(result, ensure_ascii=True) + "\n")

    summary = {
        "plan": {
            "config": str(config),
            "target": args.target,
            "dry_run": args.dry_run,
            "runs": args.runs,
            "plan_json": args.plan_json,
            "selected_count": len(selected),
        },
        "summary": summarize_results(results),
        "results": results,
    }
    write_json(output_dir / "summary.json", summary)
    json.dump(
        {
            "output_dir": str(output_dir),
            "plan_json": str(output_dir / "plan.json"),
            "summary_json": str(output_dir / "summary.json"),
            "results_jsonl": None if args.dry_run else str(output_dir / "results.jsonl"),
            "selected_count": len(selected),
            "runs": args.runs,
        },
        sys.stdout,
        indent=2,
        ensure_ascii=True,
    )
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
