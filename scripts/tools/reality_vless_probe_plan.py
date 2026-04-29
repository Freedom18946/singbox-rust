#!/usr/bin/env python3
"""Plan the next VLESS REALITY live probe batch from config + evidence rollup."""

import argparse
import collections
import json
import pathlib
import sys
from typing import Any

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import reality_vless_env_from_config as envtool  # noqa: E402
import reality_vless_probe_batch as batch  # noqa: E402

LATEST_HEALTH_VALUES = {
    "latest_all_ok",
    "latest_same_failure",
    "latest_divergence",
    "latest_unknown",
}


def load_json(path: pathlib.Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise SystemExit(f"JSON root must be an object: {path}")
    return value


def covered_outbounds(rollup: dict[str, Any]) -> dict[str, dict[str, Any]]:
    value = rollup.get("by_outbound")
    if not isinstance(value, dict):
        return {}
    output = {}
    for key, item in value.items():
        if isinstance(key, str) and isinstance(item, dict):
            output[key] = item
    return output


def has_non_all_ok(prior: dict[str, Any]) -> bool:
    labels = prior.get("latest_label_counts")
    if not isinstance(labels, dict):
        labels = prior.get("label_counts")
    if not isinstance(labels, dict):
        return False
    for key, value in labels.items():
        if key != "all_ok" and isinstance(value, int) and value > 0:
            return True
    return False


def classify_item(key: str, prior: dict[str, Any] | None) -> str:
    if prior is None:
        return "uncovered"
    if has_non_all_ok(prior):
        return "prior_non_all_ok"
    return "covered_all_ok"


def latest_health(prior: dict[str, Any] | None) -> str | None:
    if prior is None:
        return None
    value = prior.get("latest_health")
    return value if isinstance(value, str) else None


def build_plan(
    config: dict[str, Any],
    rollup: dict[str, Any],
    limit: int | None,
    include_failure_rechecks: bool,
    include_covered: bool,
    include_internal: bool,
    latest_health_filter: list[str] | None = None,
) -> dict[str, Any]:
    covered = covered_outbounds(rollup)
    health_filter = set(latest_health_filter or [])
    buckets: dict[str, list[dict[str, Any]]] = {
        "uncovered": [],
        "prior_non_all_ok": [],
        "covered_all_ok": [],
    }
    health_counts: collections.Counter[str] = collections.Counter()
    candidates = []
    for item in envtool.list_reality_vless_outbounds(config):
        if not item.get("ready"):
            continue
        name = item.get("name")
        if not isinstance(name, str):
            continue
        if not include_internal and name.startswith("__"):
            continue
        key = batch.safe_slug(name)
        prior = covered.get(key)
        reason = classify_item(key, prior)
        health = latest_health(prior)
        if health:
            health_counts[health] += 1
        planned = {
            "name": name,
            "key": key,
            "server": item.get("server"),
            "port": item.get("port"),
            "server_name": item.get("server_name"),
            "fingerprint": item.get("fingerprint"),
            "flow": item.get("flow"),
            "reason": reason,
            "latest_health": health,
            "prior": prior,
        }
        buckets[reason].append(planned)
        candidates.append(planned)

    if health_filter:
        selected = [item for item in candidates if item.get("latest_health") in health_filter]
    else:
        selected = list(buckets["uncovered"])
        if include_failure_rechecks:
            selected.extend(buckets["prior_non_all_ok"])
        if include_covered:
            selected.extend(buckets["covered_all_ok"])
    if limit is not None:
        selected = selected[:limit]
    return {
        "rollup_rounds": rollup.get("total_rounds"),
        "rollup_executed_runs": rollup.get("total_executed_runs"),
        "counts": {key: len(value) for key, value in buckets.items()},
        "latest_health_filter": sorted(health_filter),
        "latest_health_counts": dict(sorted(health_counts.items())),
        "selected_count": len(selected),
        "selected": selected,
    }


def write_json(path: pathlib.Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--rollup-json", required=True)
    parser.add_argument("--limit", type=batch.non_negative_int)
    parser.add_argument("--include-failure-rechecks", action="store_true")
    parser.add_argument("--include-covered", action="store_true")
    parser.add_argument("--include-internal", action="store_true")
    parser.add_argument(
        "--latest-health",
        action="append",
        choices=sorted(LATEST_HEALTH_VALUES),
        default=[],
        help="Select ready outbounds whose latest rollup health matches this value.",
    )
    parser.add_argument("--output-json")
    args = parser.parse_args()

    config_path = pathlib.Path(args.config)
    rollup_path = pathlib.Path(args.rollup_json)
    plan = build_plan(
        envtool.load_config(config_path),
        load_json(rollup_path),
        args.limit,
        args.include_failure_rechecks,
        args.include_covered,
        args.include_internal,
        args.latest_health,
    )
    plan["config"] = str(config_path)
    plan["rollup_json"] = str(rollup_path)
    if args.output_json:
        write_json(pathlib.Path(args.output_json), plan)
    json.dump(
        {
            "selected_count": plan["selected_count"],
            "counts": plan["counts"],
            "selected": [
                {
                    "name": item["name"],
                    "key": item["key"],
                    "reason": item["reason"],
                    "latest_health": item["latest_health"],
                }
                for item in plan["selected"]
            ],
        },
        sys.stdout,
        indent=2,
        ensure_ascii=True,
    )
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
