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
LATEST_RUN_HEALTH_VALUES = {
    "run_all_ok",
    "run_same_failure",
    "run_divergence",
    "run_unknown",
}
LATEST_PHASE_DOMINANCE_VALUES = {
    "dominant",
    "no_dominance",
    "mid",
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


def latest_run_health_counts(prior: dict[str, Any] | None) -> dict[str, int]:
    if prior is None:
        return {}
    value = prior.get("latest_run_health_counts")
    if not isinstance(value, dict):
        return {}
    return {
        key: count
        for key, count in value.items()
        if isinstance(key, str) and isinstance(count, int)
    }


def latest_phase_dominance(prior: dict[str, Any] | None) -> dict[str, Any] | None:
    if prior is None:
        return None
    value = prior.get("latest_divergence_phase_dominance")
    return value if isinstance(value, dict) else None


def phase_dominance_kind(prior: dict[str, Any] | None) -> str | None:
    dominance = latest_phase_dominance(prior)
    if dominance is None:
        return None
    if dominance.get("is_dominant") is True:
        return "dominant"
    if dominance.get("is_no_dominance") is True:
        return "no_dominance"
    return "mid"


def matches_run_health_filter(counts: dict[str, int], filters: set[str]) -> bool:
    if not filters:
        return True
    return any(counts.get(value, 0) > 0 for value in filters)


def matches_only_run_health_filter(counts: dict[str, int], filters: set[str]) -> bool:
    if not filters:
        return True
    present = {key for key, count in counts.items() if count > 0}
    return bool(present) and present.issubset(filters)


def matches_phase_dominance_filter(value: str | None, filters: set[str]) -> bool:
    if not filters:
        return True
    return value in filters


def build_plan(
    config: dict[str, Any],
    rollup: dict[str, Any],
    limit: int | None,
    include_failure_rechecks: bool,
    include_covered: bool,
    include_internal: bool,
    latest_health_filter: list[str] | None = None,
    latest_run_health_filter: list[str] | None = None,
    only_latest_run_health_filter: list[str] | None = None,
    latest_phase_dominance_filter: list[str] | None = None,
) -> dict[str, Any]:
    covered = covered_outbounds(rollup)
    health_filter = set(latest_health_filter or [])
    run_health_filter = set(latest_run_health_filter or [])
    only_run_health_filter = set(only_latest_run_health_filter or [])
    phase_dominance_filter = set(latest_phase_dominance_filter or [])
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
        run_counts = latest_run_health_counts(prior)
        phase_dominance = latest_phase_dominance(prior)
        phase_kind = phase_dominance_kind(prior)
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
            "latest_run_health_counts": run_counts,
            "latest_phase_dominance": phase_kind,
            "latest_divergence_phase_dominance": phase_dominance,
            "prior": prior,
        }
        buckets[reason].append(planned)
        candidates.append(planned)

    if health_filter or run_health_filter or only_run_health_filter or phase_dominance_filter:
        selected = [
            item
            for item in candidates
            if (not health_filter or item.get("latest_health") in health_filter)
            and matches_run_health_filter(item.get("latest_run_health_counts", {}), run_health_filter)
            and matches_only_run_health_filter(
                item.get("latest_run_health_counts", {}),
                only_run_health_filter,
            )
            and matches_phase_dominance_filter(
                item.get("latest_phase_dominance"),
                phase_dominance_filter,
            )
        ]
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
        "latest_run_health_filter": sorted(run_health_filter),
        "only_latest_run_health_filter": sorted(only_run_health_filter),
        "latest_phase_dominance_filter": sorted(phase_dominance_filter),
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
    parser.add_argument(
        "--latest-run-health",
        action="append",
        choices=sorted(LATEST_RUN_HEALTH_VALUES),
        default=[],
        help="Select ready outbounds whose latest round has at least one run with this health.",
    )
    parser.add_argument(
        "--only-latest-run-health",
        action="append",
        choices=sorted(LATEST_RUN_HEALTH_VALUES),
        default=[],
        help="Select ready outbounds whose latest round has only these run-health values.",
    )
    parser.add_argument(
        "--latest-phase-dominance",
        action="append",
        choices=sorted(LATEST_PHASE_DOMINANCE_VALUES),
        default=[],
        help="Select ready outbounds by latest divergence phase dominance bucket.",
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
        args.latest_run_health,
        args.only_latest_run_health,
        args.latest_phase_dominance,
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
                    "latest_run_health_counts": item["latest_run_health_counts"],
                    "latest_phase_dominance": item["latest_phase_dominance"],
                    "latest_divergence_phase_dominance": item["latest_divergence_phase_dominance"],
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
