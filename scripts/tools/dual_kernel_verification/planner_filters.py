"""Planner filter predicates for generic dual-kernel rollups."""

from collections.abc import Iterable, Mapping
from typing import Any


PHASE_DOMINANCE_CATEGORIES = frozenset({"dominant", "no_dominance", "mid"})


def _string_set(values: Iterable[str]) -> set[str]:
    return {value for value in values if isinstance(value, str)}


def _latest_run_health_counts(outbound_rollup: Mapping[str, Any]) -> dict[str, int]:
    value = outbound_rollup.get("latest_run_health_counts")
    if not isinstance(value, Mapping):
        return {}
    return {
        key: count
        for key, count in value.items()
        if isinstance(key, str) and isinstance(count, int)
    }


def passes_latest_health(
    outbound_rollup: Mapping[str, Any],
    allowed: Iterable[str],
) -> bool:
    allowed_set = _string_set(allowed)
    if not allowed_set:
        return True
    value = outbound_rollup.get("latest_health")
    return isinstance(value, str) and value in allowed_set


def passes_latest_run_health(
    outbound_rollup: Mapping[str, Any],
    allowed: Iterable[str],
) -> bool:
    allowed_set = _string_set(allowed)
    if not allowed_set:
        return True
    counts = _latest_run_health_counts(outbound_rollup)
    return any(counts.get(value, 0) > 0 for value in allowed_set)


def passes_only_latest_run_health(
    outbound_rollup: Mapping[str, Any],
    required: str,
) -> bool:
    if isinstance(required, str):
        required_set = {required}
    else:
        required_set = _string_set(required)
    if not required_set:
        return True
    counts = _latest_run_health_counts(outbound_rollup)
    present = {key for key, count in counts.items() if count > 0}
    return bool(present) and present.issubset(required_set)


def _dominance_category(
    dominance: Mapping[str, Any],
    *,
    dominant_threshold: float,
    no_dominance_threshold: float,
) -> str | None:
    ratio = dominance.get("dominant_ratio")
    if isinstance(ratio, int | float):
        if ratio >= dominant_threshold:
            return "dominant"
        if ratio < no_dominance_threshold:
            return "no_dominance"
        return "mid"
    if dominance.get("is_dominant") is True:
        return "dominant"
    if dominance.get("is_no_dominance") is True:
        return "no_dominance"
    return "mid"


def passes_latest_phase_dominance(
    outbound_rollup: Mapping[str, Any],
    allowed_categories: Iterable[str],
    *,
    dominant_threshold: float = 0.75,
    no_dominance_threshold: float = 0.50,
) -> bool:
    allowed = _string_set(allowed_categories).intersection(PHASE_DOMINANCE_CATEGORIES)
    if not allowed:
        return True
    dominance = outbound_rollup.get("latest_divergence_phase_dominance")
    if not isinstance(dominance, Mapping):
        return False
    category = _dominance_category(
        dominance,
        dominant_threshold=dominant_threshold,
        no_dominance_threshold=no_dominance_threshold,
    )
    return category in allowed


def passes_bi_modal(outbound_rollup: Mapping[str, Any]) -> bool:
    if outbound_rollup.get("is_bi_modal") is True:
        return True
    dominance = outbound_rollup.get("latest_divergence_phase_dominance")
    return isinstance(dominance, Mapping) and dominance.get("is_bi_modal") is True


def passes_phase_shifting(outbound_rollup: Mapping[str, Any]) -> bool:
    return outbound_rollup.get("is_phase_shifting") is True
