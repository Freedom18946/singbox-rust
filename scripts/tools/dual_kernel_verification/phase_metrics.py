"""Phase composition metrics for dual-kernel evidence."""

import collections
from collections.abc import Iterable, Mapping
from typing import Any


def compute_phase_counts(
    run_labels_list: Iterable[Iterable[str]],
    divergence_phase_labels: frozenset[str],
) -> dict[str, int]:
    counts: collections.Counter[str] = collections.Counter()
    for labels in run_labels_list:
        label_set = {label for label in labels if isinstance(label, str)}
        for label in sorted(divergence_phase_labels):
            if label in label_set:
                counts[label] += 1
    return {key: counts[key] for key in sorted(counts) if counts[key] > 0}


def compute_phase_dominance(
    phase_counts: Mapping[str, int],
    divergence_run_count: int,
    *,
    dominant_threshold: float = 0.75,
    no_dominance_threshold: float = 0.50,
) -> dict[str, Any] | None:
    if divergence_run_count <= 0:
        return None
    ordered = sorted(
        ((label, count) for label, count in phase_counts.items() if count > 0),
        key=lambda item: (-item[1], item[0]),
    )
    if not ordered:
        return {
            "dominant_phase": None,
            "dominant_count": 0,
            "dominant_ratio": 0.0,
            "is_dominant": False,
            "is_no_dominance": True,
        }
    dominant_phase, dominant_count = ordered[0]
    ratio = round(dominant_count / divergence_run_count, 4)
    return {
        "dominant_phase": dominant_phase,
        "dominant_count": dominant_count,
        "dominant_ratio": ratio,
        "is_dominant": ratio >= dominant_threshold,
        "is_no_dominance": ratio < no_dominance_threshold,
    }


def compute_bi_modal(
    divergence_run_count: int,
    total_run_count: int,
    *,
    ratio_low: float = 0.25,
    ratio_high: float = 0.75,
    min_runs: int = 6,
) -> bool:
    if total_run_count < min_runs or total_run_count <= 0:
        return False
    ratio = divergence_run_count / total_run_count
    return ratio_low < ratio < ratio_high


def compute_phase_shifting(
    dominant_phase_history: Iterable[dict[str, Any]],
    *,
    window: int = 3,
) -> bool:
    history = list(dominant_phase_history)
    if len(history) < window:
        return False
    recent = history[-window:]
    phases = [item.get("dominant_phase") for item in recent]
    if any(not isinstance(phase, str) for phase in phases):
        return False
    return len(set(phases)) >= 2
