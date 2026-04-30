"""Health classification helpers for dual-kernel evidence."""

from collections.abc import Iterable, Mapping


def _has_non_all_ok_labels(label_counts: Mapping[str, int]) -> bool:
    return any(key != "all_ok" and value > 0 for key, value in label_counts.items())


def _has_divergence_labels(label_counts: Mapping[str, int]) -> bool:
    return any("diverged" in key and value > 0 for key, value in label_counts.items())


def classify_run_health(labels: Iterable[str], divergence_phase_labels: frozenset[str]) -> str:
    label_list = [label for label in labels if isinstance(label, str)]
    if not label_list:
        return "run_unknown"
    label_counts = {label: 1 for label in label_list}
    if not _has_non_all_ok_labels(label_counts):
        return "run_all_ok"
    if any(label in divergence_phase_labels for label in label_list):
        return "run_divergence"
    return "run_same_failure"


def classify_outbound_latest_health(latest_label_counts: Mapping[str, int]) -> str:
    if not latest_label_counts:
        return "latest_unknown"
    if not _has_non_all_ok_labels(latest_label_counts):
        return "latest_all_ok"
    if _has_divergence_labels(latest_label_counts):
        return "latest_divergence"
    return "latest_same_failure"
