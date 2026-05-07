#!/usr/bin/env python3
"""Materialize per-run ``run_health`` and run-vs-phase-label totals
into a REALITY/VLESS round-summary payload (R73 round73 JSON shape).

R75 R73-evidence rematerialization helper. Per-round summary files
historically only carried ``labels`` per run; downstream consumers
had to re-derive ``run_health`` from the labels via
``classify_run_health``. This module centralizes that derivation so:

  - ``run_health`` lives directly on each ``runs[]`` entry, in the
    same shape that ``reality_vless_evidence_rollup`` later attaches
    when it builds the rollup.
  - ``summary.divergence_run_count`` /
    ``divergence_phase_label_count`` /
    ``distinct_divergence_phase_label_count`` /
    ``divergence_phase_label_breakdown`` /
    ``same_failure_run_count`` are recomputed from the per-run
    facts, never from per-occurrence label totals.

The helper is pure / no-IO: it operates on a dict and returns a new
dict with the materialized fields. Callers commit the output.

This module exists because there is no centralized "round summary
emitter" in the repo — round files are produced by ad-hoc scripts
when each round is captured. R75 audits those round files and
re-materializes ``run_health`` so future readers cannot reconstruct
the divergence_run vs phase_label conflation that R74 corrected.
"""

from __future__ import annotations

import collections
import copy
from typing import Any

from dual_kernel_verification import classify_run_health
from reality_vless_evidence_rollup import DIVERGENCE_PHASE_LABELS


def classify_run(labels: list[str]) -> str:
    """Classify one run's labels into ``run_all_ok`` /
    ``run_divergence`` / ``run_same_failure`` / ``run_unknown``.

    Wraps ``classify_run_health`` with the canonical MT-REAL-02
    phase-label set so callers cannot accidentally pass a different
    set."""
    return classify_run_health(labels, DIVERGENCE_PHASE_LABELS)


def per_run_run_health(runs: list[dict[str, Any]]) -> list[str]:
    """Return the run_health classification for each run, in order."""
    output = []
    for run in runs:
        labels = run.get("labels") if isinstance(run, dict) else None
        if not isinstance(labels, list):
            output.append("run_unknown")
            continue
        output.append(classify_run(labels))
    return output


def synthesize_round_totals(runs: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute run-level totals from a runs[] list.

    Returns a dict with keys:
      - run_all_ok
      - run_divergence
      - run_same_failure
      - run_unknown
      - divergence_run_count (== run_divergence)
      - divergence_phase_label_count (per-occurrence across divergence runs)
      - distinct_divergence_phase_label_count
      - divergence_phase_label_breakdown
      - same_failure_run_count (== run_same_failure)

    The crucial invariant: ``divergence_run_count`` increments by 1
    per run that carries any phase label, while
    ``divergence_phase_label_count`` increments by N per such run.
    """
    health_counts: collections.Counter[str] = collections.Counter()
    phase_breakdown: collections.Counter[str] = collections.Counter()
    div_phase_label_count = 0
    div_run_count = 0
    distinct_phase_labels: set[str] = set()
    for run in runs:
        labels = run.get("labels") if isinstance(run, dict) else None
        if not isinstance(labels, list):
            health_counts["run_unknown"] += 1
            continue
        kind = classify_run(labels)
        health_counts[kind] += 1
        if kind == "run_divergence":
            div_run_count += 1
            for label in labels:
                if label in DIVERGENCE_PHASE_LABELS:
                    phase_breakdown[label] += 1
                    div_phase_label_count += 1
                    distinct_phase_labels.add(label)
    return {
        "run_all_ok": health_counts.get("run_all_ok", 0),
        "run_divergence": health_counts.get("run_divergence", 0),
        "run_same_failure": health_counts.get("run_same_failure", 0),
        "run_unknown": health_counts.get("run_unknown", 0),
        "divergence_run_count": div_run_count,
        "divergence_phase_label_count": div_phase_label_count,
        "distinct_divergence_phase_label_count": len(distinct_phase_labels),
        "divergence_phase_label_breakdown": dict(sorted(phase_breakdown.items())),
        "same_failure_run_count": health_counts.get("run_same_failure", 0),
    }


def per_outbound_run_health_counts(
    runs: list[dict[str, Any]],
) -> dict[str, dict[str, int]]:
    """Group run_health by outbound name (``run.outbound``).

    Returns ``{outbound_name: {run_all_ok, run_divergence,
    run_same_failure, run_unknown}}``. Any outbound key the caller
    does not see in ``runs`` is simply absent from the result.
    """
    output: dict[str, collections.Counter[str]] = {}
    for run in runs:
        if not isinstance(run, dict):
            continue
        name = run.get("outbound")
        if not isinstance(name, str):
            continue
        labels = run.get("labels")
        if not isinstance(labels, list):
            output.setdefault(name, collections.Counter())["run_unknown"] += 1
            continue
        kind = classify_run(labels)
        output.setdefault(name, collections.Counter())[kind] += 1
    return {
        name: {
            "run_all_ok": counts.get("run_all_ok", 0),
            "run_divergence": counts.get("run_divergence", 0),
            "run_same_failure": counts.get("run_same_failure", 0),
            "run_unknown": counts.get("run_unknown", 0),
        }
        for name, counts in output.items()
    }


def per_outbound_phase_label_breakdown(
    runs: list[dict[str, Any]],
) -> dict[str, dict[str, int]]:
    """Group divergence-phase-label occurrences by outbound name.

    A phase label only counts if it sits inside a run that already
    classifies as ``run_divergence``; otherwise it is ignored. This
    matches the round-summary convention.
    """
    output: dict[str, collections.Counter[str]] = {}
    for run in runs:
        if not isinstance(run, dict):
            continue
        name = run.get("outbound")
        labels = run.get("labels")
        if not isinstance(name, str) or not isinstance(labels, list):
            continue
        if classify_run(labels) != "run_divergence":
            continue
        bucket = output.setdefault(name, collections.Counter())
        for label in labels:
            if label in DIVERGENCE_PHASE_LABELS:
                bucket[label] += 1
    return {name: dict(sorted(c.items())) for name, c in output.items()}


def materialize_run_health(payload: dict[str, Any]) -> dict[str, Any]:
    """Return a deep copy of ``payload`` with per-run ``run_health``
    fields and recomputed run-level totals.

    Inputs MUST be a round-summary dict with at minimum:
      - ``runs``: list of dicts each carrying ``labels`` and
        optional ``outbound``.
      - ``summary``: dict (any existing fields are preserved unless
        recomputed).
      - ``by_outbound``: dict (each entry gets a fresh
        ``run_health_counts`` and ``divergence_phase_label_breakdown``;
        ``divergence_phase_label_count`` is overwritten).

    The function never mutates the input.
    """
    output = copy.deepcopy(payload)
    runs = output.get("runs") if isinstance(output.get("runs"), list) else []
    health_per_run = per_run_run_health(runs)
    for run, health in zip(runs, health_per_run):
        if isinstance(run, dict):
            run["run_health"] = health

    totals = synthesize_round_totals(runs)
    summary = output.setdefault("summary", {}) if isinstance(output.get("summary"), dict) else {}
    summary["divergence_run_count"] = totals["divergence_run_count"]
    summary["divergence_phase_label_count"] = totals["divergence_phase_label_count"]
    summary["distinct_divergence_phase_label_count"] = totals[
        "distinct_divergence_phase_label_count"
    ]
    summary["divergence_phase_label_breakdown"] = totals["divergence_phase_label_breakdown"]
    summary["same_failure_run_count"] = totals["same_failure_run_count"]
    summary.setdefault(
        "accounting_note",
        (
            "divergence_run_count counts runs (a run is a divergence run iff it "
            "carries any of the four phase labels app_pre_post_diverged, "
            "app_minimal_diverged, minimal_transport_diverged, bridge_io_diverged); "
            "divergence_phase_label_count counts phase-label occurrences across "
            "those divergence runs (a single run can carry multiple phase labels). "
            "label_counts above is per-occurrence, matching "
            "divergence_phase_label_breakdown."
        ),
    )

    bo_run_health = per_outbound_run_health_counts(runs)
    bo_phase_breakdown = per_outbound_phase_label_breakdown(runs)
    by_outbound = output.get("by_outbound")
    if isinstance(by_outbound, dict):
        for name, entry in by_outbound.items():
            if not isinstance(entry, dict):
                continue
            if name in bo_run_health:
                entry["run_health_counts"] = bo_run_health[name]
            entry["divergence_phase_label_breakdown"] = bo_phase_breakdown.get(name, {})
            entry["divergence_phase_label_count"] = sum(
                bo_phase_breakdown.get(name, {}).values()
            )
    return output
