#!/usr/bin/env python3
"""Group fresh REALITY/VLESS round outbounds into confirmation cohorts.

R76 fresh-confirmation planner. Given a round-summary payload that has
already been run through ``round_summary_run_health.materialize_run_health``
(so every entry in ``by_outbound`` carries ``run_health_counts``),
this module derives three cohorts that drive the next confirmation
authorization:

  - **divergence_carrier**: any outbound with at least one run_divergence
    in this round. These need the deepest re-probe to confirm whether
    the phase divergence repeats and whether it stays inside the
    existing four-label MT-REAL-02 phase taxonomy.
  - **same_failure**: outbounds that produced only run_same_failure
    (no run_all_ok, no run_divergence). Re-probe at lower depth to
    confirm the failure stays uniform; per the closure_report rule a
    same-failure outbound only formally closes after multiple
    longer-repeat rounds.
  - **recovery_watch**: outbounds that produced only run_all_ok in
    this round. The closure_report rule says recovery classification
    needs THREE rounds; this round is just round 1, so re-probe at
    minimal depth to begin building the second round.

The module is read-only and has no IO. All identifiers are passed in
as opaque strings — for R76 callers feed neutral keys
``fresh01..fresh15`` so no raw tag/server material reaches the rendered
plan.
"""

from __future__ import annotations

from typing import Any

CohortName = str

DIVERGENCE_CARRIER = "divergence_carrier"
SAME_FAILURE = "same_failure"
RECOVERY_WATCH = "recovery_watch"
NEUTRAL = "neutral"


def _run_health_counts(entry: Any) -> dict[str, int]:
    if not isinstance(entry, dict):
        return {}
    counts = entry.get("run_health_counts")
    if not isinstance(counts, dict):
        return {}
    output: dict[str, int] = {}
    for key, value in counts.items():
        if isinstance(key, str) and isinstance(value, int):
            output[key] = value
    return output


def cohort_for_outbound(entry: Any) -> CohortName:
    """Classify a single ``by_outbound`` entry into one cohort.

    Rules (in priority order):
      1. ``run_divergence > 0`` → ``divergence_carrier``.
      2. ``run_all_ok == 0`` and ``run_same_failure > 0`` and
         ``run_divergence == 0`` → ``same_failure``.
      3. ``run_all_ok > 0`` and ``run_divergence == 0`` and
         ``run_same_failure == 0`` → ``recovery_watch``.
      4. Anything else (mixed all_ok+same_failure, all run_unknown,
         missing run_health_counts) → ``neutral``. Neutral entries
         deliberately do not enter the R76 plan; they sit out and the
         human reader decides whether to bake them in later.

    The classifier never inspects the raw labels — it relies entirely
    on the materialized ``run_health_counts`` so the cohort grouping
    is consistent with R74/R75 semantics.
    """
    counts = _run_health_counts(entry)
    div = counts.get("run_divergence", 0)
    sf = counts.get("run_same_failure", 0)
    ok = counts.get("run_all_ok", 0)
    if div > 0:
        return DIVERGENCE_CARRIER
    if ok == 0 and sf > 0:
        return SAME_FAILURE
    if ok > 0 and sf == 0:
        return RECOVERY_WATCH
    return NEUTRAL


def derive_cohorts(round_summary: dict[str, Any]) -> dict[str, list[str]]:
    """Group every ``by_outbound`` key into a cohort.

    Returns a dict keyed by cohort name with sorted neutral-key lists.
    The dict always has all four cohort buckets, possibly empty.
    """
    by_outbound = round_summary.get("by_outbound") if isinstance(round_summary, dict) else {}
    if not isinstance(by_outbound, dict):
        by_outbound = {}
    buckets: dict[str, list[str]] = {
        DIVERGENCE_CARRIER: [],
        SAME_FAILURE: [],
        RECOVERY_WATCH: [],
        NEUTRAL: [],
    }
    for name, entry in by_outbound.items():
        if not isinstance(name, str):
            continue
        buckets[cohort_for_outbound(entry)].append(name)
    for cohort in buckets:
        buckets[cohort].sort()
    return buckets


def cohort_plan(
    cohort_name: str,
    outbounds: list[str],
    runs_per_outbound: int,
    objective: str,
    entry_gate: str,
    stop_condition: str,
    expected_classifications: dict[str, str],
    notes: str | None = None,
) -> dict[str, Any]:
    """Build one cohort entry of the rendered plan.

    The runs are NOT executed here — this is a planner shape only.
    """
    if not isinstance(outbounds, list):
        raise TypeError("outbounds must be a list")
    if runs_per_outbound <= 0:
        raise ValueError("runs_per_outbound must be > 0")
    plan: dict[str, Any] = {
        "cohort": cohort_name,
        "outbounds": list(outbounds),
        "selected_count": len(outbounds),
        "runs_per_outbound": runs_per_outbound,
        "planned_total_runs": runs_per_outbound * len(outbounds),
        "objective": objective,
        "entry_gate": entry_gate,
        "stop_condition": stop_condition,
        "expected_classifications": dict(expected_classifications),
    }
    if notes:
        plan["notes"] = notes
    return plan


def total_planned_runs(plan: dict[str, Any]) -> int:
    """Sum ``planned_total_runs`` across every cohort entry in a rendered plan."""
    cohorts = plan.get("cohorts") if isinstance(plan, dict) else None
    if not isinstance(cohorts, dict):
        return 0
    total = 0
    for entry in cohorts.values():
        if isinstance(entry, dict):
            value = entry.get("planned_total_runs")
            if isinstance(value, int):
                total += value
    return total
