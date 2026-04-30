"""Generic dual-kernel verification framework.

Reusable evidence-classification primitives extracted from
reality_vless_evidence_rollup.py. Protocol-specific divergence
phase label sets are passed in by the caller; this package itself
makes no REALITY-specific assumptions.
"""

from .health import (
    classify_outbound_latest_health,
    classify_run_health,
)
from .phase_metrics import (
    compute_bi_modal,
    compute_phase_counts,
    compute_phase_dominance,
    compute_phase_shifting,
)
from .planner_filters import (
    passes_bi_modal,
    passes_latest_health,
    passes_latest_phase_dominance,
    passes_latest_run_health,
    passes_only_latest_run_health,
    passes_phase_shifting,
)

__all__ = [
    "classify_run_health",
    "classify_outbound_latest_health",
    "compute_phase_counts",
    "compute_phase_dominance",
    "compute_bi_modal",
    "compute_phase_shifting",
    "passes_latest_health",
    "passes_latest_run_health",
    "passes_only_latest_run_health",
    "passes_latest_phase_dominance",
    "passes_bi_modal",
    "passes_phase_shifting",
]
