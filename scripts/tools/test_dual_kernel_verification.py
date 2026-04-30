#!/usr/bin/env python3
"""Smoke tests for dual_kernel_verification using a fake protocol."""

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from dual_kernel_verification import (  # noqa: E402
    classify_outbound_latest_health,
    classify_run_health,
    compute_bi_modal,
    compute_phase_counts,
    compute_phase_dominance,
    compute_phase_shifting,
    passes_bi_modal,
    passes_latest_health,
    passes_latest_phase_dominance,
    passes_latest_run_health,
    passes_only_latest_run_health,
    passes_phase_shifting,
)


FAKE_PHASE_LABELS = frozenset(
    {
        "phase_alpha",
        "phase_beta",
        "phase_delta",
        "phase_gamma",
    }
)


class TestFakeProtocolHealth(unittest.TestCase):
    def test_classify_run_health_all_ok_with_fake_labels(self) -> None:
        self.assertEqual(
            classify_run_health(["all_ok"], FAKE_PHASE_LABELS),
            "run_all_ok",
        )

    def test_classify_run_health_run_same_failure_with_fake_uniform(self) -> None:
        self.assertEqual(
            classify_run_health(["fake_all_timeout"], FAKE_PHASE_LABELS),
            "run_same_failure",
        )

    def test_classify_run_health_run_divergence_with_fake_phase(self) -> None:
        self.assertEqual(
            classify_run_health(["fake_all_timeout", "phase_alpha"], FAKE_PHASE_LABELS),
            "run_divergence",
        )

    def test_classify_outbound_latest_health_with_fake_counts(self) -> None:
        self.assertEqual(
            classify_outbound_latest_health({"all_ok": 2}),
            "latest_all_ok",
        )
        self.assertEqual(
            classify_outbound_latest_health({"fake_all_timeout": 2}),
            "latest_same_failure",
        )
        self.assertEqual(
            classify_outbound_latest_health({"phase_alpha_diverged": 1}),
            "latest_divergence",
        )


class TestFakeProtocolPhaseMetrics(unittest.TestCase):
    def test_compute_phase_counts_only_picks_intersection_with_fake_set(self) -> None:
        self.assertEqual(
            compute_phase_counts(
                [
                    ["phase_alpha", "fake_noise"],
                    ["phase_beta", "phase_alpha"],
                    ["fake_noise"],
                ],
                FAKE_PHASE_LABELS,
            ),
            {"phase_alpha": 2, "phase_beta": 1},
        )

    def test_compute_phase_dominance_dominant_with_fake_phases(self) -> None:
        self.assertEqual(
            compute_phase_dominance(
                {"phase_alpha": 3, "phase_beta": 1},
                4,
            ),
            {
                "dominant_phase": "phase_alpha",
                "dominant_count": 3,
                "dominant_ratio": 0.75,
                "is_dominant": True,
                "is_no_dominance": False,
            },
        )

    def test_compute_phase_dominance_no_dominance_with_fake_phases(self) -> None:
        self.assertEqual(
            compute_phase_dominance(
                {
                    "phase_alpha": 1,
                    "phase_beta": 1,
                    "phase_delta": 1,
                    "phase_gamma": 1,
                },
                4,
            ),
            {
                "dominant_phase": "phase_alpha",
                "dominant_count": 1,
                "dominant_ratio": 0.25,
                "is_dominant": False,
                "is_no_dominance": True,
            },
        )

    def test_compute_bi_modal_with_fake_protocol(self) -> None:
        self.assertTrue(compute_bi_modal(6, 12))
        self.assertFalse(compute_bi_modal(2, 4))

    def test_compute_phase_shifting_detects_drift_in_fake_history(self) -> None:
        self.assertTrue(
            compute_phase_shifting(
                [
                    {"round": "A", "dominant_phase": "phase_alpha"},
                    {"round": "B", "dominant_phase": "phase_beta"},
                    {"round": "C", "dominant_phase": "phase_gamma"},
                ]
            )
        )
        self.assertFalse(
            compute_phase_shifting(
                [
                    {"round": "A", "dominant_phase": "phase_alpha"},
                    {"round": "B", "dominant_phase": "phase_alpha"},
                    {"round": "C", "dominant_phase": "phase_alpha"},
                ]
            )
        )


class TestFakeProtocolPlannerFilters(unittest.TestCase):
    def test_passes_latest_health_with_fake_outbound_rollup(self) -> None:
        outbound = {"latest_health": "latest_same_failure"}
        self.assertTrue(passes_latest_health(outbound, {"latest_same_failure"}))
        self.assertFalse(passes_latest_health({}, {"latest_same_failure"}))

    def test_passes_latest_run_health_with_fake_outbound_rollup(self) -> None:
        outbound = {"latest_run_health_counts": {"run_same_failure": 2}}
        self.assertTrue(passes_latest_run_health(outbound, {"run_same_failure"}))
        self.assertFalse(passes_latest_run_health(outbound, {"run_divergence"}))

    def test_passes_only_latest_run_health_with_fake_outbound_rollup(self) -> None:
        outbound = {"latest_run_health_counts": {"run_same_failure": 2}}
        mixed = {"latest_run_health_counts": {"run_same_failure": 1, "run_divergence": 1}}
        self.assertTrue(passes_only_latest_run_health(outbound, {"run_same_failure"}))
        self.assertFalse(passes_only_latest_run_health(mixed, {"run_same_failure"}))

    def test_passes_latest_phase_dominance_with_fake_categories(self) -> None:
        outbound = {
            "latest_divergence_phase_dominance": {
                "dominant_phase": "phase_alpha",
                "dominant_count": 2,
                "dominant_ratio": 0.5,
                "is_dominant": False,
                "is_no_dominance": False,
            }
        }
        self.assertTrue(passes_latest_phase_dominance(outbound, {"mid"}))
        self.assertFalse(passes_latest_phase_dominance(outbound, {"dominant"}))

    def test_passes_bi_modal_with_fake_rollup(self) -> None:
        self.assertTrue(
            passes_bi_modal({"latest_divergence_phase_dominance": {"is_bi_modal": True}})
        )
        self.assertTrue(passes_bi_modal({"is_bi_modal": True}))
        self.assertFalse(passes_bi_modal({}))

    def test_passes_phase_shifting_with_fake_rollup(self) -> None:
        self.assertTrue(passes_phase_shifting({"is_phase_shifting": True}))
        self.assertFalse(passes_phase_shifting({}))


if __name__ == "__main__":
    unittest.main()
