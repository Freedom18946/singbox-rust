# WP-G2: Interop-lab Rust Full Case Verification

**Date**: 2026-03-07
**Command**: `cargo test -p interop-lab`

---

## Summary

| Metric   | Count |
|----------|-------|
| Passed   | 27    |
| Failed   | 0     |
| Ignored  | 0     |
| Measured | 0     |

**MIG-02 Step 3 target (27+ tests): MET**

---

## Test List (all passed)

| # | Test Name |
|---|-----------|
| 1 | `attribution::tests::classify_network` |
| 2 | `attribution::tests::classify_rate_limit` |
| 3 | `attribution::tests::classify_tls` |
| 4 | `attribution::tests::classify_unknown` |
| 5 | `attribution::tests::skip_successful_traffic` |
| 6 | `case_spec::tests::parse_case_spec` |
| 7 | `diff_report::tests::oracle_ignore_and_counter_jitter_work` |
| 8 | `go_collector::tests::build_ws_url_with_token` |
| 9 | `go_collector::tests::build_ws_url_without_token` |
| 10 | `go_collector::tests::normalize_text_frame` |
| 11 | `go_collector::tests::save_go_snapshot_creates_file` |
| 12 | `leak_detector::tests::linear_regression_exact` |
| 13 | `leak_detector::tests::linear_regression_flat` |
| 14 | `leak_detector::tests::rising_fds_detected` |
| 15 | `leak_detector::tests::rising_memory_detected` |
| 16 | `leak_detector::tests::stable_fds_no_leak` |
| 17 | `leak_detector::tests::stable_memory_no_leak` |
| 18 | `leak_detector::tests::too_few_samples_no_signal` |
| 19 | `orchestrator::tests::evaluate_assertion_new_operators` |
| 20 | `orchestrator::tests::resolve_assertion_extended_paths` |
| 21 | `subscription::tests::parse_empty_string_returns_error` |
| 22 | `subscription::tests::parse_json_outbounds` |
| 23 | `subscription::tests::parse_link_with_unknown_scheme` |
| 24 | `subscription::tests::parse_malformed_json_returns_error` |
| 25 | `subscription::tests::parse_truncated_base64_returns_error` |
| 26 | `subscription::tests::parse_yaml_proxies` |
| 27 | `subscription::tests::parse_yaml_without_proxies_key` |

---

## Module Coverage

| Module | Tests |
|--------|-------|
| attribution | 5 |
| case_spec | 1 |
| diff_report | 1 |
| go_collector | 4 |
| leak_detector | 7 |
| orchestrator | 2 |
| subscription | 7 |

---

## Failures

None.

---

## Verdict: PASS

All 27 interop-lab tests passed with zero failures, matching the MIG-02 validation Step 3 baseline.
