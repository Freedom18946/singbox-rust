<!-- tier: B -->
# S5/T4 SOCKS5 throughput acceptance

Date: 2026-07-18
Status: CLOSED

## Result

`p2_bench_socks5_throughput` no longer treats a Rust-only Criterion echo loop as kernel evidence.
The strict both-kernel case now opens a fresh SOCKS5 connection for every sample, transfers and
verifies a deterministic 1 MiB TCP echo, includes negotiation plus round-trip time in the rate,
and requires every measured sample to reach 10 MiB/s.

Accepted run: `20260718T153227Z-a4f5f496-4bb1-4d05-91a3-949ffce9e6bb`.

| Kernel | Minimum | Median | Result |
| --- | ---: | ---: | --- |
| Rust | 242.13 MiB/s | 330.03 MiB/s | PASS |
| Go 1.13.13 oracle | 236.91 MiB/s | 304.88 MiB/s | PASS |

The floor is deliberately portability-safe and 100x stronger than the new action's bare
1 MiB / 10 second timeout-derived completion bound. This is coverage-neutral performance stress:
BHV-PF-001 remains the HTTP p95 contract owned by `p1_rust_core_http_via_socks`; no S4 divergence
or parity-denominator movement is claimed.

## Verification

- `cargo test -p interop-lab`: 45 passed.
- Repository case loader: all 103 cases validate, including throughput defaults and invalid zero
  sample rejection.
- Strict committed-case replay: Rust PASS, Go PASS, no errors; payload echo verified every sample.
- A cold-cache preparation replay correctly failed at Rust launch readiness while the isolated
  acceptance app compiled. Final committed configuration then passed without an environment-limit
  label or relaxed assertion.
