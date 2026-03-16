# singbox-rust Performance Baseline

> Recorded: 2026-03-17 · Platform: macOS 25.3.0 (darwin arm64) · Rust stable · `--release`

## How to run

```bash
# Domain-match benchmarks (fast, ~2 min)
cargo bench -p sb-benches --bench domain_match

# TCP relay throughput benchmark
cargo bench -p sb-benches --bench tcp_relay_e2e

# All benchmarks
cargo bench -p sb-benches
```

## CI regression gate

The `bench-regression.yml` workflow runs on every PR touching `crates/`, `benches/`, or
`app/`. It compares the PR's measurements against `reports/benchmarks/baseline.json` and
emits a warning if any benchmark regresses by >5% or >10%.

To update the baseline after a confirmed performance improvement:
1. Run `cargo bench -p sb-benches -- --save-baseline main`
2. Export the criterion JSON from `target/criterion/` into `reports/benchmarks/baseline.json`
   (or run `scripts/bench_compare.sh` to validate first)
3. Commit `reports/benchmarks/baseline.json`

## Domain matching (router hot-path)

Measured with `benches/benches/domain_match.rs`.

| Benchmark                          | Rules | Mean (ns) |
|------------------------------------|------:|----------:|
| domain_suffix_match/hit/10         |    10 |      30.6 |
| domain_suffix_match/miss/10        |    10 |     111.9 |
| domain_suffix_match/exact/10       |    10 |      18.5 |
| domain_suffix_match/keyword/10     |    10 |     105.1 |
| domain_suffix_match/hit/100        |   100 |     176.3 |
| domain_suffix_match/miss/100       |   100 |     419.1 |
| domain_suffix_match/exact/100      |   100 |      18.5 |
| domain_suffix_match/keyword/100    |   100 |     426.9 |
| domain_suffix_match/hit/1000       |  1000 |    1568.9 |
| domain_suffix_match/miss/1000      |  1000 |    3409.5 |
| domain_suffix_match/exact/1000     |  1000 |      18.7 |
| domain_suffix_match/keyword/1000   |  1000 |    3546.5 |

**Key observations**:
- Exact-match is O(1) regardless of ruleset size (hash lookup).
- Suffix/keyword matching is O(n) over the ruleset.
- Zero-allocation suffix check (`domain_matches_suffix`) eliminated the per-check
  `format!(".{suffix}")` allocation (T1-08).

## TCP relay throughput

Measured with `benches/benches/tcp_relay_e2e.rs` — loopback echo relay, 1 MiB payload.

| Buffer size | Throughput   |
|-------------|-------------|
| 16 KiB      | ~2.4 GiB/s  |
| 64 KiB      | ~3.0 GiB/s  |

After T2-09, the pump buffer was increased from 16 KiB to 64 KiB and a global buffer pool
was added (`RELAY_BUF_POOL`) to avoid per-connection heap allocation at high concurrency.

## Shadowsocks AEAD crypto

After T2-05, the per-chunk AEAD encrypt/decrypt path uses `encrypt_in_place` /
`decrypt_in_place` with a reusable `Vec<u8>` buffer. This eliminates 4–6 heap allocations
per chunk on the TCP tunnel path.

The chunk loop in `write_aead_chunk` previously allocated 2 Vecs per iteration
(len field + payload); now it reuses a single `enc_buf` passed from the caller.
The `read_aead_chunk` path similarly reuses a single `chunk_buf` for the entire stream.
