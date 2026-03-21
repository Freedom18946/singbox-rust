# Performance Benchmarking - AEAD Crypto Benchmarks

**Status**: Operational benchmark suites for real protocol E2E and AEAD crypto

## Benchmark Suites

| Benchmark Suite | What It Tests | Status |
|----------------|---------------|--------|
| socks5_throughput | SOCKS5 handshake + TCP throughput | ✅ |
| shadowsocks_throughput | Real E2E through SS server + connector | ✅ |
| trojan_throughput | Real E2E through Trojan server (TLS 1.3) | ✅ |
| tcp_relay_e2e | TCP relay throughput (16KB/64KB buffers) | ✅ |
| domain_match | DomainRuleSet matching performance | ✅ |
| rate_limit_bench | TcpRateLimiter overhead and scaling | ✅ |
| **aead_crypto** | **Real AES-256-GCM and ChaCha20-Poly1305** | ✅ |

## AEAD Crypto Benchmark Details

**[benches/benches/aead_crypto.rs](../benches/benches/aead_crypto.rs)**
- Real AES-256-GCM encryption/decryption using `aes-gcm` crate
- Real ChaCha20-Poly1305 encryption/decryption using `chacha20poly1305` crate
- Encryption overhead analysis (vs baseline copy)
- Realistic packet size scenarios (64B - 64KB)

### Key Finding: ChaCha20 Dominance on ARM

On systems without AES-NI hardware acceleration, ChaCha20-Poly1305 significantly
outperforms AES-256-GCM. Run `cargo bench -p sb-benches --bench aead_crypto` to
obtain current numbers for your platform.

## Running Benchmarks

```bash
# All benchmarks
cargo bench --package sb-benches

# Specific benchmark
cargo bench --package sb-benches --bench aead_crypto

# Compare with Go
./scripts/bench_vs_go.sh [--quick]
```

## Dependencies

- `aes-gcm` 0.10, `chacha20poly1305` 0.10 (see `benches/Cargo.toml`)
