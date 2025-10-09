# P0 Protocol Performance Baseline Results

Generated: 2025-10-08

## Test Environment

- **OS**: macOS (darwin)
- **Architecture**: ARM64 (Apple Silicon)
- **Rust Version**: 1.90+
- **Build Profile**: Test (optimized + debuginfo)
- **Network**: Localhost (127.0.0.1)

## Baseline Performance (Direct TCP)

### Metrics

| Metric | Value | Notes |
|--------|-------|-------|
| **Throughput** | 9531.40 Mbps | 1MB transfers, 10 iterations |
| **Latency P50** | 0.02 ms | 1000 requests |
| **Latency P95** | 0.07 ms | 1000 requests |
| **Latency P99** | 0.09 ms | 1000 requests |
| **Connection Time** | 0.03 ms | 100 connections |
| **Memory Usage** | 10.00 MB | Estimated |

### Analysis

The baseline TCP performance establishes the upper bound for protocol performance:

- **Throughput**: ~9.5 Gbps is excellent for localhost testing
- **Latency**: Sub-millisecond latency is expected for localhost
- **Connection Time**: Very fast connection establishment

## P0 Protocol Results

### REALITY TLS

**Status**: ⏳ Pending server setup

**Expected Performance**:
- Throughput: ≥8578 Mbps (90% of baseline)
- Latency P95: ≤0.077 ms (110% of baseline)
- Connection Time: <200ms (TLS handshake + REALITY auth)

**Implementation Notes**:
- Requires REALITY server configuration
- Need to generate test certificates
- Need to configure public/private keys

### ECH (Encrypted Client Hello)

**Status**: ⏳ Pending server setup

**Expected Performance**:
- Throughput: ≥8578 Mbps (90% of baseline)
- Latency P95: ≤0.077 ms (110% of baseline)
- Connection Time: <150ms (TLS handshake + ECH)

**Implementation Notes**:
- Requires ECH-enabled TLS server
- Need ECH configuration

### Hysteria v1

**Status**: ⏳ Pending server setup

**Expected Performance**:
- Throughput: ≥9531 Mbps (100-120% of baseline, UDP-based)
- Latency P95: ≤0.105 ms (150% of baseline, QUIC overhead)
- Connection Time: <100ms (QUIC handshake)

**Implementation Notes**:
- Requires Hysteria v1 server
- Need to configure congestion control parameters
- Test with different bandwidth settings

### Hysteria v2

**Status**: ⏳ Pending server setup

**Expected Performance**:
- Throughput: ≥9531 Mbps (100-120% of baseline)
- Latency P95: ≤0.105 ms (150% of baseline)
- Connection Time: <100ms (QUIC handshake)

**Implementation Notes**:
- Requires Hysteria v2 server
- Compare with v1 performance
- Test improved congestion control

### SSH Outbound

**Status**: ⏳ Pending server setup

**Expected Performance**:
- Throughput: ≥8102 Mbps (85% of baseline)
- Latency P95: ≤0.084 ms (120% of baseline)
- Connection Time: <300ms (SSH handshake)

**Implementation Notes**:
- Requires SSH server
- Test with different cipher suites
- Measure SSH overhead

### TUIC

**Status**: ⏳ Pending server setup

**Expected Performance**:
- Throughput: ≥9531 Mbps (100-120% of baseline, QUIC-based)
- Latency P95: ≤0.105 ms (150% of baseline)
- Connection Time: <100ms (QUIC handshake)

**Implementation Notes**:
- Requires TUIC server
- Compare with Hysteria protocols
- Test QUIC performance

## Performance Targets Summary

| Protocol | Throughput Target | P95 Latency Target | Connection Time Target | Status |
|----------|------------------|-------------------|----------------------|--------|
| Direct TCP (Baseline) | 9531.40 Mbps | 0.07 ms | 0.03 ms | ✅ Complete |
| REALITY TLS | ≥8578 Mbps | ≤0.077 ms | <200ms | ⏳ Pending |
| ECH | ≥8578 Mbps | ≤0.077 ms | <150ms | ⏳ Pending |
| Hysteria v1 | ≥9531 Mbps | ≤0.105 ms | <100ms | ⏳ Pending |
| Hysteria v2 | ≥9531 Mbps | ≤0.105 ms | <100ms | ⏳ Pending |
| SSH | ≥8102 Mbps | ≤0.084 ms | <300ms | ⏳ Pending |
| TUIC | ≥9531 Mbps | ≤0.105 ms | <100ms | ⏳ Pending |

## Next Steps

1. **Set up test servers** for each protocol
2. **Run protocol benchmarks** with server configurations
3. **Compare results** with baseline and targets
4. **Identify optimization opportunities** if targets not met
5. **Document performance characteristics** for each protocol

## Comparison with sing-box

To compare with upstream sing-box:

```bash
# Run sing-box benchmarks (if GO_SINGBOX_BIN is set)
export GO_SINGBOX_BIN=/path/to/sing-box
./scripts/run_p0_benchmarks.sh --full
```

Expected differences:
- Rust may have slightly better throughput (zero-cost abstractions)
- Memory usage should be lower in Rust
- Latency should be within 5% of Go implementation

## Stress Test Results

### High Connection Rate

**Status**: ✅ Complete

**Result**: 7546.97 connections/second (0.13s for 1000 connections)

**Target**: >100 connections/second ✅ **PASSED** (75x target)

**Analysis**: Excellent connection rate performance, far exceeding target.

### Large Data Transfer

**Status**: ✅ Complete

**Result**: 3252.31 MB/s (200MB transferred in 0.06s)

**Target**: >50 MB/s for 100MB transfer ✅ **PASSED** (65x target)

**Analysis**: Outstanding throughput for large data transfers.

### Memory Leak Detection

**Status**: ⏳ Pending (requires extended run)

**Target**: No memory leaks over 10,000 iterations

**Notes**: Requires monitoring tools for accurate measurement.

### Concurrent Connections

**Status**: ✅ Complete

**Result**: 500 concurrent connections handled in 1.03s

**Target**: Handle 500 concurrent connections in <10 seconds ✅ **PASSED**

**Analysis**: Excellent concurrent connection handling, well within target.

## References

- Requirements: `.kiro/specs/p0-production-parity/requirements.md` (9.1, 9.2, 9.4)
- Design: `.kiro/specs/p0-production-parity/design.md`
- Benchmark Documentation: `docs/benchmarks/P0_PROTOCOL_BENCHMARKS.md`
- Test Implementation: `app/tests/bench_p0_protocols.rs`

## Revision History

- 2025-10-08: Initial baseline results collected
