# Stress Testing Guide

This document describes the comprehensive stress testing framework for P0 protocols in singbox-rust.

## Overview

The stress testing framework provides:

1. **24-hour endurance tests** for all P0 protocols
2. **Memory leak detection** with automated monitoring
3. **File descriptor leak detection** with resource tracking
4. **High connection rate testing** (up to 200 conn/s)
5. **Large data transfer testing** (multi-GB transfers)
6. **Concurrent connection testing** (up to 500 concurrent)

## Quick Start

### Run Short Stress Test (5 minutes)

```bash
./scripts/run_stress_tests.sh short
```

### Run Medium Stress Test (1-2 hours)

```bash
./scripts/run_stress_tests.sh medium
```

### Run 24-Hour Endurance Test

```bash
./scripts/run_stress_tests.sh endurance
```

### Monitor Running Test

In a separate terminal:

```bash
./scripts/monitor_stress_test.sh
```

## Test Categories

### 1. Baseline Tests

Tests direct TCP connections without protocol overhead to establish performance baselines.

**Tests:**
- `stress_baseline_short_duration` - 60s test with moderate load
- `stress_baseline_high_connection_rate` - 30s test with 200 conn/s
- `stress_baseline_large_data_transfer` - 60s test with 1MB payloads
- `stress_baseline_resource_monitoring` - 2min test with resource tracking
- `stress_baseline_24_hour_endurance` - 24h endurance test

**Run:**
```bash
cargo test --test stress_tests --release -- baseline --ignored --nocapture
```

### 2. Protocol-Specific Tests

Stress tests for each P0 protocol.

#### REALITY TLS

```bash
cargo test --test stress_tests --release --features tls_reality -- reality --ignored --nocapture
```

**Tests:**
- `stress_reality_24_hour_endurance`
- `stress_reality_high_connection_rate`
- `stress_reality_large_data_transfer`

#### ECH (Encrypted Client Hello)

```bash
cargo test --test stress_tests --release --features tls_ech -- ech --ignored --nocapture
```

**Tests:**
- `stress_ech_24_hour_endurance`
- `stress_ech_high_connection_rate`

#### Hysteria v1

```bash
cargo test --test stress_tests --release --features adapter-hysteria -- hysteria_v1 --ignored --nocapture
```

**Tests:**
- `stress_hysteria_v1_24_hour_endurance`
- `stress_hysteria_v1_udp_relay`
- `stress_hysteria_v1_high_throughput`

#### Hysteria v2

```bash
cargo test --test stress_tests --release --features adapter-hysteria2 -- hysteria_v2 --ignored --nocapture
```

**Tests:**
- `stress_hysteria_v2_24_hour_endurance`
- `stress_hysteria_v2_udp_over_stream`
- `stress_hysteria_v2_with_obfuscation`

#### SSH

```bash
cargo test --test stress_tests --release --features adapter-ssh -- ssh --ignored --nocapture
```

**Tests:**
- `stress_ssh_24_hour_endurance`
- `stress_ssh_connection_pooling`
- `stress_ssh_high_connection_rate`

#### TUIC

```bash
cargo test --test stress_tests --release --features sb-core/out_tuic -- tuic --ignored --nocapture
```

**Tests:**
- `stress_tuic_24_hour_endurance`
- `stress_tuic_udp_over_stream`
- `stress_tuic_high_throughput`

### 3. Leak Detection Tests

Automated tests for detecting memory and file descriptor leaks.

```bash
cargo test --test stress_tests --release -- leak_detection --ignored --nocapture
```

**Tests:**
- `stress_memory_leak_detection` - 5 iterations with memory monitoring
- `stress_file_descriptor_leak_detection` - High connection rate with FD tracking

## Test Configuration

### StressTestConfig

```rust
pub struct StressTestConfig {
    pub duration: Duration,          // Test duration
    pub connection_rate: usize,      // Connections per second
    pub concurrent_limit: usize,     // Max concurrent connections
    pub payload_size: usize,         // Bytes per connection
    pub enable_monitoring: bool,     // Enable resource monitoring
}
```

### Default Configurations

**Short Test:**
```rust
StressTestConfig {
    duration: Duration::from_secs(60),
    connection_rate: 50,
    concurrent_limit: 100,
    payload_size: 1024,
    enable_monitoring: true,
}
```

**High Connection Rate:**
```rust
StressTestConfig {
    duration: Duration::from_secs(30),
    connection_rate: 200,
    concurrent_limit: 500,
    payload_size: 512,
    enable_monitoring: true,
}
```

**Large Data Transfer:**
```rust
StressTestConfig {
    duration: Duration::from_secs(60),
    connection_rate: 10,
    concurrent_limit: 50,
    payload_size: 1024 * 1024,  // 1 MB
    enable_monitoring: true,
}
```

**24-Hour Endurance:**
```rust
StressTestConfig {
    duration: Duration::from_secs(24 * 60 * 60),
    connection_rate: 10,
    concurrent_limit: 50,
    payload_size: 4096,
    enable_monitoring: true,
}
```

## Metrics Collected

### Connection Metrics

- **Total Connections**: Number of connection attempts
- **Successful Connections**: Connections that completed successfully
- **Failed Connections**: Connections that failed
- **Success Rate**: Percentage of successful connections
- **Peak Concurrent**: Maximum concurrent connections

### Data Transfer Metrics

- **Bytes Sent**: Total bytes sent across all connections
- **Bytes Received**: Total bytes received (should match sent for echo tests)
- **Throughput**: MB/s calculated from total data and duration

### Performance Metrics

- **Total Duration**: Total time spent in connections
- **Average Connection Time**: Mean time per connection
- **Connection Rate**: Actual connections per second achieved

### Resource Metrics

- **Open File Descriptors**: Tracked over time
- **Memory Usage**: RSS memory tracked over time
- **Peak FDs**: Maximum file descriptors used
- **Peak Memory**: Maximum memory used

## Leak Detection

### File Descriptor Leak Detection

The framework detects FD leaks by:

1. Sampling FD count every 5 seconds
2. Comparing first 10 samples vs last 10 samples
3. Flagging if FDs increased by >50%

**Example:**
```
Initial FDs:           45
Final FDs:             47
FD Change:             +2
FD Leak Detected:      ✅ NO
```

### Memory Leak Detection

The framework detects memory leaks by:

1. Sampling memory usage every 5 seconds
2. Comparing first 10 samples vs last 10 samples
3. Flagging if memory increased by >50%

**Example:**
```
Initial Memory:        12,345 KB
Final Memory:          12,567 KB
Memory Change:         +222 KB
Memory Leak Detected:  ✅ NO
```

## Monitoring

### Real-Time Monitoring

Use the monitoring script to track a running test:

```bash
./scripts/monitor_stress_test.sh [PID]
```

The script monitors:
- CPU usage (%)
- Memory usage (% and KB)
- File descriptor count
- Network connections
- Peak values

Output is logged to `reports/stress-tests/monitor_*.log`

### Manual Monitoring

**Check file descriptors (macOS):**
```bash
lsof -p $(pgrep stress_tests) | wc -l
```

**Check file descriptors (Linux):**
```bash
ls /proc/$(pgrep stress_tests)/fd | wc -l
```

**Check memory usage:**
```bash
ps -p $(pgrep stress_tests) -o %cpu,%mem,rss,vsz
```

## Reports

### Test Reports

All test runs generate reports in `reports/stress-tests/`:

- `stress_test_[type]_[timestamp].log` - Full test log
- `summary_[timestamp].txt` - Summary report
- `monitor_[timestamp].log` - Resource monitoring log

### Summary Report Format

```
P0 Protocol Stress Test Summary
================================

Test Type:    short
Timestamp:    20250109_143022
Duration:     00:05:23

Test Results:
-------------
test result: ok. 3 passed; 0 failed; 0 ignored

Resource Usage:
---------------
✓ Resource monitoring data available

Leak Detection:
---------------
✓ No file descriptor leaks detected
✓ No memory leaks detected

Full log: reports/stress-tests/stress_test_short_20250109_143022.log
```

## Best Practices

### Running 24-Hour Tests

1. **Use a dedicated machine** - Don't run on development machine
2. **Use tmux/screen** - Prevent disconnection from terminating test
3. **Monitor disk space** - Logs can grow large
4. **Set up alerts** - Monitor for failures
5. **Run in release mode** - Always use `--release` flag

**Example with tmux:**
```bash
tmux new -s stress_test
./scripts/run_stress_tests.sh endurance
# Detach: Ctrl+B, then D
# Reattach: tmux attach -t stress_test
```

### Interpreting Results

**Success Criteria:**

- ✅ Success rate > 95% for normal tests
- ✅ Success rate > 99% for 24-hour tests
- ✅ No FD leaks detected
- ✅ No memory leaks detected
- ✅ FD count stable or decreasing over time
- ✅ Memory usage stable or decreasing over time

**Warning Signs:**

- ⚠️ Success rate < 95%
- ⚠️ FD count steadily increasing
- ⚠️ Memory usage steadily increasing
- ⚠️ High failure rate under moderate load
- ⚠️ Connection timeouts

**Failure Indicators:**

- ❌ Success rate < 90%
- ❌ FD leak detected
- ❌ Memory leak detected
- ❌ Test crashes or panics
- ❌ System becomes unresponsive

### Troubleshooting

**Test fails to start:**
- Check if port is already in use
- Verify cargo can build in release mode
- Check system resource limits (`ulimit -n`)

**High failure rate:**
- Reduce connection rate
- Reduce concurrent limit
- Check system load
- Verify network connectivity

**FD leak detected:**
- Review connection cleanup code
- Check for unclosed streams
- Verify proper Drop implementations
- Use `lsof` to identify leaked FDs

**Memory leak detected:**
- Run with memory profiler (valgrind, heaptrack)
- Check for reference cycles
- Verify buffer cleanup
- Review Arc/Rc usage

## Protocol Server Setup

Most protocol-specific tests require running servers. See individual protocol documentation:

- **REALITY TLS**: See `docs/TLS.md`
- **ECH**: See `docs/ECH_CONFIG.md`
- **Hysteria v1/v2**: See upstream Hysteria documentation
- **SSH**: Use OpenSSH server
- **TUIC**: See upstream TUIC documentation

## CI Integration

### GitHub Actions Example

```yaml
name: Stress Tests

on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sunday
  workflow_dispatch:

jobs:
  stress-test:
    runs-on: ubuntu-latest
    timeout-minutes: 1500  # 25 hours
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
          profile: minimal
      
      - name: Run 24-hour stress test
        run: |
          ./scripts/run_stress_tests.sh endurance
      
      - name: Upload reports
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: stress-test-reports
          path: reports/stress-tests/
```

## Performance Targets

### Baseline (Direct TCP)

- **Throughput**: > 1 GB/s on localhost
- **Latency**: < 1ms RTT on localhost
- **Connection Rate**: > 1000 conn/s
- **Success Rate**: > 99.9%

### P0 Protocols

- **Throughput**: > 500 MB/s (protocol-dependent)
- **Latency**: < 10ms RTT (protocol-dependent)
- **Connection Rate**: > 100 conn/s
- **Success Rate**: > 99%
- **24h Stability**: No leaks, no crashes

## Future Enhancements

- [ ] Automated performance regression detection
- [ ] Comparison with upstream sing-box
- [ ] Distributed stress testing across multiple machines
- [ ] Real-world traffic pattern simulation
- [ ] Automated bisection for performance regressions
- [ ] Integration with continuous benchmarking
- [ ] Flamegraph generation for hot paths
- [ ] Memory profiling integration

## References

- [Performance Benchmarks](../app/benches/bench_p0_protocols.rs)
- [Monitoring Script](../scripts/monitor_stress_test.sh)
- [Pressure Smoke Test](../scripts/pressure-smoke.sh)
- [P0 Completion Summary](../P0_COMPLETION_SUMMARY.md)
