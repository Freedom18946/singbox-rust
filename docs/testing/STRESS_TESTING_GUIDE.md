# Stress Testing Guide

This document describes stress testing procedures for P0 protocols.

## Overview

Stress testing validates system stability and performance under extreme conditions:

1. **24-hour stress test** - Long-running stability test
2. **Memory leak detection** - Monitor for memory leaks
3. **File descriptor leak detection** - Monitor for FD leaks
4. **High connection rate** - Test rapid connection creation
5. **Large data transfers** - Test sustained high throughput

## Test Environment

### Hardware Requirements

- **CPU**: Multi-core processor (4+ cores recommended)
- **Memory**: 8GB+ RAM
- **Network**: Gigabit network interface
- **Storage**: SSD for logging

### Software Requirements

- **OS**: Linux or macOS
- **Rust**: 1.90+
- **Monitoring Tools**: 
  - `htop` or `top` for CPU/memory monitoring
  - `lsof` for file descriptor monitoring
  - `netstat` or `ss` for network monitoring

## Stress Tests

### 1. 24-Hour Stress Test

**Objective**: Verify system stability over extended period

**Duration**: 24 hours

**Test Procedure**:

```bash
# Run 24-hour stress test
cargo test --package app --test bench_p0_protocols \
    stress_24_hour -- --nocapture --ignored --test-threads=1
```

**Monitoring**:

```bash
# Monitor CPU and memory
watch -n 60 'ps aux | grep bench_p0_protocols'

# Monitor file descriptors
watch -n 60 'lsof -p $(pgrep bench_p0_protocols) | wc -l'

# Monitor network connections
watch -n 60 'netstat -an | grep ESTABLISHED | wc -l'
```

**Success Criteria**:

- [ ] No crashes or panics
- [ ] Memory usage stable (no continuous growth)
- [ ] File descriptors stable (no leaks)
- [ ] CPU usage reasonable (<80% average)
- [ ] Network connections properly closed

### 2. Memory Leak Detection

**Objective**: Detect memory leaks in protocol implementations

**Duration**: Variable (1-24 hours)

**Test Procedure**:

```bash
# Run memory leak detection test
cargo test --package app --test bench_p0_protocols \
    stress_memory_leak_detection -- --nocapture --ignored --test-threads=1
```

**Monitoring**:

```bash
# Monitor memory usage with heaptrack (Linux)
heaptrack cargo test --package app --test bench_p0_protocols \
    stress_memory_leak_detection -- --nocapture --ignored

# Analyze results
heaptrack_gui heaptrack.*.gz

# Monitor memory usage with Instruments (macOS)
instruments -t Leaks cargo test --package app --test bench_p0_protocols \
    stress_memory_leak_detection -- --nocapture --ignored
```

**Success Criteria**:

- [ ] No memory leaks detected
- [ ] Memory usage stable over time
- [ ] All allocations properly freed
- [ ] No unbounded growth in collections

### 3. File Descriptor Leak Detection

**Objective**: Detect file descriptor leaks

**Duration**: 1-4 hours

**Test Procedure**:

```bash
# Run FD leak detection test
cargo test --package app --test bench_p0_protocols \
    stress_fd_leak_detection -- --nocapture --ignored --test-threads=1
```

**Monitoring**:

```bash
# Monitor file descriptors
watch -n 10 'lsof -p $(pgrep bench_p0_protocols) | wc -l'

# List open files
lsof -p $(pgrep bench_p0_protocols)

# Check for leaked sockets
lsof -p $(pgrep bench_p0_protocols) | grep TCP
```

**Success Criteria**:

- [ ] File descriptor count stable
- [ ] All sockets properly closed
- [ ] No orphaned connections
- [ ] FD count returns to baseline after test

### 4. High Connection Rate Test

**Objective**: Test system under rapid connection creation

**Duration**: 10-30 minutes

**Test Procedure**:

```bash
# Run high connection rate test
cargo test --package app --test bench_p0_protocols \
    stress_high_connection_rate -- --nocapture --ignored --test-threads=1
```

**Monitoring**:

```bash
# Monitor connection rate
watch -n 1 'netstat -an | grep ESTABLISHED | wc -l'

# Monitor system resources
htop
```

**Success Criteria**:

- [ ] Handle >100 connections/second
- [ ] No connection failures
- [ ] Stable memory usage
- [ ] Stable CPU usage

### 5. Large Data Transfer Test

**Objective**: Test sustained high throughput

**Duration**: 10-30 minutes

**Test Procedure**:

```bash
# Run large data transfer test
cargo test --package app --test bench_p0_protocols \
    stress_large_data_transfer -- --nocapture --ignored --test-threads=1
```

**Monitoring**:

```bash
# Monitor network throughput
iftop -i lo

# Monitor system resources
htop
```

**Success Criteria**:

- [ ] Achieve >50 MB/s throughput
- [ ] Stable memory usage
- [ ] No data corruption
- [ ] Proper flow control

## Protocol-Specific Stress Tests

### REALITY TLS

```bash
# 24-hour REALITY stress test
cargo test --package app --test bench_p0_protocols \
    stress_reality_24h -- --nocapture --ignored --test-threads=1
```

**Specific Checks**:

- [ ] TLS session handling
- [ ] REALITY authentication stability
- [ ] Certificate validation
- [ ] Connection reuse

### ECH

```bash
# 24-hour ECH stress test
cargo test --package app --test bench_p0_protocols \
    stress_ech_24h -- --nocapture --ignored --test-threads=1
```

**Specific Checks**:

- [ ] ECH encryption stability
- [ ] TLS handshake handling
- [ ] Configuration updates
- [ ] Connection reuse

### Hysteria v1/v2

```bash
# 24-hour Hysteria stress test
cargo test --package app --test bench_p0_protocols \
    stress_hysteria_24h -- --nocapture --ignored --test-threads=1
```

**Specific Checks**:

- [ ] QUIC connection handling
- [ ] UDP packet processing
- [ ] Congestion control stability
- [ ] Stream multiplexing

### SSH

```bash
# 24-hour SSH stress test
cargo test --package app --test bench_p0_protocols \
    stress_ssh_24h -- --nocapture --ignored --test-threads=1
```

**Specific Checks**:

- [ ] SSH session handling
- [ ] Channel multiplexing
- [ ] Authentication stability
- [ ] Connection reuse

### TUIC

```bash
# 24-hour TUIC stress test
cargo test --package app --test bench_p0_protocols \
    stress_tuic_24h -- --nocapture --ignored --test-threads=1
```

**Specific Checks**:

- [ ] QUIC connection handling
- [ ] UDP packet processing
- [ ] Stream multiplexing
- [ ] Connection reuse

## Automated Stress Testing

### CI Integration

```yaml
# .github/workflows/stress-tests.yml
name: Stress Tests

on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly
  workflow_dispatch:

jobs:
  stress-test:
    runs-on: ubuntu-latest
    timeout-minutes: 1500  # 25 hours
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Install Rust
        uses: actions-rust-lang/setup-rust-toolchain@v1
      
      - name: Run 24-hour stress test
        run: |
          cargo test --package app --test bench_p0_protocols \
            stress_24_hour -- --nocapture --ignored --test-threads=1
      
      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: stress-test-results
          path: reports/stress-tests/
```

### Monitoring Script

```bash
#!/bin/bash
# scripts/monitor_stress_test.sh

PID=$(pgrep bench_p0_protocols)
LOG_FILE="reports/stress-tests/monitor_$(date +%Y%m%d_%H%M%S).log"

mkdir -p reports/stress-tests

echo "Monitoring PID: $PID" | tee -a "$LOG_FILE"
echo "Start time: $(date)" | tee -a "$LOG_FILE"

while kill -0 $PID 2>/dev/null; do
    echo "=== $(date) ===" | tee -a "$LOG_FILE"
    
    # CPU and memory
    ps -p $PID -o %cpu,%mem,vsz,rss | tee -a "$LOG_FILE"
    
    # File descriptors
    echo "FDs: $(lsof -p $PID 2>/dev/null | wc -l)" | tee -a "$LOG_FILE"
    
    # Network connections
    echo "Connections: $(netstat -an | grep ESTABLISHED | wc -l)" | tee -a "$LOG_FILE"
    
    sleep 60
done

echo "End time: $(date)" | tee -a "$LOG_FILE"
```

## Results Analysis

### Memory Analysis

```bash
# Analyze memory usage trends
grep "Memory:" reports/stress-tests/monitor_*.log | \
    awk '{print $2}' | \
    gnuplot -e "set terminal png; set output 'memory_trend.png'; plot '-' with lines"
```

### FD Analysis

```bash
# Analyze FD usage trends
grep "FDs:" reports/stress-tests/monitor_*.log | \
    awk '{print $2}' | \
    gnuplot -e "set terminal png; set output 'fd_trend.png'; plot '-' with lines"
```

### Connection Analysis

```bash
# Analyze connection trends
grep "Connections:" reports/stress-tests/monitor_*.log | \
    awk '{print $2}' | \
    gnuplot -e "set terminal png; set output 'conn_trend.png'; plot '-' with lines"
```

## Troubleshooting

### Memory Leaks

**Symptoms**:
- Continuous memory growth
- OOM errors
- Slow performance over time

**Investigation**:
```bash
# Use heaptrack to find leaks
heaptrack cargo test --package app --test bench_p0_protocols

# Analyze allocation sites
heaptrack_gui heaptrack.*.gz
```

**Common Causes**:
- Unclosed connections
- Unbounded caches
- Circular references
- Forgotten cleanup

### File Descriptor Leaks

**Symptoms**:
- FD count continuously growing
- "Too many open files" errors
- Connection failures

**Investigation**:
```bash
# List open FDs
lsof -p $(pgrep bench_p0_protocols)

# Check for leaked sockets
lsof -p $(pgrep bench_p0_protocols) | grep TCP | grep CLOSE_WAIT
```

**Common Causes**:
- Unclosed sockets
- Leaked file handles
- Missing cleanup in error paths

### Performance Degradation

**Symptoms**:
- Throughput decreases over time
- Latency increases over time
- CPU usage increases

**Investigation**:
```bash
# Profile hot paths
cargo flamegraph --test bench_p0_protocols

# Check for lock contention
perf record -g cargo test --package app --test bench_p0_protocols
perf report
```

**Common Causes**:
- Lock contention
- Growing data structures
- Inefficient algorithms
- Resource exhaustion

## Best Practices

### Before Testing

1. **Clean environment**: Fresh system state
2. **Baseline metrics**: Record initial resource usage
3. **Monitoring setup**: Configure monitoring tools
4. **Backup data**: Save important data

### During Testing

1. **Continuous monitoring**: Watch for anomalies
2. **Log everything**: Capture all metrics
3. **Alert on issues**: Set up alerts for problems
4. **Document observations**: Note any unusual behavior

### After Testing

1. **Analyze results**: Review all metrics
2. **Compare baselines**: Check for regressions
3. **Document findings**: Record issues and fixes
4. **Update tests**: Improve tests based on findings

## References

- **Benchmarks**: `app/tests/bench_p0_protocols.rs`
- **Performance Summary**: `reports/benchmarks/PERFORMANCE_SUMMARY.md`
- **Requirements**: `.kiro/specs/p0-production-parity/requirements.md` (9.2, 9.3, 9.5)

## Revision History

- 2025-10-08: Initial stress testing guide created
