# Stress Test Reports

This directory contains stress test execution logs and reports.

## Directory Structure

```
reports/stress-tests/
├── README.md                           # This file
├── stress_test_[type]_[timestamp].log  # Full test logs
├── summary_[timestamp].txt             # Summary reports
├── monitor_[timestamp].log             # Resource monitoring logs
└── STRESS_TEST_SUMMARY.md             # Comprehensive summary (after completion)
```

## Quick Start

### Run Short Test (5 minutes)
```bash
./scripts/run_stress_tests.sh short
```

### Run 24-Hour Test
```bash
./scripts/run_stress_tests.sh endurance
```

### Monitor Running Test
```bash
./scripts/monitor_stress_test.sh
```

## Test Types

- **short** - 5-10 minutes, quick verification
- **medium** - 1-2 hours, moderate stress
- **long** - 6 hours, extended stress
- **endurance** - 24 hours, full endurance test

## Log Files

### Test Logs
Format: `stress_test_[type]_[timestamp].log`

Contains:
- Test configuration
- Progress updates
- Connection statistics
- Resource usage
- Leak detection results

### Monitor Logs
Format: `monitor_[timestamp].log`

Contains:
- CPU usage over time
- Memory usage over time
- File descriptor counts
- Network connections
- Peak values

### Summary Reports
Format: `summary_[timestamp].txt`

Contains:
- Test overview
- Key metrics
- Leak detection status
- Resource usage summary

## Viewing Results

### View Latest Test Log
```bash
tail -f reports/stress-tests/stress_test_*.log | tail -100
```

### View Latest Monitor Log
```bash
tail -f reports/stress-tests/monitor_*.log | tail -50
```

### View Latest Summary
```bash
cat reports/stress-tests/summary_*.txt | tail -1
```

### Extract Key Metrics
```bash
# Success rate
grep "Successful:" reports/stress-tests/*.log

# Leak detection
grep "Leak Detected" reports/stress-tests/*.log

# Peak resources
grep "Peak" reports/stress-tests/*.log
```

## Cleanup

### Remove Old Logs (>7 days)
```bash
find reports/stress-tests/ -name "*.log" -mtime +7 -delete
```

### Compress Old Logs
```bash
find reports/stress-tests/ -name "*.log" -mtime +1 -exec gzip {} \;
```

### Archive Reports
```bash
tar -czf stress-tests-archive-$(date +%Y%m%d).tar.gz reports/stress-tests/
```

## Documentation

- [Stress Testing Guide](../../docs/STRESS_TESTING.md)
- [Task 9.4 Execution Guide](../../.kiro/specs/p0-production-parity/task-9.4-execution-guide.md)
- [Task 9.4 Verification Report](../../.kiro/specs/p0-production-parity/task-9.4-verification-report.md)

## Support

For issues or questions:
1. Check the troubleshooting section in the execution guide
2. Review test logs for error messages
3. Check system resources (CPU, memory, disk)
4. Verify test configuration

## Status

Last updated: January 9, 2025

Infrastructure status: ✅ Ready for execution
