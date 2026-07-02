# Stress Test Logs

This directory contains runtime-generated stress test logs.

## Log Files (Git-Ignored)

- `stress_test_[type]_[timestamp].log` - Full test execution output
- `monitor_[timestamp].log` - Resource monitoring data
- `summary_[timestamp].txt` - Test summary reports

## Running Stress Tests

```bash
# Quick verification (5 minutes)
./scripts/test/stress/run.sh short

# Medium test (1 hour)
./scripts/test/stress/run.sh medium

# Extended test (6 hours)
./scripts/test/stress/run.sh long

# Full endurance (24 hours)
./scripts/test/stress/run.sh endurance
```

## Monitoring

```bash
# Monitor active stress test
./scripts/test/stress/monitor.sh

# Or specify PID
./scripts/test/stress/monitor.sh [PID]
```

## Log Analysis

```bash
# View latest test log
tail -100 reports/stress-tests/stress_test_*.log | tail -100

# View latest monitor log
tail -50 reports/stress-tests/monitor_*.log | tail -50

# Extract success rate
grep "Successful:" reports/stress-tests/*.log

# Check for leaks
grep "Leak Detected" reports/stress-tests/*.log

# Check peak resources
grep "Peak" reports/stress-tests/*.log
```

## Cleanup

```bash
# Preview logs older than 7 days before deleting anything
find reports/stress-tests/ -name "*.log" -mtime +7 -print

# Preview old logs that could be compressed
find reports/stress-tests/ -name "*.log" -mtime +1 -print

# Preview all log files before archiving
find reports/stress-tests/ -type f -print
```

Deletion, compression, and archive creation are manual follow-up actions after the preview output is reviewed.

## Implementation

- **Test runner**: `scripts/test/stress/run.sh`
- **Monitor**: `scripts/test/stress/monitor.sh`
- **Test source**: `app/tests/stress_tests.rs`

---

**Note**: All log files are git-ignored and generated at runtime.
