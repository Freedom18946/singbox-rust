# Optimization Guide

## Overview

A short list of performance levers for production.

## Quick wins

- Simplify routing rules
- Enable connection pooling where supported
- Use metrics to identify hotspots

## Example tuning (UDP NAT)

```bash
SB_UDP_NAT_MAX=10000 singbox-rust run -c config.yaml
```

## Related

- [Benchmark Guard](../../../scripts/test/bench/guard.sh)
- [Performance Report](../../../reports/PERFORMANCE_REPORT.md)
