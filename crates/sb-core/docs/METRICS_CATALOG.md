# Metrics Catalog

This document provides a comprehensive catalog of all metrics exposed by singbox-rust.

## UDP Metrics

### UDP Failure Classification

These metrics track UDP upstream failures with detailed classification for better observability.

#### `udp_upstream_fail_total`

**Type:** Counter  
**Labels:**
- `class`: Classification of the failure type
  - `timeout`: Connection or request timeout
  - `io`: I/O errors (network issues, socket errors)
  - `decode`: Protocol decoding/parsing errors
  - `no_route`: No route found for destination
  - `canceled`: Request was canceled
  - `other`: Other unclassified errors

**Description:** Total count of UDP upstream failures by failure class.

**Units:** Count  

**Semantics:** Incremented whenever an UDP upstream operation fails. The `class` label provides detailed categorization for failure analysis and alerting.

#### `udp_nat_map_size`

**Type:** Gauge  
**Labels:** None  

**Description:** Current number of entries in the UDP NAT mapping table.

**Units:** Count  

**Semantics:** Tracks the size of the UDP NAT table for capacity monitoring.

#### `udp_nat_evict_total`

**Type:** Counter  
**Labels:**
- `reason`: Reason for eviction
  - `ttl`: Entry expired due to TTL
  - `capacity`: Entry evicted due to capacity limits

**Description:** Total number of UDP NAT entries evicted.

**Units:** Count  

**Semantics:** Tracks NAT table evictions to monitor table churn and capacity issues.

#### `udp_nat_ttl_seconds`

**Type:** Histogram  
**Labels:** None  

**Description:** UDP NAT session TTL distribution in seconds.

**Units:** Seconds  

**Semantics:** Tracks the time-to-live distribution of UDP NAT sessions for performance analysis.

### Convenience Functions

The following convenience functions are available for recording common UDP failure scenarios:

- `record_timeout_failure()` - Records a timeout failure
- `record_io_failure()` - Records an I/O failure  
- `record_decode_failure()` - Records a decode failure
- `record_no_route_failure()` - Records a no-route failure
- `record_canceled_failure()` - Records a canceled operation
- `record_other_failure()` - Records an unclassified failure

## Metrics Export

### Export Failure Classification

These metrics track failures in the metrics export pipeline itself.

#### `metrics_export_fail_total`

**Type:** Counter  
**Labels:**
- `class`: Classification of the export failure
  - `encode_error`: Serialization/encoding failures
  - `timeout`: Export operation timeout
  - `busy`: Export system too busy to process request
  - `net_error`: Network-related export failures
  - `other`: Other unclassified export errors

**Description:** Total count of metrics export failures by failure class.

**Units:** Count  

**Semantics:** Incremented whenever the metrics export process encounters an error. This provides observability into the health of the metrics system itself.

### Convenience Functions

The following convenience functions are available for recording export failures:

- `record_encode_error()` - Records an encoding failure
- `record_timeout_error()` - Records a timeout during export
- `record_busy_error()` - Records a busy/overload condition
- `record_net_error()` - Records a network-related failure
- `record_other_export_error()` - Records an unclassified export error

## Implementation Notes

### Error Classification Strategy

The error classification system follows these principles:

1. **Actionable Categories**: Each error class should suggest a specific type of remediation
2. **Mutually Exclusive**: Errors should map to exactly one category
3. **Stable Over Time**: Categories should not change frequently to maintain dashboard compatibility

### Prometheus Compatibility

All metrics follow Prometheus naming conventions:
- Snake case naming (`udp_upstream_fail_total`)
- Consistent suffixes (`_total` for counters, `_seconds` for time-based histograms)
- Descriptive help text
- Appropriate metric types

### Performance Considerations

- Metrics collection has minimal performance impact on hot paths
- Counter increments are atomic and thread-safe
- Histogram observations use efficient bucketing strategies
- Label cardinality is kept low to prevent metrics explosion

## Usage Examples

### Alerting Rules

```yaml
# High UDP failure rate
- alert: HighUDPFailureRate
  expr: rate(udp_upstream_fail_total[5m]) > 10
  labels:
    severity: warning
  annotations:
    summary: "High UDP failure rate detected"
    description: "UDP failures are occurring at {{ $value }} per second"

# NAT table capacity issues  
- alert: UDPNATCapacityHigh
  expr: udp_nat_map_size > 10000
  labels:
    severity: warning
  annotations:
    summary: "UDP NAT table capacity high"
    description: "NAT table has {{ $value }} entries"
```

### Grafana Queries

```promql
# UDP failure rate by class
rate(udp_upstream_fail_total[5m])

# NAT table utilization over time
udp_nat_map_size

# Export failure rate
rate(metrics_export_fail_total[5m])

# P95 NAT session TTL
histogram_quantile(0.95, rate(udp_nat_ttl_seconds_bucket[5m]))
```
