# Health Checks

## Overview

Monitor outbound health with URLTest and metrics.

## Key points

- Use URLTest for automatic selection.
- Expose metrics for observability.
- URLTest timing accepts second-based fields (`interval`, `timeout`, `tolerance`) or millisecond fields (`*_ms`).
- Selector/URLTest member lists accept `members` or the alias `outbounds` (prefer `members`).

## URLTest tuning

URLTest supports both second-based and millisecond-based timing fields:

```yaml
outbounds:
  - type: urltest
    tag: auto
    members: [proxy-a, proxy-b]
    url: https://www.gstatic.com/generate_204
    interval: 10s
    timeout_ms: 3000
    tolerance_ms: 100
```

## Related

- ../08-examples/advanced/load-balancing.md
- ../03-operations/monitoring/metrics.md
