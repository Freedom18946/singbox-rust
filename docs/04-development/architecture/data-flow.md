# Data Flow

Request and response flow across inbounds, router, outbounds, and transports.

## High-Level Steps

1. Inbound accepts connection
2. Router chooses outbound + strategy
3. Outbound establishes transport chain
4. Data flows through adapters and transport
5. Metrics and logs emitted

## References

- Architecture overview: `overview.md`
- Runtime notes: `../../03-operations/data-pipeline.md`
- Metrics catalog: `../../METRICS_CATALOG.md`

## Status

Skeleton page. Expand with:
- DNS lookup flow
- NAT/UDP handling
- Diagnostics and tracing hooks
