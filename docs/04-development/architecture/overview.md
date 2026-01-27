# Architecture Overview

High-level system architecture for singbox-rust. This is a lightweight entry point; deeper details live in the sibling pages.

## Scope

- Core request flow (inbound → router → outbound → transport)
- Major crate responsibilities
- How configuration maps into runtime components

## Core Crates (summary)

- `sb-core`: routing, DNS, inbound/outbound abstractions
- `sb-config`: config parsing and IR
- `sb-adapters`: protocol implementations
- `sb-transport`: transport stack (TCP/UDP/WS/H2/gRPC/QUIC)
- `sb-tls`: TLS/REALITY/ECH primitives
- `sb-runtime`: task/lifecycle utilities
- `sb-platform`: OS-specific features (process matching, TUN)

## High-Level Data Flow

1. Load config → validate → build IR
2. Spin up inbounds (listeners)
3. Accept connection → route decision
4. Dial outbound → build transport chain
5. Stream data + metrics + logs

## References

- Project layout: `../../../PROJECT_STRUCTURE_NAVIGATION.md`
- Transport behavior: `../../../TRANSPORT_STRATEGY.md`
- Transport defaults: `../transport-defaults.md`

## Next

- Router internals: `router-engine.md`
- TLS stack: `tls-infrastructure.md`
- Transport stack: `transport-layer.md`
- Data flow details: `data-flow.md`
