# Router Engine

Notes on the routing pipeline and decision model.

## Scope

- Rule evaluation order and match types
- Inbound tagging and outbound selection
- DNS strategy interaction with routing

## Current Source of Truth

- Router logic lives in `crates/sb-core` and `crates/sb-config`.
- Routing defaults and notes are tracked in `../../../TRANSPORT_STRATEGY.md`.

## Status

This page is a skeleton. Extend with:
- Rule evaluation order
- Selector/URLTest behavior
- Diagnostics/trace output
