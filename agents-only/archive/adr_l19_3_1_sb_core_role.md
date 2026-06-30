<!-- tier: A -->
# ADR L19.3.1: `sb-core` Role

Status: accepted; compressed from the old L19-L21 migration archive.

## Decision

`sb-core` is a Kernel Aggregate layer, not a pure engine-only crate.

It may contain routing, policy, planning, and orchestration logic that belongs to the core runtime model. Feature-gated web/TLS/QUIC-facing dependencies are allowed where they serve core orchestration and remain inside documented boundary budgets.

## Placement Rules

- New protocol implementation defaults to `sb-adapters/`.
- Platform capability defaults to `sb-platform/`.
- `sb-core` may keep coordination and typed core abstractions when moving them outward would create a worse ownership boundary.
- `sb-adapters -> sb-core` dependencies are managed by path/category budgets, not by the obsolete rule that every such edge is automatically a violation.

## Consequences

- Boundary gates enforce allowed edges and budgets.
- Architecture docs must say Kernel Aggregate, not pure engine layer.
- Future refactors should reduce accidental coupling, but must not reopen the old architecture debate without new evidence.
