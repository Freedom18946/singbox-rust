# Historical Verification Record

> WARNING: This file is a historical snapshot, not the current source of truth for parity or release status.
>
> Earlier versions of this report mixed stale "production ready" labels, partial rerun notes, and large placeholder sections. Those sections have been removed. For current status, use:
>
> - `labs/interop-lab/docs/dual_kernel_golden_spec.md`
> - `agents-only/active_context.md`
> - `agents-only/workpackage_latest.md`
> - `agents-only/reference/GO_PARITY_MATRIX.md`

## What This File Still Preserves

- The project previously used a 3-layer verification framing:
  - source / implementation presence
  - tests
  - runtime validation
- Historical protocol verification work was concentrated on Shadowsocks and Trojan during the earlier Phase 1 period.
- A later docs refresh on 2026-01-18 updated parity notes, but did not turn this file into a current, self-contained verification ledger.

## Why The Old Version Was Downgraded

The previous version of this document was no longer safe to read as an authority because it mixed:

- old timestamps and newer label updates
- "production ready" language with sandbox-limited partial reruns
- hundreds of empty `PENDING` templates that created false coverage signals
- inconsistent status language across top-level and per-protocol sections

## Historical Checkpoints

### 2025-11 to 2025-12

- Early protocol-focused verification work recorded successful or partially successful runs for Shadowsocks and Trojan.
- Later reruns in sandboxed environments introduced bind-related skips and partial runtime coverage.

### 2026-01-18

- Documentation and parity labels were refreshed for selected config/rule-set fixes.
- That refresh did not revalidate the broader protocol matrix represented by the older body of this file.

## Current Reading Rule

Use this file only as a pointer that historical verification work existed. Do not use it to answer:

- whether the current workspace is fully verified
- whether a protocol is currently release-ready
- whether dual-kernel parity is closed
- whether an accepted limitation has behavior-level evidence

Those questions now belong to the active reference docs and capability ledger, not to this historical report.

---

**Status**: Historical / stale snapshot  
**Last reviewed**: 2026-03-21
