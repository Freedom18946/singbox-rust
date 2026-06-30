<!-- tier: C -->
# L01-L25 Compressed History

Purpose: retain durable closed-phase conclusions after removing raw phase packets and old logs.
Current work does not live here; use `agents-only/active_context.md`.

## L01-L04

- L01/L02/L04 acceptance gaps were closed by 2026-02.
- Early architecture, requirements, implementation-guide, dependency, crate, and feature mapping docs are historical baselines.
- L03 service work completed SSMAPI, DERP config, `resolved`, CacheFile, and ConnMetadata lines. Linux `resolved` runtime/system-bus specifics remained environment-limited, not an active blocker.
- L04 was governance and quality prework. Its useful residue is current `reference/` and governance scripts, not old panel status.

## L05-L17

- L05-L14 closed as the first broad implementation/alignment wave: interop-lab foundation, modeling, GUI replay support, migration compatibility, service security/lifecycle, TLS/Endpoint advanced capability, and trend gates.
- L15-L17 were detailed pre-replacement work packages. They are superseded by later L18-L25/MT acceptance records and current `reference/` rules.
- Old package text should not be used as live next-step guidance.

## MIG-02 / L19-L21

- MIG-02 accepted on 2026-03-07: production paths eliminated implicit direct fallback.
- L19/L20/L21 migration waves produced the durable architecture decision that `sb-core` is a Kernel Aggregate, not a pure engine crate.
- `sb-core` may retain feature-gated web/TLS/QUIC-facing orchestration where boundaries are explicit and guarded.
- New protocol implementation defaults to `sb-adapters/`; platform capability defaults to `sb-platform/`.
- Detailed ADR is preserved in `adr_l19_3_1_sb_core_role.md`.

## L22

- L22 closed dual-kernel parity accounting for its time by promoting strict replay cases to `kernel_mode: both` and completing Sniff Phase A/B work.
- The archived L22 counts are historical. Current parity ledger authority remains `labs/interop-lab/docs/dual_kernel_golden_spec.md` plus `active_context.md`.
- Rust-only tests or repo-level unit tests must not be reinterpreted as dual-kernel parity completion.

## L23

- L23 closed TUN/Sniff runtime gaps, provider wiring, and T4 protocol-suite acceptance.
- The durable rule is operational: TUN, provider hot-reload, and protocol runtime work are quality/runtime work unless backed by the strict dual-kernel oracle path.

## L24

- L24 closed performance, security, quality, and functional hardening across its 30-task B1-B4 program.
- Keep the category lessons, not the old task queue. New work should be grouped by current blocker/benefit.

## L25

- L25 closed production hardening, cross-platform cleanup, and docs completion.
- TUN network-stack conclusion: use a mixed pattern. `smoltcp` is only for TUN-side L3-to-L4 assembly; system TCP remains default, userspace UDP remains default.
- L25 did not authorize workflow automation restoration.

## Durable Non-Claims

- Closed L-phase history is not current project mode.
- Archive cleanup is documentation hygiene only.
- Do not reopen old phase names unless user explicitly asks for archaeology.
