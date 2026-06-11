<!-- tier: B -->
# post_fable_package04_wireguard_dataplane

## Status

PLANNED.

## Source Findings

- CAL-03: WireGuard endpoint is built but never registered as an outbound target.
- CAL-09: legacy `wireguard` outbound remains stubbed because the feature is not wired.

## Objective

Close the WireGuard route-target gap for the Go 1.12 endpoint form and decide the
legacy outbound compatibility posture.

## Implementation Contract

- Register WireGuard endpoints into the outbound namespace through the existing
  endpoint-as-outbound adapter path.
- Add a run-path regression test where `endpoints:[wireguard]` is referenced by
  `route.final` or an equivalent route target and no longer fails with
  `default outbound not found`.
- Evaluate the `adapter-wireguard-outbound` feature and either wire it into the
  intended app feature set or document an explicit de-scope with a test-backed error.
- Do not rewrite the WireGuard protocol stack in this package.

## Out Of Scope

- Full WireGuard interoperability or performance tuning.
- TUN device integration.
- Subscription-level WireGuard import behavior unless directly needed for the
  regression fixture.

## Acceptance Criteria

- Endpoint-form WireGuard route targets resolve in the live run path.
- Legacy outbound-form WireGuard has a clear implemented or de-scoped status.
- At least one regression test covers the previously failing route-target lookup.

## Tests / Verification

- Add a config/run-path test for endpoint route target resolution.
- Run relevant `sb-core`, `sb-adapters`, or app config tests.
- Run `cargo check --workspace --all-features`.
- Run `git diff --check`.

## Docs To Update

- `agents-only/active_context.md` on completion.
- This package file, under Completion Notes.
- Any capability ledger touched by package 11.

## Dependencies

- None.
- Can run in parallel with packages 01 and 02.

## Completion Notes

Not started.
