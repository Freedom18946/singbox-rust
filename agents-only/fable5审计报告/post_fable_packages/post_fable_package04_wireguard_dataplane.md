<!-- tier: B -->
# post_fable_package04_wireguard_dataplane

## Status

DONE (2026-06-13, code commit `f70bf5ef`).

Endpoint-form WireGuard now resolves as an outbound route target in the live
startup path, and legacy outbound-form WireGuard is wired into the app `adapters`
aggregate. This does not claim full public WireGuard interoperability or
performance certification.

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

Code commit `f70bf5ef` implements:

- endpoint-as-outbound registration in both router and no-router bridge paths;
- deterministic loud failure for empty endpoint tags, duplicate endpoint tags,
  and endpoint/outbound tag conflicts;
- `EndpointAsOutbound.connect_io()` delegation to endpoint `dial_context()` for
  IP and FQDN destinations, while `connect()` remains explicitly unsupported;
- app `adapter-wireguard-outbound` feature wiring through `adapters` and
  therefore `parity`;
- WireGuard endpoint startup without nested Tokio `block_on` panic in the live
  runtime path.

Endpoint form: DONE for package04 scope. A production `app run` smoke with
`route.final: "wg-ep"` reached `sing-box started`, logged
`default outbound resolved default=wg-ep`, and did not hit
`default outbound not found`.

Legacy outbound form: feature wired and builder tested under
`adapter-wireguard-outbound`; full public peer traffic remains uncertified.

Evidence: `post_fable_package04_wireguard_dataplane_evidence.md`.
