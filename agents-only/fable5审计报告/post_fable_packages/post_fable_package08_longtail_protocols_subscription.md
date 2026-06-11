<!-- tier: B -->
# post_fable_package08_longtail_protocols_subscription

## Status

PLANNED.

## Source Findings

- CAL-18: tor, tailscale, dns, and shadowsocksr outbounds are stubs in parity builds.
- CAL-28: deepest trojan connection/timeout tests are ignored.
- H-10: subscription parser coverage for common provider formats is unknown.

## Objective

Clarify and improve long-tail protocol and subscription behavior without blocking the
GUI launch path.

## Implementation Contract

- Inventory long-tail outbound types and mark each as implemented, feature-gated,
  stubbed, or intentionally de-scoped.
- For each stubbed type, choose one status: wire the feature, add a loud unsupported
  error, or document de-scope.
- Revisit ignored trojan integration tests and either re-enable with a local harness
  or record why they remain manual.
- Build a small subscription fixture set for common provider outputs and classify
  parser behavior.

## Out Of Scope

- WireGuard, which package 04 owns.
- GUI launch and TUN dataplane.
- Full protocol parity certification.

## Acceptance Criteria

- Long-tail outbound status is no longer ambiguous in parity/full builds.
- Trojan ignored tests have a decision with evidence.
- Subscription fixtures cover at least the most common formats available in the repo
  or supplied samples.
- New failures are registered as follow-up tasks rather than hidden under generic
  capability claims.

## Tests / Verification

- Add or update tests for unsupported long-tail types to fail loudly where applicable.
- Run trojan integration tests relevant to the chosen decision.
- Run subscription fixture tests.
- Run `cargo check --workspace --all-features`.
- Run `git diff --check`.

## Docs To Update

- Long-tail protocol/subscription evidence note under `agents-only/`.
- This package file, under Completion Notes.
- Capability docs via package 11 if public-facing status changes.

## Dependencies

- None.

## Completion Notes

Not started.
