<!-- tier: B -->
# post_fable_package08_longtail_protocols_subscription

## Status

DONE (local verification; GitHub Actions stay disabled).

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

User decision for long-tail handling: **"Loud error + keep current state"** (no new
aggregates, no new app features, no heavy deps pulled into parity).

**CAL-18 (long-tail outbound status).** Calibrated against current main: the four
"stub" outbounds all have real connectors; the stub only compiles when the feature is
OFF. `dns` is already real in `adapters`/`parity` (the audit's "dns stub" was stale)
and is now locked by a regression test. The feature-OFF branches for `tor` /
`tailscale` / `shadowsocksr` now register an `InvalidConfigConnector` (via the new
`unsupported_outbound_feature_reason` helper) instead of returning a silent `None`, so
dialing fails loudly with the outbound type, the missing cargo feature, and a rebuild
hint. No aggregate / app-feature changes.

**CAL-28 (trojan ignored tests).** Both deepest ignored tests are **enabled/rewritten**
on the existing `fresh13_tls_verifier_loopback` harness (the cited obstacles — "needs a
TLS server", "CryptoProvider unavailable" — were already solved / a misdiagnosis).
Added 5 pure-local `TrojanUdpSocket` encode/decode unit tests (zero prior coverage).
`tests/trojan_integration.rs` is now 19 pass, **0 ignored**. App-level 1000-handshake /
100-concurrent / bench tests stay manual (performance/scale class).

**H-10 (subscription coverage).** Added a no-network fixture regression set under
`crates/sb-subscribe/tests/` covering Clash YAML, sing-box JSON, and URI-line provider
formats, with explicit unknown-type baselines: Clash/sing-box pass unknown types
through silently; the URI text path drops unknown schemes; only the JSON-array path
errors loudly. 4 tests pass.

Evidence (inventory matrix, decision tables, fixture coverage, follow-ups —
adapter-trojan↔shadowsocks feature gap, trojan `dial` ignores `DialOpts`, no
caller-visible skip counter → package11): `post_fable_package08_longtail_subscription_evidence.md`.

Commits: `fix(adapters): clarify long-tail outbound support` + `checkpoint: record
long-tail subscription closure`.
