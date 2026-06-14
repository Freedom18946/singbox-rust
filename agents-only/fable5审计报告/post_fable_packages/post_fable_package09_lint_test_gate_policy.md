<!-- tier: B -->
# post_fable_package09_lint_test_gate_policy

## Status

DONE (local-only; GitHub Actions stay disabled). Detail + test/gate table:
`post_fable_package09_lint_test_gate_evidence.md`.

## Source Findings

- CAL-08: workspace deny lint policy applies to only a small part of the workspace.
- CAL-19: selector/proxy-pool tests are ignored after API drift.
- CAL-27: specific feature `cargo test` builds produce warnings.
- CAL-29: known flakes have environment, timing, or filesystem roots.

## Objective

Make local quality gates honest and intentional without triggering a noisy, all-at-once
lint migration.

## Implementation Contract

- Produce a per-crate lint impact inventory before enabling additional
  `lints.workspace = true`.
- Do not enable deny lints across all crates in one step unless the inventory shows
  it is tractable and the user approves the policy.
- Fix or explicitly de-scope stale selector/proxy-pool tests.
- Remove the known feature-specific warnings.
- Harden flakes where low-risk, or document exact isolation commands where hardening
  is not worth the blast radius.

## Out Of Scope

- Re-enabling GitHub Actions.
- Rewriting broad protocol tests unrelated to the identified stale or flaky areas.
- Large-scale unwrap/expect refactors without a policy decision.

## Acceptance Criteria

- Lint policy decision is recorded with per-crate counts.
- Selector/proxy-pool ignored tests are either active again or explicitly de-scoped.
- The feature-specific warning pair is gone or documented as intentionally accepted.
- Flake handling is clearer than the current tribal-memory state.

## Tests / Verification

- Run lint inventory commands and store summarized output under `agents-only/`.
- Run affected selector/proxy-pool tests.
- Run `cargo test -p sb-core --lib` for the warning check.
- Run targeted flake tests in isolation.
- Run `cargo clippy --workspace --all-features --all-targets`.
- Run `git diff --check`.

## Docs To Update

- Lint/test gate decision note under `agents-only/`.
- `agents-only/active_context.md` on completion if gates change.
- This package file, under Completion Notes.

## Dependencies

- User policy approval is required before broad lint enforcement.

## Completion Notes

DONE (local-only). Full detail + test/gate table: `post_fable_package09_lint_test_gate_evidence.md`.

- **CAL-19** (selector test rot): rewrote `proxy_pool_select.rs` against the current
  `PoolSelector` API — 5 active tests (health filtering / lowest-RTT / no-healthy → `None` /
  bookkeeping); deleted the `selector_p2.rs` + `selector_smoke.rs` stubs. weighted/sticky
  de-scoped (not implemented by `select`). 5 other always-false-cfg sb-core tests logged as
  out-of-scope rot.
- **package08 follow-up #1** (trojan inbound feature gate — SUPERSEDED): the `trojan` feature
  now declares `shadowsocks` (the inbound's `parse_trojan_request` reuses `parse_ss_addr`);
  `cargo test -p sb-adapters --lib trojan --features adapter-trojan,trojan` → 23 passed.
- **package08 follow-up #2** (trojan dial DialOpts — SUPERSEDED): `dial` now uses
  `opts.connect_timeout.min(config)`; a deterministic lock test asserts the timeout error
  reflects the short DialOpts, not the config ceiling. `udp_relay_dial` (no opts param) left
  as a follow-up.
- **CAL-08** (lint policy): per-crate inventory recorded; only sb-tls inherits the workspace
  deny; sb-proto/sb-runtime are zero-cost enable candidates. **Decision: inventory closed,
  broad enforcement DEFERRED (needs user approval); zero `[lints]` changes.**
- **CAL-27** (warnings): RD-07's old pair is gone; `cargo clippy --workspace --all-features
  --all-targets` driven from 5 → **0** (1 self-introduced doc-markdown + 4 pre-existing
  low-risk, all mechanical, no behavior change).
- **CAL-29** (flakes): `test_fakeip_persistence_sled` hardened (explicit pre-reopen drop, 6
  consecutive runs green); the `dns_steady` pair documented (resolver-hijack + env-race, with
  isolation commands); a same-class `app outbound_builder::simple` resolver-hijack flake found
  and logged (environmental, not a regression).
