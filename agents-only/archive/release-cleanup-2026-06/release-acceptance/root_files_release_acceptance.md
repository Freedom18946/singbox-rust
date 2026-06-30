<!-- tier: B -->
# Root Files Release Acceptance

Date: 2026-06-30
Scope: root release/navigation/config files plus dependency lock hygiene touched by
root-level acceptance:

- `.gitignore`
- `AGENTS.md`
- `Cargo.toml`
- `CLAUDE.md`
- `clippy.toml`
- `deny.toml`
- `LICENSE`
- `Makefile`
- `Makefile.fuzz`
- `PROJECT_STRUCTURE_NAVIGATION.md`
- `README.md`
- `rust-toolchain.toml`
- `SECURITY.md`
- `GO_PARITY_MATRIX.md`

## Verdict

PASS-LOCAL for the reviewed root file set.

This is root/config/dependency hygiene only. It does not claim REALITY movement,
dual-kernel BHV/parity movement, workflow automation, release packaging completion,
or product behavior change beyond the dependency/API compatibility fixes listed
below.

## Findings Fixed

- `Cargo.toml` excluded stale `crates/sb-adapters/fuzz`; the real independent
  cargo-fuzz workspace is root `fuzz/`.
- `README.md` still described `agents-only/log.md` as mandatory task-end output;
  current single-source volatile state remains `agents-only/active_context.md`.
- `cargo deny check advisories` exposed direct/upgradeable security debt:
  hickory 0.24, russh 0.49, and the app JWT feature's direct `rsa`/`pkcs1`
  dependency.
- `deny.toml` lacked a documented local exception for `RUSTSEC-2023-0071`, which
  currently has no fixed `rsa` release and remains reachable only through the
  optional Arti/Tor adapter graph.
- The repository docs-link gate still saw four stale links in the archived root
  deployment page; those historical paths were pointed at current docs or changed
  to non-link historical path text.

## Dependency And API Result

- Root workspace now excludes `fuzz/` from normal workspace membership; the fuzz
  crate is validated through `Makefile.fuzz`.
- hickory is upgraded to the 0.26 line across `app`, `sb-core`, and
  `interop-lab`, with DNS message construction updated to the 0.26 API.
- russh is upgraded to 0.60.3 for the SSH adapter feature, with host-key,
  public-key, auth-result, and channel-data API updates applied.
- The JWT feature no longer depends directly on `rsa` or `pkcs1`; RS256 JWK
  conversion now uses `jsonwebtoken::DecodingKey::from_rsa_components`.
- `fuzz/Cargo.lock` and the root `Cargo.lock` were refreshed by the local gates.

## Tests Added

- `app/src/admin_debug/auth/jwt.rs` now has
  `test_rs256_jwk_uses_rsa_components`, pinning RS256 JWK conversion to the
  component-based jsonwebtoken path.

## Spike Retention Note

No spike artifact was deleted in this acceptance round. The tracked A41/A42 spike
materials under `agents-only/` remain historical projection/mapping evidence, not
an expiry-cleanup target.

## Verification

Commands run:

```bash
cargo fmt --check
cargo metadata --no-deps --format-version 1
cargo deny check advisories
cargo deny check licenses bans sources
make -f Makefile.fuzz fuzz-check
cargo test -p app test_rs256_jwk_uses_rsa_components --features jwt,admin_debug,auth,rate_limit,admin_tests
cargo check -p sb-adapters --all-features
cargo check -p app --all-features
cargo check --workspace
cargo check --workspace --all-features
cargo clippy --workspace --all-features --all-targets
make boundaries
make -n check test clippy boundaries boundaries-report verify-reality-local clean
scripts/tools/check-doc-links.sh docs
```

All commands passed. `cargo deny check licenses bans sources` still reports the
existing warning-only duplicate/source/license diagnostics and exits successfully.
`cargo clippy --workspace --all-features --all-targets` exits successfully with
the repository's existing warning-level lint reports.

## Non-claims

No `.github/workflows/*` automation was added or restored. No REALITY closure,
public fresh-cohort movement, official JA4 work, dual-kernel parity movement, or
release packaging completion is claimed.
