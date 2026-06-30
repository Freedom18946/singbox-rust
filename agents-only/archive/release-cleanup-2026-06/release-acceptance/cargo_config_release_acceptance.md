<!-- tier: B -->
# .cargo Release Acceptance

Date: 2026-06-30
Scope: `.cargo/config.toml`

## Result

`.cargo` is release-accepted after one configuration fix.

## File Review

### `.cargo/config.toml`

- `cargo xtask` alias is valid and points at the tracked `xtask` package.
- Global `--cfg reqwest_unstable` remains intentional: it is required when compiling
  `reqwest` itself with its `http3` feature, and it does not enable a project Cargo feature.
- `rustdocflags = ["-D", "warnings"]` was moved from the ignored `[doc]` table into `[build]`,
  where Cargo applies it to rustdoc invocations.
- The Apple Silicon `rust-lld` linker setting is release-usable in this workspace; a real
  `app` binary link passed on the host target.

## Follow-up Fixes

The corrected rustdoc warning policy exposed two existing rustdoc HTML-tag warnings. Both were
fixed by marking placeholder CLI text as code:

- `app/src/cli/check/args.rs`
- `app/src/cli/prom.rs`

## Verification

Commands run:

```bash
cargo check -p app --features tools_http3 --message-format short
CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER=cc cargo check -p app --features tools_http3 --message-format short
cargo build -p app --bin app
cargo xtask help
cargo doc -p app --no-deps --message-format short
cargo check --workspace --all-features --message-format short
make boundaries
./agents-only/06-scripts/verify-consistency.sh
git diff --check
```

All commands passed. The first `cargo doc` before the fix emitted rustdoc warnings while still
exiting successfully, confirming the old `[doc] rustdocflags` placement was ineffective.

## Non-claims

This is a local Cargo-configuration acceptance only. It does not claim dual-kernel BHV/parity
movement, REALITY closure movement, workflow automation, or release packaging completion.
