<!-- tier: B -->
# APP-V2RAY-SURFACE-02B - sb-api V2Ray additive explicit naming bridge

Status: DONE implementation + checkpoint. Rust code commit: `d4191964`.

## Baseline

- Starting status: only `agents-only/a0_reality_spike/` was untracked.
- Starting branch: `main...origin/main`.
- Required baseline commit confirmed: `ecbe3ffd checkpoint: propose sb-api v2ray surface redesign`.
- `agents-only/a0_reality_spike/` remains untouched, untracked, and unstaged.

## Implementation

Feature-on tonic implementation path:

```text
crates/sb-api/src/v2ray/server.rs
  #[cfg(feature = "v2ray-api")]
  grpc_impl::V2RayApiServer
```

Added explicit stable gRPC names:

```text
sb_api::v2ray::GrpcV2RayApiServer
sb_api::GrpcV2RayApiServer
```

Implementation method:

```rust
#[cfg(feature = "v2ray-api")]
pub use grpc_impl::V2RayApiServer as GrpcV2RayApiServer;
```

and crate/module re-exports from that alias. No wrapper struct, listener, shutdown abstraction,
constructor change, feature change, proto change, stats change, or runtime behavior was added.

Rustdoc updates:

- `SimpleV2RayApiServer`: documented as legacy-compatible in-memory helper; no TCP bind; no tonic
  gRPC serve.
- `sb_api::v2ray::V2RayApiServer`: documented as compatibility surface whose implementation varies
  by `v2ray-api`; new network-server callers should prefer `GrpcV2RayApiServer`.
- `GrpcV2RayApiServer`: documented as real tonic gRPC V2Ray API server requiring `v2ray-api` and
  binding/serving a network listener.

Rustdoc note: the required `RUSTDOCFLAGS="-D warnings"` gate exposed a pre-existing invalid HTML
tag in `crates/sb-api/src/clash/auth.rs` (`<token>` in module docs). The fix stayed in the allowed
`crates/sb-api/src/lib.rs` file by applying a narrow `#[allow(rustdoc::invalid_html_tags)]` to the
`clash` module declaration. No Clash implementation code changed.

## Compile Coverage

Added `crates/sb-api/tests/v2ray_public_paths.rs`, gated by `#![cfg(feature = "v2ray-api")]`.
It verifies:

```rust
use sb_api::GrpcV2RayApiServer;
use sb_api::v2ray::GrpcV2RayApiServer;
```

and confirms both paths resolve to the same type. The test does not instantiate or start a server.

## Public Path Probe

Probe method: `/tmp` rustc compile-only probes. The probe first builds `sb-api` into a temporary
target dir (`/tmp/sb_api_02b_target`) for each feature mode, then invokes `rustc` against the
generated `sb-api` rlib. No scratch files were written to the repository.

New path matrix:

| Mode | `sb_api::v2ray::GrpcV2RayApiServer` | `sb_api::GrpcV2RayApiServer` | Result |
|---|---:|---:|---|
| `--no-default-features` | absent | absent | expected compile failure, `E0432`, gated by `v2ray-api` |
| default features | absent | absent | expected compile failure, `E0432`, gated by `v2ray-api` |
| `--features v2ray-api` | present | present | compile success |
| `--all-features` | present | present | compile success |

Old path regression matrix:

| Mode | `sb_api::v2ray::SimpleV2RayApiServer` | `sb_api::v2ray::V2RayApiServer` |
|---|---:|---|
| `--no-default-features` | present | still Simple wrapper; `inner()` compiles |
| default features | present | still Simple wrapper; `inner()` compiles |
| `--features v2ray-api` | present | still tonic gRPC server; same type as new alias; `inner()` fails with `E0599` |
| `--all-features` | present | still tonic gRPC server; same type as new alias; `inner()` fails with `E0599` |

## Validation

Executed:

- `cargo fmt -p sb-api --check` - PASS
- `cargo check -p sb-api --no-default-features` - PASS
- `cargo check -p sb-api` - PASS
- `cargo check -p sb-api --features v2ray-api` - PASS
- `cargo check -p sb-api --all-features` - PASS
- `cargo test -p sb-api --no-default-features --lib v2ray` - PASS, 5/5
- `cargo test -p sb-api --no-default-features --test v2ray_api_test` - PASS, 6/6
- `cargo test -p sb-api --no-default-features --test v2ray_api_bad_inputs` - PASS, 2/2
- `cargo test -p sb-api --features v2ray-api v2ray` - PASS, includes lib 5/5,
  `v2ray_api_test` 6/6, and `v2ray_public_paths` 1/1
- `cargo test -p sb-api --features v2ray-api --test v2ray_api_bad_inputs` - PASS, 2/2
- `cargo test -p sb-api --all-features v2ray` - PASS, includes lib 5/5,
  `v2ray_api_test` 6/6, and `v2ray_public_paths` 1/1
- `cargo test -p sb-api --all-features --test v2ray_api_bad_inputs` - PASS, 2/2
- `cargo clippy -p sb-api --all-features --all-targets -- -D warnings` - PASS
- `cargo check --workspace --all-features` - PASS
- `RUSTDOCFLAGS="-D warnings" cargo doc -p sb-api --all-features --no-deps` - PASS
- `/tmp` rustc public-path probes - PASS/expected failures as documented
- `git diff --check` - PASS
- `bash agents-only/06-scripts/verify-consistency.sh` - PASS
- `bash agents-only/06-scripts/check-boundaries.sh` - PASS

## Commits

- Code: `d4191964 feat(sb-api): add explicit grpc v2ray server alias`
- Checkpoint: this file and `active_context.md` are committed separately by the
  `checkpoint: record sb-api v2ray naming bridge` commit.

`SVC-V2RAY-API-01B` remains **DEFER / POLICY REVIEW**.
