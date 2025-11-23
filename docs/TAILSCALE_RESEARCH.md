# Tailscale Implementation Research

## Status
**Blocked**. The primary candidate library `tsnet` (v0.1.0) fails to build on macOS ARM64 due to Go build constraints in its dependencies (`gvisor`).

## Attempts

### 1. `tsnet` Crate
- **Source**: [crates.io/crates/tsnet](https://crates.io/crates/tsnet)
- **Version**: 0.1.0
- **Method**: Added as optional dependency to `sb-adapters`.
- **Result**: Build failed during `cargo check`.
- **Error**:
  ```text
  package github.com/tailscale/libtailscale
        imports tailscale.com/tsnet
        ...
        imports gvisor.dev/gvisor/pkg/gohacks: build constraints exclude all Go files in ...
  ```
- **Analysis**: The `tsnet` crate seems to bundle an older version of `libtailscale` or its Go dependencies (`gvisor`) are not compatible with the current Go version (1.25.4) or the platform (darwin/arm64) in the way they are being built by the crate's `build.rs`.

## Alternatives to Explore

### 1. `libtailscale` (Official C Library)
- **Repo**: [github.com/tailscale/libtailscale](https://github.com/tailscale/libtailscale)
- **Approach**: Build `libtailscale` manually (using Go) to generate a `.a` / `.dylib` and `tailscale.h`, then generate Rust bindings using `bindgen`.
- **Pros**: Official, likely more up-to-date than the `tsnet` crate.
- **Cons**: Requires complex build setup (Go + C + Rust), manual FFI maintenance.

### 2. `libtailscale` Crate
- **Source**: [crates.io/crates/libtailscale](https://crates.io/crates/libtailscale)
- **Version**: 0.2.0
- **Method**: Added as optional dependency to `sb-adapters`.
- **Result**: Build failed during `cargo check`.
- **Error**: `assertion failed: status.success()` in `build.rs` (likely similar Go build constraint issue).
- **Analysis**: This crate also wraps the Go library and suffers from the same build environment incompatibilities on macOS ARM64.

### 3. `tailscale-rs` (Unofficial)
- **Repo**: [github.com/morgangallant/tailscale-rs](https://github.com/morgangallant/tailscale-rs)
- **Status**: Need to evaluate if it provides "endpoint" capabilities (userspace networking) or just API control.

### 4. Stub Implementation (Current)
- **Status**: Already implemented.
- **Pros**: Zero dependencies, safe.
- **Cons**: No functionality.

## Recommendation
Given that both `tsnet` and `libtailscale` fail to build on this environment due to Go/platform constraints, we should:
1.  **Keep the Stub implementation** for now.
2.  Mark the Tailscale Endpoint task as "Blocked/Research Completed".
3.  Focus on other tasks (e.g., documentation or other missing features).

