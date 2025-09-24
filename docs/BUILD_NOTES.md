# Build Notes (Stabilization)

## Why default to `scaffold`
The workspace now **defaults to `scaffold`** feature to ensure a green build even when the
`sb-adapter` crate is not present. This keeps Admin HTTP, selector, health, runtime and
minimal in/out bounds working for CI and GUI integration.

## Enable adapter-backed implementations
When `sb-adapter` is available in your workspace:
```bash
cargo build --features adapter
```
or set it in `app` crate dependency as:
```toml
sb-core = { path = "../crates/sb-core", features = ["adapter"] }
```

## DNS modules using `reqwest`
We declared an optional `dns_http` feature that brings `reqwest` (blocking, rustls). Only enable it
if you actually need HTTP-based DNS fetching:
```bash
cargo build --features "scaffold dns_http"
```
If your DNS code does not require `reqwest`, keep this feature **disabled**.

## Expected JSON contracts
No changes to `run --format json`, `version`, `check`, or `route --explain`. Admin HTTP provides
lightweight endpoints for CI only and is opt-in.