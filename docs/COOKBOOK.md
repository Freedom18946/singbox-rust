# singbox-rust Cookbook

This cookbook collects small, runnable snippets and deployment recipes.

## Minimal Configs

- Router (explain only):
  ```bash
  cargo run -q --bin singbox-rust --features router -- route \
    --config minimal.yaml --dest example.com:443 --explain --format json
  ```

- Metrics (Prometheus exposition at /metrics):
  ```bash
  cargo run -q --bin singbox-rust --features "router observe" -- prom scrape --addr 127.0.0.1:9100
  ```

- Bench (HTTP I/O, dev-only):
  ```bash
  cargo run -q --bin singbox-rust -- bench io --url http://example.com --requests 0 --json
  ```

- Admin hot-reload (subset):
  ```bash
  curl -sS http://127.0.0.1:18088/admin/ping
  ```

## Migration (v1 → v2)

- Convert legacy config to v2 and write canonical JSON (atomic):
  ```bash
  cargo run -q -p app -- check --migrate --write-normalized --config examples/v1.yaml --out target/out.v2.json
  ```
  Notes: schema_version=2 is injected; rules/default moved under route.*; socks5 is normalized to socks.

## Common Errors & Fixes

- Invalid route rule match: ensure at least one of domain/ip/port/protocol is present.
- TLS handshake issues: verify system roots and set `--insecure` only for testing.
- Bind/permission denied: pick an unprivileged port or add capabilities on Linux.

## Troubleshooting

- Increase verbosity: `RUST_LOG=debug`.
- Dump route decision: `route --explain --trace --format json`.
- Observe metrics: visit `/metrics` and check `proxy_select_score`.

## E2E & QA

- One-shot E2E (non-blocking; optional Go compat via GO_SINGBOX_BIN):
  ```bash
  scripts/e2e-run.sh
  cat .e2e/summary.json
  ```
- Preflight RC gate (artifact summary in dist/):
  ```bash
  scripts/preflight.sh
  ```

## One-shot QA Commands

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo doc --no-deps -D warnings
cargo test --doc -q
scripts/cov.sh # -> target/coverage/index.html
```
