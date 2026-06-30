<!-- tier: B -->
# APP-V2RAY-SIMPLE-01A - bootstrap V2Ray real-listener wiring

Status: DONE. Code commit: `a80a0916 fix(app): wire bootstrap v2ray api to real listener`.

## Summary

Bootstrap no longer starts `experimental.v2ray_api.listen` through
`sb_api::v2ray::SimpleV2RayApiServer`. The bootstrap helper now builds
`sb_core::services::v2ray_api::V2RayApiServer`, passes through the configured `stats`, and calls
`V2RayServer::start()` before returning a `ServiceHandle`. The app `v2ray_api` feature enables
`sb-core/service_v2ray_api`, so the reused sb-core implementation is the real pre-bound tonic
gRPC listener rather than the sb-core stub.

## Call Chain

Before:

```text
app/src/bootstrap.rs
  -> bootstrap_runtime::api_services::start_v2ray_api_server(listen)
  -> sb_api::v2ray::SimpleV2RayApiServer::new(ApiConfig)
  -> start_with_shutdown()
  -> synthetic in-memory stats loop only
```

After:

```text
app/src/bootstrap.rs
  -> bootstrap_runtime::api_services::start_v2ray_api_server(listen, stats)
  -> sb_core::services::v2ray_api::V2RayApiServer::new(V2RayApiIR)
  -> V2RayServer::start()
  -> synchronous TCP pre-bind + tonic StatsService serve task
```

## Behavioral Contract

- Non-empty valid listen addresses must bind before bootstrap returns a live-looking handle.
- Invalid listen strings and bind failures return `None`; bootstrap remains visible-but-nonfatal.
- Success logging occurs only after `start()` succeeds.
- Shutdown sends the bootstrap handle signal, calls `V2RayApiServer::close()`, and waits for the
  listen port to be reusable.
- `SimpleV2RayApiServer` is not deleted; it remains in `sb-api` for existing tests and future
  policy cleanup.
- Run-engine supervisor behavior is unchanged and still uses sb-core `V2RayApiServer`.
- `SVC-V2RAY-API-01B` remains DEFER / POLICY REVIEW.

## Tests

Added or updated in `app/src/bootstrap_runtime/api_services.rs`:

- `v2ray_api_starter_skips_invalid_listen_addresses`
- `v2ray_api_starter_skips_empty_listen_addresses`
- `v2ray_bind_conflict_returns_no_handle`
- `v2ray_successful_bind_accepts_tcp_and_shutdown_releases_port`

The tests cover invalid/empty listen skip, occupied address no-handle behavior, successful
loopback TCP connect to the real listener, and shutdown port release.

## Validation

Executed locally:

- `cargo fmt -p app --check` - PASS
- `cargo test -p app --all-features v2ray` - PASS, 7 matching tests
- `cargo clippy -p app --all-features --all-targets -- -D warnings` - PASS, 0 warnings
- `cargo check --workspace --all-features` - PASS
- `bash agents-only/06-scripts/verify-consistency.sh` - PASS
- `bash agents-only/06-scripts/check-boundaries.sh` - PASS
- `git diff --check` - PASS
- `rg "SimpleV2RayApiServer|start_v2ray_api_server|V2RayApiServer" app crates` - bootstrap now
  references sb-core `V2RayApiServer`; `SimpleV2RayApiServer` remains only under `sb-api` code/tests.

The requested `./scripts/verify-consistency.sh` and `./scripts/check-boundaries.sh` paths do not
exist in this checkout; the repository's existing script entrypoints are under
`agents-only/06-scripts/`.

## Boundary Notes

- No V2Ray proto, stats model, config schema, run-engine behavior, REALITY, fixture, Makefile,
  L18, CI, `.github`, or parity-number change.
- `agents-only/a0_reality_spike/` remains untouched untracked. It is unrelated REALITY spike
  material, not part of this checkpoint.
