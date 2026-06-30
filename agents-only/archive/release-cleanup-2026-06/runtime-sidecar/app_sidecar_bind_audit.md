<!-- tier: B -->
# APP-SIDECAR-AUDIT-01 - app sidecar bind/readiness audit

Read-only audit after SVC-V2RAY-API-01A. No app/crates source changes, no public network.

## Summary

Finding: app-layer Clash API helpers still contain the spawn-then-live-handle bug shape:
they spawn a task, the task binds inside `ClashApiServer::start_with_shutdown`, and the
caller receives a live-looking handle before the listener is known to exist.

The app-layer V2Ray helper is not the same bind-in-task bug: `SimpleV2RayApiServer` does not
open any listener at all. It accepts a listen address, starts a stats loop, and returns a handle.
That is a separate product/implementation policy gap.

Go reference strategy is synchronous listen before serving:

- Go Clash API: `experimental/clashapi/server.go:159-183` calls `net.Listen`, returns error
  on failure, then starts `httpServer.Serve(listener)` in a goroutine.
- Go V2Ray API: `experimental/v2rayapi/server.go:51-67` calls `net.Listen`, returns error on
  failure, then starts `grpcServer.Serve(listener)` in a goroutine.

## Classification Legend

- A. `PREBOUND_PROPAGATES` - bind happens before handle/success return; failure propagates.
- B. `READINESS_ACK_PROPAGATES` - async bind is allowed only if readiness ack/error propagates.
- C. `SPAWN_THEN_LIVE_HANDLE_BUG` - helper returns live-looking handle before bind result.
- D. `NOT_APPLICABLE` - no sidecar listener/startup handle surface.
- E. `NEEDS_POLICY_DECISION` - behavior cannot be fixed safely without product semantics.

## App Sidecar Inventory

| Sidecar | Entry | Listener Type | Bind Location | Helper Return | Bind Failure Visibility | Handle Looks Alive | False Success Log | Sync Pre-bind Possible | New Dep? | Class | Should Fix Separately? |
|---|---|---:|---|---|---|---|---|---|---|---|---|
| bootstrap Clash API | `app/src/bootstrap_runtime/api_services.rs:24-91` | TCP HTTP/axum | task calls `sb-api/src/clash/server.rs:234-243` (`TcpListener::bind`) | returns `Some(ServiceHandle)` at `:80-84` immediately after spawn | async `error!("Clash API server error")` at `:76-78`; caller cannot observe | yes (`oneshot` + `JoinHandle`) | no "started" log, but runtime stores handle as if service exists | yes: `serve_with_listener_and_shutdown(listener, shutdown)` already exists | no | C | yes |
| run_engine Clash API | `app/src/run_engine_runtime/admin_start.rs:107-177` | TCP HTTP/axum | task calls same `ClashApiServer::start_with_shutdown` bind path | returns `Some(ClashApiHandle)` at `:172-176` after spawn | async `error!("clash api server exited with error")` at `:165-168`; caller cannot observe | yes (`oneshot` + `JoinHandle`) | yes: `info!("started clash api server from run_engine")` at `:171` before bind | yes: same pre-bound listener API | no | C | yes |
| bootstrap V2Ray API | `app/src/bootstrap_runtime/api_services.rs:94-136` | none in current simple impl | no bind: `sb-api/src/v2ray/simple.rs:154-194` loops on interval/shutdown only | returns `Some(ServiceHandle)` at `:125-129` after spawn | no bind attempted; no bind failure possible | yes (`oneshot` + `JoinHandle`) | "Starting V2Ray API server" only; but configured listen is not actually served | not until a real listener implementation is chosen | no, if routed to existing core gRPC; otherwise depends on design | E | yes, but not as a pre-bind-only patch |

## Non-Bug Controls Checked

| Service | Evidence | Class |
|---|---|---|
| admin debug HTTP | `AdminDebugState::spawn_http_server` awaits `http_server::spawn`; `http_server::spawn` binds before returning a handle (`app/src/admin_debug/mod.rs:143-151`, `app/src/admin_debug/http_server.rs:855-896`). | A |
| core admin HTTP | `app/src/util.rs:49-76` calls `sb_core::admin::http::spawn_admin`, which `TcpListener::bind`s before thread spawn (`crates/sb-core/src/admin/http.rs:876-895`). | A |
| sb-core V2Ray gRPC sidecar | Fixed by SVC-V2RAY-API-01A (`4141724b`): pre-bind before `Ok`, rollback on failure, task guard resets `started`. | A |

## Existing Tests

- `app/src/bootstrap_runtime/api_services.rs:174-195` only checks invalid listen parsing for
  bootstrap Clash/V2Ray; it does not test bind conflict or readiness.
- `app/src/run_engine_runtime/admin_start.rs:282-299` only checks Clash listen parsing.
- `crates/sb-api/tests/clash_websocket_e2e.rs:110-126` already demonstrates the safe pattern:
  test code pre-binds a `TcpListener` and calls `serve_with_listener_and_shutdown`.
- `crates/sb-api/tests/v2ray_api_test.rs:215-245` asserts `SimpleV2RayApiServer::start()`
  returns quickly and updates stats; it does not assert a socket is listening, consistent with
  the simple implementation having no listener.

## Proposed Follow-Up

Unique recommended next card:

**APP-SIDECAR-BIND-01 - pre-bind app Clash API sidecars before returning handles**

Scope:

- Fix `app/src/bootstrap_runtime/api_services.rs::start_clash_api_server`.
- Fix `app/src/run_engine_runtime/admin_start.rs::start_clash_api_from_supervisor`.
- Use `tokio::net::TcpListener::bind(listen_addr).await` before `tokio::spawn`, then move the
  listener into `ClashApiServer::serve_with_listener_and_shutdown(listener, shutdown_rx)`.
- Add bounded bind-conflict tests for both app entry points or a shared test-only seam.
- Do not change app V2Ray behavior in this card.

Policy note:

- Minimum required behavior: no live-looking handle and no "started" log before the Clash
  listener exists.
- Go reference hard-fails through `Start(stage) error`. Rust product policy still needs an
  explicit call for whether app Clash bind failure should hard-fail `start_from_config` /
  `start_admin_services` or remain visible-but-nonfatal. The current default posture remains
  visible but non-fatal log-and-continue unless a product card says otherwise.

## Deferred Policy Items

- **SVC-V2RAY-API-01B = DEFER / POLICY REVIEW**:
  1. explicit V2Ray sidecar bind failure hard-fail vs visible non-fatal;
  2. whether V2Ray sidecar migrates into `ServiceManager` for `/services/health`.
- **APP-V2RAY-API-POLICY-01 = DEFER / POLICY REVIEW**:
  the app bootstrap V2Ray helper uses `SimpleV2RayApiServer`, which has no actual listener.
  Decide whether to remove it, route it to the sb-core gRPC V2Ray sidecar, or implement a real
  sb-api V2Ray listener before adding bind/readiness tests.

## Audit Disposition

- C-class bug exists: yes, two Clash app sidecar entries.
- E-class policy item exists: yes, app bootstrap V2Ray simple helper; SVC-V2RAY-API-01B also
  remains deferred.
- No source changes made under `app/` or `crates/`.
- Stop here; do not enter APP-SIDECAR-BIND-01 in this card.
