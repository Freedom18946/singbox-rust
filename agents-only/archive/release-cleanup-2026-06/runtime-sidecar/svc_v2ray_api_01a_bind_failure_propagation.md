<!-- tier: B -->
# SVC-V2RAY-API-01A — V2Ray gRPC sidecar bind/task-exit honesty (checkpoint)

Makes the V2Ray gRPC API sidecar return `Err` from `start()` (and keep `started=false`) when
its listener does not bind, and resets `started` when the tonic serve task exits, so the
supervisor never reports it "wired" for a dead port and the sidecar does not keep stale
started state after shutdown/serve failure/cancellation.
**Tracked change confined to one business-source file:
`crates/sb-core/src/services/v2ray_api.rs` (impl + in-file tests). No Cargo change, no
ServiceManager registration, no other listener, no supervisor change, no public network.**
`agents-only/a0_reality_spike/` untouched untracked.

## A. Root cause

`impl V2RayServer for V2RayApiServer::start()` (feature `service_v2ray_api`) only **parsed**
`listen_addr`, set `self.started.store(true)` **before** any bind, then `tokio::spawn`-ed a
tonic `Server::serve_with_shutdown(listen_addr, …)`. tonic binds the TCP listener **inside
that task**; a bind/serve failure (`AddrInUse`, EACCES) was only `tracing::error!`-ed
(`:430-435` pre-fix) while `start()` had already returned `Ok` and `started` read `true`.

## B. Sidecar vs ServiceManager lifecycle (why this is distinct from SVC-DNS-01)

`V2RayApiServer` implements the **`V2RayServer`** trait (`context.rs:760`,
`fn start(&self) -> anyhow::Result<()>`), **not** the sb-types `Service` trait. It is wired by
the supervisor's `wire_experimental_sidecars` (`supervisor.rs:1167-1177`), **not** registered
with `ServiceManager`. Therefore it has **no `/services/health` `ServiceStatus` projection** —
the misreport channel here is the supervisor's `else`-branch ("V2Ray API server wired" +
`with_v2ray_server`) and the `started` flag, not `ServiceStatus::Running`. This is why the
listener-audit classified it **E** (bug-shaped, off the health path), not the SVC-DNS-01 class-C.

## C. `started` state machine (pre vs post)

- **Pre:** `started.store(true)` set **before** the bind-bearing spawn; never rolled back on
  bind failure; only reset by `close()`. → sticky-true on failure; duplicate `start()` set it
  again + spawned a second (failing) server. After SVC-V2RAY-API-01A pre-bind, a second
  stale-started edge remained: if the tonic serve task returned `Err`, completed normally after
  a shutdown signal sent outside `close()`, or was cancelled/dropped during runtime teardown,
  `started` could stay true because cleanup lived only in `close()`.
- **Post:** `compare_exchange(false→true)` claims a single-start slot; on any `pre_bind`
  failure → `store(false)` rollback + return `Err`; `started` is `true` **only** after a
  successful bind+register; `close()` still resets to `false`. The flag is now an
  `Arc<AtomicBool>` so the spawned task can hold only the exact state bit it must clean up.
  Duplicate `start()` → `compare_exchange` fails → idempotent `Ok` no-op (no second listener).

## D. Pre-bind approach (Option A; no Cargo change)

`start()` now: parse `listen_addr` (unconfigured → `Ok` no-op as before) → `compare_exchange`
claim → **`pre_bind(addr)`**: `std::net::TcpListener::bind` → `set_nonblocking(true)` →
`tokio::net::TcpListener::from_std`, each `map_err(addr+reason)?` (rollback `started` + `Err` on
failure) → spawn tonic `serve_with_incoming_shutdown(incoming, shutdown)`. The incoming stream
is built **dependency-free** from the pre-bound listener via
`Box::pin(futures::stream::unfold(listener, |l| async move { Some((l.accept().await.map(|(s,_)|s), l)) }))`
— `futures` 0.3 is already a sb-core dep; `tokio::net::TcpStream: tonic::transport::server::Connected`
and `io::Error: Into<tonic::Error>`, so tonic 0.11 `serve_with_incoming_shutdown` accepts it.
Mirrors the dns_forwarder / DERP / SSM-API std-bind → `from_std` precedent.

## D.1 Task-exit cleanup (SVC-V2RAY-API-01A.1)

The spawned tonic serve task now owns a private file-local RAII guard:
`ResetStartedOnDrop { started: Arc<AtomicBool> }`. Its `Drop` stores `false` with
`Ordering::Release`. The guard is constructed after the synchronous bind succeeds and is moved
into the `tokio::spawn` future before `serve.await`; it therefore covers:

- normal graceful shutdown (`serve_with_incoming_shutdown` returns `Ok`);
- tonic serve errors after startup (`serve.await` returns `Err`);
- task cancellation / future drop, including runtime teardown before the task is polled.

`close()` keeps its explicit `store(false)` and sends the one-shot shutdown signal. Duplicate
`store(false)` is intentional and harmless. The guard does not widen the sidecar lifecycle into
ServiceManager, does not change the supervisor strategy, and does not introduce dependencies.

## E. supervisor change — NONE needed

`supervisor.rs:1171-1176` is already `if let Err(e) = v2ray_server.start() { warn "failed to
start V2Ray API server" } else { with_v2ray_server; info "V2Ray API server wired" }`. After
this fix, a bind failure makes `start()` return `Err` → the supervisor takes the **warn**
branch, does **not** print "wired", and does **not** store the server in `Context`. So the
honesty fix flows through the existing branch unchanged. **Sidecar failure remains visible
(warn) but non-fatal under current policy (log-and-continue)** — supervisor not modified.

## F. Cargo change — NONE

No new dependency/feature. `tonic = 0.11` (transport) provides `serve_with_incoming_shutdown`;
`futures = 0.3` (already a direct sb-core dep) provides `stream::unfold`; `tokio` (full)
provides `TcpListener`/`from_std`. `tokio-stream` (the usual `TcpListenerStream` source) is
**not** a sb-core dep and is **not** required — the `futures::stream::unfold` path avoids it.

## G. Tests (7 new, feature-gated; `cargo test -p sb-core --all-features --lib v2ray_api` = 10/10)

Driven directly on `V2RayApiServer` (not ServiceManager), ephemeral `:0` ports, no public network:
1. `bind_conflict_returns_error_and_keeps_not_started` — occupy port → `start()` `Err` w/
   bind/address-in-use semantics + `started==false`.
2. `successful_bind_marks_started` — free port → `Ok` + `started==true`.
3. `restart_after_failed_bind` — occupy → `Err` (started false) → release → `start()` `Ok`
   (failure not sticky).
4. `duplicate_start_does_not_create_second_listener` — after success, a 2nd `start()` is an
   idempotent `Ok` (a real 2nd bind on the held port would `Err`, so `Ok` proves no re-bind).
5. `shutdown_allows_restart` — `start` → `close` (started false) → bounded-retry `start` on the
   same port succeeds once the serve task drains.
6. `task_exit_resets_started` — starts a real server, sends the shutdown one-shot directly
   without calling `close()`, waits with a bounded retry until the task-owned guard resets
   `started=false`, then verifies restart succeeds.
7. `reset_started_guard_drop_resets_state` — structured unit coverage for the guard Drop path,
   including cancellation/future-drop semantics that are not reliably observable through the
   public `V2RayServer` API.

Dynamic coverage note: normal shutdown is covered by `shutdown_allows_restart` and
`task_exit_resets_started`; post-start serve `Err` and runtime cancellation/drop share the same
task-owned RAII `Drop` path, covered structurally by `reset_started_guard_drop_resets_state`.

## H. Verification

- `cargo fmt -p sb-core --check`: clean · `cargo test -p sb-core --all-features --lib v2ray_api`:
  **10 passed** (3 existing + 7 new) · `cargo clippy -p sb-core --all-features --all-targets --
  -D warnings`: **0** · `cargo check --workspace --all-features`: **PASS** ·
  `verify-consistency.sh`: exit 0 · `check-boundaries.sh`: exit 0 · `git diff --check`: clean.
- Working-tree diff: **only `v2ray_api.rs`**; no Cargo/trojan/other-listener; `a0_reality_spike/`
  untouched untracked.
- Independent adversarial code-review: **PASS, no blocker** (correctness / duplicate-block
  cleanliness / tonic typing / compare_exchange-close / tests / scope all verified).
- Pre-existing sb-core full-suite flakes (`test_fakeip_persistence_sled`, `dns_steady::*`) are
  unrelated to this file (fail on clean HEAD; documented under SVC-DNS-01); the targeted
  `--lib v2ray_api` run is deterministic.

## I. Unhandled product-semantics question (deferred → SVC-V2RAY-API-01B, NOT this card)

This card fixes **honesty** (no false "wired"); it does **not** change **policy**. Two open
product decisions, both requiring a Go-parity call, are deferred as
**SVC-V2RAY-API-01B = DEFER / POLICY REVIEW**:
1. Should an **explicitly-configured** sidecar bind failure be **fatal** to the process
   (hard-fail) instead of log-and-continue? Current policy is log-and-continue; no repo spec
   mandates hard-fail, so this card preserves it.
2. Should V2Ray API be **registered with `ServiceManager`** for a `/services/health` projection
   (Go-parity health reporting), instead of a supervisor sidecar? Out of scope here.
→ If desired, open **SVC-V2RAY-API-01B** (product semantics), do not auto-upgrade behavior.

## J. App-sidecar follow-up (separate, NOT this card)

`app/src/bootstrap_runtime/api_services.rs::{start_clash_api_server, start_v2ray_api_server}`
share the same spawn-then-log-return shape (bind inside the task at
`sb-api/src/clash/server.rs:237`; returns a live-looking `ServiceHandle` regardless). They
produce **no tracked `ServiceStatus`** (only a handle), so no health lie — but the same
pre-bind hardening (bind in the synchronous caller, move the bound listener into the task)
would let them return `None`/error on bind failure. Recommend a follow-up card.

## Disposition / commit proposal

Saved: this report + the v2ray_api.rs fix. Commit sequence: one code commit for
`crates/sb-core/src/services/v2ray_api.rs`, then one agents checkpoint commit for this report
and `active_context.md`. Next card after checkpoint: **APP-SIDECAR-AUDIT-01** read-only audit.
