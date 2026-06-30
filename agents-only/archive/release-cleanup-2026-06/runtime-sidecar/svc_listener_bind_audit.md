<!-- tier: B -->
# SVC-LISTENER-AUDIT-01 — listener-service bind-failure propagation audit (read-only)

Read-only audit of every listener-type service for the **spawn-then-log-return bind
antipattern** (the bug just fixed in `dns_forwarder` under SVC-DNS-01): `start()` →
`tokio::spawn(task)` → task binds inside itself → bind failure only `tracing::error!` +
`return` → `start()` returned `Ok` early → lifecycle reports **Running** with no listener.
**No business-source change; no public network; no commit.** Method: read
`crate::service::{Service, StartStage, ServiceManager.start_stage}` (the honesty contract,
`service.rs:292-304`: `Err→Failed`, `Ok@Started→Running`), then every `services/` file +
`v2ray_api` (`V2RayServer` trait) + DERP + ssmapi + sb-adapters resolved + a whole-repo
sweep, cross-referenced against `impl Service for` / `impl Endpoint for` / `impl V2RayServer`.

## Headline

- **The ServiceManager lifecycle family is consistently class A.** dns_forwarder was the
  lone outlier; after SVC-DNS-01 there is **no remaining `C_SPAWN_THEN_LOG_RETURN_BUG` on
  the ServiceManager `/services/health` path**.
- **One genuine bug-shaped instance: `v2ray_api`** — structurally identical to the old
  dns_forwarder bug, but on the **separate `V2RayServer` trait / supervisor sidecar wiring**
  (not ServiceManager), so it does **not** misreport via `/services/health`. Dispositioned
  **E_NEEDS_MANUAL_REVIEW** → recommend a scoped fix card (**SVC-V2RAY-API-01**).
- Two **out-of-scope app sidecars** (`api_services.rs` clash/v2ray) share the shape but
  produce no tracked `ServiceStatus` (only a `ServiceHandle`) — noted for completeness.

## Classification table

| Service | File | Proto | Bind location | start() Ok? | Failure propagation | Misreport Running? | Class | Action |
|---------|------|-------|---------------|-------------|---------------------|--------------------|-------|--------|
| **DnsForwarderService** (resolved) | `sb-core/services/dns_forwarder.rs` | UDP | **in start()** `:212` std-bind+`from_std` `:224` | after bind | `map_err?` → `Err` pre-Ok → `Failed` | **No** | **A** | none (fixed reference, SVC-DNS-01) |
| **DerpService** | `sb-core/services/derp/server.rs` | mixed (TCP+UDP STUN) | **in start()** `:3083`/`:3132` socket2 bind→`from_std` | after binds | `?` → `Err` pre-spawn(`:3097`/`:3137`) → `Failed` | **No** | **A** | none (in-repo precedent; opt. add bind-conflict test) |
| **SsmapiService** | `sb-core/services/ssmapi/server.rs` | TCP | **in start()** `:908` `create_listener()` socket2 bind→`from_std` | after bind | `return Err` `:916` pre-spawn(`:920`) → `Failed` | **No** | **A** | none (opt: move TLS-config load pre-spawn too) |
| **ResolvedService** (systemd-resolved) | `sb-adapters/service/resolved_impl.rs` | mixed (UDP+TCP) | `spawn_udp/tcp` `.bind().await.map_err?` `:90`/`:201` **before** spawn; `block_on(..)?` in start() `:374-382` | after binds | `?` → `Err` pre-Ok → `Failed` | **No** | **A** | none |
| **StubService** (feature/platform fallback) | `sb-adapters/service_stubs.rs` | none | none | always `Err` | start() returns `Err` → `Failed` (honest) | **No** | **D** | none (negative control) |
| **v2ray_api / V2RayApiServer** | `sb-core/services/v2ray_api.rs` | TCP (gRPC) | **in spawned task** `:422` tonic `serve_with_shutdown(listen_addr)` | **Ok `:441` before bind**; `started=true` `:399` | serve err only `tracing::error!` `:430-435`; **not** propagated | not via /services/health (different trait) | **E** | **fix card SVC-V2RAY-API-01** |
| tailscale Coordinator | `sb-core/services/tailscale/coordinator.rs` | none (outbound) | none (login/poll_map HTTP outbound) | `:172` | outbound `?` to caller | No | **D** | none |
| tailscale Endpoint | `sb-core/endpoint/tailscale.rs` | UDP (data-plane on-demand) | `:502` per-conn helper (returns `Err` via `?`); lifecycle start() spawns outbound control-plane only | `:783` | self-reported `TailscaleState`, not ServiceManager | No | **D** | none |
| ntp | `sb-core/services/ntp.rs` | UDP (client) | `:122` ephemeral `0.0.0.0:0` client probe (not a Service) | n/a | client probe; loop warns+continues | No | **D** | none |
| time | `sb-core/services/time.rs` | none | none (clock wrapper) | n/a | n/a | No | **D** | none |
| cache_file | `sb-core/services/cache_file.rs` | none | none (sled on-disk + std-thread) | n/a | n/a | No | **D** | none |
| urltest_history | `sb-core/services/urltest_history.rs` | none | none (in-memory DashMap) | n/a | n/a | No | **D** | none |

**Counts:** A = 4 (DnsForwarder, Derp, Ssmapi, Resolved) · B = 0 · **C = 0** (on the
ServiceManager lifecycle) · D = 7 · **E = 1** (v2ray_api).

## v2ray_api control-flow conclusion (deep-dive, 8 answers)

`crates/sb-core/src/services/v2ray_api.rs`, `impl V2RayServer for V2RayApiServer::start()`
(`fn start(&self) -> anyhow::Result<()>`, **not** the sb-types `Service` trait):

1. **Bind after spawn?** **Yes.** `listen_addr` is only *parsed* (`:388`) before the spawn;
   the actual TCP bind happens inside `tokio::spawn` (`:422`) via tonic
   `Server::builder()…serve_with_shutdown(listen_addr, …)`.
2. **Bind failure only logged?** **Yes.** `if let Err(e) = serve.await { tracing::error!(…) }`
   (`:430-435`) inside the task; nothing propagates out.
3. **start() returns Ok early?** **Yes** — `Ok(())` at `:441`, synchronously after the spawn,
   before any bind is attempted. Worse: `self.started.store(true)` at `:399` *before* the spawn.
4. **Misreport Running/healthy?** **Not via `/services/health`** (it has no `ServiceStatus`
   projection — different trait). But `started` reads `true` regardless of bind outcome, and
   `supervisor.rs:1171-1175` takes the `Ok` branch → logs "V2Ray API server wired" + stores
   the server in `Context` even when the gRPC port never bound (e.g. `AddrInUse`).
5. **Reuse SVC-DNS-01 sync pre-bind?** **Yes, with a tonic adapter.** Pre-bind a
   `std::net::TcpListener::bind(addr)` (sync) → `set_nonblocking(true)` →
   `tokio::net::TcpListener::from_std` in `start()`, propagate `Err`; then in the spawn use
   `serve_with_incoming_shutdown(TcpListenerStream::new(listener), …)` instead of
   `serve_with_shutdown(addr, …)`.
6. **Minimal propagation path (tonic/hyper takes the socket):** bind the `TcpListener`
   synchronously in `start()` (returning `Err` on failure), move the *already-bound* listener
   into the task, and serve over it via `serve_with_incoming[_shutdown]`. Have `supervisor.rs`
   propagate the `start()` `Err` (the `if let Err(e)` branch at `:1171` already exists — it
   just needs to escalate rather than only warn, per the desired Go-parity posture).
7. **Readiness channel needed?** **No** — `from_std` registration is synchronous in `start()`
   (same as dns_forwarder). A channel is only needed if pre-bind is infeasible; it is feasible
   here.
8. **bind-conflict test today?** **None.** `v2ray_api` tests (`:557-650`) cover
   `StatsManager` + server creation + `listen_addr` parsing only; no test asserts a gRPC bind
   failure surfaces anywhere (the failure is currently unobservable by design).

Also fix: do **not** set `started=true` (`:399`) until the listener is bound.

## G. Other C-class instances?

**None on the ServiceManager lifecycle.** All four lifecycle listeners (DnsForwarder/Derp/
Ssmapi/Resolved) are class A. The only bug-shaped listener is **v2ray_api** (class E, off the
health path). Two **out-of-scope app sidecars** share the structural shape but are **not**
ServiceManager-tracked and produce **no `ServiceStatus`** (only a `ServiceHandle` = name +
shutdown + JoinHandle):
- `app/src/bootstrap_runtime/api_services.rs::start_clash_api_server` (`:75`) and
  `start_v2ray_api_server` (`:120`) — `tokio::spawn` → `ClashApiServer::start_with_shutdown`
  binds `TcpListener` inside the task (`sb-api/src/clash/server.rs:237`); bind `Err` only
  `error!`s; `Some(ServiceHandle)` returned regardless. (`admin_start.rs:166` awaits directly
  → propagates, OK.) No tracked-status lie, but the same pre-bind hardening would let them
  return `None`/error on bind failure.

## H. E-class (NEEDS_MANUAL_REVIEW)

**v2ray_api** — structurally the antipattern, but the "manual review" is the **disposition
decision**: (a) apply the pre-bind fix so `start()` returns `Err` on bind failure (clear win);
and (b) decide whether to **also register v2ray_api with ServiceManager** for Go-parity health
reporting, or keep it as a supervisor sidecar with escalated `Err` handling. (b) needs a Go-
parity call; (a) is unambiguous.

## I. Single recommended next card — **SVC-V2RAY-API-01**

- **Goal:** make the V2Ray gRPC API listener bind-failure honest — `start()` returns `Err`
  (and `started` stays false) when the listener does not bind, so the supervisor stops
  reporting "wired" for a dead port.
- **Scope (in):** `crates/sb-core/src/services/v2ray_api.rs` (pre-bind `TcpListener` via
  std-bind→`from_std` in `start()`, serve via `serve_with_incoming_shutdown`, move
  `started=true` to after a successful bind) + minimal `supervisor.rs:1171` escalation
  decision + a `bind_conflict` regression test. Mirrors SVC-DNS-01 / the DERP+Ssmapi precedent.
- **Explicitly NOT:** no ServiceManager re-registration unless the Go-parity review (H-b)
  approves it (separate decision); no other service; no parity-number change; no REALITY /
  fixture / harness / Makefile / L18 / CI / `.github` / `a0_reality_spike/` change; no public
  network.
- **Why:** the single genuine actionable bug-shaped listener left after SVC-DNS-01; same
  class as the just-fixed dns_forwarder, low-risk, well-precedented.
- **Follow-up (separate, optional):** apply the same pre-bind hardening to the two app
  sidecars (`api_services.rs` clash/v2ray) so they return no live-looking handle on bind
  failure.

## J. Deferrable hygiene (unchanged; not this card)

- **trojan fmt drift** — `crates/sb-adapters/src/outbound/trojan.rs` +
  `tests/trojan_integration.rs` carry a pre-existing rustfmt drift (surfaced when SVC-DNS-01's
  `cargo fmt` touched them as collateral; reverted to keep scope minimal). A standalone
  `cargo fmt` hygiene commit would clear it.
- **`agents-only/a0_reality_spike/` DROP** — superseded scratch spike (per roadmap report §F);
  recommend delete, still untracked/untouched.

## K. Verification (read-only card)

- `git diff --check`: clean · `cargo check --workspace --all-features`: PASS ·
  `verify-consistency.sh`: exit 0 · `check-boundaries.sh`: exit 0.
- No business source changed (audit is read-only). Only new file: this report (+ optional
  active_context pointer). `a0_reality_spike/` untouched untracked.

## Disposition

Saved: this audit report. **No commit; stop at the report proposal.** Recommended next card =
**SVC-V2RAY-API-01** (do not auto-enter).
