<!-- tier: B -->
# SVC-DNS-01 — resolved / DNS-forwarder bind-failure propagation (checkpoint)

Fixes the `resolved` (DNS forwarder) service so a listener **bind failure propagates** to
the control plane (`ServiceStatus::Failed`) instead of being logged from a detached task
while the service is reported healthy. **Tracked change confined to a single business-source
file: `crates/sb-core/src/services/dns_forwarder.rs` (impl + in-file tests).** No public
network; no parity-number change; no REALITY / fixture / harness / Makefile / L18 / CI /
`.github` change; `agents-only/a0_reality_spike/` untouched untracked.

## A. Root cause

`DnsForwarderService::start(StartStage::Start)` did `tokio::spawn(run_server)` and then
unconditionally returned `Ok(())`. The UDP `bind` happened **inside** the spawned task
(`run_server`): on failure it only `tracing::error!`-ed and `return`-ed. The error never
reached `start()`'s return value, so `ServiceManager.start_stage` saw `Ok` and (at the
`Started` stage) recorded `ServiceStatus::Running` — a bind-failed `resolved` service read
as healthy via `/services/health`. This directly weakened the fault-isolation honesty that
`p1_service_failure_isolation` / DIV-H-006 (the one axis where the Rust kernel leads the Go
reference) rely on.

`resolved` **is** `DnsForwarderService` (same file; the file header notes it "corresponds to
`resolved` config type"). There is no separate `resolved.rs`, so this single fix covers both
names.

## B. Lifecycle (post-fix)

```
ServiceManager.start_all()                       [async, on the Tokio runtime]
 ├─ start_stage(Initialize) → statuses.clear()
 ├─ start_stage(Start): status=Starting; r = svc.start(Start)
 │     DnsForwarderService::start(Start):
 │       std::net::UdpSocket::bind(addr)   ─fail→ Err ┐
 │       set_nonblocking(true)             ─fail→ Err ┤  (map_err(..)? — all synchronous,
 │       UdpSocket::from_std(std_socket)   ─fail→ Err ┤   before any spawn)
 │       tokio::spawn(run_loop(socket,…))               │
 │       Ok(())                                          │
 │     r=Ok → status=Starting           r=Err ──────────┴→ status=Failed(msg)  [skipped later]
 ├─ start_stage(PostStart) / start_stage(Started): Ok@Started → status=Running
 └─ health_status() → /services/health  (DIV-H-006 / LC-003 Rust-side projection)
```

`start_stage` (service.rs:292-304) maps `Err → ServiceStatus::Failed(e.to_string())` and a
`Failed` service is skipped in later stages (service.rs:279-286), so a failed bind can never
be flipped to `Running`.

## C. Chosen fix (Option A — synchronous bind+register before spawn)

In `start(StartStage::Start)`: bind a **`std::net::UdpSocket`** synchronously, `set_nonblocking(true)`,
then `tokio::net::UdpSocket::from_std(..)` — each via `map_err(format!(addr+reason))?` — and
only then `tokio::spawn` the receive loop (`run_loop`) with the ready socket. `start()` now
returns `Ok` **iff** the socket is bound **and** reactor-registered; any failure returns a
structured `Err` carrying the address + underlying reason.

- The bind moved out of the (renamed) loop fn `run_server → run_loop`, which now takes an
  already-bound `Arc<UdpSocket>`.
- `from_std` is done in `start()` too (not only the spawn) so a reactor-registration failure
  also propagates — closing the residual "registered-in-task → Running-but-no-listener" gap.

**Why not the alternatives:**
- *Readiness channel (Option B)* — unnecessary: `std::net::UdpSocket::bind` is synchronous, so
  the error is available in `start()` directly without a channel + timeout + await machinery.
  The task's guidance ("若 bind 可安全移到 spawn 前完成，优先采用更简单的同步传播") favors A.
- *Status-poke after spawn (Option C)* — race-prone and against the `Service` contract
  (`start()`'s `Result` is the single source of the start outcome).

This mirrors the **DERP server's established in-repo precedent** (`derp/server.rs:1239-1244`,
`:1290-1293`: socket2 `bind`/`set_nonblocking` → `from_std` with `?` propagation). `start()`
already required a Tokio runtime (it `tokio::spawn`s), so `from_std` adds **no** new
requirement; production path `Supervisor::start (async) → run_context_stage → start_stage →
start()` runs on the runtime (no `spawn_blocking` wrap), and all tests run under `#[tokio::test]`.

## D. Modified files

- `crates/sb-core/src/services/dns_forwarder.rs` — `start()` rewrite (sync bind+register
  propagation), `run_server → run_loop` (takes bound socket), + 3 regression tests. (Only file.)

## E. Tests (all pass; `cargo test -p sb-core --all-features --lib`, 3/3, repeated green)

Driven through the **real `ServiceManager`** (the `/services/health` projection path), using
the **real `DnsForwarderService`** with real ephemeral-port (`bind 127.0.0.1:0`) conflicts —
no public network, no fixed-port contention:

1. `bind_conflict_marks_dns_forwarder_failed` — occupy a UDP port, start the service on it →
   asserts `ServiceStatus::Failed` whose message carries bind/address-in-use semantics, and
   **not** `Running`/`Starting`.
2. `successful_bind_reaches_running` — reserve+release an ephemeral port, `start_all` →
   asserts `Running`.
3. `restart_after_failed_bind` — occupy → `Start` → `Failed`; release the port → fresh
   `start_all` → asserts `Running` (the failure must not stick; no double-bind/leak because
   the failed attempt errors at `bind` before any socket/spawn).

Existing `test_dns_forwarder_service` still passes under the new synchronous bind.

## F. `resolved` impact

`resolved` and `DnsForwarderService` are the **same** service (one file, no separate
`resolved.rs`); the fix covers both. No parameterized variant needed.

## G. Compatibility boundaries / non-goals

- Confined to dns_forwarder.rs; non-`Start` stages untouched; DNS query/response logic
  (`handle_query`/`build_response`) byte-for-byte identical; no parity-number change.
- `close()` (notify_waiters) shutdown semantics unchanged; `run_loop` still breaks on notify.
- **Not extended** to other services (out of scope): DERP already binds synchronously
  (the precedent); ssmapi is a separate HTTP-API server; `ntp`/`time` bind ephemeral client
  sockets (not listeners); `v2ray_api` uses a different `start()` signature/trait and may
  share a similar spawn-then-Ok pattern — **flagged as a follow-up, not fixed here**.
- Known non-issue (pre-existing, unchanged by this fix): `start(Start)` is not idempotent —
  no production path calls `Start` twice on a live instance (Supervisor drives the 4 stages
  once; reload builds a fresh instance).

## H. Verification

- `cargo fmt -p sb-core --check`: **clean** (dns_forwarder.rs).
- 3 new tests + existing `test_dns_forwarder_service`: **pass**.
- `cargo clippy -p sb-core --all-features --all-targets -- -D warnings`: **0 warnings**.
- `cargo check --workspace --all-features`: **PASS**.
- `bash agents-only/06-scripts/verify-consistency.sh`: **exit 0**.
- `bash agents-only/06-scripts/check-boundaries.sh`: **exit 0**.
- `git diff --check`: clean. Working-tree diff: **only `dns_forwarder.rs`**; `a0_reality_spike/`
  untouched untracked.
- Independent adversarial code-review: **PASS, no blocker** (correctness / rename-safety /
  runtime-context / stop-restart / tests / scope all verified).

**Pre-existing flaky tests (NOT this change):** the full `cargo test -p sb-core --all-features`
suite has environment/timing-flaky tests that fail nondeterministically and **also fail on a
clean HEAD** (verified by stashing this change): `services::cache_file::tests::test_fakeip_persistence_sled`
(sled/disk), `dns_steady::{udp_pool_timeout_is_handled, bad_domain_returns_err}` (system-resolver
/ UDP-timing). Different ones fail per run; all pass in isolation. Not attributable to SVC-DNS-01.

## I. Disposition / next card

Saved: this report + the dns_forwarder.rs fix (staged-ready, uncommitted). Recommend a single
`fix(services): …` commit for the code (+ a `docs(agents)` checkpoint for this report, per the
T3 convention). **Next-card candidates** (do not auto-enter): (1) audit `v2ray_api` (and any
other listener service) for the same spawn-then-Ok bind pattern and apply the same propagation
if confirmed; (2) the DRIFT follow-ups still queued (roadmap report); (3) return to roadmap
prioritization. **No public network; no REALITY work.**
