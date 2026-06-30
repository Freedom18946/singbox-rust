<!-- tier: B -->
# APP-SIDECAR-LIVENESS-01D — generation-aware V2Ray runtime snapshot proposal

> Proposal only. No Rust code, no new state types, watch channels, monitor tasks, trait methods, or
> tests were added. Builds on `app_sidecar_liveness_01b/01c`. Designs the **minimum correct**
> runtime snapshot contract for a repeatedly-startable `sb-core` V2Ray server, so an old
> generation's late exit can never overwrite a newer generation's live state or mis-report it.

---

## A. Accepted-checkpoint push result

`git push origin main` succeeded: `90562381..6746a5d5  main -> main`.
Post-push: `## main...origin/main` + untracked `agents-only/a0_reality_spike/` (left untouched).

## B. Baseline git status

- `## main...origin/main`
- `?? agents-only/a0_reality_spike/`

Synced commit chain confirmed:

- `6746a5d5 checkpoint: record v2ray runtime completion contract`
- `90562381 checkpoint: propose sidecar runtime completion projection`
- `ab7f19db checkpoint: audit app sidecar runtime liveness`

## Verification method note

The control-flow verdicts below (C–J, O) were produced by reading the real source and then
**adversarially re-verified** by independent skeptic reviewers (one per claim) instructed to refute.
Result: C1/C2/C3/C4/C6/C7 CONFIRMED; C5 REFUTED for the cross-instance reload reading and re-scoped
to the single-instance reading (see E/P). A completeness critic added hazards H1–H8 (see K/N/Q).
File anchors are `crates/sb-core/src/services/v2ray_api.rs` unless noted.

---

## C. `start()` / `close()` lock boundary

There is **no single shared mutex** serializing the two methods (verified, claim C6 CONFIRMED).

- `started: Arc<AtomicBool>` (`:334`) — the single-start slot, mutated by lock-free CAS/store.
- `shutdown_tx: parking_lot::Mutex<Option<oneshot::Sender<()>>>` (`:337`) — a *separate* mutex.

`start()` (`service_v2ray_api`): CAS `false→true` on `started` (`:431`) → `pre_bind` (`:446`) →
`*self.shutdown_tx.lock() = Some(tx)` (`:468`) → spawn serve task (`:481`). The shutdown-sender
install is a **distinct, later** critical section from the start-claim; nothing holds a lock spanning
"claim generation + install sender".

`close()`: `started.store(false)` (`:510`) then, separately, `shutdown_tx.lock().take()` +
`tx.send(())` (`:514-516`). Again two independent sync points; the atomic store precedes the mutex
take.

The CAS at `:431` *does* serialize concurrent `start()` callers (only one wins the slot), so two
listeners are never spawned simultaneously — but that is the only ordering guarantee.

## D. Does the old task still run when `close()` returns?

**Yes — possible (C1 CONFIRMED).** `close()` only sends the oneshot signal and returns `Ok(())`
synchronously; it holds no `JoinHandle` and never awaits the serve task. The serve task observes the
signal at `shutdown_rx.await` (`:490`), then `serve.await` drains in-flight connections, then the
task body ends and `ResetStartedOnDrop` (`:349`) flips `started=false`. Test `task_exit_resets_started`
(`:909`) confirms `started` flips only later via polling `wait_until_not_started`. `shutdown_context`
(`supervisor.rs:1289`) is itself a **synchronous** fn that fire-and-forgets `v2ray.close()`.

## E. Is immediate restart after `close()` allowed?

**Restart-attempt: yes. Immediate same-address rebind: may transiently fail (C2 CONFIRMED).**
`close()` sets `started=false`, so a subsequent `start()` can immediately win the CAS. But `pre_bind`
uses plain `std::net::TcpListener::bind` with **no `SO_REUSEADDR`/`SO_REUSEPORT`** (`:391`); while the
old generation's serve task still owns its listener, the new bind returns `EADDRINUSE`, and `start()`
rolls back `started=false` (`:449`) and returns `Err`. This is exactly why the tests restart through
`restart_with_retry` (`:749`) and bootstrap polls `wait_for_v2ray_api_bind_release`
(`api_services.rs:147`). The accepted contract is therefore **"close → eventually-restartable on the
same port"**, NOT "close returns → immediately rebind with no wait" (answers card §5.8).

## F. Listen-address reuse and rebind risk

The instance's address is **fixed and reused** (C3 CONFIRMED). `cfg.listen` is set once in `new()`
(`:355`), read through `listen_addr(&self)` (`:380`); no method takes `&mut self` or mutates it, and
the trait object is held as `Arc<dyn V2RayServer>` so the owner cannot get `&mut`. **There is no
different-address restart capability per instance** (card §5.6 = impossible). A reload that needs a
new address constructs a brand-new `V2RayApiServer` from a fresh IR (`supervisor.rs:1168`), i.e. a new
instance, not a rebind. Same-address rebind risk = the transient `EADDRINUSE` of E.

## G. Can multiple draining generations exist?

**At most one draining tail overlapping one new active generation — never two concurrently serving
(C4 CONFIRMED).** The pre-bound listener (no `SO_REUSEADDR`) is an OS-level mutex: generation N+1
cannot bind until generation N's serve task drops its listener. Drop order inside the spawned block
(`:481-503`): `_reset_started` is declared first, the `incoming` stream owning the listener after; Rust
drops locals in reverse declaration order, so the **listener drops first, then the `_reset_started`
guard**. Thus the port frees, N+1 can bind and reach `Running`, while N's residual tail (the final
log at `:501` and the guard's `started.store(false)` at `:349`) still executes — a genuine but tiny
overlap. Because binding serializes serving, the snapshot never needs to represent ≥2 simultaneously
*serving* generations; it needs only **one active + at-most-one draining-tail** distinction. (This is
the decisive evidence against classification C.)

## H. Existing tests' restart contract

| Test (`:line`) | Contract it pins |
| --- | --- |
| `restart_after_failed_bind` (`:820`) | a failed `start()` is retryable on the same instance |
| `shutdown_allows_restart` (`:879`) | `start → close → (retry) start` accepted on the same instance |
| `task_exit_resets_started` (`:909`) | direct shutdown signal (no `close()`) resets `started`, then restartable |
| `duplicate_start_does_not_create_second_listener` (`:853`) | duplicate running `start()` = idempotent `Ok`, no 2nd bind |
| `restart_with_retry` helper (`:749`) | **bounded retry is part of the accepted behavior** |

Conclusion: the suite requires *eventual* restartability through retry, **not** zero-wait restart, and
**not** a single-lifecycle instance. Any new contract must preserve all five.

## I. Compatibility impact of making `close()` wait for terminal

**Rejected — high risk.** `close()` returns `anyhow::Result<()>` and is **synchronous**; its callers
(`shutdown_context` at `supervisor.rs:1286`, the bootstrap waiter at `api_services.rs:128`) call it
from contexts where a blocking await is not free. Making `close()` await the serve task's terminal
would require `blocking_recv`/block-on inside code that may run on a runtime worker → blocking-in-async
and potential deadlock; it would also turn the currently-idempotent non-blocking `close()` into a call
whose duration depends on in-flight connection drain. It changes the observable contract pinned by H.
Do not pursue Route 1.

## J. Compatibility impact of rejecting restart while draining

**Rejected — breaks pinned tests.** If `start()` returned `Err`/no-op while a previous generation is
draining, `shutdown_allows_restart` and `task_exit_resets_started` (which restart *while the old task
is still tearing down*, relying on bounded retry) would change meaning. The current `EADDRINUSE`
rollback already provides a *self-clearing* back-pressure: restart fails transiently and succeeds once
the port frees. An explicit draining-reject would be stricter than today and is unnecessary given G.
Do not pursue Route 2.

---

## K. Generation contract invariants

The contract the snapshot must guarantee (card §6):

- **A. Unique id** — every *successful* start (CAS won **and** `pre_bind` succeeded) mints exactly one
  generation id.
- **B. Monotonic** — ids strictly increase; never reused, never decrease.
- **C. No phantom generation on bind failure** — a `pre_bind` failure (`:446` `Err`) mints **no**
  generation and publishes no `Running` (startup failure is already surfaced by `start()`'s `Result`).
- **D. Duplicate running start = no new generation** — a CAS-failed duplicate `start()` (`:431` →
  `:436` no-op) leaves the current generation untouched (relatedly H1: it must **not** be read as
  "a fresh live generation exists").
- **E. Targeted shutdown** — a shutdown request applies only to its target generation; a stale request
  must not mark a newer generation as shutting down (today `close()` is generation-blind — see H3).
- **F. At-most-once terminal** — each generation commits **one** terminal outcome.
- **G. No terminal regression** — an older generation's terminal must never overwrite a newer
  generation's active state (the core race; see N).
- **H. Late subscriber readable** — a subscriber that attaches after events still reads the current
  snapshot.
- **I. Snapshot = state truth, not audit log** — the snapshot carries current state + latest-by-id
  terminal, not the full ordered terminal history.
- **J. Supervisor events are a later consumer layer** — out of scope here.

**Generation id type:** `u64` is sufficient — at any realistic restart cadence (even 1e6/s) u64
wraps in ~585,000 years. Overflow policy must still be **explicit, not silent**: mint via
`checked_add(1)`; on `None`, do **not** wrap — keep the current generation, log an error, and treat it
as an unreachable logic fault. Never `wrapping_add`.

## L. Three snapshot models compared

### Model A — single `{generation, state}`
Insufficient (matches 01C finding). If gen N+1 publishes `Running` and gen N then commits its terminal
(the G/H overlap of section G is real), a single `state` field forces a choice between losing N+1's
`Running` or losing N's terminal. Cannot satisfy invariant G **and** retain a terminal for late
subscribers. **Reject.**

### Model B — `{current: Option<Active>, last_exit: Option<ExitRecord>}`  ✅ recommended
```rust
struct V2RayServerRuntimeSnapshot { current: Option<ActiveGeneration>, last_exit: Option<ExitRecord> }
struct ActiveGeneration { generation: u64, phase: ActivePhase }      // Starting | Running | ShutdownRequested
struct ExitRecord       { generation: u64, exit: V2RayServerExit }
```
`current` always reflects the newest *active* generation; an older generation's exit updates only
`last_exit` and leaves `current` untouched. Given G (one active + one draining tail), this two-slot
shape is exactly expressive enough: the draining generation's terminal lands in `last_exit` without
disturbing the new `current`. Late subscribers read both the live generation and the most recent
terminal. **This is the minimum late-subscriber-safe shape.**

### Model C — `{active, draining: Vec<..>, last_exit}`
Over-built. A `Vec<draining>` is only justified if the runtime can hold **multiple** draining
generations that must be individually exposed. Section G shows binding serializes serving, so there is
never more than one draining tail of interest, and that tail's only observable output is its terminal
(→ `last_exit`). The vector adds capacity management, ordering, and history semantics the liveness
goal does not need. **Reject unless a future audit requirement appears.**

## M. `last_exit` — the single chosen semantics

**`last_exit` = the terminal outcome of the highest generation id seen so far** (Route 2,
highest-generation terminal), **not** completion-order.

- A terminal for generation `g` updates `last_exit` **only if** `g >= last_exit.generation` (and `g`
  is `> ` any prior, by B). An older generation finishing *after* a newer one (the G overlap) is
  therefore **dropped from the snapshot**, never allowed to overwrite a newer terminal.
- This keeps the snapshot **monotonic** and trivially explainable to a late subscriber ("the newest
  thing that has terminated"), and directly enforces invariant G.
- **Accepted cost:** a straggler older-generation terminal can be absent from `last_exit`. This is
  acceptable for a *liveness* snapshot. The **complete** ordered terminal stream (if a consumer ever
  needs every exit, including out-of-order stragglers) is deferred to a later consumer-facing event
  channel (J / Phase 3), which is the right place for full history — the snapshot is state truth, not
  an audit log (invariant I). Answers card §8: loss of full event history in the snapshot **is**
  acceptable here.

## N. Terminal-writer design (single writer)

Adopt **one outer monitor task per generation as the sole terminal writer**:

```
start() (generation g):  pre_bind ok → mint g → publish current = Running(g) → spawn monitor(g)
close():                 mark current = ShutdownRequested(g)  +  send shutdown signal   (NO terminal)
inner serve task:        does NOT self-publish terminal; just runs serve_with_incoming_shutdown
outer monitor(g):        awaits inner JoinHandle → maps Ok/Err/panic/cancel → commits terminal for g
```

Terminal mapping (unchanged from 01C, retained):

| Inner result | Terminal |
| --- | --- |
| `Ok(Ok(()))` with shutdown requested for `g` | `CleanShutdown` |
| `Ok(Ok(()))` without shutdown requested for `g` | `UnexpectedCompletion` |
| `Ok(Err(e))` | `ServeError(e.to_string())` |
| `Err(join)` `is_panic()` | `Panicked(payload)` |
| `Err(join)` `is_cancelled()` | `Cancelled` |

Card §9 answers:
1. **Terminal compare-and-set helper still needed?** Yes — but it collapses to the `last_exit`
   highest-generation rule of M: "commit terminal for `g` iff `g >= last_exit.generation`, and clear
   `current` iff `current.generation == g`". One small helper under the lifecycle lock.
2. **Per-generation guard needed?** Yes, but it is just the generation id captured by the monitor; no
   separate guard object. The current `ResetStartedOnDrop` (generation-blind `store(false)`) is
   **replaced** by the monitor's generation-checked commit (it must not blindly reset shared state).
3. **Monitor commits using only the generation id?** Yes — `g` + the two CAS rules above are
   sufficient; no other identity needed.
4. **Old monitor avoiding clobber of newer `current`:** the `current.generation == g` guard means an
   old monitor only clears `current` if it still owns it; if a newer generation already replaced
   `current`, the old monitor leaves `current` alone and only (conditionally) touches `last_exit`.
   This is the structural fix for the C5 hazard (see P) and invariant G.
5. **Old monitor still logs?** Yes — log the terminal at the monitor (the single writer), tagged with
   `g`, even when it does not become `last_exit`. Logging ≠ snapshot mutation.
6. **Snapshot dropping an old terminal → need event channel?** Yes — if a consumer must observe
   *every* terminal including out-of-order stragglers, that requires the later consumer-facing event
   channel (J). The snapshot intentionally does not retain it.

## O. Five timelines — conclusions

- **(A) First normal run:** `pre_bind` ok → mint gen 1 → `current = Running(1)` → spawn monitor(1) →
  `start` returns `Ok`. ✔ matches `successful_bind_marks_started`.
- **(B) Normal shutdown:** `close` → `current = ShutdownRequested(1)` + signal → monitor(1) sees clean
  inner exit → `current = None`, `last_exit = {1, CleanShutdown}`. ✔
- **(C) Close then restart:** gen 1 `ShutdownRequested` → `start` mints gen 2 (after the port frees;
  transient `EADDRINUSE` retried per E) → `current = Running(2)` → gen 1 monitor later exits →
  `current.generation==2 ≠ 1` so `current` **stays Running(2)**; `last_exit` updated to `{1,..}` only
  if `1 >= last_exit.generation` (it is, first exit). ✔ invariant G holds.
- **(D) Older generation finishes after a newer one already exited:** gen 1 draining → gen 2 starts →
  gen 2 exits → `last_exit = {2, terminal}` → gen 1 later exits → `1 >= 2` is **false** → `last_exit`
  is **NOT** rolled back to `{1,..}`. **Definitive answer to card §10.D: no regression permitted.** ✔
- **(E) Rapid multi-generation:** gen1 close → gen2 start/close → gen3 start → gens exit in any order.
  Because binding serializes serving (G), at most one is `Running` and `current` always tracks the
  newest active id; `last_exit` only ratchets upward by id. Model B remains correct without a draining
  set. ✔

## P. Lock and control-state design

Card §11 answers — replace the lock-free `started` + generation-blind drop guard with **one
`parking_lot::Mutex` over a small lifecycle control struct**, plus a `watch::Sender` for publishing:

```rust
struct LifecycleControl {
    next_generation: u64,                              // counter; mint via checked_add
    current: Option<RunningGeneration>,                // { generation, shutdown_tx: oneshot::Sender }
}
// published via: watch::Sender<V2RayServerRuntimeSnapshot>
```

1. **Generation counter location:** inside `LifecycleControl` behind the lifecycle mutex (single
   source of monotonic ids).
2. **Does `started` survive?** No — superseded by `current.is_some()` semantics; remove the standalone
   `AtomicBool` to eliminate the generation-blind store sites (`:349`, `:449`, `:510`).
3. **Is `shutdown_sender` generation-bound?** Yes — moved into `RunningGeneration { generation,
   shutdown_tx }` so a shutdown always targets a specific generation (fixes H3/E-invariant).
4. **`RunningGeneration` struct?** Yes, as above.
5. **`start()`: mint generation + store sender in one critical section?** Yes — take the lock, mint
   `g`, install `RunningGeneration{g, tx}`, set `current = Running(g)`, drop lock, **then** spawn. This
   makes "claim + sender install" atomic, closing the C/H1 split.
6. **`close()`: read target generation + take sender in one critical section?** Yes — take the lock,
   read `current.generation`, take its `shutdown_tx`, set phase `ShutdownRequested(g)`, drop lock,
   **then** `tx.send(())` outside the lock.
7. **Monitor updates snapshot under the same lock?** Yes — terminal commit takes the lifecycle lock to
   run the two CAS rules of M/N, then publishes.
8. **Watch sender as the only sync primitive?** No — `watch` publishes but cannot do the
   compare-and-set across (current, last_exit). The lifecycle mutex is the CAS primitive; `watch`
   is the read/broadcast surface.
9. **Extra mutex for lifecycle control?** The one lifecycle mutex above suffices; no second mutex.
10. **Avoid holding the lock across `.await`?** Yes — all `.await` (serve drain, `tx.send`, spawn) is
    done **outside** the lock; the lock only guards short synchronous CAS/field updates. No lock is
    held across an await point.

**C5 re-scoping (verified).** The adversarial pass REFUTED C5 for the cross-instance reload reading:
each reload calls `V2RayApiServer::new`, allocating a **fresh** `Arc<AtomicBool>`, so an old
generation's guard can only touch its own dead instance's flag. For the **single-instance** repeated
start/close/start path (this card's actual subject), the `started` Arc *is* shared across generations
and the drop guard's unconditional `store(false)` (`:349`) is generation-blind — a *vanishingly
narrow but non-zero* theoretical clobber window exists between an old task's listener-drop and its
guard-drop (section G). Either way the fix is identical: the generation-checked commit (N.4) replaces
the blind store, so the design is sound regardless of how narrow the window is.

## Q. Trait exposure design

Additive default method on `V2RayServer` (`context.rs:760`):

```rust
fn subscribe_runtime_state(&self)
    -> Option<tokio::sync::watch::Receiver<V2RayServerRuntimeSnapshot>> { None }
```

Card §12 answers:
1. **Object safety preserved?** Yes — no generics, no `async`, returns an owned `Option<Receiver>`;
   `V2RayServer` stays `dyn`-compatible (it is held as `Arc<dyn V2RayServer>` at `context.rs:91`).
2. **Default avoids breaking external implementors?** Yes — defaulting to `None` means any current or
   external implementor compiles unchanged and simply reports "no runtime state".
3. **Snapshot type placement:** define in **`crates/sb-core/src/context.rs`**, next to the trait, so
   the trait signature has no cross-module/crate dependency and no cycle. (`v2ray_api.rs` already
   `use`s `crate::context::V2RayServer`, so the type is naturally visible to the implementor.)
4. **Crate-root re-export?** Yes — re-export the snapshot/exit types from the sb-core crate root for
   ergonomic app consumption, mirroring existing context-type exposure.
5. **App can map purely from the trait return?** Yes — the app adapter (Phase 1) consumes only the
   `watch::Receiver<V2RayServerRuntimeSnapshot>` from `subscribe_runtime_state()`; it needs no
   concrete `V2RayApiServer` type.
6. **Expose an event channel here?** No — **this card exposes only the snapshot receiver.** A
   consumer-facing event channel is deferred (J / Phase 3).

## R. Five routes compared

| Route | Verdict |
| --- | --- |
| **1. `close()` awaits old terminal** | Reject — changes the sync, idempotent, non-blocking `close()` contract; blocking-in-async/deadlock risk; breaks H (see I). |
| **2. Reject restart while draining** | Reject — stricter than today; breaks `shutdown_allows_restart` / `task_exit_resets_started`; the `EADDRINUSE` rollback already self-clears (see J). |
| **3. Generation-aware `current + last_exit`** | **Recommend** — minimal, covers late subscriber + overlap (Model B + highest-gen `last_exit` + single monitor writer); fits the app adapter. |
| **4. Generation set / history queue** | Reject — over-design; only justified by a full-audit requirement the liveness goal does not have (see L, G). |
| **5. mpsc terminal events, no snapshot** | Reject — late subscribers lose state; not a source-of-truth (fails invariant H). |

**Unique recommended route: Route 3.**

## S. Staged implementation plan (not implemented here)

- **Phase 0 — `APP-SIDECAR-LIVENESS-01E` (sb-core only):** define `V2RayServerRuntimeSnapshot` +
  `ActiveGeneration`/`ActivePhase` + `ExitRecord`/`V2RayServerExit` in `context.rs`; add additive
  default `subscribe_runtime_state()`; implement on `V2RayApiServer` (lifecycle mutex + `watch` sender
  + outer monitor as sole terminal writer; remove generation-blind `started`/guard); generation-scoped
  deterministic tests (monotonic ids, late subscriber reads current, timeline D no-regression, no
  phantom generation on bind failure, duplicate-start mints no generation). **Do not** mint a fresh
  `StatsManager` per generation (see H5 in N/Q notes) — stats identity stays instance-scoped.
- **Phase 1 — `APP-SIDECAR-LIVENESS-01F` (app):** bootstrap / run-engine adapter mapping the V2Ray
  source snapshot into app sidecar completion. No failure-policy change.
- **Phase 2 — `APP-SIDECAR-LIVENESS-01G` (app):** Clash runtime completion projection, **reusing** the
  app-level completion semantics from 01F (no parallel model).
- **Phase 3 — `APP-SIDECAR-LIVENESS-01H` (policy):** sidecar runtime exit consumer policy review —
  choose log-only / degrade / supervisor-event / hard-fail / restart. Mechanism only; no policy mixed
  in earlier.

**Out-of-scope hazards surfaced for separate tracking (do not fold into 01E):**
- **H5** — `StatsManager` is one shared `Arc` (`:356`), `stats()` always returns a clone (`:522`), and
  dataplane consumers cache it for their lifetime (bridge / adapter / socks5 / http_connect / runtime).
  Counters are **not** generation-scoped; a per-generation reset would change observable semantics and
  strand cached recorder `Arc`s. The snapshot must cover **liveness only**, never stats identity.
- **H6** — supervisor reload starts the **new** server before `shutdown_context` closes the **old**
  one (`supervisor.rs` new-start before `:689` close), so the new same-address `pre_bind` can
  `EADDRINUSE` and the new V2Ray API is silently dropped with only a warn (`:1171`). This is a
  **supervisor ordering** bug across *separate instances*; a single-instance snapshot does not fix it.
  Candidate future card: reload close-before-start ordering for same-address sidecars.
- **H7** — `stats()` returns `Some` unconditionally even after `close()`; it is not a liveness probe.
  Consumers needing liveness must use the new snapshot, not `stats().is_some()`.

## T. Classification

**`B. GENERATION_AWARE_SNAPSHOT_READY`**

Rationale: binding serializes serving (G/C4), so `current + last_exit` (Model B) with
highest-generation `last_exit` and a single per-generation monitor writer is **sufficient and
minimal** — no draining set (C rejected), no lifecycle-boundary redesign (D rejected, the additive
trait + lifecycle mutex are local to `V2RayApiServer`), and evidence is sufficient (E rejected).
`close()`-waits-for-terminal (A) is rejected as contract-breaking (I).

## U. Unique recommended next card

**`APP-SIDECAR-LIVENESS-01E — implement V2Ray generation-aware runtime snapshot`** (sb-core only;
scope = Phase 0 of S). One card only.

## V. Checkpoint / push / final status

See repository checkpoint `checkpoint: propose generation-aware v2ray runtime snapshot`.
`git diff --check`, `verify-consistency.sh`, `check-boundaries.sh` run before commit; only
`agents-only/active_context.md` and this file committed; `agents-only/a0_reality_spike/` left
untracked. Final `git status --short --branch` recorded in the session report.

---

## State

`APP-SIDECAR-LIVENESS-01D` = `B. GENERATION_AWARE_SNAPSHOT_READY`; next = `APP-SIDECAR-LIVENESS-01E`.
`SVC-V2RAY-API-01B` remains `DEFER / POLICY REVIEW`. V2Ray breaking cleanup = `DEFER / FUTURE MAJOR
WINDOW`. `APP-V2RAY-SURFACE-02D` remains `CLOSED`.
