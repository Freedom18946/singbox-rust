<!-- tier: B -->
# APP-RELOAD-SIDECAR-ORDER-01B — V2Ray reload continuity fix proposal

> **Design proposal only. No Rust changed, no test added, no reload order altered, no
> listener handoff / sidecar lease / activation split implemented.** This card designs the
> minimal, rollback-safe, verifiable fix for the confirmed V2Ray same-address reload
> continuity bug (01A classification `B/V2RAY_SAME_ADDRESS_RELOAD_CONTINUITY_BUG`). The fix,
> when implemented, lands in **sb-core** (`crates/sb-core/src/runtime/supervisor.rs` +
> `crates/sb-core/src/context.rs`).
>
> Every load-bearing source fact below was independently re-derived by a 5-agent adversarial
> verification sweep (all CONFIRMED, high confidence, no counter-evidence). Line anchors are
> against the tree at HEAD `50e0e35d`.

---

## A. Baseline git status

`## main...origin/main`; tracked tree clean; only `agents-only/a0_reality_spike/` pre-existing
untracked (untouched, not staged, not committed). `git diff --check` clean. Chain confirmed
synced and present: `50e0e35d` audit reload sidecar bind ordering · `be630924` accept sidecar
runtime exit policy · `93059aff` record run-engine sidecar runtime event bridge · `ce980d58`
bridge run-engine sidecar runtime events · `fffe916d` audit sidecar runtime completion consumers.

## B. `Context.v2ray_server` representation and disabled semantics

- Field: `pub v2ray_server: Option<Arc<dyn V2RayServer>>` on both `Context`
  (`context.rs:91`) and `ContextRegistry` (`context.rs:114`). The trait
  (`context.rs:824-840`) is `start()`, `close() -> anyhow::Result<()>`, `stats() ->
  Option<Arc<StatsManager>>` (default `None`), `subscribe_runtime_state() ->
  Option<watch::Receiver<V2RayServerRuntimeSnapshot>>` (default `None`).
- **Disabled** is expressed as `None` (not a noop object, not a default impl). `Context::new`
  sets `v2ray_server: None` (`context.rs:159`); `wire_experimental_sidecars` only attaches a
  server when `exp.v2ray_api` is `Some` **and** `start()` returned `Ok`
  (`supervisor.rs:1167-1177`). The only production constructor is the real `V2RayApiServer`
  (`supervisor.rs:1168`); there is no production noop/default implementor.
- Because the disabled state is `None`, "is V2Ray on for this generation" is
  `ctx.v2ray_server.is_some()`, and "is it the real, introspectable server" is
  `ctx.v2ray_server.as_ref().and_then(|s| s.subscribe_runtime_state()).is_some()` (the trait
  default returns `None`, the real server returns `Some` — `v2ray_api.rs:763-765`).

## C. `Context` drop / shutdown paths

- **`Context` has no `impl Drop`** and no custom `Clone`; it `#[derive(Clone, Debug)]`
  (`context.rs:77`). `V2RayApiServer` also has **no `Drop`** and derives only `Debug`
  (`v2ray_api.rs:383`). (sb-core's only `Drop` impls are unrelated guard types.)
- Therefore `Context::clone()` is a **shallow** clone: it bumps each `Arc` refcount. A cloned
  context shares the *same* `V2RayApiServer` instance. `handle_reload` step 0 binds
  `old_context = state_guard.context.clone()` (`supervisor.rs:581`), so the old context shares
  every `Arc` (including `v2ray_server`) with the live state until the swap.
- **The only production path that closes the server is `shutdown_context()`**
  (`supervisor.rs:1286-1320`): `if let Some(v2ray) = &ctx.v2ray_server { v2ray.close() }`
  (`:1289-1293`) — unconditional on `Some`. Every other production access of `.v2ray_server`
  only reads `.stats()` (inbound `socks5.rs:303/638`, `http_connect.rs:346`, `adapter/mod.rs:543/562`,
  `adapter/bridge.rs:774/788`, `runtime/mod.rs:101`, `sb-adapters/register.rs` ×16). The app
  layer only *subscribes* to the runtime snapshot (`run_engine_runtime/supervisor.rs:217`); it
  never closes or aborts the server.
- `shutdown_context` is invoked from: startup rollback (`supervisor.rs:192/200/252/262` and the
  no-router twins `:377/:383/:428/:438`), graceful shutdown (`:973`), and reload old-context
  teardown (`:689`, `:796`). **Crucially, dropping the server `Arc` does NOT close the
  listener** — see H.

## D. `StatsManager` relationship across reload

- `StatsManager` is created **fresh per server**: the sole production path is
  `V2RayApiServer::new` → `Arc::new(StatsManager::new(cfg.stats.clone()))` (`v2ray_api.rs:397`),
  stored in the private `V2RayApiState.stats` (`:319`). There is no setter and no trait method
  to inject or share a `StatsManager` between two distinct servers; `stats()` is a read-only
  getter (`:500-502`, `:759-761`).
- Consequence:
  - **Reusing the same `Arc<dyn V2RayServer>`** across a reload preserves `StatsManager`
    identity → traffic counters keep accumulating; the live consumers
    (`adapter/bridge.rs`, `adapter/mod.rs`, `register.rs`, inbounds) read through
    `ctx.v2ray_server...stats()` and continue to hit the same counters.
  - **Rebuilding a new server** (current behavior, `supervisor.rs:1168`) yields a brand-new
    `StatsManager` with zeroed counters → stats history resets on every reload that touches
    V2Ray. Reuse is therefore strictly better for stats continuity (and aligns with H5: stats
    identity is instance-scoped; we are preserving the instance, not bridging two).

## E. Runtime snapshot can decide reuse eligibility

- The real server overrides `subscribe_runtime_state()` → `Some(self.runtime_tx.subscribe())`
  (`v2ray_api.rs:763-765`); a `watch::Receiver` exposes `.borrow()` returning
  `V2RayServerRuntimeSnapshot { current: Option<V2RayServerActiveGeneration{generation, phase}>,
  last_exit }` (`context.rs:772-797`). `phase ∈ {Running, ShutdownRequested}`.
- So inside `handle_reload`, before the swap, the reload code can read the old server's live
  phase: `old_context.v2ray_server.as_ref().and_then(|s| s.subscribe_runtime_state())
  .map(|rx| rx.borrow().current.map(|g| g.phase))`. This distinguishes **Running** (reuse-safe)
  from **ShutdownRequested / no-current (exited)** (not reuse-safe). No `.await`, no blocking.

## F. Swap-pre failure points (where the new context can fail before commit)

`handle_reload` (`supervisor.rs:563-694`) timeline, with the failure edges:

| step | line | can fail before swap? | on failure |
| --- | --- | --- | --- |
| `Engine::from_ir(&new_ir)?` | :595 | yes (`?`) | early return, old kept, **no new V2Ray yet** |
| `build_context_from_ir(&new_ir)` → `wire_experimental_sidecars` → **new `V2RayApiServer::new`+`start()`** | :599 / :1168-1176 | bind err is **swallowed** (`:1172` warn, not attached) | continues; same-addr → V2Ray dropped this gen |
| `run_context_stage(Initialize)?` | :603 | yes (`?`) | early return; **if new V2Ray bound (free addr), it LEAKS — see H** |
| `populate_bridge_managers(...).await?` | :613 | yes (`?`) | same as above |
| `run_context_stage(Start)?` | :616 | yes (`?`) | same |
| `run_context_stage(PostStart)?` / `Started?` | :642 / :643 | yes (`?`) | same |
| **state swap** `state_guard.context = new_context` | :668 | infallible | commit point |
| `shutdown_context(&old_context)` → old V2Ray `close()` | :689 | best-effort | — |

The new V2Ray listener is bound at **:599** (inside `wire_experimental_sidecars`), and stages
**:603 / :613 / :616 / :642 / :643** can each `?`-return *after* that bind but *before* the swap.

## G. Pre-swap cleanup status for the new context's sidecar — **none today**

On a pre-swap `?`-return, `new_context` is simply dropped (it is a local). There is **no**
`shutdown_context(&new_context)` on the failure path and **no** cleanup guard. For managers this
is harmless (their `close()` is idempotent and they hold no bound port until Start), but for a
**successfully-bound new V2Ray listener it is not** — see H. The existing rollback comments only
cover the *old* context (kept alive); the *new* context's just-started sidecar has no owner once
the local is dropped.

## H. Address-different new-listener leak — **CONFIRMED, and it is a distinct defect**

> Registered as separate evidence, **not** folded into the same-address continuity description.

In a `service_v2ray_api` build, once `V2RayApiServer::start()` succeeds (`v2ray_api.rs:564-699`):
the `listener` is moved into the inner serve task; `shutdown_tx` is stored in
`V2RayLifecycle.current.shutdown_tx` (`:620`) behind `Arc<Mutex<V2RayLifecycle>>` (`:389`); the
monitor task captures a **clone** of that lifecycle `Arc` (`:645`) and is spawned detached (its
`JoinHandle` discarded, `:650`). Therefore:

- Dropping the `Arc<V2RayApiServer>` (held only by `Context.v2ray_server`, `supervisor.rs:1174`)
  drops the struct but **not** the lifecycle Arc (the monitor's clone keeps it alive), so
  `shutdown_tx` is **neither sent nor dropped** → `shutdown_rx.await` (`:661`) never resolves.
- The incoming stream is a `futures::stream::unfold` that returns `Some` **even on `accept()`
  error** (`:654-657`) → it never yields `None` → `serve_with_incoming_shutdown` never ends →
  `inner.await` (`:667`) never returns → the monitor never reaches `commit_terminal` (`:695`).
- Net: the serve task and its **bound listener leak indefinitely**. Only `close()`
  (`:729-756`, the sole taker/sender of `shutdown_tx`) stops it; nothing calls it on drop.

**When this bites at reload:** the new V2Ray binds successfully (a *free* address — i.e.
`disabled→enabled(A)`, or `enabled(A)→enabled(B)`), then a stage at :603/:613/:616/:642/:643
`?`-returns before the swap. `new_context` is dropped without `shutdown_context`, so the
just-bound listener leaks. (The same-address `EADDRINUSE` case does **not** leak: `pre_bind`
fails, the server is never attached, nothing is spawned — `v2ray_api.rs:602` + `supervisor.rs:1172`.)

This leak is **independent of** the same-address continuity bug and of the reuse fix: the reuse
handoff (Route 3) creates **no** new server in the same-config path, so it neither introduces nor
relies on this leak. It is registered as a separate follow-up (see S/U), not bundled into 01C.

## I. Reuse eligibility conditions

Reuse the old `Arc<dyn V2RayServer>` into the new context **iff all** hold (computed in
`handle_reload`, pre-build, from `old_context` + `state_guard.current_ir` + `new_ir`):

```
A. old enabled & realized   old_context.v2ray_server.is_some()
B. new enables V2Ray        new_ir.experimental?.v2ray_api.is_some()
C. config equivalent        old_ir.experimental?.v2ray_api == new_ir.experimental?.v2ray_api   (V2RayApiIR: Eq)
D. (folded into C)          listen AND stats equal — structural == on the whole V2RayApiIR
E. real introspectable srv  old_context.v2ray_server.subscribe_runtime_state().is_some()        (filters noop/mock)
F. currently Running        snapshot.current.map(|g| g.phase) == Some(Running)                  (not ShutdownRequested / exited / none)
G. stats compatible         implied by C (same stats cfg) + reusing the same StatsManager instance
```

If any fails → fall through to current behavior (build a fresh server). Reuse is **opt-in and
conservative**: only a definitely-`Running`, config-identical, real server is carried over.

## J. `:0` and address-normalization handling

- **Compare the config IR, never the running bound port.** `V2RayApiIR` derives `Eq`
  (`experimental.rs:59-65`), so `==` compares the `listen` string (and `stats`) structurally.
- For `listen: "127.0.0.1:0"`, old and new IR strings are equal → eligible → **reuse keeps the
  old server bound on its already-assigned ephemeral port**. This is the *only* correct behavior:
  rebuilding `:0` would bind a *different* random port and silently move the endpoint. Comparing
  the IR (not the resolved/observed port) gets this right for free.
- Do **not** normalize via `SocketAddr::parse` for the eligibility compare: (1) it reintroduces
  the `:0`→port-0 trap (parsed `:0` loses the real running port), and (2) the server only ever
  binds parseable `SocketAddr`s anyway (`listen_addr()` = `parse().ok()`, `v2ray_api.rs:511-513`;
  a hostname like `localhost` yields `None` → never binds, `start()` returns `Ok` without a
  listener, `:566-575`). String/structural IR equality is the smallest predictable gate.

## K. Three lifecycle phases (borrowed → commit → final)

- **Phase A — pre-swap borrowed.** The new context holds a **clone** of the old `Arc` (same
  instance). The **old context remains the close-owner.** If any pre-swap stage fails, the new
  context is dropped: its Arc clone decrements, the old context still holds the original → the
  server keeps serving; `shutdown_context(&old_context)` is **not** reached (we returned before
  :689). No close of the borrowed server. ✔
- **Phase B — swap commit.** At :668 the new context (carrying the reused Arc) moves into state.
  The subsequent old-context teardown (:689) **must skip closing the reused server**. This is
  recorded as a **reload-local boolean** computed *before* the swap:
  `preserve_v2ray = match (&old.v2ray_server, &new.v2ray_server) { (Some(o), Some(n)) =>
  Arc::ptr_eq(o, n), _ => false }`. It is **not** written into the server or into `Context`
  permanent state; it scopes exactly this one old-shutdown call.
- **Phase C — final shutdown.** When the now-current context is later torn down (next reload's
  old-shutdown, or graceful shutdown via `handle_shutdown`→`shutdown_context`, :973), it owns the
  reused server and closes it **normally** (no exclusion). The next reload computes its own
  `ptr_eq(old=current, new)`: if it also reuses → skip (correct, the newer context keeps it); if
  it rebuilds/disables → `ptr_eq` false → close (correct). The exclusion is thus correct
  transitively: a reload only ever skips closing a server the *incoming* context still holds.

Answers: (1) `handle_reload` records the skip, as a local. (2) Skip affects only this old-shutdown
call, never the server/Context. (3) Final shutdown never skips because graceful shutdown passes no
preserve flag and the chained reload always recomputes `ptr_eq`. (4) A
`ShutdownContextOptions`/`preserve_v2ray_server` is **not** required — a private inner flag is
enough (see M). (5) `Arc::ptr_eq(old, new)` is computed pre-swap (the new Arc is captured before
:668). (6) `Arc::ptr_eq` is valid on `Arc<dyn V2RayServer>` (std compares the data pointer; same
clone ⇒ equal). (7) No lease token needed; a local reload parameter suffices.

## L. Old-close exclusion design

Compute `preserve_v2ray: bool` in `handle_reload` *before* the swap (both contexts in scope),
then drive the old-context teardown through a variant that skips the V2Ray `close()` when
`preserve_v2ray` is true. The generic `shutdown_context(ctx)` used by startup-rollback (×8) and
graceful-shutdown (×1) stays **byte-identical** — only the reload teardown site changes its call.
The skip is a pure control-flow guard around `v2ray.close()` (`:1289-1293`); all other manager
closes run unchanged.

## M. Minimal API form — recommendation: **Option B (reload-only helper over a private inner)**

| Option | Shape | Verdict |
| --- | --- | --- |
| **A** | `shutdown_context(ctx, preserve_v2ray_server: Option<&Arc<dyn V2RayServer>>)` | Workable, but pollutes the signature shared by **9** startup/graceful callers with a concern that exists only at reload; every caller must pass `None`. Rejected (blast radius, altitude). |
| **B ✅** | `shutdown_replaced_context(old_ctx, preserve_v2ray: bool)` reload-only; both it and `shutdown_context(ctx)` delegate to a private `shutdown_context_inner(ctx, close_v2ray: bool)` | Narrowest public surface; `shutdown_context(ctx)` unchanged for all 9 existing callers; no duplicated manager-close ladder; `Arc::ptr_eq` computed in `handle_reload`. **Recommended.** |
| C | `V2RayServerLease` token type carried through Context | Most explicit, but over-engineered for a single sidecar with one reuse site; new type + threading. Rejected. |
| D | Split `Context` build vs activate | Larger lifecycle-boundary change; this is Route 5 / the escalation, not the minimal fix. Rejected as primary. |

**Recommended:** extract the existing body of `shutdown_context` into
`shutdown_context_inner(ctx, close_v2ray: bool)`; keep `pub fn shutdown_context(ctx)` calling it
with `true` (so the 9 existing callers are untouched); add a reload-only call with `false` when
`preserve_v2ray` is set. This is the smallest write-set that does not change any other caller and
keeps the generic teardown honest.

## N. Reuse-hint injection point — **eligibility in `handle_reload`; thread through
`build_context_from_ir` → realize in `wire_experimental_sidecars`**

| Route | Shape | Verdict |
| --- | --- | --- |
| **A ✅ (entry)** | `build_context_from_ir(ir, inherited_v2ray: Option<Arc<dyn V2RayServer>>)` | `build_context_from_ir` is private to `supervisor.rs` (`:1183`) with two callers — startup (`:173`/`:362`, pass `None`) and reload (`:599`, pass the eligible Arc). Threading one param is internal. **Recommended entry.** |
| **B ✅ (realization)** | `wire_experimental_sidecars(ctx, ir, inherited_v2ray: Option<…>)` | Also private (`:1155`). When `inherited` is `Some`, **skip** `V2RayApiServer::new`+`start()` and instead `ctx.with_v2ray_server(inherited)` (`context.rs:184`). This is where the skip-and-inject lands. **Recommended realization.** |
| C | Build fully, then replace the server afterward | **Too late** — the build already bound a second listener at :599 (the bug). Rejected. |

Eligibility (I) is computed in `handle_reload` because only it sees `old_context`,
`state_guard.current_ir` (old IR, `supervisor.rs:67/81`), and `new_ir` together. The eligible Arc
is threaded via Route A into Route B, which performs the skip+inject. Disabled / changed-address
paths pass `None` → unchanged current behavior. **No app-layer change** is required: the app only
reads `context.v2ray_server` (`run_engine_runtime/supervisor.rs:217`, documented "no sb-core
change"); it consumes whichever Arc sb-core installs.

## O. Config matrix — target behavior

| old | new | reuse? | new bind? | old shutdown skips close? | reload-fail keeps old listener? |
| --- | --- | ---: | ---: | ---: | ---: |
| disabled | disabled | no | no | N/A | N/A |
| disabled | enabled(A) | no | yes | N/A | N/A (old had none) — **but new listener leaks on later pre-swap failure → H** |
| enabled(A) Running | disabled | no | no | no (old A closed normally) | keep A until close |
| **enabled(A) Running** | **enabled(A)** | **yes** | **no** | **yes (exclude reused Arc)** | **yes (old still owns the shared Arc; old-close not reached)** |
| enabled(A) Running | enabled(B) | no | yes (bind B) | no | partial — old A closed after swap; **new B leaks on later pre-swap failure → H** |
| enabled(A) Running | enabled(B occupied) | no | bind B fails (swallowed) | no | medium — B dropped silently, reload "success" (pre-existing) |
| enabled(A) Exited | enabled(A) | no (phase≠Running) | yes (A likely free) | no | **new A leaks on later pre-swap failure → H** |
| enabled(A) ShutdownRequested | enabled(A) | no (phase≠Running) | yes (attempt; may EADDRINUSE while draining → swallowed) | no | residual edge (reload-during-drain); rare |
| enabled(`:0`) Running | enabled(`:0`) | **yes** | **no** | **yes** | **yes** (keeps the real ephemeral port — see J) |

**Core target:** `enabled(A) Running → enabled(A)` (and any reload that does not change the
V2Ray config) preserves continuity — no rebind, listener stays online, reload reports success
*and is honest*. This is exactly the 01A "V2Ray dies on reloads that don't touch it" scenario.

## P. Rollback invariants (must all hold)

```
new IR / Engine / Initialize / Start / PostStart fails
  → no state swap → old context valid → old V2Ray listener NOT closed      ✔ (return before :668/:689)

same-config reused Arc enters new context (Phase A borrowed)
  → still old-owned pre-swap → swap failure must NOT close it              ✔ (old retains original; old-close not reached)

swap succeeds
  → old shutdown skips the reused server (ptr_eq) → new context owns final close   ✔ (preserve_v2ray boolean)

different-address new listener B bound, then pre-swap failure
  → who closes B?  → CURRENTLY NOBODY (H leak)                             ✖ pre-existing gap, NOT closed by this fix
```

The last line is the **only** unmet invariant. The reuse handoff does not create a new server
in the same-config path, so it neither introduces nor cures it. It is left to a dedicated
cleanup card (S/U), not patched inside 01C.

## Q. Six fix-route comparison

| Route | Summary | Continuity | Rollback | Startup honesty | Verdict |
| --- | --- | --- | --- | --- | --- |
| 1 status quo | rebuild+rebind same addr, swallow EADDRINUSE | ✖ lost | ✔ | ✔ | **Reject** |
| 2 close-old-first | close old V2Ray before building new | ✔ | ✖ (lose old if new build fails) + outage window | ✔ | **Reject** |
| **3 reuse + old-close exclusion** | carry the unchanged `Arc` into new ctx; skip closing it in old teardown | ✔ | ✔ | ✔ | **RECOMMEND (primary)** |
| 4 same-addr hard-reject | refuse a reload that would rebind an in-use V2Ray addr | ✔ (no loss) | ✔ | ✔ | Fallback only — too blunt (rejects unrelated reloads) |
| 5 build/activate split | build sans-sidecar → swap → close old → start new | ✔ | needs new post-swap failure semantics | ✔ | Defer (larger; escalation if reuse+leak need structural fix) |
| 6 listener/socket handoff | hand the bound FD to the new generation | ✔ | complex | ✔ | Only if reuse infeasible — not needed |

**Recommended: Route 3**, fallback **Route 4** (if reuse proves infeasible in implementation,
reject the unsafe same-address rebind rather than silently dropping the listener). Route 5 is the
escalation reserved for when the H leak forces an activation-boundary redesign.

## R. Cross-sidecar generalization?

**No — keep it V2Ray-specific.** `wire_experimental_sidecars` has exactly two sidecars:
`cache_file` (holds no listener, no bind conflict, `supervisor.rs:1157-1165`) and `v2ray_api`.
Clash API is **app-owned** (`AdminServices`, started once outside the reload loop) and is not
rebuilt on reload; bootstrap sidecars have no reload path (01A E/F/H). Do **not** widen this into
a generic context-sidecar reuse framework — that would be unjustified abstraction for a one-site
problem.

## S. Split-card judgment

1. Same-config reuse as a single implementation card? **Yes** (01C — bounded, sb-core-local).
2. Pre-swap new-listener leak real? **Yes** (H, LB3 confirmed).
3. Must it be solved in the same card as the continuity fix? **No** — independent; reuse creates
   no new server in the same-config path, so it neither introduces nor depends on the leak.
4. Need `APP-RELOAD-CONTEXT-CLEANUP-01A` *first*? **Not a prerequisite.** Register it as a
   follow-up (after 01C), addressing the address-change/exited-path pre-swap leak (e.g.
   `shutdown_context(&new_context)` on the pre-swap `?`-failure paths, scoped to a
   successfully-bound new sidecar).
5. Activation-boundary redesign (Route 5) needed now? **No** — only if the cleanup card shows a
   local guard is insufficient.
6. Keep V2Ray-specific (not a sidecar framework)? **Yes**.

## T. Unique classification

**`A. V2RAY_REUSE_HANDOFF_READY`.**

Local reuse injection (N: thread the eligible `Arc` through `build_context_from_ir` →
`wire_experimental_sidecars`) **plus** old-close exclusion (L/M: reload-local `Arc::ptr_eq`
preserve flag over a private `shutdown_context_inner`) is **sufficient** to fix the same-address
continuity bug while preserving continuity + rollback + startup honesty (P). It does not require a
pre-swap cleanup guard (that is the separate H leak, which the reuse path does not trigger), so it
is not `B`; the fix is local to `wire_experimental_sidecars`/`build_context_from_ir`/`shutdown_context`
and does not require an activation-boundary redesign, so it is not `C`; the leak found (H) is
V2Ray-specific and orthogonal, not a broader pre-swap rollback-cleanup bug that blocks the
continuity fix, so it is not `D`; evidence is complete and verified, so it is not `E`.

## U. Unique recommended next card

**`APP-RELOAD-SIDECAR-ORDER-01C — implement V2Ray same-config reload reuse handoff`** (sb-core).

Scope (in): compute reuse eligibility (I) in `handle_reload`; thread the eligible
`Arc<dyn V2RayServer>` through `build_context_from_ir` into `wire_experimental_sidecars`, which
skips `V2RayApiServer::new`+`start()` and injects the inherited Arc via `with_v2ray_server`;
compute `preserve_v2ray = Arc::ptr_eq(old, new)` before the swap and route the old-context
teardown through a private `shutdown_context_inner(ctx, close_v2ray=false)` (Option B). Tests:
add a sb-core reload regression proving `enabled(A) Running → enabled(A)` keeps the *same*
`Arc`/listener and the same `StatsManager` counters, and that a reload changing V2Ray config (or
disabling it) still rebuilds/closes; assert `shutdown_context` callers are unchanged. Scope note:
**this lands in sb-core** — call out the crate-boundary change vs the app-only 01F/01G/01H work.

Follow-up queue (registered, **not** the next card):
- **`APP-RELOAD-CONTEXT-CLEANUP-01A`** — close a successfully-bound *new* V2Ray listener on the
  pre-swap `?`-failure paths (the H/LB3 address-change leak). Independent of 01C.
- Defers unchanged: `APP-SIDECAR-LIVENESS-01` CLOSED; `APP-SIDECAR-POLICY-02A`,
  `SVC-V2RAY-API-01B` = DEFER; `APP-V2RAY-SURFACE-02D` = CLOSED; V2Ray breaking cleanup,
  `TIDY-RUSTDOC-LINKS`, `TIDY-APP-BREAKER-FLAKE` = DEFER. Out-of-scope unchanged: H5, H7.

## V. Checkpoint commit + push

Two docs only — `agents-only/active_context.md` + `agents-only/app_reload_sidecar_order_01b_fix_proposal.md`.
Gates run before commit: `git diff --check`, `verify-consistency.sh`, `check-boundaries.sh`.
Checkpoint `checkpoint: propose v2ray reload continuity fix`; `a0_reality_spike/` left untracked;
pushed to `origin main`. No Rust / Cargo / crate / fixture change.

## W. Final status

Recorded in the session report.

## State

`APP-RELOAD-SIDECAR-ORDER-01B` = **`A. V2RAY_REUSE_HANDOFF_READY`** (design-only; fix lands in
sb-core). Next = `APP-RELOAD-SIDECAR-ORDER-01C` (implement same-config reuse handoff). New
follow-up registered: `APP-RELOAD-CONTEXT-CLEANUP-01A` (address-change pre-swap new-listener
leak, H/LB3). H6 is now characterized + designed, not yet fixed. Out-of-scope unchanged: H5, H7.
