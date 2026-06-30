<!-- tier: B -->
# APP-SIDECAR-LIVENESS-01E-R1 — serialize V2Ray runtime snapshot publication

> Verification + fix of the `V2RayApiServer` runtime-snapshot **publication ordering**. Result:
> **情况 B** (off-lock publication existed) → code fix. sb-core only; not pushed.

Fix commit: `fix(sb-core): serialize v2ray runtime snapshot publication`.

## A. Baseline git status

`## main...origin/main [ahead 2]` + untracked `agents-only/a0_reality_spike/`. Chain `9fc7b2bd` /
`140d2d25` / `877aefff` confirmed.

## B. All snapshot publication points (pre-fix)

| Path | lifecycle mutation | snapshot capture | `send_replace` | same mutex throughout? |
| --- | --- | --- | --- | ---: |
| feature `start()` → `Running(g)` | in lock | in lock | **in lock** | YES |
| feature `close()` → `ShutdownRequested(g)` | in lock | in lock | **after unlock** | NO |
| `commit_terminal(g, exit)` | in lock | in lock | **after unlock** | NO |
| stub `start()` → `Running(g)` | in lock | in lock | **after unlock** | NO |
| stub `close()` → `CleanShutdown(g)` | in lock | in lock | **after unlock** | NO |
| bind failure | none (early `?`) | none | none | N/A |
| overflow failure | none (early `Err`, no `current` set) | none | none | N/A |

Only feature `start()` published in-lock; the other four captured under the lock but called
`send_replace` after unlocking — the **backflow** shape.

## C. `start()` published in-lock?

Yes (feature). Pre-fix it inlined `send_replace` inside the locked block; post-fix it calls the
shared `publish_snapshot_locked` helper inside the same block. Stub `start()` was off-lock pre-fix;
fixed.

## D. `close()` published in-lock?

**No (pre-fix)** — both feature and stub `close()` published after unlock. **Fixed**: both publish
via the helper inside the lock. The feature `close()` shutdown signal (`oneshot::Sender::send`) still
fires outside the lock — only snapshot publication must be serialized; the oneshot send is
generation-bound and cannot reorder snapshots.

## E. `commit_terminal()` published in-lock?

**No (pre-fix)** — captured under lock, sent after unlock. **Fixed**: the generation-checked mutation
and the publish now share one `MutexGuard`; `publish_snapshot_locked` is the last statement before the
guard drops.

## F. Backflow risk confirmed?

**Yes, pre-fix.** Capture-under-lock + send-after-unlock means an older `commit_terminal` could
compute snapshot `S_old`, release the lock, and have its `send_replace(S_old)` execute *after* a
concurrent newer `start`/`close` already published `S_new` — leaving the watch channel showing the
stale `S_old`. The fix closes this by making capture+send atomic under the mutex (watch ordering now
matches lifecycle ordering).

## G. Fix vs doc-only

**情况 B → code fix.** Introduced `publish_snapshot_locked(lifecycle: &V2RayLifecycle, runtime_tx:
&watch::Sender<…>)` — the single `send_replace` site — and routed all five publication paths through
it inside their critical section. No revision counter, no extra channel, no new lock (the one
lifecycle mutex suffices). `send_replace` is synchronous (no `.await`), so in-lock publication is
safe.

## H. `Running` → monitor-spawn straight-line review

Confirmed safe. Between the `Running` publish (inside the locked block) and `tokio::spawn(monitor)`
there is **no fallible operation**: lock releases with the tuple, then `tokio::spawn(counter-init)` →
`tracing::info!` → build `StatsServiceImpl` → clone `lifecycle`/`runtime_tx` → `tokio::spawn(monitor)`
→ `Ok(())`. No `?`, no early return. There is **no reachable path where `Running` is published but the
task is never spawned**.

## I. Early shutdown safe?

Yes. If `close()` fires after the lock releases but before the monitor spawns: `close()` takes the
lock, marks `ShutdownRequested(g)`, sets the generation-local `shutdown_requested` marker, and takes
that generation's `shutdown_tx`, then sends `()`. The matching `shutdown_rx` is still a live local in
`start()` being moved into the (about-to-spawn) inner serve task — it is **not dropped**. `oneshot`
buffers the sent value, so the later-spawned inner task's `shutdown_rx.await` resolves immediately and
the monitor maps `Ok(())` + marker=true → `CleanShutdown`. Early shutdown is correctly observed.

## J. Stale terminal rule review

Unchanged and correct: `commit_terminal` clears `current` only if `current.generation == g`, and
advances `last_exit` only if `g > last_exit.generation` (else no regression). Stale terminals not
entering the snapshot are still logged once by their monitor.

## K. Tests added / adjusted

Added two deterministic helper-level tests (both-build):
- `publish_snapshot_locked_sends_current_state` — the single publish site publishes the post-mutation
  state captured + sent under the lock (固化s the helper API shape; guards against
  capture-then-delayed-send).
- `stale_terminal_after_newer_running_does_not_backflow` — gen 1 runs→exits, gen 2 runs, then a late
  stale gen-1 terminal arrives: `current` stays `Running(2)`, `last_exit` stays generation 1 (no
  backflow). Retained C/D coverage (`arbitrary_stale_monitor_order_preserves_state`,
  `late_subscriber_reads_terminal`). v2ray_api total: **23 tests**.

## L. Gates + rustdoc baseline

- `cargo fmt -p sb-core --check`: PASS.
- `cargo test -p sb-core --all-features --lib v2ray_api`: **23 passed; 0 failed**.
- `cargo test -p sb-core --all-features`: 0 failures (all binaries).
- `cargo clippy -p sb-core --all-features --all-targets -- -D warnings`: PASS.
- `cargo check --workspace --all-features`: PASS; `cargo test -p app --all-features v2ray`: 0 failures.
- `git diff --check`: PASS. `verify-consistency.sh`: PASS. `check-boundaries.sh`: exit 0 (537
  assertions, 0 violations).
- `RUSTDOCFLAGS="-D warnings" cargo doc -p sb-core --all-features --no-deps`: **BASELINE RED — 14
  pre-existing broken intra-doc links** in unrelated modules (error.rs, inbound/router/dns), unchanged
  from before; **01E-R1 adds 0** (verified: no doc error cites v2ray / snapshot / generation /
  context.rs / V2RayServer). Hygiene-debt candidate registered: **TIDY-RUSTDOC-LINKS** (historical
  sb-core broken intra-doc links). Not fixed here (out of scope).

## M. New commits

- `fix(sb-core): serialize v2ray runtime snapshot publication`
- `checkpoint: record serialized v2ray snapshot publication`

## N. Final status

`## main...origin/main [ahead 4]` + untracked `agents-only/a0_reality_spike/`. Not pushed.
`SVC-V2RAY-API-01B` remains `DEFER / POLICY REVIEW`.

## State

`APP-SIDECAR-LIVENESS-01E-R1` = DONE (snapshot publication serialized; single in-lock publish site).
Next candidate = 01F (app adapter). Hygiene debt: `TIDY-RUSTDOC-LINKS`. Out-of-scope unchanged:
H5 (instance-scoped stats), H6 (reload start-before-close), H7 (stats ≠ liveness probe).
