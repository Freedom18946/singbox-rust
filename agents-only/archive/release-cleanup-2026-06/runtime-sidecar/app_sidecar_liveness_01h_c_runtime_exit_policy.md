<!-- tier: B -->
# APP-SIDECAR-LIVENESS-01H-C — sidecar runtime exit policy review

> Product-policy audit only. No Rust / no log-level change. Decides what run-engine does with sidecar
> runtime events, now and (as registered future proposals) later. Mechanism/policy stay separated.

## A. Accepted-commits push result

`git push origin main` → `fffe916d..93059aff main -> main` (01H-B bridge + checkpoint on remote).
Post-push: `## main...origin/main` + untracked `agents-only/a0_reality_spike/`.

## B. Baseline git status

`## main...origin/main` + untracked `a0_reality_spike/`. Chain `93059aff`/`ce980d58`/`fffe916d`
confirmed.

## C. Current log matrix

Source terminal loggers are identical for both sidecars (Clash: `admin_start.rs` outer monitor;
V2Ray: `sb-core v2ray_api.rs` outer monitor). The run-engine consumer adds a `debug` breadcrumb for
`Exited` and a `warn` for `ProjectionClosed`; action is always `Continue`.

| Event / state | source logger | consumer logger | current action | duplicate-log risk |
| --- | --- | --- | --- | --- |
| Clash `CleanShutdown` | `info` "stopped (clean shutdown)" | `debug` breadcrumb | `Continue` | No (info vs debug, distinct targets) |
| Clash `UnexpectedCompletion` | `warn` | `debug` breadcrumb | `Continue` | No (warn vs debug) |
| Clash `ServeError` | `error` (with error) | `debug` breadcrumb | `Continue` | No (error vs debug) |
| Clash `Panicked` | `error` (with panic) | `debug` breadcrumb | `Continue` | No |
| Clash `Cancelled` | `warn` | `debug` breadcrumb | `Continue` | No |
| Clash `Unknown` | `warn` | `debug` breadcrumb | `Continue` | No |
| V2Ray (each, same mapping) | same levels (sb-core monitor) | `debug` breadcrumb | `Continue` | No |
| `ProjectionClosed` | N/A (consumer-side channel) | `warn` | `Continue` | No (only logger) |

Startup bind failure (both sidecars): `warn!(... skipping)` + return `None` → engine continues
(visible-but-nonfatal). No duplicate-log risk exists today: the consumer breadcrumb sits at `debug`,
strictly below the source's per-severity level, and `ProjectionClosed` has no source counterpart.

## D. Clash API product role

1. **Not a core forwarding dataplane** — it is the external-controller management/observability HTTP
   API (proxies, selectors, connections, traffic-WS, logs-WS, config), configured under
   `experimental.clash_api`. Proxy forwarding is done by inbounds/outbounds/router independently.
2. After Clash API death, established **and** new proxy flows continue (the dataplane never depended
   on the HTTP API).
3. What is lost: external management/selection, connection/traffic/log observability, config push via
   the API — not traffic itself.
4. Startup bind failure already lets the engine continue (`api_services.rs` / `admin_start.rs`
   `warn ... skipping`), because the API is auxiliary.
5. Runtime death is **not** more severe than startup failure — both leave the dataplane intact; there
   is no reason runtime death should be stricter than the already-accepted startup policy.
6. No doc / test / historical decision requires "Clash API death → engine must exit." (The only
   liveness requirement found is *startup honesty* — SVC-V2RAY-API-01A — not runtime-fatality.)

## E. V2Ray API product role

1. **Not a core forwarding dataplane** — it is the gRPC stats service (GetStats / QueryStats /
   SysStats), under `experimental.v2ray_api`.
2. Currently an **experimental / optional** sidecar (`service_v2ray_api` feature; `experimental`
   config block).
3. After death: stats query/reset and external gRPC stats clients fail; the dataplane and traffic
   counters' in-process recording are unaffected (counters live in the shared `StatsManager`, H5).
4. Startup bind failure already continues (`api_services.rs` `warn ... skipping`).
5. No reason to escalate runtime death to fatal — stats-only, optional, dataplane-independent.
6. `SVC-V2RAY-API-01B` (ServiceManager health/liveness projection) remains `DEFER / POLICY REVIEW`;
   it constrains this card to **not** pre-empt that review by inventing a health/fatal policy here.

**Principle:** repo evidence supports the default — sidecar startup failure is visible-but-nonfatal,
so sidecar runtime failure must not be silently escalated to fatal.

## F. Startup vs runtime policy consistency

Startup: both sidecars `warn + skip` → engine continues. Runtime (today): source logs per severity +
consumer `Continue`. These are **consistent** — neither startup nor runtime failure is fatal, matching
the auxiliary role of both sidecars. Escalating only runtime death to fatal would be an inconsistent,
surprising asymmetry with no evidence to justify it.

## G. Seven terminal-type judgments

| Exit | semantics | expected | source visible | consumer action |
| --- | --- | ---: | ---: | --- |
| `CleanShutdown` | explicit shutdown done | yes | low-noise `info` | `Continue` (debug breadcrumb only) |
| `UnexpectedCompletion` | serve returned `Ok` without a shutdown request | no | yes (`warn`) | `Continue` (source `warn` is the visibility; no consumer escalation) |
| `ServeError(String)` | serve future returned `Err` | no | yes (`error`) | `Continue` (source `error` already visible) |
| `Panicked(String)` | inner task panicked | no | yes (`error`) | `Continue` (source `error` already visible) |
| `Cancelled` | inner task cancelled | usually no | yes (`warn`) | `Continue` |
| `Unknown` | future variant degraded | unclear | yes (`warn`) | `Continue` (degrade, never normalize to clean) |
| `ProjectionClosed` | state-projection channel gone | ≠ sidecar terminal | N/A | `Continue` + consumer `warn` |

**`ProjectionClosed` ≠ `CleanShutdown` ≠ confirmed sidecar death** — a broken projection link must not
be read as a dataplane fault; it is surfaced as a standalone `warn` and nothing more.

## H. Normal-shutdown timeline

`RuntimeLifecycle::shutdown()`: `watch.shutdown()` → `admin_services.shutdown()` (Clash `close()` →
publishes `ShutdownRequested` → monitor commits `CleanShutdown`) → `bridge.shutdown()` (abort
still-waiting observers, await consumer) → `metrics_exporter.shutdown()`. The supervisor's own
`shutdown_graceful()` (which closes the V2Ray server via sb-core `shutdown_context`) runs **after**
`RuntimeLifecycle::shutdown()` in `run_supervisor`.

## I. Lifecycle-phase false-alarm risk

1. Clash normal shutdown **does** typically project `Exited(CleanShutdown)` (close happens in
   `admin_services.shutdown()`, before `bridge.shutdown()`), → consumer `debug` breadcrumb. Harmless.
2. V2Ray observer is typically **aborted by `bridge.shutdown()` before** the V2Ray terminal (V2Ray
   `close()` is in the later `shutdown_context`), so it usually emits no terminal during normal
   shutdown — no false alarm.
3. The consumer **cannot** distinguish a runtime exception from a normal-shutdown event today (no
   `shutdown_in_progress` marker). With `action = Continue` this does not matter — neither path
   raises an alarm.
4. `Continue` is therefore sufficient to avoid normal-shutdown false alarms.
5. **Key finding:** if a future `degraded`/`fatal` policy is introduced, it MUST carry a runtime
   lifecycle phase / `shutdown_in_progress` marker so a normal-shutdown `CleanShutdown` (or an aborted
   observer) is not mistaken for a fault. (Not implemented here.)

## J. Five action-model comparison

- **Action 1 `Continue`** (current): log visibility + engine continues, no restart/degrade. Fits the
  auxiliary-sidecar role and matches startup policy. **Recommended for this version.**
- **Action 2 `ContinueWithWarning`**: the source monitor already logs `warn`/`error` per severity, so a
  second consumer `warn` is redundant noise. Not needed. Reject.
- **Action 3 `MarkDegraded`**: there is **no** degraded-state container today (supervisor `State` is a
  struct with `current_ir`/`context`/`bridge`, no `Degraded`/`Stopped`/`Fatal`), and no consumer of a
  degraded flag. Would expand public surface; must be a separate proposal. Defer.
- **Action 4 `TerminateEngine`**: conflicts with startup visible-but-nonfatal (F); no sidecar here is
  core dataplane (D/E); would need user opt-in; is product policy, not a technical fix. Reject as
  default; only viable as opt-in strict mode (future proposal).
- **Action 5 `RestartSidecar`**: Clash has no restart control path wired; V2Ray restart is bounded by
  generation/`EADDRINUSE`-retry semantics and would interact with H6 (reload start-before-close); needs
  backoff/max-retries/jitter/observability. Must be a separate proposal. Defer.

## K. Five strategy-route comparison

- **Route 1 (keep log-only `Continue`)**: source terminal logger + run-engine breadcrumb +
  `ProjectionClosed` warn + `Continue`. Satisfies the current goal. **Recommended.**
- **Route 2 (consumer `warn` on unexpected terminal)**: duplicates the source `warn`/`error`. Reject.
- **Route 3 (degraded state)**: no real consumer / no container today → register as proposal, don't
  implement.
- **Route 4 (optional strict mode, opt-in fatal)**: needs config schema + compat + tests + the phase
  marker of I.5; product decision → register as proposal, don't implement.
- **Route 5 (auto restart)**: high complexity + H6 interaction → register as proposal, don't implement.

## L. Current-version unique policy judgment

The already-implemented **log-only `Continue` is the correct, complete landing point for this runtime
liveness work.** All acceptance criteria hold: startup is visible-but-nonfatal; neither sidecar is a
core dataplane; the source terminal logger preserves per-severity visibility; run-engine receives a
structured event; `ProjectionClosed` is separately warned; and no degraded/fatal/restart product
policy is approved.

## M. Close `APP-SIDECAR-LIVENESS-01`?

**Yes — close `APP-SIDECAR-LIVENESS-01`.** The full liveness line is delivered and accepted:
sb-core generation-aware snapshot (01E/E-R1) → app adapter (01F) → Clash task-owner projection (01G-B)
→ run-engine log-only consumer (01H-B) → policy accepted (01H-C). Stricter behavior is deliberately
out of scope and registered as future proposals (N), not folded back into this line.

## N. Future strict / degraded / restart proposal registration

Register **one** evidence-backed future proposal (not auto-claimed):

- **`APP-SIDECAR-POLICY-02A` — optional strict / degraded sidecar runtime policy proposal**
  (DEFER / FUTURE, opt-in). Rationale grounded in real findings: (a) the lifecycle-phase /
  `shutdown_in_progress` marker gap (I.5) is a concrete prerequisite any non-`Continue` policy needs;
  (b) it would coordinate with `SVC-V2RAY-API-01B` (ServiceManager health/liveness, already
  DEFER/POLICY REVIEW). Covers Route 3 (degraded) + Route 4 (opt-in strict) together.

**Not** registering a separate restart proposal: no repo evidence of a real auto-restart requirement,
and restart-on-reload ordering is already tracked by **H6**. Manufacturing a `*-RESTART-03A` backlog
without demand is avoided per the card's guidance.

## O. Backlog priority judgment (next independent card — NOT claimed here)

From active-context candidates, by functional value:

1. **H6 (supervisor reload same-address start-before-close)** — a real *correctness* defect: on reload
   the new sidecar's same-address `pre_bind` can `EADDRINUSE` and the new API is silently dropped.
   Highest value; touches behavior, not just hygiene. **Recommended next.**
2. **TIDY-APP-BREAKER-FLAKE** — intermittent CI failure (parallel global-metrics state). Reliability;
   medium.
3. **SVC-V2RAY-API-01B** — ServiceManager health/liveness projection (policy review); pairs with the
   01H-C-registered `APP-SIDECAR-POLICY-02A`.
4. **TIDY-RUSTDOC-LINKS** — 14 historical broken intra-doc links (gates rustdoc `-D warnings`); hygiene.
5. **TIDY-A0 / TROJAN-FMT** — lower-priority hygiene; scope unconfirmed from active context.

## P. Classification

**`A. LOG_ONLY_CONTINUE_POLICY_ACCEPTED`.** The current log-only `Continue` satisfies the product
semantics (D–L): auxiliary sidecars, startup-consistent, source-visible, structured event delivered,
projection-closed warned, no approved stricter policy. Not B (no degraded container / consumer today),
not C/D (strict/restart are opt-in future product decisions, registered as proposals), not E
(evidence is sufficient).

## Q. Unique recommended next step

**Close `APP-SIDECAR-LIVENESS-01`** and do not claim another sidecar-liveness implementation card.
The next *independent* card (per O, not auto-claimed this turn) should be **H6 — supervisor reload
same-address start-before-close** (highest functional value). `APP-SIDECAR-POLICY-02A` is registered
as a deferred future proposal, not the immediate next step.

## R. Files modified

`agents-only/active_context.md` + `agents-only/archive/release-cleanup-2026-06/runtime-sidecar/app_sidecar_liveness_01h_c_runtime_exit_policy.md` only.
No Rust / Cargo / crate / fixture change.

## S. Checkpoint commit + push

Checkpoint `checkpoint: accept sidecar runtime exit policy` (the two docs); `git diff --check` /
`verify-consistency.sh` / `check-boundaries.sh` run; `a0_reality_spike/` left untracked; then pushed.

## T. Final status

Recorded in the session report. Defers unchanged plus new `APP-SIDECAR-POLICY-02A` (DEFER / FUTURE).

## State

`APP-SIDECAR-LIVENESS-01H-C` = `A. LOG_ONLY_CONTINUE_POLICY_ACCEPTED`; **`APP-SIDECAR-LIVENESS-01`
CLOSED** (runtime liveness line delivered + policy accepted). Registered future proposal:
`APP-SIDECAR-POLICY-02A` (optional strict/degraded, DEFER/FUTURE). Recommended next independent card:
**H6**. Defers unchanged: `SVC-V2RAY-API-01B` = DEFER/POLICY REVIEW; `APP-V2RAY-SURFACE-02D` = CLOSED;
V2Ray breaking cleanup = DEFER/FUTURE MAJOR; `TIDY-RUSTDOC-LINKS`, `TIDY-APP-BREAKER-FLAKE` = DEFER.
Out-of-scope unchanged: H5/H6/H7.
