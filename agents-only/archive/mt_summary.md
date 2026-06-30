<!-- tier: C -->
# MT Lines Compressed History

Purpose: compact old MT maintenance, GUI, deployment, and audit records.
Live frontier and build/gate status remain in `agents-only/active_context.md`.

## MT Maintenance

- MT-OBS, MT-RTC, MT-HOT-OBS, MT-SVC, MT-TEST, MT-RD, MT-PERF, MT-ADP, MT-MLOG, MT-ADM, MT-DEEP, MT-CONTRACT, and MT-CONV closed in the 2026-04 maintenance/acceptance cycle.
- Maintenance recap conclusion: current repo facts supported archive-safe closeout; no active blocker was carried from the maintenance line.
- Future work should be grouped by real blocker or high-level theme, not by reviving `WP-30k`-style micro-cards.
- Maintenance, docs, runtime hygiene, and repo-level tests are not dual-kernel parity completion.

## MT-GUI

- MT-GUI-01 ran broad GUI-driven Go/Rust acceptance and found the `downloadTotal` divergence later tracked as covered behavior.
- MT-GUI-02 and MT-GUI-03 classified control-plane/data-plane divergence families.
- MT-GUI-04 performed exhaustive per-capability acceptance over the declared GUI-facing capability set. Outcome at that time: no new fail and no new finding; results were classified as strict pass, documented divergence covered, or environment-limited.
- Covered divergence families included `/configs`, `/proxies`, `/connections`, delay endpoint behavior, DNS query body shape, non-resolvable DNS behavior, and cumulative `downloadTotal`.
- WebSocket curl limitations were environment-limited in that sweep but covered elsewhere by real WS interop/lab probes.
- MT-GUI records are acceptance evidence, not current parity ledger authority.

## MT-DEPLOY

- Deployment baseline checked debug/release build parity, clippy all-features, app library tests, version/config checks, `run --check`, near-startup bind behavior, and package script smoke paths.
- Network, Docker, and orchestration checks remained environment-limited.
- Old deployment-next-stage wording was superseded first by MT-REAL-02 and later by the current `active_context.md` frontier.

## MT-AUDIT

- MT-AUDIT-01 was audit-quality work, not parity movement.
- Main categories: globals/singletons, async lifecycle/spawns, panic surface, config boundaries, mega-files, build/tests, lint/gate.
- Resolved or absorbed areas included HTTP client global handling, prefetch global handling, AnyTLS/SSH spawn elimination, validator v2 split, IR facade, bootstrap reduction, `deny_unknown_fields` / Raw bridge work, and no-unwrap hotpath gate.
- Future-boundary areas remained: lifecycle-aware compat shells, prometheus metrics statics, registry bootstrap, tracked spawns, stale boundary assertions, mega-files, and selected TUN/protocol corner cases.
- Correct use: combine current source facts, `reference/Rust_spec_v2.md`, and this compressed audit memory. Do not quote old raw audit counts as current blockers.
