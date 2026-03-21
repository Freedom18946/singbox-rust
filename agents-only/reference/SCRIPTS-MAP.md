# Scripts Map

> Last updated: 2026-03-21
> Scope: top-level `scripts/` only. This file exists to stop agents from guessing old paths, old binary names, or stale CI assumptions.

## What `scripts/` is

`scripts/` is the repository's local automation layer. It replaces GitHub Actions and mixes:

- local CI / acceptance entrypoints
- E2E smoke and scenario orchestration
- release packaging helpers
- test/bench/stress/fuzz runners
- legacy-but-still-referenced L18/L19 certification scripts

Do not confuse it with `agents-only/06-scripts/`:

- `scripts/` = repo runtime/test/release scripts
- `agents-only/06-scripts/` = AI governance and boundary-check helpers

## Current directory map

```text
scripts/
├── ci/            # Local CI replacement; main verification entrypoints
├── e2e/           # Manual/local E2E orchestration
├── test/          # Acceptance, bench, fuzz, stress runners
├── tools/         # Preflight, release, probe, validation helpers
├── lib/           # Shared shell helpers used by other scripts
├── scenarios.d/   # JSON-returning scenario fragments used by run-scenarios
├── dev/           # Small developer convenience wrappers
├── capabilities/  # Capability report generation helpers
├── l18/           # Historical certification scripts; still referenced by active docs/scripts
├── l19/           # Capability contract helper(s); still referenced
├── soak/          # Long-running soak entrypoint
├── lint/          # Small static checks
├── run            # Human-friendly script dispatcher
├── run-scenarios  # Batch scenario runner with metrics/assert integration
└── root *.sh      # Older standalone utilities; keep per-file judgment
```

## Stable entrypoints agents should know

| Task | Preferred entrypoint | Notes |
|------|----------------------|-------|
| Local CI sweep | `scripts/ci/local.sh` | Fast local verification bundle |
| Acceptance bundle | `scripts/ci/accept.sh` | Local replacement for old CI acceptance jobs |
| Strict local CI | `scripts/ci/strict.sh` | Stricter gate wrapper |
| Batch scenario run | `scripts/run-scenarios` | Uses `scenarios.d/*.zsh` |
| E2E bundle | `scripts/e2e/run.sh` | Wraps compatibility + acceptance subset |
| Preflight | `scripts/tools/preflight.sh` | Local pre-commit / release-prep checks |
| Release matrix | `scripts/tools/release/release-matrix.sh` | Current release packaging entrypoint |
| Metrics validator | `scripts/tools/validation/validate-metrics.sh` | Current validator path |
| Bench acceptance | `scripts/test/bench/l19_perf_acceptance.sh` | Still consumes `scripts/l18/perf_gate.sh` |

## Binary and crate mapping

Many historical scripts assumed a vanished `target/debug/singbox-rust` binary. Current reality:

- `target/debug/app`: multi-command CLI (`check`, `route`, `version`, etc.)
- `target/debug/run`: runtime supervisor for `--config ...`
- `target/debug/sb-explaind`: explain-side service binary
- `target/debug/sb-udp-echo`: UDP echo helper
- `target/debug/sb-version`: version/report helper

Rule of thumb:

- use `app` for `check`, `route`, `version`, formatting, config validation
- use `run` for long-running service startup
- do not introduce new references to `singbox-rust` unless intentionally kept as compatibility fallback

## Example/program mapping

Several scripts call Rust examples directly. The current reliable mappings are:

- `crates/sb-core/examples/socks5_udp_probe.rs`
- `crates/sb-core/examples/dns_query.rs`
- `crates/sb-core/examples/dns_cache_show.rs`
- `crates/sb-core/examples/mock_socks5_upstream.rs`
- `crates/sb-core/examples/router_eval.rs`
- `crates/sb-core/examples/socks5_stub.rs`

When invoking these from scripts, prefer:

```bash
cargo run -q --manifest-path crates/sb-core/Cargo.toml --example <name> -- ...
```

Avoid relying on workspace-root `cargo run --example ...` resolution.

## Directory-specific guidance

### `scripts/ci/`

- Active.
- This is the local CI replacement after `.github/workflows/` disablement.
- `accept.sh`, `local.sh`, `strict.sh`, and `ci/tasks/*.sh` are the main operator-facing entrypoints.
- `ci/tasks/*.sh` generally assume repo root, not `scripts/ci/`, when resolving relative paths.

### `scripts/e2e/`

- Active, but mostly local/manual orchestration.
- `run.sh` is the top-level bundle.
- `README.md` now points users to local entrypoints instead of GitHub Actions.
- Most direct example invocations should go through `crates/sb-core` via `--manifest-path`.

### `scripts/test/`

- Active.
- `acceptance/` holds the A1-A5 style acceptance scripts currently used by `scripts/e2e/run.sh`.
- `bench/`, `fuzz/`, and `stress/` are still meaningful and should not be treated as archive noise.

### `scripts/tools/`

- Active.
- Key subareas:
  - `release/` for packaging and matrix verification
  - `validation/` for focused validators like `validate-metrics.sh`
  - root probe scripts (`probe-http.py`, `probe-http-multi.py`, `probe-socks.py`)
- Current filenames use hyphens, not underscore variants.

### `scripts/scenarios.d/`

- Active.
- Used by `scripts/run-scenarios`.
- These scripts emit JSON snippets; they are not generic standalone user entrypoints.
- Validation-style scenarios now expect:
  - `APP_BIN` for `check`
  - `RUN_BIN` for service startup

### `scripts/l18/` and `scripts/l19/`

- Historical in naming, but not fully dead.
- Still referenced by:
  - `scripts/test/bench/l19_perf_acceptance.sh`
  - multiple `agents-only` reference/archive docs
- Do not archive or delete them casually.

## Agent do / do not

Do:

- inspect the actual script before assuming it is historical noise
- prefer existing active entrypoints over inventing new wrappers
- keep `scripts/` and `agents-only/06-scripts/` mentally separate
- update this file when script entrypoints or binary mapping changes materially

Do not:

- restore GitHub Actions references into `scripts/`
- reintroduce `singbox-rust` as the primary runtime binary name
- assume `scripts/l18/` or `scripts/l19/` are safe to archive just because the phase closed
- assume workspace-root `cargo run --example ...` resolves to the intended crate
