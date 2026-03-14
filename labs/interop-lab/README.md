# interop-lab

`interop-lab` is a workspace subproject for Go sing-box / GUI for sing-box / Rust kernel interoperability simulation.

## Scope

- Replay GUI-facing Clash API HTTP/WS contracts.
- Model subscription parse paths (JSON / YAML / Base64).
- Simulate upstream services (HTTP/TCP/UDP/WS/DNS/TLS echo).
- Produce normalized snapshots and Go-vs-Rust diff reports.

## Layout

- `cases/`: YAML `CaseSpec` definitions.
- `artifacts/`: run outputs (`summary.json`, snapshots, diff reports).
- `docs/`: L5 contract matrix, case backlog, oracle rules.

## CLI

```bash
cargo run -p interop-lab -- case list
cargo run -p interop-lab -- case run l6_local_harness_smoke
cargo run -p interop-lab -- case run --kernel both
cargo run -p interop-lab -- case diff p0_clash_api_contract
cargo run -p interop-lab -- report open p0_clash_api_contract --print
```

## Build prerequisites

Cases that launch the Rust app binary now require Clash API support in the built artifact.

```bash
cargo build -p app --features acceptance,clash_api --bin app
```

If `bootstrap.<kernel>.command` is omitted, `interop-lab` treats that kernel as externally running and only probes its API readiness.

## External Clash API replay

`p0_clash_api_contract` targets already-running kernels by default.

```bash
export INTEROP_RUST_API_BASE=http://127.0.0.1:19090
export INTEROP_RUST_API_SECRET=your-secret
export INTEROP_GO_API_BASE=http://127.0.0.1:29090
export INTEROP_GO_API_SECRET=your-secret
cargo run -p interop-lab -- case run p0_clash_api_contract --kernel both
cargo run -p interop-lab -- case diff p0_clash_api_contract
```

## CaseSpec schema (current)

Top-level fields:

- `id`
- `kernel_mode` (`rust|go|both`)
- `env_class` (`strict|env_limited`, default `strict`)
- `tags` (optional string array)
- `owner` (optional)
- `bootstrap` (`rust` / `go` launch config)
- `gui_sequence`
- `upstream_topology`
- `traffic_plan`
- `subscription_input`
- `faults`
- `assertions`
- `oracle`

`traffic_plan` additional actions:

- `kernel_control` (`action=restart|reload`, `target=rust|go`, `wait_ready_ms`)
- `fault_jitter` (`target`, `base_ms`, `jitter_ms`, `ratio`)
- `api_ws_soak` (`path`, `clients_per_wave`, `waves`, `wave_delay_ms`, `min_success_ratio`, `frame_timeout_ms`)

`assertions` operators:

- `eq`, `ne`, `exists`, `not_exists`, `gt`, `gte`, `lt`, `lte`, `contains`, `regex`

A run writes `NormalizedSnapshot` JSON with:

- `http_results`
- `ws_frames`
- `conn_summary`
- `traffic_counters`
- `memory_series`
- `subscription_result`
- `errors`

## Notes

- String placeholders support `${ENV_VAR}` and `{{upstream.<name>}}`.
- `case run` supports filters: `--priority`, `--tag`, `--exclude-tag`, `--env-class`.

## `/connections` WS soak workflows

`p2_connections_ws_concurrency_suite`, `p2_connections_ws_soak_suite`, and `p2_connections_ws_soak_dual_core` now use the built-in `api_ws_soak` traffic action. The action opens waves of WebSocket clients directly against `session.api`, validates `/connections` frame structure, and records success/failure into the case snapshot.

Rust-only runs:

```bash
cargo build -p app --features acceptance,clash_api --bin app
cargo run -p interop-lab -- case run p2_connections_ws_concurrency_suite
cargo run -p interop-lab -- case run p2_connections_ws_soak_suite
```

Dual-kernel replay with a manually managed Go oracle:

```bash
go_fork_source/sing-box-1.12.14/sing-box run -c labs/interop-lab/configs/l18_gui_go.json
cargo run -p interop-lab -- case run p2_connections_ws_soak_dual_core
cargo run -p interop-lab -- case diff p2_connections_ws_soak_dual_core
```

Dual-kernel trend gate with a script-managed Go oracle:

```bash
MANAGE_GO_ORACLE=1 ITERATIONS=1 KERNEL=both RUN_ENV_CLASS=strict \
  labs/interop-lab/scripts/run_case_trend_gate.sh p2_connections_ws_soak_dual_core
```

Dual-kernel aggregate report with a script-managed Go oracle:

```bash
MANAGE_GO_ORACLE=1 ITERATIONS=1 KERNEL=both RUN_ENV_CLASS=strict \
  ARTIFACTS_DIR=labs/interop-lab/artifacts/dual_core_trend \
  labs/interop-lab/scripts/aggregate_trend_report.sh p2_connections_ws_soak_dual_core
```

`run_case_trend_gate.sh`, `run_dual_kernel_diff_replay.sh`, and `aggregate_trend_report.sh` all honor the following optional environment variables when `MANAGE_GO_ORACLE=1`:

- `GO_ORACLE_BIN`
- `GO_ORACLE_CONFIG`
- `GO_ORACLE_API_URL`
- `GO_ORACLE_API_SECRET`
- `GO_ORACLE_BUILD_IF_MISSING`
