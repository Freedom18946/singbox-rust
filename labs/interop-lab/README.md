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
- `bootstrap` (`rust` / `go` launch config)
- `gui_sequence`
- `upstream_topology`
- `traffic_plan`
- `subscription_input`
- `faults`
- `assertions`
- `oracle`

A run writes `NormalizedSnapshot` JSON with:

- `http_results`
- `ws_frames`
- `conn_summary`
- `traffic_counters`
- `memory_series`
- `subscription_result`
- `errors`

## Notes

- If `bootstrap.<kernel>.command` is omitted, `interop-lab` treats the kernel as externally running and probes `api.base_url` readiness.
- String placeholders support `${ENV_VAR}` and `{{upstream.<name>}}`.
