# L19 Reality Alignment Report

## Snapshot

- Date (UTC): 2026-03-04T15:53:00Z
- Scope: L19 Batch A-E closure (`L19.1.1` to `L19.5.2`)
- Baseline: `agents-only/03-planning/13-L19-REALITY-ALIGNMENT-WORKPACKAGES.md`

## Delivery Summary

| Batch | Workpackages | Status | Key evidence |
| --- | --- | --- | --- |
| A | `L19.1.1`~`L19.1.4` | ✅ closed | `reports/capabilities.json`, `scripts/check_claims.sh`, `docs/capabilities.md` |
| B | `L19.2.1`~`L19.2.4` | ✅ closed | capability probe + TLS provider logs + QUIC/ECH guardrail |
| C | `L19.3.1`~`L19.3.3` | ✅ closed | ADR + strict boundary gate + overlap migration matrix |
| D | `L19.4.1`~`L19.4.3` | ✅ closed | `scripts/test/tun_linux_e2e.sh`, `scripts/test/tun_macos_longrun.sh`, `scripts/test/bench/l19_perf_acceptance.sh` |
| E | `L19.5.1`~`L19.5.2` | ✅ closed | `GET /capabilities` contract endpoint + GUI contract suite |

## Commit Evidence

- `fa14627` - L19 Batch A (capability ledger + claim guard)
- `b74b48e` - `L19.3.1` ADR decision
- `ad1b78b` - `L19.3.2` strict boundary upgrade
- `17cf1e6` - `L19.3.3` overlap matrix + migration backlog
- `53efee3` - `L19.4.1` Linux TUN e2e profile
- `1d4906b` - `L19.4.2` macOS TUN longrun profile
- `ed13cdf` - `L19.4.3` layered performance acceptance contract
- `0429a3e` - `L19.5.1` `/capabilities` endpoint + HTTP contract coverage

## L19.5 Contract Closure

### Endpoint Contract

`GET /capabilities` now returns machine-readable capability negotiation payload:

- `schema_version`
- `compat_version`
- `clash_api_compat_version`
- `feature_flags`
- `source`
- `capability_matrix[]`

Source file: `crates/sb-api/src/clash/handlers.rs`
Router binding: `crates/sb-api/src/clash/server.rs`

### GUI Contract Suite (fixed request set + shape checks)

Suite: `sb-api.capabilities_contract_suite`

Fixed request set:

- `GET /`
- `GET /version`
- `GET /capabilities`
- `GET /proxies`
- `GET /connections`
- `GET /providers/proxies`

Artifacts:

- `crates/sb-api/tests/capabilities_contract.rs`
- `scripts/l19/capabilities_contract.sh`
- `reports/l19/contracts/capabilities_contract.json`
- `reports/l19/contracts/capabilities_contract.log`

Execution result:

- status: `PASS`
- command: `cargo test -p sb-api capabilities_contract_suite -- --nocapture`
- exit_code: `0`

## Gate Results

- `bash scripts/check_claims.sh` -> `PASS`
- `bash agents-only/06-scripts/check-boundaries.sh` -> `PASS`
- `bash scripts/ci/tasks/docs-links.sh` -> `PASS`
- `bash scripts/l19/capabilities_contract.sh` -> `PASS`

## Residual Notes

- `/capabilities` reads `reports/capabilities.json` (supports env override `SB_CAPABILITIES_JSON`); when source is missing it returns deterministic fallback with `errors` field.
- Performance acceptance in `L19.4.3` has a unified entrypoint, but full baseline/router/parity benchmark execution depends on local runtime prerequisites.

## Conclusion

L19 objective is closed for current scope: documentation claims, compile/runtime capability evidence, boundary governance, real dataplane/performance contracts, and GUI-facing machine contract are aligned and auditable.
