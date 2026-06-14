<!-- tier: B -->
# post_fable_package10_runtime_config_hygiene_evidence

## Status

DONE. Package10 closes CAL-11, CAL-20, CAL-21, CAL-22, CAL-23, CAL-24, and CAL-25
with minimal runtime/config hygiene changes. No package11 external-doc calibration, package05/06
reload/liveness reopening, `.github/workflows/*`, `agents-only/a0_reality_spike/`, or original
fable5 audit body edits.

## CAL Disposition

| CAL | Disposition |
|---|---|
| CAL-11 | Replaced the remaining production `eprintln!` calls in HTTP stop/shutdown paths with `tracing::debug!`. The original tuic/hysteria2 audit hits are absent in current HEAD. |
| CAL-20 | Kept `ServiceManager::close` as a compatibility no-op, documented that supervisor `stop_services` snapshots own service shutdown, and added a test that `Startable::close(&ServiceManager)` does not call service `close()`. |
| CAL-21 | Added validator errors for malformed FakeIP CIDR masks: non-numeric masks emit `TypeMismatch`; out-of-range masks emit `RangeExceeded`; full config load now rejects invalid masks. |
| CAL-22 | Added top-level experimental validation. Malformed typed blocks such as `experimental.cache_file: true` now emit `/experimental` `TypeMismatch`; unknown experimental sub-keys remain forward-compatible. |
| CAL-23 | Unsupported `SystemProxyManager` target cfg now returns `io::ErrorKind::Unsupported` instead of warn-plus-Ok/enabled. Supported macOS/Linux/Windows/Android behavior is unchanged. HTTP inbound keeps its existing non-macOS warn-plus-continue posture. |
| CAL-24 | Replaced the unowned HTTP heartbeat spawn with an RAII guard that aborts the task when `serve_http` exits. |
| CAL-25 | Marked `bootstrap::start_from_config` as legacy compatibility, and pinned CLI/bin live entrypoints to `run_engine::run_supervisor` with source tests. |

## Verification

| Command | Result |
|---|---|
| `cargo test -p sb-config --lib fakeip` | PASS: 5 passed |
| `cargo test -p sb-config --lib experimental` | PASS: 7 passed |
| `cargo test -p sb-config --lib config_from_raw_value` | PASS: 2 passed |
| `cargo test -p sb-core --lib service_manager` | PASS: 5 passed |
| `cargo test -p sb-platform --lib system_proxy` | PASS: 5 passed |
| `cargo test -p sb-adapters --lib http` | PASS: 1 passed; default-feature filter does not compile the HTTP inbound module |
| `cargo test -p sb-adapters --lib http --features "http,socks"` | PASS: 7 passed; covers HTTP inbound readiness/heartbeat guard tests |
| `cargo test -p app --lib --features adapters,clash_api,v2ray_api` | PASS: 184 passed |
| `cargo test -p sb-core --lib` | PASS: 571 passed, 9 ignored |
| `cargo check --workspace --all-features` | PASS |
| `cargo clippy --workspace --all-features --all-targets` | PASS, no warnings emitted |
| `git diff --check` | PASS |

## Residual Follow-Up

No package10 residual follow-up. One existing test ergonomics note remains outside this package:
the HTTP inbound module is behind `sb-adapters` feature `http`, while the current crate feature
matrix pulls `sb-transport` through `socks`; therefore the actual HTTP inbound coverage command
uses `--features "http,socks"`.
