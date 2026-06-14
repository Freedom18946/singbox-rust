<!-- tier: B -->
# post_fable_package14_gui_runtime_build_profile_evidence

## Scope

Package14 closes package07/F-2 only. It defines `app` feature profile
`gui_runtime` as the GUI.for SingBox process-contract runtime build:
`router + adapters + clash_api`. The default app build remains minimal and is
not documented as a GUI drop-in proxy runtime.

## Implementation Evidence

| Area | Evidence |
|---|---|
| Feature contract | `app/Cargo.toml` declares `gui_runtime = ["router", "adapters", "clash_api"]`. |
| Default build positioning | `default = ["router"]` is retained and the manifest comment states it is not a GUI drop-in proxy runtime. |
| V2Ray API scope | `gui_runtime` intentionally excludes `v2ray_api`; use `--features gui_runtime,v2ray_api` for configs that require it. |
| Build/profile guard | `app/tests/gui_runtime_profile.rs` parses the manifest and asserts the GUI runtime/default feature relationship; under `--features gui_runtime` it also asserts the expected compile-time cfgs. |
| Harness guidance | `post_fable_package07_probe_harness.sh` now points missing kernels and build instructions at `cargo build -p app --bin app --features gui_runtime`. |
| package07 status | package07 docs mark F-2 closed by package14 but keep package07 PARTIAL because interactive Wails desktop-window E2E remains blocked. |

## Verification Results

| Command | Result |
|---|---|
| `cargo test -p app --test gui_runtime_profile` | PASS: 2 passed. |
| `cargo test -p app --test gui_runtime_profile --features gui_runtime` | PASS: 3 passed. |
| `cargo build -p app --bin app --features gui_runtime` | PASS. |
| `./target/debug/app version` | PASS: printed `sing-box version 0.1.0`. |
| `WORK=/tmp/pf14_gui_runtime bash agents-only/fable5审计报告/post_fable_packages/post_fable_package07_probe_harness.sh` | PASS: harness 14/14. |
| `cargo test -p app --lib --features gui_runtime,v2ray_api` | PASS: 184 passed. |
| `cargo test -p app --test inbound_http --features gui_runtime` | PASS: 6 passed. |
| `cargo test -p sb-adapters --test e2e_proxy_flow --features "http,socks"` | PASS: 5 passed. |
| `cargo check --workspace --all-features` | PASS. |
| `cargo clippy --workspace --all-features --all-targets` | PASS. |
| `git diff --check` | PASS. |

## Residual Limits

- `gui_runtime` is not full `parity`; it is the GUI process-contract runtime
  profile.
- V2Ray API remains opt-in by design.
- package07 remains PARTIAL until a real interactive Wails desktop-window flow
  can be driven.
