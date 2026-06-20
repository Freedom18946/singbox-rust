<!-- tier: B -->
# post_fable_package03_tun_dataplane

## Status

DONE (2026-06-20, post003 extension). Live privileged proof passed end-to-end for
TCP IPv4 + IPv6 through a configured HTTP proxy outbound; UDP NAT and IPv6 reply
packets implemented and verified (UDP by unit test, IPv6 live).

Earlier state was PARTIAL (2026-06-16, code commit `edf42095` + 03b harness boxed;
privileged rerun blocked by missing root). The post003 extension closed it: it added
the UDP/IPv6 datapath, fixed `DirectUdpTransport` connected-socket sends (macOS
EISCONN), and — surfaced by the first live privileged run — fixed TUN egress through
proxy outbounds (`connect_tcp_stream` + boxed-stream session relay), which had
silently limited the TUN datapath to `direct` only.

Runtime wiring and startup honesty (from `edf42095`) remain: `mixed`/default/`smoltcp`
enter Enhanced/smoltcp, `gvisor` enters the same backend with a compatibility warning,
unsupported `system` and non-dry-run `manual` fail loudly, and TUN open/configure failure
blocks startup before `sing-box started`.

Evidence: `post_fable_package03_tun_dataplane_evidence.md` (see the post003 extension and
the privileged proof sections).

## Source Findings

- CAL-10: TUN defaults to skeleton/no-op behavior and GUI stack names are not usable.
- H-5: smoltcp/Enhanced TUN quality is not proven with real traffic.

## Objective

Turn GUI TUN mode from config-accepted into a real, validated dataplane path or make
remaining platform/runtime limits explicit and test-backed.

## Implementation Contract

- Decide and implement how GUI stack values `system`, `gvisor`, and `mixed` map to
  Rust TUN backends.
- Prefer a real backend for GUI defaults; if a value cannot be supported, fail loudly
  with a clear compatibility note rather than silently no-op.
- Validate Enhanced/smoltcp behavior with real traffic on the available platform.
- Preserve existing accepted limitations for redirect/tproxy/tun2socks unless this
  package explicitly changes them.

## Out Of Scope

- Schema acceptance for TUN fields; package 02 owns that.
- GUI launch contract; package 01 owns that.
- Full cross-platform TUN certification beyond the available local platform.

## Acceptance Criteria

- GUI TUN stack values no longer hit the current `InvalidInput` or Manual no-op path
  silently.
- A macOS local TUN smoke test is documented: start, route a simple request, verify
  traffic uses the configured outbound or record a precise platform blocker.
- Unsupported stacks or platforms emit explicit errors or warnings that are visible
  to the operator.

## Tests / Verification

- Add unit tests for stack-name parsing/mapping.
- Add or document a live TUN smoke script under `agents-only` or test fixtures.
- Run TUN-related Rust tests.
- Run `cargo check --workspace --all-features`.
- Run `git diff --check`.

## Docs To Update

- TUN dataplane evidence note under `agents-only/`.
- `agents-only/active_context.md` on completion or de-scope.
- This package file, under Completion Notes.

## Dependencies

- Depends on package 02.
- Benefits from package 07 once GUI launch is available.

## Completion Notes

Code commit `edf42095` implements:

- stack policy for `mixed`, `gvisor`, `system`, `smoltcp`, `manual`, default, and
  unknown values;
- default real runtime (`dry_run: false`) with explicit `dry_run: true` reserved
  for diagnostic manual/no-op;
- runtime mapping for GUI `address`, `route_address`, and
  `route_exclude_address`;
- Enhanced/smoltcp startup preparation of TUN device plus platform hooks before
  supervisor readiness;
- fatal startup propagation through `Bridge.startup_errors` and
  `Supervisor::start_with_registry`.

Evidence: `post_fable_package03_tun_dataplane_evidence.md`.

Verification snapshot:

- `cargo test -p sb-adapters --lib tun --features "adapter-tun tun router"` PASS.
- `cargo test -p sb-adapters --lib enhanced --features "adapter-tun tun router"` PASS.
- `cargo test -p sb-config --lib pf02` PASS.
- `cargo build -p app --bin app --features adapters,clash_api` PASS.
- `cargo check --workspace --all-features` PASS.
- package07 probe harness PASS after the TUN changes.

Live smoke conclusion: normal-user macOS run with GUI-style `stack: "mixed"` TUN
config exited before `sing-box started`; log showed
`failed to prepare TUN runtime backend ... Operation not permitted (os error 1)`.

03b acceptance harness:

- `post_fable_package03b_tun_smoke_harness.sh` added under this package directory.
- Normal-user mode PASS: config validation passed; TUN startup failed before
  `sing-box started` with `Operation not permitted (os error 1)`.
- Privileged mode BLOCKED in this environment: non-root UID 501 and no
  noninteractive sudo (`sudo: a password is required`). The harness exits 3 and
  records exact rerun instructions for a root/admin run.
- Result: package03 remains PARTIAL, but the remaining privileged dataplane proof
  is now boxed behind a reproducible one-command harness.

Package15 closeout:

- `post_fable_package15_acceptance_closeout_manual_gates.sh` indexes the same
  03b normal/privileged gates and records non-root privileged runs as
  `BLOCKED_PRIVILEGE` instead of promoting package03 to DONE.

Package17 external acceptance execution:

- `cargo build -p app --bin app --features gui_runtime` PASS.
- `PF03B_MODE=normal` PASS again under `/tmp/pf17_tun_normal`: config validation
  passed; TUN startup failed before `sing-box started` with
  `Operation not permitted (os error 1)`.
- `PF03B_MODE=privileged` under `/tmp/pf17_tun_privileged` returned exit 3 with
  `status: "BLOCKED"` because this session is UID 501 and `sudo -n true`
  requires a password.
- No root/admin dataplane PASS evidence was obtained, so package03 remains
  PARTIAL. The root rerun command stays:
  `sudo -E PF03B_SKIP_BUILD=1 PF03B_MODE=privileged WORK=/tmp/pf17_tun_privileged bash agents-only/fable5审计报告/post_fable_packages/post_fable_package03b_tun_smoke_harness.sh`.
