<!-- tier: B -->
# post_fable_package15_acceptance_closeout_manual_gates_evidence

## Scope

Package15 is a closeout/runbook package. It changes no product code and does
not claim package03/package07 DONE. It records the automatic closeout state and
the two remaining external acceptance gates.

## State Summary

| Area | Status | Evidence |
|---|---|---|
| Automatic post-FABLE packages | DONE | 01/02/04/05/06/08/09/10/11/12/13/14 are closed in the package map. |
| package03 TUN dataplane | PARTIAL boxed | 03b normal-user proof is deterministic; privileged real-traffic proof needs root/admin. |
| package07 GUI E2E | PARTIAL blocked | Process-contract harness passes; interactive Wails desktop-window flow is not agent-drivable. |
| package11 capabilities generator | Non-blocking residual | Static evidence map remains stale; package11 recorded it as future doc-tool repair, not a package15 blocker. |

## Closeout Script Evidence

Path:

```bash
agents-only/fable5审计报告/post_fable_packages/post_fable_package15_acceptance_closeout_manual_gates.sh
```

Behavior:

- writes all artifacts under `WORK`;
- builds `app --features gui_runtime`;
- runs package07 process-contract harness;
- runs package03b normal-user proof when non-root;
- runs package03b privileged proof and records non-root exit 3 as
  `BLOCKED_PRIVILEGE`;
- records real Wails GUI as `MANUAL_REQUIRED`.

## Verification Results

| Command | Result |
|---|---|
| `cargo build -p app --bin app --features gui_runtime` | PASS. |
| `./target/debug/app version` | PASS: printed `sing-box version 0.1.0 (0d1cbe7b1426)`. |
| `WORK=/tmp/pf15_gui_runtime bash agents-only/fable5审计报告/post_fable_packages/post_fable_package07_probe_harness.sh` | PASS: 14/14. |
| `PF03B_SKIP_BUILD=1 WORK=/tmp/pf15_tun_normal PF03B_MODE=normal bash agents-only/fable5审计报告/post_fable_packages/post_fable_package03b_tun_smoke_harness.sh` | PASS: permission/backend failure before `sing-box started`. |
| `PF03B_SKIP_BUILD=1 WORK=/tmp/pf15_tun_privileged PF03B_MODE=privileged bash agents-only/fable5审计报告/post_fable_packages/post_fable_package03b_tun_smoke_harness.sh` | BLOCKED, exit 3: root/admin privileges required. |
| `WORK=/tmp/pf15_acceptance_closeout bash agents-only/fable5审计报告/post_fable_packages/post_fable_package15_acceptance_closeout_manual_gates.sh` | PASS_WITH_MANUAL_BLOCKERS: 4 pass, 2 blocked, 0 fail. |
| `cargo test -p app --test gui_runtime_profile --features gui_runtime` | PASS: 3 passed. |
| `cargo test -p app --test inbound_http --features gui_runtime` | PASS: 6 passed. |
| `cargo test -p sb-adapters --lib tun --features "adapter-tun tun router"` | PASS: 71 passed, 1 ignored. |
| `cargo check --workspace --all-features` | PASS. |
| `cargo clippy --workspace --all-features --all-targets` | PASS. |
| `git diff --check` | PASS. |

## Environment Result

- Root/admin available: no. Local UID was 501 and `sudo -n true` failed with
  `sudo: a password is required`.
- Interactive Wails desktop window driven: no; manual acceptance remains required.

## Remaining Manual Gates

- package03 can become DONE only after the privileged 03b dataplane proof passes.
- package07 can become DONE only after a real Wails desktop-window run is driven
  and documented.
