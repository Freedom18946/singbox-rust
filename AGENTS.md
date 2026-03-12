# AGENTS

## Current Goal

- Primary objective: increase `Both-Covered` in `labs/interop-lab/docs/dual_kernel_golden_spec.md`.
- Do not treat Rust-only tests, repo-level unit tests, or workflow automation as dual-kernel parity completion.
- Prefer promoting existing strict Rust replay cases to `kernel_mode: both` over adding new Rust-only tests.

## Latest Dual-Kernel Status

- `dual_kernel_golden_spec.md` is the source of truth for parity coverage.
- Current verified total after the 2026-03-12 update: `21 / 60` behaviors are `Both-Covered` (`35.0%`).
- Newly promoted and verified strict both-cases:
  - `p0_clash_api_contract_strict`
  - `p1_gui_proxy_switch_replay`
- Verified artifacts:
  - `labs/interop-lab/artifacts/p0_clash_api_contract_strict/20260312T003634Z-c20d5d82-232b-4f38-a377-9f358218d952/`
  - `labs/interop-lab/artifacts/p1_gui_proxy_switch_replay/20260312T003648Z-0230db00-789d-47c9-8f06-2468ec4e73c8/`

## Known Strict Both-Mode Oracle Rules

- `p0_clash_api_contract_strict` currently needs documented oracle ignores for:
  - `/configs`
  - `/proxies`
  - `/connections`
  - `/proxies/direct/delay*`
- These ignores are tracked in `dual_kernel_golden_spec.md` as:
  - `DIV-M-006`
  - `DIV-M-007`
  - `DIV-M-008`
  - `DIV-M-009`

## Next Priority Order

1. `p1_gui_full_boot_replay`
2. `p1_gui_proxy_delay_replay`
3. `p1_gui_full_session_replay`

## Execution Rules

- For each promoted both-case:
  - ensure case YAML has real `bootstrap.go`
  - ensure required Go config exists
  - add only minimal oracle ignores/tolerances needed for stable parity
  - run the case in both mode
  - run `case diff`
  - update:
    - `labs/interop-lab/docs/dual_kernel_golden_spec.md`
    - `labs/interop-lab/docs/compat_matrix.md`
    - `labs/interop-lab/docs/case_backlog.md` when needed
- Prefer fixing product/config gaps only when they block a target both-case from passing.
- Do not revert unrelated workspace changes.

## Useful Commands

```bash
cargo build -p app --features acceptance,clash_api --bin app

cargo run -p interop-lab -- case run p0_clash_api_contract_strict --kernel both --env-class strict
cargo run -p interop-lab -- case diff p0_clash_api_contract_strict

cargo run -p interop-lab -- case run p1_gui_proxy_switch_replay --kernel both --env-class strict
cargo run -p interop-lab -- case diff p1_gui_proxy_switch_replay
```
