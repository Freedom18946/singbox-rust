# AGENTS

## Project Status

All phases (L1-L25) are **Closed**. The repository is in **maintenance mode**.

## Authoritative Sources

- Dual-kernel parity status: `labs/interop-lab/docs/dual_kernel_golden_spec.md` (single source of truth)
- Current context: `agents-only/active_context.md`
- Phase map: `agents-only/workpackage_latest.md`

## Hard Rules

- GitHub Actions / workflow automation is permanently disabled in this repository; do not add or restore `.github/workflows/*`.
- Do not treat Rust-only tests, repo-level unit tests, or workflow automation as dual-kernel parity completion.
- Prefer promoting existing strict Rust replay cases to `kernel_mode: both` over adding new Rust-only tests.
- Do not revert unrelated workspace changes.
- Treat repo-level maintenance work (TUN, provider hot-reload e2e, flaky test isolation) as quality work, not parity completion.

## Dual-Kernel Oracle Rules

- `p0_clash_api_contract_strict` has documented oracle ignores for `/configs`, `/proxies`, `/connections`, `/proxies/direct/delay*` — tracked as `DIV-M-006` through `DIV-M-009` in `dual_kernel_golden_spec.md`.
