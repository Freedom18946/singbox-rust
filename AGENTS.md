# AGENTS

## Project Status

L1-L25 baseline phases and the 2026-04 MT-* maintenance/acceptance lines are **Closed**.
The **MT-REAL-02** REALITY ClientHello line reached its local-mainline closure via the T3
track (T3-0..T3-2) and is **boxed**: local functional + normalized-profile + coordinated-
GREASE parity are closed, and the official FoxIO JA4 algorithm cross-check is closed (vendored
FoxIO BSD-3 vectors, 2026-07-12); only external/research tail items stay open (extension-order
distribution, HelloChrome_Auto drift, tier-2 camouflage). The repo is **NOT
in pure maintenance mode**, but REALITY is no longer an open implementation frontier; the
current recommended next step lives in `agents-only/active_context.md` (single source of
truth — do not assert a stale phase here).

## Authoritative Sources (read in this order)

- **Live frontier state** (what's happening now, latest round, next step):
  `agents-only/active_context.md` — single source of truth for volatile state.
- **MT-REAL-02 boxed history** (only when a task touches REALITY):
  `agents-only/archive/mt_real_02/` (long report + intakes) +
  `agents-only/mt_real_02_evidence/` (kept in place — paths hard-coded in
  `scripts/tools/test_reality_probe_tools.py` regression tests).
- **Dual-kernel parity ledger** (closed-item accounting only): `labs/interop-lab/docs/dual_kernel_golden_spec.md`.
  This is authoritative for the parity *ledger*, NOT for the live MT-REAL-02 experiment.
- **Phase map**: `agents-only/workpackage_latest.md`.
- **Stable project memory / conventions**: `CLAUDE.md`.

## Hard Rules

- GitHub Actions / workflow automation is permanently disabled in this repository; do not add or restore `.github/workflows/*`.
- Do not treat Rust-only tests, repo-level unit tests, or workflow automation as dual-kernel parity completion.
- Prefer promoting existing strict Rust replay cases to `kernel_mode: both` over adding new Rust-only tests.
- Do not revert unrelated workspace changes.
- Treat repo-level maintenance work (TUN, provider hot-reload e2e, flaky test isolation) as quality work, not parity completion.
- Do not duplicate volatile numbers (parity, test counts, gate status) across docs — point to the single source of truth (see `CLAUDE.md` → 单一真相源).
- Do not create working/scratch directories in the repo root; agent artifacts go under `agents-only/`.

## Dual-Kernel Oracle Rules

- `p0_clash_api_contract_strict` has documented oracle ignores for `/configs`, `/proxies`, `/connections`, `/proxies/direct/delay*` — tracked as `DIV-M-006` through `DIV-M-009` in `dual_kernel_golden_spec.md`.


每一组任务完成之后，自己写测试用例（或者魔改已有的相关的）、自己验证、重新review一遍，没做完不要停，直至没问题；单组实质性验收取得之后，就更新agents-only中相关文档，然后提交相关更改并push到main;
