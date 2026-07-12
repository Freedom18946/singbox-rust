<!-- tier: B -->
# MT-INTEROP-03 final acceptance

Date: 2026-07-12
Status: CLOSED

## Result

Final full run selected all 103 cases and completed with:

- 101 `PASS`
- 1 `DIV-COVERED`: `p1_fakeip_cache_flush_contract` (`DIV-M-001`, `DIV-M-012`)
- 1 `ENV-LIMITED`: `p2_vmess_dual_dataplane_local`
- 0 `FAIL`

Final red-team rerun window: `l6_local_harness_smoke/20260712T130355Z-*` through
`p2_bench_socks5_throughput/20260712T131304Z-*`.

## Acceptance evidence

- `cargo test -p interop-lab`: 43 passed, including repository-wide case/S4 validation and
  explicit checks that static divergence labels cannot suppress failures.
- Focused DNS cache, WireGuard validator, VLESS address-order tests passed.
- Four self-managed API cases, DNS TTL, WS soak, graceful drain, reload, GUI group-delay,
  FakeIP, deprecated WireGuard, and five protocol-local cases were rerun individually.
- Full `target/debug/interop-lab case run`: 103 selected, 103 unique summaries; outcome counts
  above. FakeIP had zero raw failures. VMess had only its four declared kernel/stage pairs.
- Red-team order regression: a shared `target/debug/app` rebuilt by `p2_protocol_unit_*` caused a
  later lifecycle singleton to fail launch. All legacy debug-app references now resolve through
  the isolated acceptance launcher; the poisoned-shared-binary lifecycle rerun and final full run
  both pass.
- Final hygiene gates: workspace all-target/all-feature check, interop-lab `-D warnings`
  clippy (`--no-deps`; workspace dependency warnings are pre-existing), fmt, boundary V1-V8,
  consistency, shell syntax, and diff hygiene passed.

VMess environment limit is stage-exact. It does not suppress launch failures or unrelated
assertion failures. No S4 label suppresses a raw runtime/assertion failure.
