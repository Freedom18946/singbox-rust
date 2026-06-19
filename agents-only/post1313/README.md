<!-- tier: B -->
# post1313 Planning Index

Purpose: planning-only work package set after refreshing the external references to
Go `sing-box@v1.13.13` and GUI.for SingBox `v1.25.1`.

This directory does not reopen REALITY T3, does not resume Wails desktop automation, and
does not claim implementation completion. It translates the current diff evidence into
small executable packages for later implementation rounds.

## Source Anchors

- Live state: `agents-only/active_context.md`
- Go parity ledger / diff table: `agents-only/reference/GO_PARITY_MATRIX.md`
- Go design extraction: `agents-only/reference/GO-DESIGN-REFERENCE.md`
- GUI 1.25.1 source snapshot: `GUI_fork_source/GUI.for.SingBox-1.25.1`
- GUI 1.25.1 upgrade report: `GUI_fork_source/GUI.for.SingBox-1.25.1/UPGRADE_1.19.0_TO_1.25.1.md`
- post-FABLE closeout map: `agents-only/fable5审计报告/post_fable_packages/README.md`
- Capability snapshot caveat: `docs/capabilities.md` and `reports/capabilities.json`

## Planning Rules

- `active_context.md` remains the only volatile status source.
- GUI joint testing remains paused; package20 / desktop automation stays closed until the
  user explicitly resumes that line.
- Go/GUI source snapshots are evidence, not vendored implementation targets.
- Do not touch `agents-only/a0_reality_spike/`.
- GitHub Actions stay disabled; all future acceptance is local.
- Do not treat Rust-only unit tests or accepted-limitation closure as dual-kernel parity
  movement.
- Every future implementation package must add/adapt tests, verify locally, review, update
  relevant `agents-only` docs, then commit and push.

## Files

- `diff_analysis.md`: evidence-backed diff analysis and prioritization.
- `package_index.md`: sequence, dependency graph, and package map.
- `p1313_01_config_schema_and_gui_fixtures.md`
- `p1313_02_dns_transport_manager.md`
- `p1313_03_dns_rule_actions_and_cache_semantics.md`
- `p1313_04_route_rule_engine_and_network_strategy.md`
- `p1313_05_lifecycle_managers_and_start_order.md`
- `p1313_06_adapter_surface_contracts.md`
- `p1313_07_cachefile_persistence.md`
- `p1313_08_clash_api_and_gui_channel_contract.md`
- `p1313_09_udp_nat_and_packet_dataplane.md`
- `p1313_10_v2ray_stats_and_router_tracker.md`
- `p1313_11_service_regression_closeout.md`
- `p1313_12_gui1251_low_priority_contract.md`

## Recommended Order

1. P1313-01 establishes current config fixtures and prevents schema drift while other
   packages move.
2. P1313-02 and P1313-03 close DNS core semantics in layers: transport/client first, rule
   action/cache behavior second.
3. P1313-05 then regularizes startup/lifecycle order so DNS, Clash, cache, and service
   packages have a stable container.
4. P1313-06 and P1313-07 expose the missing adapter/cache surfaces used by route, DNS,
   Clash, selector, and FakeIP flows.
5. P1313-04 and P1313-09 finish routing semantics and UDP dataplane behavior on top of the
   stabilized adapter layer.
6. P1313-08 and P1313-10 close externally visible control-plane contracts.
7. P1313-11 revalidates service-specific tails without expanding scope.
8. P1313-12 refreshes GUI 1.25.1 golden shape while desktop automation remains paused.
