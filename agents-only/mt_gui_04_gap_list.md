<!-- tier: B -->
# MT-GUI-04: Gap List

**Date**: 2026-04-12
**Purpose**: Precise enumeration of every item that is NOT fully closed by the exhaustive sweep.

---

## 1. Capabilities NOT fully closed in this sweep

**Count: 0 within the 55-item GUI-surface inventory.**

Every declared-complete capability (A-01 through F-02) has a status of PASS-STRICT,
PASS-DIV-COVERED, or PASS-ENV-LIMITED. None are FAIL. None are NEW FINDING.

---

## 2. ENV-LIMITED items (have real coverage elsewhere)

These 13 items are PASS-ENV-LIMITED in this sweep because the test uses curl HTTP Upgrade
probes rather than real RFC 6455 WebSocket clients. All have real WS coverage in the
interop-lab test suite:

| Cap ID | Capability | Real coverage |
|--------|-----------|--------------|
| B-14 | WS /traffic | `p0_clash_api_contract_strict` (both), `p1_gui_full_boot_replay` (both) |
| B-15 | WS /memory | `p0_clash_api_contract_strict` (both), `p1_gui_full_boot_replay` (both) |
| B-16 | WS /connections | `p2_connections_ws_soak_dual_core` (both) |
| B-17 | WS /logs | `p0_clash_api_contract_strict` (both), `p1_gui_full_boot_replay` (both) |
| B-18 | WS auth valid | `p1_clash_api_auth_enforcement` (both) |
| B-19 | WS auth wrong | `p1_clash_api_auth_enforcement` (both) |
| B-20 | WS auth missing | `p1_clash_api_auth_enforcement` (both) |
| C-12 | WS through SOCKS5 | MT-GUI-02 DP-12 PASS-STRICT (Python WS client) |
| C-13 | TCP echo via SOCKS5 | MT-GUI-02 DP-11 PASS-STRICT (Python TCP client) |
| E-03 | /traffic WS observable | Same as B-14 |
| E-04 | /memory WS observable | Same as B-15 |
| E-05 | /logs WS observable | Same as B-17 |
| (B-18) | (duplicate of WS auth) | — |

**Conclusion**: 0 items lack real verification evidence when combining this sweep with
interop-lab and MT-GUI-02.

---

## 3. Golden spec BHVs outside GUI-surface scope

These BHVs are in the golden spec (56 total) but are NOT in the GUI-surface capability
inventory because they test non-GUI kernel behaviors:

| BHV | Domain | Status | Where verified |
|-----|--------|--------|----------------|
| BHV-DP-002 | SOCKS5 UDP | Covered | `p1_rust_core_udp_via_socks` (both) |
| BHV-DP-003 | HTTP CONNECT | Covered | `p1_http_connect_via_http_proxy` (both) |
| BHV-DP-004 | Mixed inbound | Covered | `p1_mixed_inbound_dual_protocol` (both) |
| BHV-DP-007 | URLTest auto | Covered | `p1_urltest_auto_select_replay` (both) |
| BHV-DP-009 | Chain proxy | Covered | `p2_dataplane_chain_proxy` (both) |
| BHV-DP-010 | Rule dispatch | Covered | `p1_gui_connections_tracking` (both) |
| BHV-DP-011 | route.final | Covered | `p1_gui_full_session_replay` (both) |
| BHV-DP-012 | Domain rules | Covered | `p1_domain_rule_via_socks` (both) |
| BHV-DP-013 | IP-CIDR rules | Covered | `p1_ip_cidr_rule_via_socks` (both) |
| BHV-DP-014 | Sniff detect | Covered | `p1_sniff_rule_action_tls` (both) |
| BHV-DP-015 | DNS resolve | Covered | `p1_rust_core_dns_via_socks` (both) |
| BHV-DP-016 | FakeIP pool | Covered | `p1_fakeip_dns_query_contract` (both) |
| BHV-DP-017 | FakeIP flush | Covered | `p1_fakeip_cache_flush_contract` (both) |
| BHV-DP-018 | DNS cache TTL | Covered | `p1_dns_cache_ttl_via_socks` (both) |
| BHV-LC-005 | Hot reload | Covered | `p1_inbound_hot_reload_sighup` (both) |
| BHV-LC-006 | State preservation | Covered | `p1_selector_switch_traffic_replay` (both) |
| BHV-LC-008 | WS close notify | Covered | `p1_gui_ws_reconnect_behavior` (both) |
| BHV-LC-009 | Resource cleanup | Covered | `p1_lifecycle_restart_reload_replay` (both) |
| BHV-PF-001 | HTTP latency | Covered | `p1_rust_core_http_via_socks` (both) |
| BHV-PF-002 | API latency | Covered | `p0_clash_api_contract_strict` (both) |
| BHV-PF-003 | Peak RSS | Covered | `p2_connections_ws_soak_dual_core` (both) |
| BHV-PF-004 | Memory stable | Covered | `p2_connections_ws_soak_dual_core` (both) |
| BHV-PF-005 | Startup time | Covered | `p1_version_endpoint_contract` (both) |

**All 23 are covered by interop-lab `kernel_mode: both` cases. None are gaps.**

---

## 4. Structurally uncoverable BHVs

| BHV | Reason | DIV ID | Resolution |
|-----|--------|--------|------------|
| BHV-SV-005 | Go provider endpoints return stubs | DIV-H-005 | Rust-only e2e via `clash_http_e2e.rs` |
| BHV-SV-006 | Go provider endpoints return stubs | DIV-H-005 | Rust-only e2e via `clash_http_e2e.rs` |
| BHV-SV-007 | Go provider endpoints return stubs | DIV-H-005 | Rust-only e2e via `clash_http_e2e.rs` |
| BHV-LC-003 | Service failure isolation not real | DIV-H-006 | Rust-only diagnostic only |

**These 4 cannot be dual-kernel tested regardless of sweep methodology.** They are the same
4/56 gap documented in the golden spec since its creation. This is a Go-side limitation,
not a Rust-side gap.

---

## 5. Summary

| Category | Count |
|----------|-------|
| GUI-surface capabilities verified | 55 / 55 (100%) |
| Interop-lab BHVs verified (outside GUI scope) | 23 / 23 (100%) |
| Structurally uncoverable BHVs | 4 (unchanged) |
| **Total BHV coverage** | **52 / 56 (92.9%)** — unchanged from golden spec |
| Items with "coarse pass, fine unverified" | **0** |
| New blockers | **0** |
| New findings | **0** |
