<!-- tier: A -->
# Dual Kernel Golden Spec

> Authoritative behavioral alignment standard for Go (sing-box 1.13.13) and Rust (singbox-rust) dual-kernel testing.
> Stable reference for diff report interpretation, case promotion planning, and parity auditing.

---

## S1: Functional Domain Map

| Code | Domain | Sub-domains | Behaviors | Both-Covered | Coverage |
|------|--------|-------------|-----------|--------------|----------|
| CP | Control Plane | 4 (HTTP / WS / Auth / Non-GUI) | 21 | 21 | 100.0% |
| DP | Data Plane | 4 (Inbound / Outbound / Routing / DNS) | 41 | 41 | 100.0% |
| LC | Lifecycle | 3 (Startup / Reload / Shutdown) | 9 | 8 | 88.9% |
| SV | Services | 1 (Provider) | 3 | 0 | 0% |
| PF | Performance | 3 (Latency / Memory / Startup) | 5 | 5 | 100.0% |
| **Total** | | **15** | **79** | **75** | **94.9%** |

> **Reading this table**: "Both-Covered" = at least one `kernel_mode: both` case exercises this behavior.
> Coverage gaps still cluster in SV (structural) and LC (1 infeasible).
>
> **SV.1 Reclassification (2026-03-16)**: 4 subscription-parsing BHVs (BHV-SV-001…004) removed from
> the dual-kernel parity denominator. These behaviors test the interop-lab harness's own subscription
> parser (`labs/interop-lab/src/subscription.rs`), not kernel behavior. Neither Go nor Rust kernel
> performs subscription parsing — it is a GUI-layer function handled externally by GUI.for.SingBox.
> Promoting these cases to `kernel_mode: both` would produce trivially clean diffs (same harness code
> parsing the same input twice) without adding any parity evidence. The 8 subscription case YAMLs
> remain as Rust-only harness validation tests.

---

## S2: Diff Engine Dimension Map

Maps `diff_report.rs` comparison dimensions to behavior IDs in S3. When a diff fails, look up the dimension here to find the relevant BHV-IDs.

| Diff Dimension | Field in DiffReport | Compares | Related BHV-IDs | Oracle Controls |
|----------------|---------------------|----------|-----------------|-----------------|
| HTTP | `http_mismatches` | status + body_hash per endpoint | BHV-CP-001 … 007, 018 … 021 | `ignore_http_paths` |
| WebSocket | `ws_mismatches` | frame_count + frame_hash per stream | BHV-CP-008 … 011 | `ignore_ws_paths` |
| Subscription | `subscription_mismatches` | format + node_count | ~~BHV-SV-001 … 004~~ | — |

> **Subscription dimension deprecated (2026-03-16)**: BHV-SV-001…004 reclassified as harness-only.
> The subscription diff dimension remains functional in the harness but does not contribute to
> dual-kernel parity scoring. See S1 reclassification note.
| Traffic | `traffic_mismatches` | action success + counter up/down | BHV-DP-001 … 016, BHV-DP-018 … 041, BHV-PF-001, BHV-PF-002 | `tolerate_counter_jitter`, `counter_jitter_abs` |
| Connections | `connection_mismatches` | connections.count + downloadTotal/uploadTotal | BHV-CP-006, BHV-DP-005 … 009 | `tolerate_counter_jitter` |
| Memory | `memory_mismatches` | peak memory ratio (>2x = mismatch) | BHV-PF-003, BHV-PF-004 | `ignore_memory_ratio_on_non_linux` (RSS/Go-heap metrics are incomparable off Linux; Linux gate remains strict) |

> **Tester workflow**: diff report shows `http_mismatches` on `/proxies` → look up BHV-CP-003 → check S4 for known divergences → decide pass/fail.

---

## S3: Behavior Registry

Stable ID format: `BHV-{domain}-{seq}`. Each row = one testable behavior.

**Column key**: `Both` = case IDs with `kernel_mode: both` covering this behavior. `Rust-Only` = key rust-only cases. Empty Both = coverage gap.

### CP.1: Clash API HTTP Endpoints

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-CP-001 | GET /configs returns runtime config | GET /configs | 200 + JSON with `mode`, `mixed-port` | HTTP | `p0_clash_api_contract`, `p0_clash_api_contract_strict`, `p1_gui_full_boot_replay` | — | — |
| BHV-CP-002 | PATCH /configs updates mode | PATCH /configs `{"mode":"rule"}` | 204 No Content | HTTP | `p0_clash_api_contract`, `p0_clash_api_contract_strict`, `p1_clash_mode_rule_switch_via_socks` | — | — |
| BHV-CP-003 | GET /proxies lists groups+members | GET /proxies | 200 + JSON with `proxies` map | HTTP | `p0_clash_api_contract`, `p1_gui_proxy_switch_replay`, `p0_clash_api_contract_strict`, `p1_gui_full_boot_replay` | — | — |
| BHV-CP-004 | PUT /proxies/{group} switches active | PUT /proxies/{group} `{"name":"..."}` | 204 + selector.now updated | HTTP | `p1_gui_proxy_switch_replay` | — | — |
| BHV-CP-005 | GET /proxies/{name}/delay tests latency | GET /proxies/{name}/delay?timeout=N | 200 + `{"delay": ms}` or timeout | HTTP | `p0_clash_api_contract`, `p0_clash_api_contract_strict`, `p1_gui_proxy_delay_replay`, `p1_gui_group_delay_replay` | — | DIV-M-009 |
| BHV-CP-006 | GET /connections lists active conns | GET /connections | 200 + `{connections[], downloadTotal, uploadTotal}` | HTTP, Conn | `p0_clash_api_contract`, `p0_clash_api_contract_strict`, `p1_gui_connections_tracking` | — | DIV-M-008 |
| BHV-CP-007 | DELETE /connections/{id} closes conn | DELETE /connections/{id} | 204 or 404 | HTTP | `p0_clash_api_contract`, `p0_clash_api_contract_strict` | — | — |

### CP.2: Clash API WebSocket Streams

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-CP-008 | /traffic streams real-time bandwidth | WS /traffic | JSON frames `{up, down}` | WS | `p0_clash_api_contract`, `p0_clash_api_contract_strict`, `p1_gui_full_boot_replay` | — | — |
| BHV-CP-009 | /memory streams RSS usage | WS /memory | JSON frames `{inuse, oslimit}` | WS | `p0_clash_api_contract`, `p0_clash_api_contract_strict`, `p1_gui_full_boot_replay` | — | — |
| BHV-CP-010 | /connections streams conn updates | WS /connections | JSON frames with connection list | WS | `p0_clash_api_contract`, `p2_connections_ws_soak_dual_core` | `p2_connections_ws_concurrency_suite` | — |
| BHV-CP-011 | /logs streams log entries | WS /logs | JSON frames with log message | WS | `p0_clash_api_contract`, `p0_clash_api_contract_strict`, `p1_gui_full_boot_replay` | — | DIV-M-002 |

### CP.3: Authentication

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-CP-012 | Valid Bearer token → HTTP 200 | `Authorization: Bearer {secret}` | 200 on protected endpoints | HTTP | `p0_clash_api_contract`, `p1_clash_api_auth_enforcement` | — | — |
| BHV-CP-013 | Wrong Bearer token → HTTP 401 | `Authorization: Bearer wrong` | 401 Unauthorized | HTTP | `p1_auth_negative_wrong_token`, `p1_clash_api_auth_enforcement` | — | — |
| BHV-CP-014 | Missing Bearer token → HTTP 401 | No Authorization header | 401 Unauthorized | HTTP | `p1_auth_negative_missing_token`, `p1_clash_api_auth_enforcement` | — | — |
| BHV-CP-015 | Valid WS ?token= → connected | WS upgrade with `?token={secret}` | Connection accepted, frames flow | WS | `p0_clash_api_contract`, `p1_clash_api_auth_enforcement` | — | — |
| BHV-CP-016 | Wrong WS ?token= → rejected | WS upgrade with `?token=wrong` | Connection rejected (401/close) | WS | `p1_auth_negative_wrong_token`, `p1_clash_api_auth_enforcement` | — | — |
| BHV-CP-017 | Missing WS ?token= → rejected | WS upgrade without token param | Connection rejected (401/close) | WS | `p1_auth_negative_missing_token`, `p1_clash_api_auth_enforcement` | — | — |

### CP.4: Non-GUI Endpoints

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-CP-018 | GET /providers returns provider list | GET /providers/proxies | 200 + provider JSON | HTTP | `p1_optional_endpoints_contract` | — | DIV-H-003 |
| BHV-CP-019 | GET /rules returns rule list | GET /rules | 200 + rules array | HTTP | `p1_optional_endpoints_contract` | — | — |
| BHV-CP-020 | GET /version returns version info | GET /version | 200 + `{version, ...}` | HTTP | `p1_version_endpoint_contract` | — | — |
| BHV-CP-021 | GET /dns/query resolves domain | GET /dns/query?name=example.com | 200 + DNS result JSON | HTTP | `p1_dns_query_endpoint_contract` | — | DIV-M-010 |

### DP.1: Inbound

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-DP-001 | SOCKS5 TCP CONNECT proxies streams | TCP via SOCKS5 | Round-trip echo success | Traffic | `p1_rust_core_tcp_via_socks` | — | — |
| BHV-DP-002 | SOCKS5 UDP relays packets | UDP via SOCKS5 | Round-trip echo success | Traffic | `p1_rust_core_udp_via_socks` | — | DIV-C-002 |
| BHV-DP-003 | HTTP CONNECT proxies tunnels | HTTP CONNECT via proxy | HTTP GET through proxy succeeds | Traffic | `p1_http_connect_via_http_proxy` | — | — |
| BHV-DP-004 | Mixed inbound detects protocol | SOCKS5 or HTTP to same port | Auto-detect and handle | Traffic | `p1_mixed_inbound_dual_protocol` | `p0_clash_api_contract_strict` | — |

### DP.2: Outbound

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-DP-005 | Direct outbound connects to target | Routed to direct | TCP connection established | Traffic, Conn | `p1_rust_core_http_via_socks` | — | DIV-C-001 |
| BHV-DP-006 | Selector switches via PUT API | PUT /proxies/{group} | Subsequent traffic uses new path | Traffic | `p1_selector_switch_traffic_replay` | `p1_gui_proxy_switch_replay` | — |
| BHV-DP-007 | URLTest auto-selects lowest latency | urltest group configured | Auto-selects best outbound | Traffic | `p1_urltest_auto_select_replay` | `p1_gui_proxy_delay_replay` | — |
| BHV-DP-008 | Block outbound rejects connection | Routed to block | Connection refused/reset | Traffic | `p1_block_outbound_via_socks` | — | — |
| BHV-DP-009 | Chain proxy (multi-hop) | SOCKS5→SOCKS5→direct | End-to-end connectivity | Traffic | `p2_dataplane_chain_proxy` | — | — |

### DP.3: Routing

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-DP-010 | Rule match dispatches correctly | Traffic matching a rule | Dispatched to rule's outbound | Traffic | `p1_gui_connections_tracking` | — | — |
| BHV-DP-011 | route.final handles unmatched | Traffic matching no rule | Dispatched to final outbound | Traffic | `p1_gui_full_session_replay` | `p1_rust_core_http_via_socks` | — |
| BHV-DP-012 | Domain rules match FQDN | Request to domain pattern | Correct outbound selected | Traffic | `p1_domain_rule_via_socks` | — | — |
| BHV-DP-013 | IP-CIDR rules match addresses | Request to IP in CIDR | Correct outbound selected | Traffic | `p1_ip_cidr_rule_via_socks` | — | — |
| BHV-DP-014 | Sniff detects protocol from payload | TLS/HTTP payload inspection | Protocol detected, domain extracted | Traffic | `p1_sniff_rule_action_tls` | — | — |
| BHV-DP-019 | domain_suffix matches FQDN suffix | Request to suffix-matching domain | Matched outbound; non-match → final | Traffic | `p1_domain_suffix_rule_via_socks` | — | — |
| BHV-DP-020 | domain_keyword matches substring | Request to keyword-containing domain | Matched outbound; non-match → final | Traffic | `p1_domain_keyword_rule_via_socks` | — | — |
| BHV-DP-021 | port rule matches destination port | Request to matching dest port | Matched outbound; other port → final | Traffic | `p1_port_rule_via_socks` | — | — |
| BHV-DP-022 | network rule matches tcp/udp | TCP vs UDP request | Per-network outbound (tcp→match, udp→final) | Traffic | `p1_network_rule_via_socks` | — | — |
| BHV-DP-023 | port_range matches destination interval | Request inside `start:end` range | Matched outbound; outside range → final | Traffic | `p1_port_range_rule_via_socks` | — | — |
| BHV-DP-024 | domain_regex matches FQDN | Request matching configured regex | Matched outbound; non-match → final | Traffic | `p1_domain_regex_rule_via_socks` | — | — |
| BHV-DP-025 | source_ip_cidr matches client address | SOCKS client source inside CIDR | Matched outbound; source outside CIDR → final | Traffic | `p1_source_ip_cidr_rule_via_socks` | — | — |
| BHV-DP-026 | local source rule_set matches domain | Domain present in a local source JSON rule set | Matched outbound; non-member → final | Traffic | `p1_local_rule_set_domain_via_socks` | — | — |
| BHV-DP-027 | logical AND honors nested invert | AND sub-rules with an inverted domain sub-rule | Composite match → outbound; AND/invert miss → final | Traffic | `p1_logical_and_invert_rule_via_socks` | — | — |
| BHV-DP-028 | inbound tag selects route | Same destination through two tagged inbounds | Matching inbound → outbound; other inbound → final | Traffic | `p1_inbound_rule_via_socks` | — | — |
| BHV-DP-029 | clash_mode tracks runtime mode | Traffic before/after PATCH /configs mode changes | Global match → outbound; Rule mode → final | Traffic | `p1_clash_mode_rule_switch_via_socks` | — | — |
| BHV-DP-030 | logical OR matches either child | Domain child, port child, or neither | Either child → outbound; neither → final | Traffic | `p1_logical_or_rule_via_socks` | — | — |
| BHV-DP-031 | private destination/source IP selects route | Private destination or private SOCKS peer source | Non-public address → outbound; public destination → final | Traffic | `p1_private_ip_rule_via_socks` | — | — |
| BHV-DP-032 | remote source rule_set loads before routing | HTTP-served source JSON via direct download detour | Domain/IP member → outbound; non-member → final | Traffic | `p1_remote_rule_set_via_socks` | — | — |
| BHV-DP-033 | source_port and source_port_range select route | Fixed SOCKS peer source ports | Exact/range member → outbound; outside → final | Traffic | `p1_source_port_rule_via_socks` | — | — |
| BHV-DP-034 | ip_version selects destination address family | IPv4 and IPv6 literal destinations | IPv4 → outbound; IPv6 → final | Traffic | `p1_ip_version_rule_via_socks` | — | — |
| BHV-DP-035 | auth_user matches authenticated SOCKS TCP user exactly | Two valid users differing only by case | Exact user → outbound; other user → final | Traffic | `p1_auth_user_rule_via_socks` | — | — |
| BHV-DP-036 | rule_set IP CIDR source mode selects source address | Same IPv4 destination from IPv4 and IPv6 SOCKS peers | Source member → outbound; destination-only member → final | Traffic | `p1_rule_set_source_ip_cidr_via_socks` | — | — |
| BHV-DP-037 | reject route action denies matched connection | Matched and unmatched destination ports | Match rejected; miss → final direct | Traffic | `p1_reject_rule_action_via_socks` | — | — |
| BHV-DP-038 | direct route action is non-terminal in Go 1.13.13 | Matching direct action before final block | Action continues; final block denies connection | Traffic | `p1_direct_rule_action_via_socks` | — | — |
| BHV-DP-039 | empty bypass action continues without bypass support | Matching empty bypass before reject | Later reject rule denies connection | Traffic | `p1_bypass_rule_action_via_socks` | — | — |
| BHV-DP-040 | route-options rewrites destination and continues | Address/port override before IP+port route | Later rule matches rewritten target; dial reaches override | Traffic | `p1_route_options_override_via_socks` | — | — |
| BHV-DP-041 | resolve action feeds later destination-IP rules | Domain resolve before IP-CIDR route | Resolved IP matches later route; port miss reaches final | Traffic | `p1_resolve_rule_action_via_socks` | — | — |

### DP.4: DNS

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-DP-015 | DNS resolves via configured servers | Domain lookup | IP address returned | Traffic | `p1_rust_core_dns_via_socks` | — | — |
| BHV-DP-016 | FakeIP pool allocates addresses | Domain in fakeip range | Fake IP from pool | Traffic | `p1_fakeip_dns_query_contract` | — | — |
| BHV-DP-017 | FakeIP cache flush via API | POST /cache/fakeip/flush | Mappings cleared, allocator cursor preserved, 204 | HTTP | `p1_fakeip_cache_flush_contract` | — | — |
| BHV-DP-018 | DNS result caching and TTL | Repeated domain lookup | Cached response, respects TTL | Traffic | `p1_dns_cache_ttl_via_socks` | — | — |

### LC.1: Startup

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-LC-001 | Config validate and parse | JSON config file | Parse success or structured error | — | `p1_lifecycle_restart_reload_replay` | `p1_deprecated_v1_style_config` | — |
| BHV-LC-002 | API ready signal on startup | Process start | GET /version returns 200 | HTTP | `p1_gui_full_session_replay`, `p1_lifecycle_restart_reload_replay` | — | — |
| BHV-LC-003 | Concurrent service initialization | Multiple services configured | All services started, failures isolated | — | — | `p1_service_failure_isolation` | DIV-H-006 |

### LC.2: Reload

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-LC-004 | PATCH /configs mode switch | PATCH /configs `{"mode":"..."}` | Mode updated, 204 | HTTP | `p0_clash_api_contract_strict`, `p1_clash_mode_rule_switch_via_socks` | — | — |
| BHV-LC-005 | Inbound hot-reload on config change | Config file update + signal | Inbound rebind without restart | — | `p1_inbound_hot_reload_sighup` | — | — |
| BHV-LC-006 | State preservation across reload | Reload signal | Connections/proxy state preserved | — | `p1_selector_switch_traffic_replay` | — | — |

### LC.3: Shutdown

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-LC-007 | Graceful shutdown drains connections | SIGTERM / shutdown signal | Active connections drain before exit | — | `p1_graceful_shutdown_drain` | — | DIV-M-003 |
| BHV-LC-008 | Connection close notification | Shutdown initiated | WS /connections notified | WS | `p1_gui_ws_reconnect_behavior` | — | — |
| BHV-LC-009 | Resource cleanup on exit | Process exit | FDs/sockets released, no leak | Memory | `p1_lifecycle_restart_reload_replay` | — | — |

### SV.1: Subscription Parsing — NOT-APPLICABLE for Dual-Kernel Parity

> **Reclassified 2026-03-16**: These BHVs test the interop-lab harness's own subscription parser
> (`labs/interop-lab/src/subscription.rs`), not kernel behavior. Neither Go nor Rust kernel performs
> subscription parsing — the GUI handles it externally. The `subscription_parse` gui_sequence step
> runs harness-side code against inline content without involving the kernel process.
> These BHVs are excluded from the S1 denominator and S6 coverage formulas.

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| ~~BHV-SV-001~~ | JSON outbounds parsing | JSON subscription blob | Parsed nodes with protocol types | Sub | N/A | `p0_subscription_json` (harness-only) | N/A |
| ~~BHV-SV-002~~ | YAML proxies parsing | YAML subscription blob | Parsed nodes with protocol types | Sub | N/A | `p0_subscription_yaml` (harness-only) | N/A |
| ~~BHV-SV-003~~ | Base64 auto-decode | Base64-encoded subscription | Decoded then parsed | Sub | N/A | `p0_subscription_base64` (harness-only) | N/A |
| ~~BHV-SV-004~~ | URL fetch and parse | HTTP URL to subscription | Fetched, decoded, parsed | Sub | N/A | `p1_subscription_file_urls` (harness-only) | N/A |

### SV.2: Provider

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-SV-005 | Proxy provider list via API | GET /providers/proxies | Provider entries with nodes | HTTP | — | `test_get_proxy_providers_with_data` | DIV-H-005 |
| BHV-SV-006 | Rule provider list via API | GET /providers/rules | Rule provider entries | HTTP | — | `test_get_rule_providers_with_data` | DIV-H-005 |
| BHV-SV-007 | Provider healthcheck via API | POST /providers/proxies/{name}/healthcheck | Health status response | HTTP | — | `test_healthcheck_proxy_provider_with_data` | DIV-H-005 |

### PF.1: Latency

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-PF-001 | HTTP proxy p95 latency | HTTP via SOCKS5 under load | p95 < threshold | Traffic | `p1_rust_core_http_via_socks` | — | — |
| BHV-PF-002 | API response p95 latency | GET /proxies repeated | p95 < threshold | Traffic | `p0_clash_api_contract_strict` | — | — |

### PF.2: Memory

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-PF-003 | Peak RSS within bounds | Steady-state operation | Rust peak < 2x Go peak | Memory | `p2_connections_ws_soak_dual_core` | `p2_connections_ws_soak_suite` | — |
| BHV-PF-004 | WS connection memory stable | Long-running WS streams | No linear memory growth | Memory | `p2_connections_ws_soak_dual_core` | `p2_connections_ws_soak_suite` | — |

### PF.3: Startup

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-PF-005 | Time to API ready | Process launch | /version 200 within timeout | — | `p1_version_endpoint_contract` | `p1_lifecycle_restart_reload_replay` | — |

---

## S4: Divergence Registry

Stable ID format: `DIV-{severity}-{seq}`. Each entry links to BHV-IDs affected.

| Tag | Meaning | Disposition |
|-----|---------|-------------|
| INTENTIONAL | MIG-02 design decision | Oracle ignore; not a failure |
| KNOWN-GAP | Rust feature not yet implemented | Track; promote when implemented |
| COSMETIC | Format difference, semantically equivalent | Oracle tolerance |
| ARCH-LIMIT | Structurally unreachable because the Rust runtime lacks an upstream-equivalent capability | Accept as known deviation; exclude from active parity debt |

### Architecture Limits

No active REALITY architecture limit remains. Real-network camouflage sufficiency is an external
deployment/measurement boundary, not a missing Rust runtime capability.

### Resolved Architecture Limits

| Decision ID | Resolution | Scope | Disposition | Evidence |
|-------------|------------|-------|-------------|----------|
| DEV-REALITY-01 | RESOLVED locally (2026-07-20) | REALITY (`vless+reality`): bidirectional Vision dataplane, production-configured Rust server, Chrome-current ClientHello shape/order/GREASE/JA4, canonical session_id auth, active-probing relay and first-flight ordering, reverse Go-client interop, plus success-path target cipher/keyshare/record-shape borrowing all closed locally | Vendored rustls now supports opt-in TLS 1.3 handshake splitting and exact record-length padding for ring/aws-lc-rs; `RealityAcceptor` narrows cipher/group to the captured decoy profile. Combined and separate wire regressions plus A1 20-run gate pass. Real-network camouflage remains external; REALITY has no S3 BHV-ID and causes no `52/56` increment. | ServerHello acceptance `agents-only/archive/reality_serverhello_borrowing/acceptance.md`; A1 fixture `labs/interop-lab/reality_local_fixture/`; active-probing differential `agents-only/archive/reality_active_probing/`; Chrome canary `labs/interop-lab/reality_chrome_canary/`; parity harness `labs/interop-lab/reality_clienthello_parity/`; R93 evidence `agents-only/mt_real_02_evidence/round93_external_healthy_cohort.{json,md}` |

#### REALITY Acceptance: Three-Tier Model

REALITY client parity is accepted in three distinct tiers. Do not conflate them, do
not let one substitute for another, and do not claim closure of one from another.

1. **Local deterministic gate.**
   - Entry: `make verify-reality-local` → `run_fixture.py --runs 20`
     (the controlled local REALITY client functional-parity fixture,
     `labs/interop-lab/reality_local_fixture/`).
   - Validates: both client directions (Go/Rust → Go server, Go → Rust server),
     REALITY client/server functional path + VLESS dataplane + four negative controls
     + teardown — offline, deterministic, zero public node. Reverse lane uses canonical
     `xtls-rprx-vision` through production `app run -c rust_server.json`; Rust inbound
     config lowering, flow validation, and framing are blocking.
   - Status: **normative merge-precheck**, wired as the opt-in `REALITY_LOCAL` L18
     capstone gate. It is not server-side automatic merge enforcement; CI remains disabled.
   - Does NOT prove: real-network camouflage quality. Chrome-current ClientHello
     shape/order/JA4 and success-path ServerHello target-profile borrowing are covered by
     separate local regressions.
2. **External healthy-cohort observation — pre-release only.**
   - Purpose: pre-release real-network observation (the MT-REAL-02 public
     fresh-cohort rounds).
   - **Not a merge gate.** Bound to no single public node identity; a dead node such
     as `fresh09` must never constitute a permanent closure blocker.
   - Verdicts are tri-state: PASS / DEGRADED / INCONCLUSIVE (defined below).
   - Node-infrastructure failure (outage / timeout / reset) must NOT be recorded as a
     Rust functional regression.
   - Governed by the External Healthy-Cohort Observation Protocol below.
   - Latest accepted observation: R93 **PASS**, banked at three consecutive fixed-cohort
     all-ok rounds. This remains observational and may be rerun before release.
3. **ClientHello fingerprint parity — tier-3 (T3 track, 2026-06-07).**
   Re-scoped from a single "residual open item" into layered, individually-tracked
   facts. The blanket "`0/21` / needs a uTLS-equivalent / rustls lacks Chrome shaping"
   narrative is **retired**: Rust carries a patched-rustls Chrome shaping layer
   (`build_chrome_client_hello_fingerprint`) and the items below are validated by a
   committed local harness, not deferred to a future uTLS port. (Naming note: this
   "T3" is the REALITY ClientHello track T3-0…T3-2; it is unrelated to the S5 "T3"
   promotion tier, which is the closed SV.1 subscription reclassification.)

   **Closed (local):**
   - *Functional dataplane* — the controlled local REALITY client functional-parity
     fixture (tier 1 above) gives reproducible Go/Rust token-match;
     `direct_reality` / `transport_reality` / `vless_dial` / `vless_probe_io` are
     repeatably verified and the L18 capstone is wired to the `REALITY_LOCAL` gate.
     This is a local gate, **not** server-side automatic merge enforcement.
   - *Canonical non-auth first flight* — the server dials the decoy before reading client
     input, mirrors each partial read immediately, and relays an early decoy response before
     ClientHello completion. The active-probing harness locks all three ordering assertions;
     a backpressure unit test locks non-cancellation of an in-flight mirror write when target
     response is already ready. Real-network camouflage quality remains external.
   - *Success-path target ServerHello profile* — authenticated Rust server captures the decoy's
     TLS 1.3 cipher suite, key-share group, and combined or split first-flight record lengths.
     Opt-in vendored-rustls splitting plus TLSInnerPlaintext padding reproduces those lengths for
     ring and aws-lc-rs. Wire regressions assert both Go-supported shapes and complete REALITY
     proxy payload. Evidence: `agents-only/archive/reality_serverhello_borrowing/acceptance.md`.
   - *Chrome-current ClientHello profile* — sanitized full-browser Chrome 150 canary at
     `labs/interop-lab/reality_chrome_canary/`; blocking Rust shape includes
     `trust_anchors`, ML-DSA signature schemes, REALITY-transformed groups/key shares,
     JA4 `t13d1517h2_8daaf6152771_cb7bf5808d99`, record-length ladder, token match, and
     redaction. Pinned Go/uTLS v1.8.4 Chrome133 remains compatibility-only.
   - *Extension-order semantics* — current BoringSSL reverse Fisher-Yates with independent
     `OsRng` u32 words over middle extensions; GREASE extensions are written separately at
     both ends. Legacy u16 shared seed and empirical order-ranking tables removed.
   - *Coordinated GREASE structure* — T3-1C (`6f8ae63a`): each ClientHello constructs a
     `ChromeGreaseProfile` from an **independent `OsRng`** (it does **not** reuse the
     extension-order seed). cipher / supported_versions / group / ext_head / ext_tail
     are drawn independently; `supported_groups` GREASE == `key_share` GREASE;
     `ext_head != ext_tail`; unrelated slots may collide naturally. The GREASE advisory
     flipped **FIXED → RANDOMIZED**. Sampled observation: 230,242 unique profiles in
     262,144 Rust draws (a *sampled* observation, **not** a full state-space proof); a
     256-draw sanitized Go sample shows the same structural constraints. This is **not**
     a claim of full probability-distribution equivalence.

   **Closed — JA4 (local + FoxIO algorithm cross-check, 2026-07-12):**
   - *from-spec JA4* — Chrome-current Rust equals full Chrome 150 at
     `t13d1517h2_8daaf6152771_cb7bf5808d99`. The from-spec JA4 **algorithm**
     is now cross-checked against FoxIO's OWN published reference values — the canonical
     worked example (`t13d1516h2_8daaf6152771_e5627efa2ab1`) plus the full ALPN-segment
     mapping table — vendored under BSD-3 `LICENSE-JA4` at
     `fixtures/foxio_reference_vectors/` and enforced by the offline blocking test
     `tests/test_foxio_reference_vectors.py`. The earlier "weak independent confirmation"
     caveat is retired: the from-spec code itself is FoxIO-verified, so live Go == Rust
     under it is a real independent claim. **Scope caveat**: this is algorithm/vector
     conformance (our JA4 == FoxIO's published JA4), **not** a second-tool (tshark/FoxIO
     binary) fingerprint of live captures, and **not** byte-level identity.

   **Still OPEN (must not be faked closed):** real-network camouflage sufficiency.

   **Local runtime closure (A2.3, 2026-07-20):** fixed-profile L18 produced a terminal
   status with every selected local implementation gate proven. Docker remained advisory and
   GUI remained untested under the selected core profile. Evidence:
   `agents-only/archive/a2_3_runtime_status/acceptance.md`.

   **External progress, not closure (R94, 2026-07-19):** a redacting ordinary-TLS fallback
   comparator observed XTLS/REALITY's network-visible TLS/H2/redirect subset on all 9
   proxy/public-DNS-SNI pairs of the banked R93 cohort. Client config does not reveal server's
   actual target; sufficiency remains `NOT_ASSESSED`. R94 cannot classify GFW/deployment location,
   and public endpoints are not a controlled Rust deployment or multi-vantage censor experiment.
   Evidence:
   `agents-only/mt_real_02_evidence/round94_external_camouflage_observation.{json,md}`.

   **Explicit non-goals:**
   - L4 raw-byte identity / byte-for-byte ClientHello equality (two real Chrome
     instances also differ byte-for-byte).
   - forcing the per-hello randomized fields into alignment.
   - treating pinned Go/uTLS Chrome133 as current-browser authority.
   - reinstating the retired `fresh09` fixed-node obligation.

   Tiers remain independent: R93's banked external cohort does not close real-network
   camouflage. (Standing constraint: do not return to a static
   ClientHello template, and do not hard-code precedence or position-to-mode behavior.) **No `52/56`
   BHV increment**: REALITY has no BHV-ID in the S3 registry and is not in the S1/S6
   denominator, so this tier-3 closure does not move the coverage dashboard (see S6).

#### External Healthy-Cohort Observation Protocol

Formalizes the **existing** MT-REAL-02 rules (extracted from
`agents-only/archive/mt_real_02/mt_real_02_baseline.md`, `archive/mt_real_02/closure_report.md`,
`active_context.md`); no new N×M thresholds are invented. This tier is observational
and never blocks a merge. The named tri-state (PASS/DEGRADED/INCONCLUSIVE) is the
synthesis label set for this tier; it maps onto the pre-existing run-health labels.

**A. External cohort admission gate.** A node enters a cohort round only if ALL hold:
   - credentials present; AND
   - config parses; AND
   - `reality_vless_ready_reason` fields complete (vless type, name, server, port,
     uuid, reality `public_key`, plain-TCP); AND
   - the run plan passes the **R81 subset-schema dry-run gate**
     (`subset_schema_gate_passed=true`, `violations=[]`; rejects `__`-prefixed
     GUI-only fields and any field outside the REALITY/VLESS allow-list); AND
   - `intake_counts` consistent (`fresh_ready` / `covered_existing` / `duplicate` /
     `not_ready`).
   This is a config/intake gate only — it introduces **no** pre-screen numeric
   liveness SLA.

**B. Runtime infra-health classification** (assessed *after* a run, never a
   pre-screen):
   - node liveness has **no committed numeric SLA**;
   - `timeout`, `connection_reset`, REALITY-dest-unavailable, etc. are **post-run**
     classifications;
   - a uniform same-class failure where `probe_io class == reality class` is bucketed
     **infrastructure-dead**;
   - infrastructure-dead is **excluded from the Rust-client regression verdict** and
     the node may be **replaced** (see E);
   - **node outage != Rust regression**.

**C. Observation record unit** (one row per node per round):
   `cohort_id, node_id, round_id, timestamp, config_fingerprint, direct_reality,
   transport_reality, vless_dial, vless_probe_io, infra_health, verdict,
   exclusion_reason?`. The four phase axes and run-health labels already exist in the
   probe / rollup; `cohort_id` and `exclusion_reason` are made explicit here.

**D. Verdict (tri-state)**, mapped from existing run-health labels:
   - **PASS** — healthy cohort meeting the existing formal threshold: `run_all_ok`
     with `run_same_failure==0 ∧ run_divergence==0`, `matrix_status=0`; for
     recovery-watch, **3 consecutive all_ok rounds** (a single 3/3 round is only
     "banked", not closure).
   - **DEGRADED** — a *reproducible client* anomaly: `run_divergence>0` carrying phase
     labels (`app_*_diverged` / `*_transport_diverged` / `bridge_io_diverged`)
     reproducibly across rounds (cross-round `is_phase_shifting` comparison), not yet
     attributable to a known taxonomy entry. A node leaves the suspect list only when
     `is_phase_shifting=false` stably across 3+ longer-repeat rounds — and when the
     residual failure is then uniform same-class it lands in INCONCLUSIVE (infra-dead,
     per B/E), NOT in PASS.
   - **INCONCLUSIVE** — too few healthy nodes, node death / infrastructure
     same-failure (uniform timeout/reset), abnormal network, matrix error
     (`matrix_timeout`/exit 124 → `matrix_error_inconclusive`, `run_unknown`), or
     incomplete evidence. INCONCLUSIVE rounds are **not banked** and do not count
     toward closure.

**E. Identity & replacement.**
   - Closure does **not** require `fresh09` (or any specific node) to recover. The
     historical "original cohort C identity = `fresh01+fresh09+fresh15`" binding is
     **retired** under this tier.
   - A dead node may be replaced by any admission-gate-passing node; the replacement
     **must be recorded** (node_id + round_id + reason).
   - The sample face must not be **silently expanded** (R81 + `intake_counts` enforce
     this); a per-rep public-node result never gates a merge.
   - Rust-only / client-only results must **not** be written as a dual-kernel
     (`52/56`) behavior-parity increment.

**F. Threshold provenance** (kept verbatim from MT-REAL-02, no invention; under this
   tier these are *observation* thresholds, not merge gates): cohort buckets
   (`run_divergence>0`→divergence-carrier; `run_all_ok==0 ∧ run_same_failure>0 ∧
   run_divergence==0`→same-failure; `run_all_ok>0 ∧ run_same_failure==0 ∧
   run_divergence==0`→recovery-watch; else neutral/manual review); recovery closure =
   3 consecutive all_ok rounds; original cohort sizes (A `fresh02,fresh06` ×5 runs;
   B `fresh03,fresh04,fresh05,fresh07` ×3; C 3 reps ×3). A broken chain cannot be
   patched — restart opens a fresh sequence at round 1.

**Machine-readable form.** A record schema + read-only validator + pass/fail
fixtures for this protocol live at `labs/interop-lab/reality_external_observation/`
(`external_observation.schema.json`, `validate_external_observation.py`); they
structure §A–§F without inventing thresholds, and are observational (not a merge
gate).

### Critical (User-Visible)

| DIV ID | Tag | Description | Affected BHV | Oracle Action |
|--------|-----|-------------|--------------|---------------|
| DIV-C-001 | INTENTIONAL | No implicit direct fallback — unresolvable destinations return error instead of silently falling back to direct. MIG-02 wave#200. | BHV-DP-005, BHV-DP-011 | `ignore_http_paths` for affected traffic test endpoints |
| DIV-C-002 | CLOSED | SOCKS5 UDP ASSOCIATE now defaults to ON (Go parity). Opt-out with `SB_SOCKS_UDP_ENABLE=0`. | BHV-DP-002 | — |
| DIV-C-003 | CLOSED | Sniff rule action now implemented: inbounds read initial bytes, run sniff_stream(), populate protocol/host, and re-decide. | BHV-DP-014 | — |

### High (Partial Scenario Failure)

| DIV ID | Tag | Description | Affected BHV | Oracle Action |
|--------|-----|-------------|--------------|---------------|
| DIV-H-001 | CLOSED | Inbound hot-reload validated: SIGHUP triggers reload and inbound rebinds on both kernels. | BHV-LC-005 | — |
| DIV-H-002 | CLOSED | Redirect inbound now supports IPv6 via `IP6T_SO_ORIGINAL_DST`. | BHV-DP-001 | — |
| DIV-H-003 | CLOSED | Provider background update loop implemented (L23-T4). ProviderManager now sweeps stale providers on a configurable tick interval. | BHV-CP-018, BHV-SV-005 | — |
| DIV-H-004 | CLOSED | Provider healthcheck now performs real TCP probe via outbound registry (L23-T5). Falls back to healthy when no registry configured. | BHV-SV-007 | — |
| DIV-H-005 | STRUCTURAL | Go fork provider endpoints are intentionally unwired stubs, not just empty maps. `experimental/clashapi/provider.go` and `ruleprovider.go` (audit 2026-05-04 R66): (a) `GET /providers/proxies` returns hard-coded `{"providers": {}}` and `GET /providers/rules` returns `{"providers": []}` — note also a shape divergence (object vs array) between the two routes; (b) `findProviderByName` / `findRuleProviderByName` middleware always render `ErrNotFound` (404) — the `tunnel.ProxyProviders()` / `tunnel.RuleProviders()` lookups are commented out in source; (c) `getProvider`, `updateProvider`, `healthCheckProvider`, `getRuleProvider`, `updateRuleProvider` all `render.NoContent` (204) with their actual provider-action bodies commented out; (d) Go declares `GET /providers/proxies/:name/healthcheck` while Rust uses `POST` — method divergence on BHV-SV-007 alone. Rust side audited honest as of R66 (2026-05-04): provider routes are wired to `provider_manager` (`crates/sb-api/src/clash/handlers.rs:1136-1264`, `crates/sb-api/src/managers.rs:528-534`). Rust-only e2e baseline `test_get_proxy_providers_with_data`, `test_get_rule_providers_with_data`, `test_healthcheck_proxy_provider_with_data` all PASS via `cargo test -p sb-api --test clash_http_e2e`. SV.2 BHVs stay uncovered for dual-kernel parity until upstream sing-box wires the commented-out tunnel lookups; this is not a cosmetic gap. | BHV-SV-005, BHV-SV-006, BHV-SV-007 | Rust-only e2e coverage via `clash_http_e2e.rs` (3 tests verified R66) |
| DIV-H-006 | STRUCTURAL | Go fork has no analog for fault-isolated runtime service health: (1) Go `experimental/clashapi/server.go` exposes no `/services/health` route (only `/configs`, `/proxies`, `/rules`, `/connections`, `/providers/{proxies,rules}`, `/script`, `/profile`, `/cache`, `/dns`); (2) Go `adapter/service/manager.go` holds no per-service status — no `Starting/Running/Failed/Stopped` enum and no status map; (3) Go `Manager.Start` returns the first service error directly (`return E.Cause(...)`), aborting kernel boot rather than isolating the failure. Rust-side fixture (`rust_core_broken_service.json` binds `aaa-broken` ssmapi to port 1 → EACCES, `zzz-survivor` to 39200) and Rust `GET /services/health` (live `ServiceManager.health_status()` projection) are real and audited as of R65 (2026-05-04); the structural blocker is Go fork only. BHV-LC-003 stays Rust-only diagnostic until Go fork grows a status-aware service manager and a `/services/health` endpoint. | BHV-LC-003 | Keep Rust-only diagnostic coverage; do not promote to `kernel_mode: both` |

### Cosmetic (Format Differences)

| DIV ID | Tag | Description | Affected BHV | Oracle Action |
|--------|-----|-------------|--------------|---------------|
| DIV-M-002 | COSMETIC | /logs WS: Rust frames include extra `timestamp` and `source` fields not in Go. | BHV-CP-011 | `ignore_ws_paths: ["/logs"]` or structural diff |
| DIV-M-003 | COSMETIC | Shutdown grace period: Rust configurable, Go fixed 30s. | BHV-LC-007 | No oracle action (not observed in API) |
| DIV-M-008 | COSMETIC | Memory telemetry uses process RSS on Rust/macOS and Go runtime heap on Go, so exact values and peak ratios are not comparable off Linux. | BHV-CP-006, BHV-PF-003 | Connection HTTP bodies compare through the dedicated connection dimension; `ignore_memory_ratio_on_non_linux: true` records, but does not gate, the off-Linux ratio. Linux keeps the 2x gate. |
| DIV-M-009 | COSMETIC | `/proxies/{name}/delay` exact millisecond values are timing-sensitive across kernels even when status is consistent. | BHV-CP-005 | Path-specific `ignore_http_paths` until numeric tolerance exists |
| DIV-M-010 | COSMETIC | `/dns/query` on non-resolvable name: Rust propagates the internal resolver's lookup error as HTTP 500; Go's internal DNS router synthesizes a fake-IP-shaped answer (`198.18.x.x`, `"Server":"internal"`) and returns 200. Successful-answer wire shape is now exact after DIV-M-005 closed. Design divergence, not a parity gap — Rust should not adopt Go's fake-answer path. Evidence: `agents-only/archive/MT-GUI/mt_gui_02_evidence/control_plane.txt` CP-13, `extra_shape_probe.txt`. Classified by MT-GUI-03 (2026-04-12). | BHV-CP-021 | Dual-kernel cases probing non-resolvable names must use path-scoped ignore plus kernel-specific status assertions |

### Resolved Cosmetic

| DIV ID | Closed | Resolution |
|--------|--------|------------|
| DIV-M-001 | 2026-07-23 | Rust fake-IP flush now uses Go's POST + 204 contract. |
| DIV-M-004 | 2026-07-23 | Connections WS honors the requested interval. |
| DIV-M-005 | 2026-07-23 | Successful `/dns/query` responses use Go DNS-message fields and compare exactly. |
| DIV-M-006 | 2026-07-23 | Strict fixtures align lowercase GUI mode; Rust derives nested route/DNS mode-list entries in Go order and matches zero ports, absent interface-name, and null tun. |
| DIV-M-007 | 2026-07-23 | Proxy wire projection matches Go, including group-only `all`, empty GLOBAL `all`, and configured GLOBAL `now`. |
| DIV-M-011 | 2026-07-23 | Connection totals remain accumulated after active connections close. |
| DIV-M-012 | 2026-07-23 | Fake-IP flush clears isolated persistent mappings while retaining v4/v6 allocation cursors. |

---

## S5: Case Promotion Roadmap

### Effort Levels

| Level | Scope | Typical Changes | Effort |
|-------|-------|-----------------|--------|
| E1 | Trivial | Add `go:` bootstrap + change `kernel_mode: both` | ~10 lines YAML |
| E2 | Config | E1 + create Go config JSON (field remapping per S8) | ~30 lines YAML + JSON |
| E3 | Oracle | E2 + add oracle ignore/tolerance rules | ~40 lines |
| E4 | Infra | E3 + new upstream topology or Rust code changes | Variable |

### Priority Tiers

| Tier | Target | Cases | Cumulative Both | Projected Coverage |
|------|--------|-------|-----------------|-------------------|
| Current | Expanded routing-rule breadth | 65 | 65 / 126 | 94.9% (75/79 BHV) |
| T1 Immediate (Completed) | GUI critical path strict | +0 | 31 / 95 | 92.9% (52/56 BHV) |
| T2 Near-term (Promoted) | Coverage-neutral strict promotions | +3 | 30 / 92 | 92.9% (52/56 BHV) |
| T3 | CLOSED — SV.1 reclassified as harness-only | — | — | — |
| T4 Long-term | Protocol suites + perf | +3 | 36 / 92 | coverage-neutral (no new BHVs) — VLESS/VMess done |

### T1: Immediate (5 cases, all E2-E3)

These cases already exist as Rust-only strict and are the GUI critical path.

| # | Case ID | Current Mode | Effort | New BHVs Covered | Notes |
|---|---------|-------------|--------|------------------|-------|
| 1 | `p0_clash_api_contract_strict` | both | E3 | BHV-CP-001…007, 008…011 (strict), BHV-LC-004, BHV-PF-002 | Promoted on 2026-03-12 with self-managed Go bootstrap + strict oracle; re-verified on 2026-03-14 with repeated `/proxies` p95 latency contract |
| 2 | `p1_gui_full_boot_replay` | both | E3 | BHV-CP-001, BHV-CP-003, BHV-CP-008…011 (parallel WS) | Promoted on 2026-03-12 with self-managed Go bootstrap + `/configs` `/proxies` oracle ignores |
| 3 | `p1_gui_proxy_switch_replay` | both | E3 | BHV-CP-004, BHV-DP-006 | Promoted on 2026-03-12 with self-managed Go bootstrap + `/proxies` oracle ignore |
| 4 | `p1_gui_proxy_delay_replay` | both | E3 | BHV-CP-005 (strict), BHV-DP-007 | Promoted on 2026-03-12 with self-managed Go bootstrap + delay-path oracle ignore |
| 5 | `p1_gui_full_session_replay` | both | E3 | BHV-LC-002, BHV-DP-011 | Promoted on 2026-03-12 with self-managed Go bootstrap + strict oracle |

### T2: Near-term (+2 cases)

(Promoted — see Recent Promotions below)

### T3: ~~Planned~~ CLOSED (2026-03-16)

> SV.1 subscription BHVs reclassified as harness-only (not kernel behavior). See S1 note.
> No cases to promote — removed from roadmap.

### Recent Promotions

> **2026-07-23 strict-wire closeout:** the eight Clash API cases were already strict
> `kernel_mode: both` and already credited in S3/S6. Live Go/Rust replay closed
> DIV-M-001/004/005/006/007/011/012 without adding a case or a BHV; coverage and inventory
> therefore remain unchanged. Evidence: `agents-only/archive/clash_api_strict_parity/acceptance.md`.

| # | Case ID | Current Mode | Effort | New BHVs Covered | Notes |
|---|---------|-------------|--------|------------------|-------|
| 1 | `p1_rust_core_tcp_via_socks` | both | E2 | BHV-DP-001 | Promoted on 2026-03-12 with shared self-managed Clash API bootstrap + `/version` oracle ignore |
| 2 | `p1_rust_core_http_via_socks` | both | E2 | BHV-DP-005, BHV-PF-001 | Promoted on 2026-03-12 after replacing curl-only SOCKS traffic with `reqwest+socks` and `/version` oracle ignore; re-verified on 2026-03-14 with repeated HTTP GET p95 latency through SOCKS5 |
| 3 | `p1_rust_core_dns_via_socks` | both | E2 | BHV-DP-015 | Promoted on 2026-03-12 with shared self-managed Clash API bootstrap + `/version` oracle ignore |
| 4 | `p1_rust_core_udp_via_socks` | both | E2 | BHV-DP-002 | Promoted on 2026-03-12 with shared self-managed Clash API bootstrap and `/version` oracle ignore; `SB_SOCKS_UDP_ENABLE` env removed after DIV-C-002 CLOSED (default ON) |
| 5 | `p1_http_connect_via_http_proxy` | both | E3 | BHV-DP-003 | Promoted on 2026-03-12 after adding HTTP CONNECT proxy support to `tcp_round_trip` harness |
| 6 | `p1_selector_switch_traffic_replay` | both | E3 | BHV-DP-006 | Promoted on 2026-03-12 with selector defaulting to `block`, then switching to `direct` via PUT API |
| 7 | `p1_dns_query_endpoint_contract` | both | E1 | BHV-CP-021 | Promoted on 2026-03-12 after wiring Rust Clash API `dns_resolver` into managed runtime startup |
| 8 | `p1_ip_cidr_rule_via_socks` | both | E2 | BHV-DP-013 | Promoted on 2026-03-12 with an `ip_cidr` allow rule for `127.0.0.0/8` ahead of final `block` |
| 9 | `p1_version_endpoint_contract` | both | E1 | BHV-CP-020, BHV-PF-005 | Re-verified on 2026-03-12 with `/version` readiness probes on both kernels (`20260312T032518Z-036e6de0-2003-487a-b4e8-586c710f58a6`) |
| 10 | `p1_gui_connections_tracking` | both | E2 | BHV-CP-006 (strict), BHV-DP-010 | Promoted on 2026-03-13 with a live slow-request window, mid-traffic `/connections` capture, and `/connections` oracle ignore for body-shape divergence |
| 11 | `p1_lifecycle_restart_reload_replay` | both | E2 | BHV-LC-001, BHV-LC-009 | Re-verified on 2026-03-13 with explicit `shutdown -> restart` on both kernels, proving same-port recovery and post-exit API availability (`20260313T225412Z-d0aa81be-d8d3-4eb8-9467-ea3c622f79da`) |
| 12 | `p1_fakeip_dns_query_contract` | both | E2 | BHV-DP-016 | Promoted on 2026-03-13 with shared fakeip DNS configs and normalized `/dns/query` answer-IP assertions across Go and Rust |
| 13 | `p1_fakeip_cache_flush_contract` | both | E3 | BHV-DP-017 | Promoted on 2026-03-13 after adding per-kernel API method overrides, Rust fakeip flush wiring, and a real v4+v6 bucket warm-up before reset |
| 14 | `p1_gui_ws_reconnect_behavior` | both | E3 | BHV-LC-008 | Promoted on 2026-03-13 by asserting `/connections` WS closes during restart on both kernels, then re-establishes after readiness (`20260313T205356Z-5b7cf97d-6e5d-463e-8073-6868f00c0427`) |
| 15 | `p1_selector_switch_traffic_replay` | both | E3 | BHV-LC-006 | Re-verified on 2026-03-13 with cache-file-backed selector state surviving reload on both kernels (`20260313T222658Z-d6eb7e2c-1164-4bce-bbe0-5a1f19ee6049`) |
| 16 | `p0_clash_api_contract_strict` | both | E3 | BHV-PF-002 | Re-verified on 2026-03-14 with repeated `GET /proxies` latency sampling on both kernels; p95 remained <500ms and diff stayed clean (`20260314T001307Z-51a9f922-3013-47b2-b57e-1bababc1af1e`) |
| 17 | `p1_rust_core_http_via_socks` | both | E2 | BHV-PF-001 | Re-verified on 2026-03-14 with repeated HTTP GET via SOCKS5 on both kernels; p95 remained <500ms and diff stayed clean (`20260314T002122Z-f4af4a62-2000-4d39-aacb-ba3831f73ce0`) |
| 18 | `p1_dns_cache_ttl_via_socks` | both | E4 | BHV-DP-018 | Promoted on 2026-03-14 after wiring Rust direct-connect resolution into the configured DNS resolver, adding TTL cache to the no-rule resolver path, and constraining the Rust config to honor `TTL=1` for expiry replay (`20260314T021211Z-247eb412-7cb4-43ce-8a64-927df58a5ff7`) |
| 19 | `p1_domain_rule_via_socks` | both | E4 | BHV-DP-012 | Promoted on 2026-03-15 after fixing `direct_connect` to try all resolved addresses instead of only `[0]`; on macOS `localhost` resolves to `[::1, 127.0.0.1]` and the old code only tried IPv6 (`20260314T222007Z-a029a54e-b96c-4a04-b5cc-e39cac72fcdb`) |
| 20 | `p2_connections_ws_soak_dual_core` | both | — | BHV-PF-004 | Spec correction on 2026-03-15: case already had `memory.leak_detected: false` assertion covering linear memory growth detection; was previously only credited for BHV-PF-003 |
| 21 | `p1_mixed_inbound_dual_protocol` | both | E4 | BHV-DP-004 | Promoted on 2026-03-15 after fixing mixed inbound `peek()` → `read_exact()` bug (peek is non-destructive, causing PeekedStream to duplicate the first byte; SOCKS5 got 0x05 twice, HTTP got "CCONNECT" instead of "CONNECT") (`20260314T225307Z-621867dc-a773-486f-b629-8f373043f691`) |
| 22 | `p1_graceful_shutdown_drain` | both | E3 | BHV-LC-007 | Promoted on 2026-03-15 with new `TcpDrainDuringShutdown` harness action; both kernels show identical SIGTERM behavior (fast exit, no extended drain) confirming parity (`20260314T231033Z-e8dc8539-58aa-4b7f-82ec-5d2e4d571073`) |
| 23 | `p1_urltest_auto_select_replay` | both | E3 | BHV-DP-007 | Promoted on 2026-03-15 after fixing Rust `SelectorGroup::now()` to call `select_by_latency()` for URLTest mode and running initial health check immediately (Go parity: `PostStart` → `CheckOutbounds`); both kernels show `now: "direct"` and route traffic through the best outbound (`20260314T233646Z-536ab378-faec-4190-8a08-57827f1a97fa`) |
| 24 | `p1_inbound_hot_reload_sighup` | both | E2 | BHV-LC-005 | Promoted on 2026-03-15: SIGHUP triggers full reload on both kernels; data-plane TCP traffic via SOCKS5 survives two consecutive reloads; DIV-H-001 closed (`20260315T013347Z-88281e77-ea4d-4109-b15c-71982b0a4703`) |
| 25 | `p1_clash_api_auth_enforcement` | both | E2 | BHV-CP-012…017 | Promoted on 2026-03-16 with Go config at port 18907/9090; strict auth coverage (no-auth→401, correct→200, wrong→401) |
| 26 | `p1_gui_group_delay_replay` | both | E2 | BHV-CP-005 (group variant) | Promoted on 2026-03-16 reusing `l18_gui_go.json`; `ignore_http_paths` for timing-sensitive group delay path (DIV-M-009 pattern) |
| 27 | `p2_vless_dual_dataplane_local` | both | E3 | BHV-DP-001 (VLESS variant) | New on 2026-03-16: VlessInbound upstream kind + Rust/Go configs (port 12083); TCP round-trip with UUID auth (ok/bad). No UDP (inbound TCP-only). |
| 28 | `p2_vmess_dual_dataplane_local` | both | E3 | — (coverage-neutral VMess variant) | Canonical Go-compatible VMess TCP AEAD replaced the former local dialect. Linux committed-case replay is strict PASS on both kernels (`20260717T142243Z-34b05275-47aa-41ff-bcfa-39220788da3d`); no S4 label or denominator change. |
| 29 | `p2_bench_socks5_throughput` | both | E3 | — (coverage-neutral perf stress) | Promoted on 2026-07-18 from a Rust-only Criterion wrapper that bypassed both kernels to a strict live 1 MiB SOCKS5 connect+echo floor on Rust and Go. |
| 30 | `p1_domain_suffix_rule_via_socks` | both | E2 | BHV-DP-019 | New on 2026-07-21: `domain_suffix` routing rule; `localhost` (suffix)→direct, `nope.invalid`→final block. Both kernels emit identical routing decision (match=true / miss=false). |
| 31 | `p1_domain_keyword_rule_via_socks` | both | E2 | BHV-DP-020 | New on 2026-07-21: `domain_keyword` substring rule (`ocalhos`)→direct, `nope.invalid`→final block. Both kernels identical. |
| 32 | `p1_port_rule_via_socks` | both | E2 | BHV-DP-021 | New on 2026-07-21: destination `port` rule with dual echo; matched port→direct, other port→final block. Config representation differs (Rust `port` as string per `deserialize_string_or_list`, Go as uint16); routing decision identical on both kernels. |
| 33 | `p1_network_rule_via_socks` | both | E3 | BHV-DP-022 | New on 2026-07-21: `network` rule `tcp`→direct / udp→final block; SOCKS5 UDP ASSOCIATE default-on (DIV-C-002). Both kernels identical (tcp success / udp blocked). |
| 34 | `p1_port_range_rule_via_socks` | both | E2 | BHV-DP-023 | New on 2026-07-21: canonical `start:end` destination range; Rust parser fixed to accept Go colon/open-bound syntax. Both kernels identical (inside=true / outside=false). |
| 35 | `p1_domain_regex_rule_via_socks` | both | E2 | BHV-DP-024 | New on 2026-07-21: `^localhost$`→direct, `nope.invalid`→final block. Both kernels identical. |
| 36 | `p1_source_ip_cidr_rule_via_socks` | both | E3 | BHV-DP-025 | New on 2026-07-21: IPv4 loopback client source matches `127.0.0.1/32`; IPv6 loopback source misses. Rust SOCKS TCP now carries peer source metadata, and IPv6 listen normalization is bracket-correct. Both kernels identical. |
| 37 | `p1_local_rule_set_domain_via_socks` | both | E4 | BHV-DP-026 | New on 2026-07-22: local source JSON `rule_set` routes `localhost` to direct and a non-member to final block. Rust now rejects unreadable local rule-set files instead of silently omitting them. |
| 38 | `p1_logical_and_invert_rule_via_socks` | both | E4 | BHV-DP-027 | New on 2026-07-22: logical AND hit/miss plus nested default-rule invert true/false. Rust now applies invert to default rules and rejects malformed logical type/mode/empty rules. |
| 39 | `p1_inbound_rule_via_socks` | both | E2 | BHV-DP-028 | New on 2026-07-22: two SOCKS inbounds target the same echo; only the matching inbound tag routes direct. |
| 40 | `p1_clash_mode_rule_switch_via_socks` | both | E4 | BHV-DP-029 | New on 2026-07-22: default Rule blocks, PATCH Global routes direct, PATCH Rule blocks again. Rust schema-v2 lowering now preserves `clash_mode` instead of compiling an empty match-all rule. |
| 41 | `p1_logical_or_rule_via_socks` | both | E2 | BHV-DP-030 | New on 2026-07-22: domain and destination-port children independently satisfy logical OR; neither child falls through to final block. |
| 42 | `p1_private_ip_rule_via_socks` | both | E4 | BHV-DP-031 | New on 2026-07-22: destination and source private-address rules route direct while a public destination falls through. Rust now matches Go's complete non-public classification, including multicast and unspecified addresses. |
| 43 | `p1_remote_rule_set_via_socks` | both | E4 | BHV-DP-032 | New on 2026-07-22: a source JSON rule set is fetched from a local HTTP fixture through explicit direct detour before traffic starts; domain/IP members route direct and a non-member falls through. Rust startup/reload now loads remote sets asynchronously and fails on invalid initial content or unsupported effective download detours. |
| 44 | `p1_source_port_rule_via_socks` | both | E4 | BHV-DP-033 | New on 2026-07-22: fixed SOCKS peer ports prove exact and canonical `start:end` source-port routing plus an outside-range final-block miss. Harness source binding uses abortive close for repeatable dual-lane reuse. |
| 45 | `p1_ip_version_rule_via_socks` | both | E2 | BHV-DP-034 | New on 2026-07-22: IPv4 literal destination matches `ip_version=4`; IPv6 literal destination falls through to final block. Rust now rejects invalid or multiple route IP-version values instead of compiling a permanent miss. |
| 46 | `p1_auth_user_rule_via_socks` | both | E4 | BHV-DP-035 | New on 2026-07-22: two valid SOCKS users differing only by case prove Go-exact auth-user matching. Rust now carries multi-user inbound config and authenticated username into both initial and post-sniff route decisions; harness supports RFC 1929 credentials in SOCKS URLs. |
| 47 | `p1_rule_set_source_ip_cidr_via_socks` | both | E4 | BHV-DP-036 | New on 2026-07-22: IPv4 source matches a local source rule set while IPv6 source misses even though both destinations match its IPv4 CIDR. Rust now separates domain, destination-IP, and source-IP rule-set tags for Go source-mode semantics. |
| 48 | `p1_reject_rule_action_via_socks` | both | E2 | BHV-DP-037 | New on 2026-07-22: matched destination port is rejected by route action; unmatched port reaches final direct on both kernels. |
| 49 | `p1_direct_rule_action_via_socks` | both | E4 | BHV-DP-038 | New on 2026-07-23: live Go 1.13.13 and source audit prove `direct` is non-terminal in the route loop; both kernels continue to final block while an explicit route control succeeds (`20260722T204419Z-8f796e28-f2ed-41b9-9568-2c654237fcd8`). |
| 50 | `p1_bypass_rule_action_via_socks` | both | E4 | BHV-DP-039 | New on 2026-07-23: empty `bypass` on SOCKS, where bypass support is unavailable, continues to a later reject rule; explicit route control stays connected (`20260722T204542Z-d47bd3c4-e82f-4748-988b-3b683062d314`). |
| 51 | `p1_route_options_override_via_socks` | both | E4 | BHV-DP-040 | New on 2026-07-23: non-terminal route-options rewrites a TEST-NET destination to loopback, updates later IP+port rule matching, and dials the rewritten target (`20260722T204641Z-8e87c9c6-02d1-49c5-8e23-1def894d09ce`). |
| 52 | `p1_resolve_rule_action_via_socks` | both | E4 | BHV-DP-041 | New on 2026-07-23: default resolve populates destination addresses for a later loopback CIDR rule; a resolved port miss reaches final block (`20260722T204744Z-6b7debce-4f1c-463f-abf8-cd6d9f620010`). |

### T4: Long-term — CLOSED (2026-07-18)

| # | Case ID | Effort | New BHVs Covered | Status |
|---|---------|--------|------------------|--------|
| 1 | `p2_trojan_dual_dataplane_local` | E4 | BHV-DP-001 (Trojan variant) | ✅ pre-existing both |
| 2 | `p2_shadowsocks_dual_dataplane_local` | E4 | BHV-DP-001 (SS variant) | ✅ pre-existing both |
| 3 | `p2_vless_dual_dataplane_local` | E3 | BHV-DP-001 (VLESS variant) | ✅ delivered 2026-03-16 |
| 4 | `p2_vmess_dual_dataplane_local` | E3 | — | ✅ delivered 2026-07-17; canonical local peer, strict both-kernel PASS |
| 5 | `p2_bench_socks5_throughput` | E3 | coverage-neutral perf stress (BHV-PF-001 covered by `p1_rust_core_http_via_socks`) | ✅ delivered 2026-07-18; strict live both-kernel throughput floor |

### Non-Promotable Cases

These cases should **never** be promoted to `kernel_mode: both`:

| Case ID | Reason |
|---------|--------|
| `l6_local_harness_smoke` | Infrastructure self-test (already both but covers 0 domain BHVs) |
| `p1_deprecated_wireguard_outbound` | Rust-specific migration detection |
| `p1_deprecated_v1_style_config` | Rust-specific deprecation handling |
| `p1_deprecated_mixed_config` | Rust-specific config migration |
| `p1_cli_generate_uuid_format` | CLI tool, no Go equivalent |
| `p1_cli_generate_rand_base64` | CLI tool, no Go equivalent |
| `p1_cli_ruleset_convert_adguard` | CLI tool, no Go equivalent |
| `p1_cli_ech_keypair_pem_format` | CLI tool, no Go equivalent |
| `p2_protocol_unit_shadowsocks` | Rust cargo test wrapper |
| `p2_protocol_unit_vmess` | Rust cargo test wrapper |
| `p1_tls_fragment_wiring` | Rust TLS implementation detail |
| `p1_service_failure_isolation` | Rust-only honest diagnostic (R65 2026-05-04 audit): real broken-service fixture and live `/services/health` projection both verified. Promotion blocked by Go fork: no `/services/health` route, no `ServiceStatus` model, fail-fast `Manager.Start`. See DIV-H-006. |
| `p0_subscription_json` | Harness-side subscription parsing; not kernel behavior (SV.1 reclassification) |
| `p0_subscription_yaml` | Harness-side subscription parsing; not kernel behavior (SV.1 reclassification) |
| `p0_subscription_base64` | Harness-side subscription parsing; not kernel behavior (SV.1 reclassification) |
| `p1_subscription_file_urls` | Harness-side subscription parsing; not kernel behavior (SV.1 reclassification) |
| `p2_subscription_malformed_json` | Harness-side subscription parsing; not kernel behavior (SV.1 reclassification) |
| `p2_subscription_truncated_base64` | Harness-side subscription parsing; not kernel behavior (SV.1 reclassification) |
| `p2_subscription_empty_input` | Harness-side subscription parsing; not kernel behavior (SV.1 reclassification) |
| `p2_subscription_unknown_protocol` | Harness-side subscription parsing; not kernel behavior (SV.1 reclassification) |

---

## S6: Coverage Dashboard

### Current Metrics

| Metric | Formula | Value |
|--------|---------|-------|
| Both-mode case ratio | both cases / total cases | 51.6% (65/126) |
| Behavioral coverage (all) | BHVs with ≥1 both case / total BHVs | 94.9% (75/79) |
| Behavioral coverage (strict) | BHVs with ≥1 strict both case / total BHVs | 82.3% (65/79) |
| GUI endpoint coverage | GUI BHVs (CP.1+CP.2) with both case / GUI BHVs | 100.0% (11/11) |
| GUI endpoint coverage (strict) | GUI BHVs with strict both case / GUI BHVs | 100.0% (11/11) |
| MIG-02 divergence coverage | DIV-C/H BHVs with both case / DIV-C/H BHVs | 55.6% (5/9) |

> **Note**: SV.1 (4 subscription BHVs) excluded from denominator since 2026-03-16.
> See S1 reclassification note. Remaining gaps: 3 SV.2 (STRUCTURAL) + 1 LC (NOT-FEASIBLE).
> The 2026-07-23 Clash API strict-wire closeout changed divergence status, not the S6 numerator:
> all eight cases and their BHVs were already counted as strict/both before the replay.

### Projected Coverage by Tier

> **Retired (2026-06-08).** This forward-projection table used the pre-2026-03-16 `/60`
> denominator (the old 56 + 4 SV.1 basis); its "Current 45/60 (75.0%)" row is superseded and
> contradicts the authoritative Current Metrics above. All S5 tiers are delivered/closed (see
> S5), so a per-tier projection is obsolete and no mechanical per-tier recompute is meaningful
> for closed tiers. **Authoritative current coverage = `94.9% (75/79)`** (Current Metrics
> above; S1). No REALITY tier-3 BHV is added to the denominator.
> **Note on the `/79`:** the current denominator is `56 BHV + 23 routing-rule/action BHVs`
> (DP-019…041, added 2026-07-21/22/23, each both-covered) — a different basis from the retired
> pre-2026-03-16 `56 + 4 SV.1` `/60`. The 4 open gaps (3 SV.2 STRUCTURAL + 1 LC) are unchanged.

---

## S7: Maintenance Protocol

### Update Triggers

| Event | Required Action |
|-------|-----------------|
| New case added to `cases/` | Add entry to `case_backlog.md`; if `kernel_mode: both`, update S3 Both Cases column + S6 |
| Case promoted to `both` | Update S3 Both Cases column + S5 tier status + S6 metrics |
| New divergence discovered | Add entry to S4 with BHV cross-reference; update S3 Known Div column |
| Divergence resolved (Rust implements feature) | Move DIV entry to "Resolved" appendix; update S3 |
| diff_report.rs gains new dimension | Add row to S2; create new BHV entries if needed |
| New Clash API endpoint added | Add BHV entry to appropriate CP sub-section |

### Document Boundaries (Non-Overlapping)

| Document | Owns | Does NOT Own |
|----------|------|--------------|
| **This spec** (golden_spec) | BHV definitions, DIV registry, coverage metrics, promotion roadmap | Case YAML content, implementation status |
| `case_backlog.md` | Case list, priority, implementation status | Behavior definitions, divergence tracking |
| `compat_matrix.md` | API × case cross-reference table | Promotion planning, coverage metrics |
| `GO_PARITY_MATRIX.md` | Code-level implementation parity (209/209) | Behavioral equivalence, test coverage |
| `REFERENCE.md` | Go/Rust config field mapping, build params | Behavior definitions, test orchestration |

---

## S8: Go Config Translation Guide

Mechanical steps for creating a Go config when promoting a case to `kernel_mode: both`.

### Step 1: Copy Rust Config as Template

```bash
cp labs/interop-lab/configs/rust_core_*.json labs/interop-lab/configs/go_core_<name>.json
```

### Step 2: Apply Field Remapping

| Rust Field | Go Field | Example |
|------------|----------|---------|
| `name` (in inbounds/outbounds) | `tag` | `"socks-in"` → `"socks-in"` (same value, different key) |
| `port` (in inbounds) | `listen_port` | `11810` → `11811` |
| `external_controller` (in experimental.clash_api) | `external_controller` | `127.0.0.1:19090` → `127.0.0.1:9090` |

### Step 3: Apply Port Convention

| Role | Rust Port | Go Port |
|------|-----------|---------|
| Clash API | 19090 | 9090 |
| SOCKS inbound | 11810 | 11811 |
| Admin API | 19190 | — (not used) |

### Step 4: Validate

```bash
cd go_fork_source/sing-box-1.13.13
./sing-box check -c ../../labs/interop-lab/configs/go_core_<name>.json
```

### Step 5: Update Case YAML

```yaml
kernel_mode: both
bootstrap:
  rust:
    command: ./target/debug/app
    args: [-c, labs/interop-lab/configs/rust_core_<name>.json, run]
    api:
      base_url: http://127.0.0.1:19090
      secret: test-secret
  go:
    command: go_fork_source/sing-box-1.13.13/sing-box
    args: [run, -c, labs/interop-lab/configs/go_core_<name>.json]
    api:
      base_url: http://127.0.0.1:9090
      secret: test-secret
```

### Step 6: Add Oracle Rules (if needed)

For known divergences (S4), add oracle ignore/tolerance rules:

```yaml
oracle:
  ignore_http_paths:
    - /proxies/direct/delay* # DIV-M-009
    - /dns/query?name=unresolvable* # DIV-M-010
  ignore_ws_paths:
    - /logs               # DIV-M-002
  tolerate_counter_jitter: true
  counter_jitter_abs: 10  # byte-level jitter tolerance
  ignore_memory_ratio_on_non_linux: true # DIV-M-008
```
