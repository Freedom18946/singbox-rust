<!-- tier: A -->
# Dual Kernel Golden Spec

> Authoritative behavioral alignment standard for Go (sing-box 1.12.14) and Rust (singbox-rust) dual-kernel testing.
> Stable reference for diff report interpretation, case promotion planning, and parity auditing.

---

## S1: Functional Domain Map

| Code | Domain | Sub-domains | Behaviors | Both-Covered | Coverage |
|------|--------|-------------|-----------|--------------|----------|
| CP | Control Plane | 4 (HTTP / WS / Auth / Non-GUI) | 21 | 21 | 100.0% |
| DP | Data Plane | 4 (Inbound / Outbound / Routing / DNS) | 18 | 18 | 100.0% |
| LC | Lifecycle | 3 (Startup / Reload / Shutdown) | 9 | 8 | 88.9% |
| SV | Services | 2 (Subscription / Provider) | 7 | 0 | 0% |
| PF | Performance | 3 (Latency / Memory / Startup) | 5 | 5 | 100.0% |
| **Total** | | **16** | **60** | **52** | **86.7%** |

> **Reading this table**: "Both-Covered" = at least one `kernel_mode: both` case exercises this behavior.
> Coverage gaps still cluster in DP/SV, but both domains now have an initial strict dual-kernel foothold.

---

## S2: Diff Engine Dimension Map

Maps `diff_report.rs` comparison dimensions to behavior IDs in S3. When a diff fails, look up the dimension here to find the relevant BHV-IDs.

| Diff Dimension | Field in DiffReport | Compares | Related BHV-IDs | Oracle Controls |
|----------------|---------------------|----------|-----------------|-----------------|
| HTTP | `http_mismatches` | status + body_hash per endpoint | BHV-CP-001 … 007, 018 … 021 | `ignore_http_paths` |
| WebSocket | `ws_mismatches` | frame_count + frame_hash per stream | BHV-CP-008 … 011 | `ignore_ws_paths` |
| Subscription | `subscription_mismatches` | format + node_count | BHV-SV-001 … 004 | — |
| Traffic | `traffic_mismatches` | action success + counter up/down | BHV-DP-001 … 017, BHV-PF-001, BHV-PF-002 | `tolerate_counter_jitter`, `counter_jitter_abs` |
| Connections | `connection_mismatches` | connections.count + downloadTotal/uploadTotal | BHV-CP-006, BHV-DP-005 … 009 | `tolerate_counter_jitter` |
| Memory | `memory_mismatches` | peak RSS ratio (>2x = mismatch) | BHV-PF-003, BHV-PF-004 | — |

> **Tester workflow**: diff report shows `http_mismatches` on `/proxies` → look up BHV-CP-003 → check S4 for known divergences → decide pass/fail.

---

## S3: Behavior Registry

Stable ID format: `BHV-{domain}-{seq}`. Each row = one testable behavior.

**Column key**: `Both` = case IDs with `kernel_mode: both` covering this behavior. `Rust-Only` = key rust-only cases. Empty Both = coverage gap.

### CP.1: Clash API HTTP Endpoints

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-CP-001 | GET /configs returns runtime config | GET /configs | 200 + JSON with `mode`, `mixed-port` | HTTP | `p0_clash_api_contract`, `p0_clash_api_contract_strict`, `p1_gui_full_boot_replay` | — | DIV-M-006 |
| BHV-CP-002 | PATCH /configs updates mode | PATCH /configs `{"mode":"rule"}` | 204 No Content | HTTP | `p0_clash_api_contract`, `p0_clash_api_contract_strict` | — | — |
| BHV-CP-003 | GET /proxies lists groups+members | GET /proxies | 200 + JSON with `proxies` map | HTTP | `p0_clash_api_contract`, `p1_gui_proxy_switch_replay`, `p0_clash_api_contract_strict`, `p1_gui_full_boot_replay` | — | DIV-M-007 |
| BHV-CP-004 | PUT /proxies/{group} switches active | PUT /proxies/{group} `{"name":"..."}` | 204 + selector.now updated | HTTP | `p1_gui_proxy_switch_replay` | — | DIV-M-007 |
| BHV-CP-005 | GET /proxies/{name}/delay tests latency | GET /proxies/{name}/delay?timeout=N | 200 + `{"delay": ms}` or timeout | HTTP | `p0_clash_api_contract`, `p0_clash_api_contract_strict`, `p1_gui_proxy_delay_replay` | — | DIV-M-009 |
| BHV-CP-006 | GET /connections lists active conns | GET /connections | 200 + `{connections[], downloadTotal, uploadTotal}` | HTTP, Conn | `p0_clash_api_contract`, `p0_clash_api_contract_strict`, `p1_gui_connections_tracking` | — | DIV-M-008 |
| BHV-CP-007 | DELETE /connections/{id} closes conn | DELETE /connections/{id} | 204 or 404 | HTTP | `p0_clash_api_contract`, `p0_clash_api_contract_strict` | — | — |

### CP.2: Clash API WebSocket Streams

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-CP-008 | /traffic streams real-time bandwidth | WS /traffic | JSON frames `{up, down}` | WS | `p0_clash_api_contract`, `p0_clash_api_contract_strict`, `p1_gui_full_boot_replay` | — | — |
| BHV-CP-009 | /memory streams RSS usage | WS /memory | JSON frames `{inuse, oslimit}` | WS | `p0_clash_api_contract`, `p0_clash_api_contract_strict`, `p1_gui_full_boot_replay` | — | — |
| BHV-CP-010 | /connections streams conn updates | WS /connections | JSON frames with connection list | WS | `p0_clash_api_contract`, `p2_connections_ws_soak_dual_core` | `p2_connections_ws_concurrency_suite` | DIV-M-004 |
| BHV-CP-011 | /logs streams log entries | WS /logs | JSON frames with log message | WS | `p0_clash_api_contract`, `p0_clash_api_contract_strict`, `p1_gui_full_boot_replay` | — | DIV-M-002 |

### CP.3: Authentication

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-CP-012 | Valid Bearer token → HTTP 200 | `Authorization: Bearer {secret}` | 200 on protected endpoints | HTTP | `p0_clash_api_contract` | `p1_clash_api_auth_enforcement` | — |
| BHV-CP-013 | Wrong Bearer token → HTTP 401 | `Authorization: Bearer wrong` | 401 Unauthorized | HTTP | `p1_auth_negative_wrong_token` | `p1_clash_api_auth_enforcement` | — |
| BHV-CP-014 | Missing Bearer token → HTTP 401 | No Authorization header | 401 Unauthorized | HTTP | `p1_auth_negative_missing_token` | `p1_clash_api_auth_enforcement` | — |
| BHV-CP-015 | Valid WS ?token= → connected | WS upgrade with `?token={secret}` | Connection accepted, frames flow | WS | `p0_clash_api_contract` | `p1_clash_api_auth_enforcement` | — |
| BHV-CP-016 | Wrong WS ?token= → rejected | WS upgrade with `?token=wrong` | Connection rejected (401/close) | WS | `p1_auth_negative_wrong_token` | `p1_clash_api_auth_enforcement` | — |
| BHV-CP-017 | Missing WS ?token= → rejected | WS upgrade without token param | Connection rejected (401/close) | WS | `p1_auth_negative_missing_token` | `p1_clash_api_auth_enforcement` | — |

### CP.4: Non-GUI Endpoints

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-CP-018 | GET /providers returns provider list | GET /providers/proxies | 200 + provider JSON | HTTP | `p1_optional_endpoints_contract` | — | DIV-H-003 |
| BHV-CP-019 | GET /rules returns rule list | GET /rules | 200 + rules array | HTTP | `p1_optional_endpoints_contract` | — | — |
| BHV-CP-020 | GET /version returns version info | GET /version | 200 + `{version, ...}` | HTTP | `p1_version_endpoint_contract` | — | — |
| BHV-CP-021 | GET /dns/query resolves domain | GET /dns/query?name=example.com | 200 + DNS result JSON | HTTP | `p1_dns_query_endpoint_contract` | — | DIV-M-005 |

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

### DP.4: DNS

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-DP-015 | DNS resolves via configured servers | Domain lookup | IP address returned | Traffic | `p1_rust_core_dns_via_socks` | — | — |
| BHV-DP-016 | FakeIP pool allocates addresses | Domain in fakeip range | Fake IP from pool | Traffic | `p1_fakeip_dns_query_contract` | — | DIV-M-001 |
| BHV-DP-017 | FakeIP cache flush via API | DELETE /cache/fakeip/flush | Cache cleared, 204 | HTTP | `p1_fakeip_cache_flush_contract` | — | DIV-M-001 |
| BHV-DP-018 | DNS result caching and TTL | Repeated domain lookup | Cached response, respects TTL | Traffic | `p1_dns_cache_ttl_via_socks` | — | — |

### LC.1: Startup

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-LC-001 | Config validate and parse | JSON config file | Parse success or structured error | — | `p1_lifecycle_restart_reload_replay` | `p1_deprecated_v1_style_config` | — |
| BHV-LC-002 | API ready signal on startup | Process start | GET /version returns 200 | HTTP | `p1_gui_full_session_replay`, `p1_lifecycle_restart_reload_replay` | — | — |
| BHV-LC-003 | Concurrent service initialization | Multiple services configured | All services started, failures isolated | — | — | `p1_service_failure_isolation` | — |

### LC.2: Reload

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-LC-004 | PATCH /configs mode switch | PATCH /configs `{"mode":"..."}` | Mode updated, 204 | HTTP | `p0_clash_api_contract_strict` | — | DIV-M-006 |
| BHV-LC-005 | Inbound hot-reload on config change | Config file update + signal | Inbound rebind without restart | — | `p1_inbound_hot_reload_sighup` | — | — |
| BHV-LC-006 | State preservation across reload | Reload signal | Connections/proxy state preserved | — | `p1_selector_switch_traffic_replay` | — | — |

### LC.3: Shutdown

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-LC-007 | Graceful shutdown drains connections | SIGTERM / shutdown signal | Active connections drain before exit | — | `p1_graceful_shutdown_drain` | — | DIV-M-003 |
| BHV-LC-008 | Connection close notification | Shutdown initiated | WS /connections notified | WS | `p1_gui_ws_reconnect_behavior` | — | — |
| BHV-LC-009 | Resource cleanup on exit | Process exit | FDs/sockets released, no leak | Memory | `p1_lifecycle_restart_reload_replay` | — | — |

### SV.1: Subscription Parsing

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-SV-001 | JSON outbounds parsing | JSON subscription blob | Parsed nodes with protocol types | Sub | — | `p0_subscription_json` | — |
| BHV-SV-002 | YAML proxies parsing | YAML subscription blob | Parsed nodes with protocol types | Sub | — | `p0_subscription_yaml` | — |
| BHV-SV-003 | Base64 auto-decode | Base64-encoded subscription | Decoded then parsed | Sub | — | `p0_subscription_base64` | — |
| BHV-SV-004 | URL fetch and parse | HTTP URL to subscription | Fetched, decoded, parsed | Sub | — | `p1_subscription_file_urls` | — |

### SV.2: Provider

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-SV-005 | Proxy provider list via API | GET /providers/proxies | Provider entries with nodes | HTTP | — | `test_get_proxy_providers_with_data` | DIV-H-005 |
| BHV-SV-006 | Rule provider list via API | GET /providers/rules | Rule provider entries | HTTP | — | `test_get_rule_providers_with_data` | DIV-H-005 |
| BHV-SV-007 | Provider healthcheck via API | POST /providers/proxies/{name}/healthcheck | Health status response | HTTP | — | `test_healthcheck_proxy_provider_with_data` | DIV-H-005 |

### PF.1: Latency

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-PF-001 | HTTP proxy p95 latency | HTTP via SOCKS5 under load | p95 < threshold | Traffic | `p1_rust_core_http_via_socks` | `p2_bench_socks5_throughput` | — |
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

### Critical (User-Visible)

| DIV ID | Tag | Description | Affected BHV | Oracle Action |
|--------|-----|-------------|--------------|---------------|
| DIV-C-001 | INTENTIONAL | No implicit direct fallback — unresolvable destinations return error instead of silently falling back to direct. MIG-02 wave#200. | BHV-DP-005, BHV-DP-011 | `ignore_http_paths` for affected traffic test endpoints |
| DIV-C-002 | KNOWN-GAP | SOCKS5 UDP ASSOCIATE defaults to off unless explicitly enabled on the Rust inbound. | BHV-DP-002 | Set `SB_SOCKS_UDP_ENABLE=1` for Rust strict both-mode cases |
| DIV-C-003 | CLOSED | Sniff rule action now implemented: inbounds read initial bytes, run sniff_stream(), populate protocol/host, and re-decide. | BHV-DP-014 | — |

### High (Partial Scenario Failure)

| DIV ID | Tag | Description | Affected BHV | Oracle Action |
|--------|-----|-------------|--------------|---------------|
| DIV-H-001 | CLOSED | Inbound hot-reload validated: SIGHUP triggers reload and inbound rebinds on both kernels. | BHV-LC-005 | — |
| DIV-H-002 | KNOWN-GAP | Redirect inbound IPv6 not supported. | BHV-DP-001 | Use IPv4 only in both-mode configs |
| DIV-H-003 | CLOSED | Provider background update loop implemented (L23-T4). ProviderManager now sweeps stale providers on a configurable tick interval. | BHV-CP-018, BHV-SV-005 | — |
| DIV-H-004 | CLOSED | Provider healthcheck now performs real TCP probe via outbound registry (L23-T5). Falls back to healthy when no registry configured. | BHV-SV-007 | — |
| DIV-H-005 | STRUCTURAL | Go provider endpoints return empty stubs (empty map / 404 for all provider routes). SV.2 BHVs cannot be dual-kernel tested. | BHV-SV-005, BHV-SV-006, BHV-SV-007 | Rust-only e2e coverage via `clash_http_e2e.rs` |

### Cosmetic (Format Differences)

| DIV ID | Tag | Description | Affected BHV | Oracle Action |
|--------|-----|-------------|--------------|---------------|
| DIV-M-001 | COSMETIC | FakeIP flush: Rust uses DELETE /cache/fakeip/flush, Go uses POST. | BHV-DP-016, BHV-DP-017 | `ignore_http_paths: ["/cache/fakeip/flush"]` |
| DIV-M-002 | COSMETIC | /logs WS: Rust frames include extra `timestamp` and `source` fields not in Go. | BHV-CP-011 | `ignore_ws_paths: ["/logs"]` or structural diff |
| DIV-M-003 | COSMETIC | Shutdown grace period: Rust configurable, Go fixed 30s. | BHV-LC-007 | No oracle action (not observed in API) |
| DIV-M-004 | COSMETIC | /connections WS: Rust hardcodes 1s push interval, Go uses `?interval=` param. | BHV-CP-010 | `tolerate_counter_jitter: true` for connection counts |
| DIV-M-005 | COSMETIC | /dns/query response: Rust returns simplified JSON vs Go's full dig-style output. | BHV-CP-021 | `ignore_http_paths: ["/dns/query*"]` |
| DIV-M-006 | COSMETIC | `/configs` payload normalization still differs in mode casing, mode-list, and exposed port fields under strict self-managed configs. | BHV-CP-001, BHV-LC-004 | `ignore_http_paths: ["/configs"]` |
| DIV-M-007 | COSMETIC | `/proxies` inventory differs because Rust injects synthetic entries and richer group metadata than Go. | BHV-CP-003, BHV-CP-004 | `ignore_http_paths: ["/proxies"]` |
| DIV-M-008 | COSMETIC | `/connections` HTTP snapshot includes runtime/platform-specific `memory` values; Rust returns 0 on non-Linux. | BHV-CP-006 | `ignore_http_paths: ["/connections"]` |
| DIV-M-009 | COSMETIC | `/proxies/{name}/delay` exact millisecond values are timing-sensitive across kernels even when status is consistent. | BHV-CP-005 | Path-specific `ignore_http_paths` until numeric tolerance exists |

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
| Current | Baseline | 32 | 32 / 95 | 78.3% (47/60 BHV) |
| T1 Immediate (Completed) | GUI critical path strict | +0 | 31 / 95 | 75.0% (45/60 BHV) |
| T2 Near-term | Coverage-neutral strict promotions | +3 | 30 / 92 | ~61.7% (37/60 BHV) |
| T3 Planned | Subscription both-cases | +2 | 32 / 92 | ~65.0% (39/60 BHV) |
| T4 Long-term | Protocol suites + perf | +4 | 36 / 92 | ~68.3% (41/60 BHV) |

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

| # | Case ID | Effort | New BHVs Covered |
|---|---------|--------|------------------|
| 1 | `p1_clash_api_auth_enforcement` | E2 | BHV-CP-012…017 (strict auth coverage) |
| 2 | `p1_gui_group_delay_replay` | E2 | BHV-CP-005 (group variant) |

### T3: Planned (+2 cases)

| # | Case ID | Effort | New BHVs Covered |
|---|---------|--------|------------------|
| 1 | `p0_subscription_json` | E2 | BHV-SV-001 |
| 2 | `p0_subscription_yaml` | E2 | BHV-SV-002 |

### Recent Promotions

| # | Case ID | Current Mode | Effort | New BHVs Covered | Notes |
|---|---------|-------------|--------|------------------|-------|
| 1 | `p1_rust_core_tcp_via_socks` | both | E2 | BHV-DP-001 | Promoted on 2026-03-12 with shared self-managed Clash API bootstrap + `/version` oracle ignore |
| 2 | `p1_rust_core_http_via_socks` | both | E2 | BHV-DP-005, BHV-PF-001 | Promoted on 2026-03-12 after replacing curl-only SOCKS traffic with `reqwest+socks` and `/version` oracle ignore; re-verified on 2026-03-14 with repeated HTTP GET p95 latency through SOCKS5 |
| 3 | `p1_rust_core_dns_via_socks` | both | E2 | BHV-DP-015 | Promoted on 2026-03-12 with shared self-managed Clash API bootstrap + `/version` oracle ignore |
| 4 | `p1_rust_core_udp_via_socks` | both | E2 | BHV-DP-002 | Promoted on 2026-03-12 with shared self-managed Clash API bootstrap, `SB_SOCKS_UDP_ENABLE=1`, and `/version` oracle ignore |
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

### T4: Long-term (+4 cases)

| # | Case ID | Effort | New BHVs Covered |
|---|---------|--------|------------------|
| 1 | `p2_trojan_protocol_suite` | E4 | BHV-DP-001 (Trojan variant) |
| 2 | `p2_shadowsocks_protocol_suite` | E4 | BHV-DP-001 (SS variant) |
| 3 | `p2_bench_socks5_throughput` | E3 | coverage-neutral perf stress (BHV-PF-001 now covered by `p1_rust_core_http_via_socks`) |
| 4 | `p0_subscription_base64` | E2 | BHV-SV-003 |

### Non-Promotable Cases (11)

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

---

## S6: Coverage Dashboard

### Current Metrics

| Metric | Formula | Value |
|--------|---------|-------|
| Both-mode case ratio | both cases / total cases | 36.0% (36/100) |
| Behavioral coverage (all) | BHVs with ≥1 both case / total BHVs | 86.7% (52/60) |
| Behavioral coverage (strict) | BHVs with ≥1 strict both case / total BHVs | 70.0% (42/60) |
| GUI endpoint coverage | GUI BHVs (CP.1+CP.2) with both case / GUI BHVs | 100.0% (11/11) |
| GUI endpoint coverage (strict) | GUI BHVs with strict both case / GUI BHVs | 100.0% (11/11) |
| MIG-02 divergence coverage | DIV-C/H BHVs with both case / DIV-C/H BHVs | 55.6% (5/9) |

> **Note**: strict both-mode coverage is no longer the main bottleneck.
> The remaining parity gap is concentrated in routing, lifecycle, and service behaviors that still need product fixes or richer dual-kernel scenarios.

### Projected Coverage by Tier

| After Tier | Both Cases | BHV Coverage | Strict BHV Coverage |
|------------|-----------|--------------|---------------------|
| Current | 31 | 75.0% (45/60) | 61.7% (37/60) |
| T1 | 11 | ~50.0% (30/60) | ~18.3% (11/60) |
| T2 | 15 | ~58.3% (35/60) | ~25.0% (15/60) |
| T3 | 32 | ~65.0% (39/60) | ~51.7% (31/60) |
| T4 | 36 | ~73.3% (44/60) | ~60.0% (36/60) |

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
cd go_fork_source/sing-box-1.12.14
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
    command: go_fork_source/sing-box-1.12.14/sing-box
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
    - /dns/query          # DIV-M-005
    - /cache/fakeip/flush # DIV-M-001
  ignore_ws_paths:
    - /logs               # DIV-M-002
  tolerate_counter_jitter: true
  counter_jitter_abs: 10  # byte-level jitter tolerance
```
