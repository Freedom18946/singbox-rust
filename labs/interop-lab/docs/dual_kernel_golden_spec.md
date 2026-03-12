<!-- tier: A -->
# Dual Kernel Golden Spec

> Authoritative behavioral alignment standard for Go (sing-box 1.12.14) and Rust (singbox-rust) dual-kernel testing.
> Stable reference for diff report interpretation, case promotion planning, and parity auditing.

---

## S1: Functional Domain Map

| Code | Domain | Sub-domains | Behaviors | Both-Covered | Coverage |
|------|--------|-------------|-----------|--------------|----------|
| CP | Control Plane | 4 (HTTP / WS / Auth / Non-GUI) | 21 | 19 | 90.5% |
| DP | Data Plane | 4 (Inbound / Outbound / Routing / DNS) | 18 | 0 | 0% |
| LC | Lifecycle | 3 (Startup / Reload / Shutdown) | 9 | 1 | 11.1% |
| SV | Services | 2 (Subscription / Provider) | 7 | 0 | 0% |
| PF | Performance | 3 (Latency / Memory / Startup) | 5 | 1 | 20.0% |
| **Total** | | **16** | **60** | **21** | **35.0%** |

> **Reading this table**: "Both-Covered" = at least one `kernel_mode: both` case exercises this behavior.
> Coverage gaps still cluster in DP/SV; LC now has its first strict dual-kernel behavior via `PATCH /configs`.

---

## S2: Diff Engine Dimension Map

Maps `diff_report.rs` comparison dimensions to behavior IDs in S3. When a diff fails, look up the dimension here to find the relevant BHV-IDs.

| Diff Dimension | Field in DiffReport | Compares | Related BHV-IDs | Oracle Controls |
|----------------|---------------------|----------|-----------------|-----------------|
| HTTP | `http_mismatches` | status + body_hash per endpoint | BHV-CP-001 … 007, 018 … 021 | `ignore_http_paths` |
| WebSocket | `ws_mismatches` | frame_count + frame_hash per stream | BHV-CP-008 … 011 | `ignore_ws_paths` |
| Subscription | `subscription_mismatches` | format + node_count | BHV-SV-001 … 004 | — |
| Traffic | `traffic_mismatches` | action success + counter up/down | BHV-DP-001 … 014, BHV-PF-001 | `tolerate_counter_jitter`, `counter_jitter_abs` |
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
| BHV-CP-001 | GET /configs returns runtime config | GET /configs | 200 + JSON with `mode`, `mixed-port` | HTTP | `p0_clash_api_contract`, `p0_clash_api_contract_strict` | — | DIV-M-006 |
| BHV-CP-002 | PATCH /configs updates mode | PATCH /configs `{"mode":"rule"}` | 204 No Content | HTTP | `p0_clash_api_contract`, `p0_clash_api_contract_strict` | — | — |
| BHV-CP-003 | GET /proxies lists groups+members | GET /proxies | 200 + JSON with `proxies` map | HTTP | `p0_clash_api_contract`, `p1_gui_proxy_switch_replay`, `p0_clash_api_contract_strict` | — | DIV-M-007 |
| BHV-CP-004 | PUT /proxies/{group} switches active | PUT /proxies/{group} `{"name":"..."}` | 204 + selector.now updated | HTTP | `p1_gui_proxy_switch_replay` | — | DIV-M-007 |
| BHV-CP-005 | GET /proxies/{name}/delay tests latency | GET /proxies/{name}/delay?timeout=N | 200 + `{"delay": ms}` or timeout | HTTP | `p0_clash_api_contract`, `p0_clash_api_contract_strict` | `p1_gui_proxy_delay_replay` | DIV-M-009 |
| BHV-CP-006 | GET /connections lists active conns | GET /connections | 200 + `{connections[], downloadTotal, uploadTotal}` | HTTP, Conn | `p0_clash_api_contract`, `p0_clash_api_contract_strict` | `p1_gui_connections_tracking` | DIV-M-008 |
| BHV-CP-007 | DELETE /connections/{id} closes conn | DELETE /connections/{id} | 204 or 404 | HTTP | `p0_clash_api_contract`, `p0_clash_api_contract_strict` | — | — |

### CP.2: Clash API WebSocket Streams

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-CP-008 | /traffic streams real-time bandwidth | WS /traffic | JSON frames `{up, down}` | WS | `p0_clash_api_contract`, `p0_clash_api_contract_strict` | `p1_gui_full_boot_replay` | — |
| BHV-CP-009 | /memory streams RSS usage | WS /memory | JSON frames `{inuse, oslimit}` | WS | `p0_clash_api_contract`, `p0_clash_api_contract_strict` | `p1_gui_full_boot_replay` | — |
| BHV-CP-010 | /connections streams conn updates | WS /connections | JSON frames with connection list | WS | `p0_clash_api_contract`, `p2_connections_ws_soak_dual_core` | `p2_connections_ws_concurrency_suite` | DIV-M-004 |
| BHV-CP-011 | /logs streams log entries | WS /logs | JSON frames with log message | WS | `p0_clash_api_contract`, `p0_clash_api_contract_strict` | `p1_gui_full_boot_replay` | DIV-M-002 |

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
| BHV-CP-020 | GET /version returns version info | GET /version | 200 + `{version, ...}` | HTTP | — | — | — |
| BHV-CP-021 | GET /dns/query resolves domain | GET /dns/query?name=example.com | 200 + DNS result JSON | HTTP | — | — | DIV-M-005 |

### DP.1: Inbound

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-DP-001 | SOCKS5 TCP CONNECT proxies streams | TCP via SOCKS5 | Round-trip echo success | Traffic | — | `p1_rust_core_tcp_via_socks` | — |
| BHV-DP-002 | SOCKS5 UDP relays packets | UDP via SOCKS5 | Round-trip echo success | Traffic | — | `p1_rust_core_udp_via_socks` | DIV-C-002 |
| BHV-DP-003 | HTTP CONNECT proxies tunnels | HTTP CONNECT via proxy | HTTP GET through proxy succeeds | Traffic | — | `p1_rust_core_http_via_socks` | — |
| BHV-DP-004 | Mixed inbound detects protocol | SOCKS5 or HTTP to same port | Auto-detect and handle | Traffic | — | `p0_clash_api_contract_strict` | — |

### DP.2: Outbound

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-DP-005 | Direct outbound connects to target | Routed to direct | TCP connection established | Traffic, Conn | — | `p1_rust_core_http_via_socks` | DIV-C-001 |
| BHV-DP-006 | Selector switches via PUT API | PUT /proxies/{group} | Subsequent traffic uses new path | Traffic | — | `p1_gui_proxy_switch_replay` | — |
| BHV-DP-007 | URLTest auto-selects lowest latency | urltest group configured | Auto-selects best outbound | Traffic | — | `p1_gui_proxy_delay_replay` | — |
| BHV-DP-008 | Block outbound rejects connection | Routed to block | Connection refused/reset | Traffic | — | — | — |
| BHV-DP-009 | Chain proxy (multi-hop) | SOCKS5→SOCKS5→direct | End-to-end connectivity | Traffic | — | `p2_dataplane_chain_proxy` | — |

### DP.3: Routing

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-DP-010 | Rule match dispatches correctly | Traffic matching a rule | Dispatched to rule's outbound | Traffic | — | `p1_gui_connections_tracking` | — |
| BHV-DP-011 | route.final handles unmatched | Traffic matching no rule | Dispatched to final outbound | Traffic | — | `p1_rust_core_http_via_socks` | — |
| BHV-DP-012 | Domain rules match FQDN | Request to domain pattern | Correct outbound selected | Traffic | — | — | — |
| BHV-DP-013 | IP-CIDR rules match addresses | Request to IP in CIDR | Correct outbound selected | Traffic | — | — | — |
| BHV-DP-014 | Sniff detects protocol from payload | TLS/HTTP payload inspection | Protocol detected, domain extracted | Traffic | — | — | DIV-C-003 |

### DP.4: DNS

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-DP-015 | DNS resolves via configured servers | Domain lookup | IP address returned | Traffic | — | `p1_rust_core_dns_via_socks` | — |
| BHV-DP-016 | FakeIP pool allocates addresses | Domain in fakeip range | Fake IP from pool | Traffic | — | — | DIV-M-001 |
| BHV-DP-017 | FakeIP cache flush via API | DELETE /cache/fakeip/flush | Cache cleared, 204 | HTTP | — | — | DIV-M-001 |
| BHV-DP-018 | DNS result caching and TTL | Repeated domain lookup | Cached response, respects TTL | Traffic | — | — | — |

### LC.1: Startup

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-LC-001 | Config validate and parse | JSON config file | Parse success or structured error | — | — | `p1_deprecated_v1_style_config` | — |
| BHV-LC-002 | API ready signal on startup | Process start | GET /version returns 200 | HTTP | — | `p1_lifecycle_restart_reload_replay` | — |
| BHV-LC-003 | Concurrent service initialization | Multiple services configured | All services started, failures isolated | — | — | `p1_service_failure_isolation` | — |

### LC.2: Reload

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-LC-004 | PATCH /configs mode switch | PATCH /configs `{"mode":"..."}` | Mode updated, 204 | HTTP | `p0_clash_api_contract_strict` | — | DIV-M-006 |
| BHV-LC-005 | Inbound hot-reload on config change | Config file update + signal | Inbound rebind without restart | — | — | — | DIV-H-001 |
| BHV-LC-006 | State preservation across reload | Reload signal | Connections/proxy state preserved | — | — | — | — |

### LC.3: Shutdown

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-LC-007 | Graceful shutdown drains connections | SIGTERM / shutdown signal | Active connections drain before exit | — | — | — | DIV-M-003 |
| BHV-LC-008 | Connection close notification | Shutdown initiated | WS /connections notified | WS | — | — | — |
| BHV-LC-009 | Resource cleanup on exit | Process exit | FDs/sockets released, no leak | Memory | — | — | — |

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
| BHV-SV-005 | Proxy provider list via API | GET /providers/proxies | Provider entries with nodes | HTTP | — | — | DIV-H-003 |
| BHV-SV-006 | Rule provider list via API | GET /providers/rules | Rule provider entries | HTTP | — | — | — |
| BHV-SV-007 | Provider healthcheck via API | POST /providers/proxies/{name}/healthcheck | Health status response | HTTP | — | — | DIV-H-004 |

### PF.1: Latency

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-PF-001 | HTTP proxy p95 latency | HTTP via SOCKS5 under load | p95 < threshold | Traffic | — | `p2_bench_socks5_throughput` | — |
| BHV-PF-002 | API response p95 latency | GET /proxies repeated | p95 < threshold | HTTP | — | — | — |

### PF.2: Memory

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-PF-003 | Peak RSS within bounds | Steady-state operation | Rust peak < 2x Go peak | Memory | `p2_connections_ws_soak_dual_core` | `p2_connections_ws_soak_suite` | — |
| BHV-PF-004 | WS connection memory stable | Long-running WS streams | No linear memory growth | Memory | — | `p2_connections_ws_soak_suite` | — |

### PF.3: Startup

| BHV ID | Behavior | Input | Expected Output | Diff Dim | Both Cases | Rust-Only Cases | Known Div |
|--------|----------|-------|-----------------|----------|------------|-----------------|-----------|
| BHV-PF-005 | Time to API ready | Process launch | /version 200 within timeout | — | — | `p1_lifecycle_restart_reload_replay` | — |

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
| DIV-C-002 | KNOWN-GAP | SOCKS5 UDP ASSOCIATE defaults to off. Clients must explicitly enable. | BHV-DP-002 | Skip UDP tests in both-mode unless Go config also disables |
| DIV-C-003 | KNOWN-GAP | Sniff/Resolve/Hijack actions rejected on inbound path. Go allows them; Rust treats as config error. | BHV-DP-014 | Omit sniff-dependent routing rules from Go config |

### High (Partial Scenario Failure)

| DIV ID | Tag | Description | Affected BHV | Oracle Action |
|--------|-----|-------------|--------------|---------------|
| DIV-H-001 | KNOWN-GAP | Inbound hot-reload not implemented. Restart required for port changes. | BHV-LC-005 | Do not test inbound rebind in both-mode |
| DIV-H-002 | KNOWN-GAP | Redirect inbound IPv6 not supported. | BHV-DP-001 | Use IPv4 only in both-mode configs |
| DIV-H-003 | KNOWN-GAP | Provider has no background update loop. Only responds to manual refresh. | BHV-CP-018, BHV-SV-005 | Ignore provider update timestamps in diff |
| DIV-H-004 | KNOWN-GAP | Provider healthcheck always returns healthy (no actual probe). | BHV-SV-007 | Ignore healthcheck result field in diff |

### Cosmetic (Format Differences)

| DIV ID | Tag | Description | Affected BHV | Oracle Action |
|--------|-----|-------------|--------------|---------------|
| DIV-M-001 | COSMETIC | FakeIP flush: Rust uses DELETE /cache/fakeip/flush, Go uses POST. | BHV-DP-016, BHV-DP-017 | `ignore_http_paths: ["/cache/fakeip/flush"]` |
| DIV-M-002 | COSMETIC | /logs WS: Rust frames include extra `timestamp` and `source` fields not in Go. | BHV-CP-011 | `ignore_ws_paths: ["/logs"]` or structural diff |
| DIV-M-003 | COSMETIC | Shutdown grace period: Rust configurable, Go fixed 30s. | BHV-LC-007 | No oracle action (not observed in API) |
| DIV-M-004 | COSMETIC | /connections WS: Rust hardcodes 1s push interval, Go uses `?interval=` param. | BHV-CP-010 | `tolerate_counter_jitter: true` for connection counts |
| DIV-M-005 | COSMETIC | /dns/query response: Rust returns simplified JSON vs Go's full dig-style output. | BHV-CP-021 | `ignore_http_paths: ["/dns/query"]` |
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
| Current | Baseline | 8 | 8 / 83 | 35.0% (21/60 BHV) |
| T1 Immediate | GUI critical path strict | +5 | 11 / 83 | ~50% (30/60 BHV) |
| T2 Near-term | Control plane complete | +4 | 15 / 83 | ~58% (35/60 BHV) |
| T3 Planned | Data plane core + lifecycle | +7 | 22 / 83 | ~68% (41/60 BHV) |
| T4 Long-term | Protocol suites + perf | +4 | 26 / 83 | ~75% (45/60 BHV) |

### T1: Immediate (5 cases, all E2-E3)

These cases already exist as Rust-only strict and are the GUI critical path.

| # | Case ID | Current Mode | Effort | New BHVs Covered | Notes |
|---|---------|-------------|--------|------------------|-------|
| 1 | `p0_clash_api_contract_strict` | both | E3 | BHV-CP-001…007, 008…011 (strict), BHV-LC-004 | Promoted on 2026-03-12 with self-managed Go bootstrap + strict oracle |
| 2 | `p1_gui_full_boot_replay` | rust | E2 | BHV-CP-008…011 (parallel WS) | 4 WS parallel + HTTP GET startup sequence |
| 3 | `p1_gui_proxy_switch_replay` | both | E3 | BHV-CP-004, BHV-DP-006 | Promoted on 2026-03-12 with self-managed Go bootstrap + `/proxies` oracle ignore |
| 4 | `p1_gui_proxy_delay_replay` | rust | E2 | BHV-CP-005 (strict), BHV-DP-007 | GET /proxies/{name}/delay |
| 5 | `p1_gui_full_session_replay` | rust | E3 | BHV-LC-002, BHV-DP-010, BHV-DP-011 | Needs oracle for /logs format divergence (DIV-M-002) |

### T2: Near-term (+4 cases)

| # | Case ID | Effort | New BHVs Covered |
|---|---------|--------|------------------|
| 1 | `p1_clash_api_auth_enforcement` | E2 | BHV-CP-012…017 (strict auth coverage) |
| 2 | `p1_gui_connections_tracking` | E2 | BHV-CP-006 (strict), BHV-DP-010 |
| 3 | `p1_gui_group_delay_replay` | E2 | BHV-CP-005 (group variant) |
| 4 | `p1_gui_ws_reconnect_behavior` | E3 | BHV-LC-002 (restart recovery) |

### T3: Planned (+7 cases)

| # | Case ID | Effort | New BHVs Covered |
|---|---------|--------|------------------|
| 1 | `p1_rust_core_http_via_socks` | E2 | BHV-DP-001, BHV-DP-003, BHV-DP-005, BHV-DP-011 |
| 2 | `p1_rust_core_tcp_via_socks` | E2 | BHV-DP-001 |
| 3 | `p1_rust_core_udp_via_socks` | E3 | BHV-DP-002 (needs DIV-C-002 oracle) |
| 4 | `p1_rust_core_dns_via_socks` | E2 | BHV-DP-015 |
| 5 | `p1_lifecycle_restart_reload_replay` | E3 | BHV-LC-001…004 |
| 6 | `p0_subscription_json` | E2 | BHV-SV-001 |
| 7 | `p0_subscription_yaml` | E2 | BHV-SV-002 |

### T4: Long-term (+4 cases)

| # | Case ID | Effort | New BHVs Covered |
|---|---------|--------|------------------|
| 1 | `p2_trojan_protocol_suite` | E4 | BHV-DP-001 (Trojan variant) |
| 2 | `p2_shadowsocks_protocol_suite` | E4 | BHV-DP-001 (SS variant) |
| 3 | `p2_bench_socks5_throughput` | E3 | BHV-PF-001 |
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
| Both-mode case ratio | both cases / total cases | 7.2% (6/83) |
| Behavioral coverage (all) | BHVs with ≥1 both case / total BHVs | 31.7% (19/60) |
| Behavioral coverage (strict) | BHVs with ≥1 strict both case / total BHVs | 1.7% (1/60) |
| GUI endpoint coverage | GUI BHVs (CP.1+CP.2) with both case / GUI BHVs | 90.9% (10/11) |
| GUI endpoint coverage (strict) | GUI BHVs with strict both case / GUI BHVs | 0% (0/11) |
| MIG-02 divergence coverage | DIV-C/H BHVs with both case / DIV-C/H BHVs | 0% (0/7) |

> **Note**: Current both-mode coverage is heavily skewed toward `env_limited` cases (5/6 both cases are env_limited).
> The operational gap is in **strict** both-mode coverage, which requires managed kernel bootstrap.

### Projected Coverage by Tier

| After Tier | Both Cases | BHV Coverage | Strict BHV Coverage |
|------------|-----------|--------------|---------------------|
| Current | 6 | 31.7% (19/60) | 1.7% (1/60) |
| T1 | 11 | ~50.0% (30/60) | ~18.3% (11/60) |
| T2 | 15 | ~58.3% (35/60) | ~25.0% (15/60) |
| T3 | 22 | ~68.3% (41/60) | ~40.0% (24/60) |
| T4 | 26 | ~75.0% (45/60) | ~46.7% (28/60) |

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
