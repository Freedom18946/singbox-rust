<!-- tier: B -->
# P1313-03 DNS Rule Actions And Cache Semantics

Priority: P0

Status: DONE (2026-06-20)

Primary evidence:

- `agents-only/reference/GO_PARITY_MATRIX.md` PX-003, PX-004, PX-013
- `go_fork_source/sing-box-1.13.13/option/rule_dns.go`
- `go_fork_source/sing-box-1.13.13/option/rule_action.go`
- `go_fork_source/sing-box-1.13.13/dns/router.go`
- `go_fork_source/sing-box-1.13.13/dns/client_truncate.go`
- `go_fork_source/sing-box-1.13.13/dns/extension_edns0_subnet.go`

## Goal

Align DNS rule matching, DNS rule actions, and cache semantics with Go 1.13.13 so DNS
behavior is no longer a high-fanout divergence.

## Current Gap

PX-004 records missing EDNS0 subnet, TTL rewrite, RDRC, reverse mapping, and transport-aware
rule/action flow. PX-003 records rule action/logical/schema mismatch history.

## Closure Notes (2026-06-20)

- DNS IR/Raw/facade lowering now accepts Go DNS rule fields for logical rules and runtime
  context matchers, while the deprecated `rule_set_ipcidr_match_source` spelling is rejected.
- DNS rule compilation now emits `Rule::Logical` for logical rules and richer `DefaultRule`
  matchers for context, source/destination, process/user, network, and interface fields.
- Rule-engine routing decisions are keyed by full matcher context; destination IP CIDR/GeoIP
  are ignored pre-query and rechecked against answer IPs after upstream response.
- `route-options` accumulates strategy, disable-cache, rewrite TTL, and ECS overrides; route
  actions apply their own options, and FakeIP routes bypass answer-cache writes.
- A/AAAA answer cache is wired inside `DnsRuleEngine` with `disable_cache`, `disable_expire`,
  `independent_cache`, `cache_capacity`, and `rewrite_ttl`; rule-engine resolvers are no
  longer double-wrapped by the generic cached resolver.
- RDRC rejection checks/saves use the existing `CacheFileService` transport/domain/qtype API;
  reverse mapping writes require `dns.reverse_mapping=true` and skip FakeIP answers.
- Wire exchange now returns REFUSED for reject and builds predefined `rcode`/`answer`/`ns`/
  `extra` responses, including text RR and base64 packed RR inputs with owner-name rewrite.

## Task Split

1. DNS rule condition coverage.
   - `query_type`, `network`, `auth_user`, `protocol`.
   - domain/exact/suffix/keyword/regex/geosite.
   - `geoip`, `ip_cidr`, `ip_is_private`, `ip_accept_any`.
   - source IP/port, destination port, process fields, package/user fields.
   - `outbound`, `clash_mode`, network type/expensive/constrained, WiFi fields.
   - interface address and default interface address.
   - `rule_set`, `rule_set_ip_cidr_match_source`, `rule_set_ip_cidr_accept_empty`.

2. DNS action coverage.
   - `route`: server, strategy, disable_cache, rewrite_ttl, client_subnet.
   - `route-options`: strategy, disable_cache, rewrite_ttl, client_subnet.
   - `reject`: method mapping and response behavior.
   - `predefined`: rcode/answer/ns/extra behavior.
   - Logical rules: `and`/`or`, nested rules, invert.

3. Cache semantics.
   - `disable_cache` bypass.
   - `disable_expire` no-expiry behavior.
   - `independent_cache` per-transport keying.
   - `cache_capacity` enforcement.
   - remaining TTL/peek behavior for API/debug visibility.

4. EDNS0 / Client Subnet.
   - Inject ECS into query when configured.
   - Preserve existing OPT records and append ECS option.
   - Add IPv4 and IPv6 prefix tests.

5. RDRC and reverse mapping.
   - Save rejection cache with timeout.
   - Respect `rdrc_timeout`.
   - Store IP to domain reverse mapping after successful real answers.
   - Ensure FakeIP and real DNS mapping do not corrupt each other.

6. Truncation and wire response.
   - Match Go behavior for truncated UDP responses and TCP fallback eligibility.
   - Cover A, AAAA, HTTPS, and unsupported qtype paths.

## Acceptance

- `cargo test -p sb-config --test dns_rule_parity`
- `cargo test -p sb-config --test route_options_parity`
- `cargo test -p sb-core dns --features router,dns_udp,dns_doh,dns_dot,dns_doq,dns_doh3`
- `cargo check -p app --features parity`
- `cargo check --workspace --all-features`
- `./agents-only/06-scripts/verify-consistency.sh`

## Non-Goals

- DNS transport construction belongs to P1313-02.
- CacheFile persistence backing belongs to P1313-07.
