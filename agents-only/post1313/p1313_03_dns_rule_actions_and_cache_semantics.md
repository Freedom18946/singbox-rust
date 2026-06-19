<!-- tier: B -->
# P1313-03 DNS Rule Actions And Cache Semantics

Priority: P0

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

- `cargo test -p sb-config dns_rule_parity`
- `cargo test -p sb-config route_options_parity`
- `cargo test -p sb-core dns`
- Add at least one end-to-end DNS via SOCKS or inbound DNS replay case if existing harness
  support is sufficient.

## Non-Goals

- DNS transport construction belongs to P1313-02.
- CacheFile persistence backing belongs to P1313-07.
