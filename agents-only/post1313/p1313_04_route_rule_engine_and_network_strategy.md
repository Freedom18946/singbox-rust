<!-- tier: B -->
# P1313-04 Route Rule Engine And Network Strategy

Priority: P1

Primary evidence:

- `agents-only/reference/GO_PARITY_MATRIX.md` PX-003, PX-005
- `go_fork_source/sing-box-1.13.13/option/route.go`
- `go_fork_source/sing-box-1.13.13/option/rule.go`
- `go_fork_source/sing-box-1.13.13/option/rule_action.go`
- `go_fork_source/sing-box-1.13.13/route/router.go`
- `go_fork_source/sing-box-1.13.13/route/conn.go`

## Goal

Align route rule parsing and execution with Go 1.13.13 after the DNS/cache foundations are
stable.

## Current Gap

PX-005 records route dataplane partials; PX-003 shows historical route/rule schema drift.
Go route options include default domain resolver, network strategy, network type,
fallback network type, fallback delay, and direct/bypass/reject/sniff/resolve action behavior.

## Task Split

1. Route root options.
   - `geoip`, `geosite`, `final`, `find_process`, `auto_detect_interface`.
   - `override_android_vpn`, `default_interface`, `default_mark`.
   - `default_domain_resolver`.
   - `default_network_strategy`, `default_network_type`,
     `default_fallback_network_type`, `default_fallback_delay`.

2. Route rule conditions.
   - Match Go `RawDefaultRule` field coverage.
   - Add regression cases for `preferred_by`, `interface_address`,
     `network_interface_address`, `default_interface_address`.
   - Confirm deprecated `rule_set_ipcidr_match_source` alias behavior.

3. Route action behavior.
   - `route` outbound selection.
   - `route-options`: override address/port, network strategy, fallback delay,
     UDP flags, TLS fragmentation flags.
   - `direct` action using dialer options.
   - `bypass` action semantics.
   - `reject` method mapping.
   - `hijack-dns`, `sniff`, and `resolve` action ordering.

4. Process and platform metadata.
   - Ensure process lookup result enters rule context consistently.
   - Keep unsupported platform behavior loud and documented.
   - Avoid making macOS/Linux-only claims from generic unit tests.

5. RuleSet integration.
   - Inline/local/remote source and binary rule sets.
   - Rule-set IP CIDR source matching.
   - Hot update callback boundaries if needed by adapter Router API.

6. Tests.
   - Config-level parser tests.
   - Router decision table tests.
   - Minimal dataplane replay for route action behavior where feasible.

## Acceptance

- `cargo test -p sb-config route`
- `cargo test -p sb-core router`
- Existing interop route cases promoted or extended only when the oracle is clear.
- No manual update to parity counts outside authoritative docs.

## Non-Goals

- UDP NAT implementation belongs to P1313-09.
- DNS rule cache semantics belong to P1313-03.
- Platform-only route behavior can remain accepted limitation if documented.
