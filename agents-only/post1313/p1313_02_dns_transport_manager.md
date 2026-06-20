<!-- tier: B -->
# P1313-02 DNS Transport Manager

Priority: P0

Primary evidence:

- `agents-only/reference/GO_PARITY_MATRIX.md` PX-004
- `go_fork_source/sing-box-1.13.13/dns/client.go`
- `go_fork_source/sing-box-1.13.13/dns/router.go`
- `go_fork_source/sing-box-1.13.13/dns/transport_manager.go`
- `go_fork_source/sing-box-1.13.13/dns/transport_registry.go`
- `go_fork_source/sing-box-1.13.13/option/dns.go`

## Goal

Replace the current minimal/env-gated DNS execution posture with a Go-style DNS transport
manager and client path that all later DNS rules, FakeIP, Clash API, and services can share.

## Current Gap

PX-004 says Rust lacks a Go-style `DNSRouter` / `TransportManager` / transport registry
flow. The Go option surface supports local, hosts, udp, tcp, tls, quic, https, h3, dhcp,
fakeip, and legacy upgrade behavior, plus client cache options.

## Task Split

1. Transport registry contract.
   - Define a Rust registry that maps DNS server `type` to parser + runtime transport.
   - Preserve feature-gated transports without silently accepting unsupported types.
   - Add a strict unknown type error matching Go's `unknown transport type`.

2. Server option parity.
   - Local: `prefer_go`, dialer options, legacy client subnet.
   - Hosts: `path`, `predefined`.
   - Remote UDP/TCP/TLS/QUIC/HTTPS/H3: `server`, `server_port`, `path`, `method`,
     `headers`, `domain_resolver`, `detour`, fallback behavior.
   - DHCP: `interface`.
   - FakeIP: `inet4_range`, `inet6_range`.

3. Legacy DNS upgrade compatibility.
   - Convert legacy `address`/scheme forms into typed server options.
   - Cover `rcode://` legacy rewrite into predefined DNS rule action.
   - Preserve a controlled "do not upgrade" path only for tests or explicit compatibility.

4. Client options.
   - `strategy`, `disable_cache`, `disable_expire`, `independent_cache`,
     `cache_capacity`, `client_subnet`.
   - Ensure cache keying is ready for per-transport isolation.

5. Runtime manager.
   - Manager owns transport instances by tag.
   - Start/close semantics integrate with P1313-05 lifecycle stages.
   - Missing final server and duplicate DNS server tags have deterministic errors.

6. Tests.
   - Parser tests for every DNS server type.
   - Manager construction tests with mixed transports.
   - Negative tests for unknown type and invalid server address.

## Acceptance

- `cargo test -p sb-config dns`
- `cargo test -p sb-core dns`
- `cargo check -p app --features parity`
- A new evidence note in this package file or a sibling evidence file.

## Implementation Evidence (2026-06-20)

Status: DONE.

Implemented:

- `sb-config` DNS IR now preserves Go-style typed server fields: `prefer_go`, `method`,
  `headers`, per-server `cache_capacity`, and top-level `cache_capacity`.
- `lower_dns` accepts local, hosts, udp, tcp, tls/dot, quic/doq, https, h3/http3/doh3,
  dhcp, fakeip/fake-ip, tailscale, and resolved typed servers; unknown types emit the
  stable error `unknown transport type: <type>`.
- Legacy `address` compatibility is retained: plain host addresses upgrade to UDP,
  `local`/`fakeip` stay special, and `rcode://...` servers are removed from runtime
  upstreams after rewriting referencing rules to `action: predefined` + mapped `rcode`.
- `sb-core` now builds DNS through `DnsServerManager`, which owns tag-to-upstream
  construction, deterministic dependency ordering, default selection, fakeip accounting,
  and loud errors for duplicate tags, missing defaults/dependencies, cycles, fakeip default,
  multiple fakeip servers, and unknown/invalid server addresses.
- DNS rule construction now carries predefined `rcode`/answer records through to runtime,
  including legacy `rcode://...` rule rewrites; IR-built DNS RuleSets also populate the
  suffix-trie index when that feature is enabled.
- `resolver_from_ir` remains the external compatibility entry point; internally it uses
  the manager and applies cache knobs with priority config > env > default.

Verification:

- `cargo test -p sb-config dns`
- `cargo test -p sb-core dns`
- `cargo test -p sb-core dns --features router,dns_udp,dns_doh,dns_dot,dns_doq,dns_doh3`
- `cargo check -p app --features parity`
- `./agents-only/06-scripts/verify-consistency.sh`
- `cargo check --workspace --all-features`

Audit hardening (2026-06-20):

- Rechecked P1313-02 against this package definition and tightened the remaining edge
  evidence: invalid server addresses now have a deterministic manager test, and resolver /
  rule-engine lifecycle tests prove dependency-first start with reverse close order.
- `DnsRuleEngine` now accepts the manager's deterministic lifecycle order while preserving
  existing direct-construction compatibility.
- Re-ran `cargo test -p sb-config dns`, `cargo test -p sb-core dns` (sandboxed run hit a
  local TCP bind permission error; sandbox-external rerun passed), `cargo check -p app
  --features parity`, and `cargo check --workspace --all-features`.

## Non-Goals

- DNS rule action behavior belongs to P1313-03.
- Clash `/dns/*` API behavior belongs to P1313-08.
- Public DNS network probing is not required.
