# Go-Rust Parity Matrix (2025-12-09 Reality Check v2)

Objective: compare `singbox-rust` against Go reference `go_fork_source/sing-box-1.12.12` for functional, type, API, comment, and directory parity.

## Executive Summary

| Area | Status | Notes |
| --- | --- | --- |
| Tailscale endpoint/data plane | ❌ Not aligned | Go uses tsnet+gVisor stack; Rust relies on stub/daemon with host sockets only |
| Tailscale outbound & MagicDNS | ❌ Not aligned | Go routes via tsnet + DNS hooks; Rust modes are ad-hoc with raw MagicDNS client |
| DNS transports (DHCP/Resolved/Tailscale) | ◐ Partial | DHCP passive only; resolved/tailscale transports not feature-equivalent |
| TLS uTLS wiring | ❌ Not aligned | Fingerprints exist but never applied to TLS handshakes |
| Resolved service | ◐ Partial | Linux-only minimal D-Bus server; no netmon callbacks or per-link routing |
| DERP service | ❌ Not aligned | Go ships full DERP+STUN+mesh+ws/H2; Rust has partial HTTP/STUN relay |
| SSMAPI service | ❌ Not aligned | Go binds to managed inbounds with TLS/cache; Rust is standalone Axum without trackers |
| Protocol/Service coverage claims | ⚠️ Unverified | “100% parity” claims remain unsubstantiated by sources/tests |

## Detailed Findings

### 1) Tailscale endpoint vs Go
- Go endpoint builds a tsnet server with gVisor netstack, router/filter, DNS hooks, and both TCP/UDP handling (`go_fork_source/sing-box-1.12.12/protocol/tailscale/endpoint.go:1-180`).
- Rust endpoint uses stub/daemon control plane and dials via host sockets; UDP dial unsupported, no tsnet session, no DNS hook, no netstack (`crates/sb-core/src/endpoint/tailscale.rs:240-472`).
- Result: Tailnet connectivity/routing still far below Go feature set.

### 2) Tailscale outbound & MagicDNS
- Go binds outbound and MagicDNS to the tsnet stack and reacts to reconfig events (`go_fork_source/sing-box-1.12.12/protocol/tailscale/dns_transport.go:38-152`).
- Rust outbound modes (WireGuard/SOCKS/direct/Managed) are decoupled from any tsnet session; Managed mode depends on a `Coordinator` stub, and WireGuard mode never joins the Tailnet (`crates/sb-adapters/src/outbound/tailscale.rs:1-212`).
- MagicDNS is a raw UDP client to 100.100.100.100 with a hand-rolled parser, not tied to control-plane state or IPv6/fallbacks (`crates/sb-transport/src/tailscale_dns.rs:1-110`).
- Result: Tailnet routing and DNS resolution diverge from Go implementation.

### 3) DNS transport matrix
- Go supports UDP/TCP/DoT/DoH/DoQ/DoH3/FakeIP/Hosts/Local/Resolved/Tailscale/DHCP with active DHCP INFORM and interface probing.
- Rust DHCP transport only tails `resolv.conf` and does not probe interfaces or send INFORM (`crates/sb-core/src/dns/upstream.rs:74-187`).
- Resolved/tailscale transports are feature-gated; non-Linux falls back to stubs and even on Linux uses system resolver without network monitor integration (`crates/sb-adapters/src/service/resolved_impl.rs:10-110`).
- Result: DHCP discovery and tailscale/resolved behaviours remain incomplete.

### 4) TLS uTLS integration
- Go wires uTLS into TLS clients/servers and Reality/ShadowTLS paths (`go_fork_source/sing-box-1.12.12/common/tls/utls_client.go:1-170`).
- Rust defines fingerprints/config but has no consumers outside the module (no call sites beyond `crates/sb-tls/src/utls.rs:1-200`).
- Result: uTLS is effectively disabled; Reality/ShadowTLS parity fails when uTLS is required.

### 5) Resolved service
- Go exports a full D-Bus server, tracks per-link DNS/domain state, registers network monitor callbacks, and serves TCP/UDP DNS (`go_fork_source/sing-box-1.12.12/service/resolved/service.go:34-185`).
- Rust Linux implementation is minimal (system resolver, no netmon callbacks, no per-link routes) and non-Linux compiles to stub only (`crates/sb-adapters/src/service/resolved_impl.rs:10-210`).
- Result: Platform and feature gaps persist.

### 6) DERP service
- Go enforces TLS, loads DERP configs, exposes HTTP/2 + websocket DERP handlers, STUN, latency probes, and mesh PSK support tied to tailscale client libs (`go_fork_source/sing-box-1.12.12/service/derp/service.go:73-238`).
- Rust marks DERP as partial in docs and implements a standalone TCP stub with optional STUN/mesh; no HTTP/2, websocket upgrade, tailscale client integration, or verify-client hooks (`crates/sb-core/src/services/derp/mod.rs:1-13`, `crates/sb-core/src/services/derp/server.rs:1070-1184`).
- Result: DERP service parity is not achieved.

### 7) SSMAPI service
- Go binds to managed Shadowsocks inbounds, wires Traffic/User managers, supports TLS, and persists cache (`go_fork_source/sing-box-1.12.12/service/ssmapi/server.go:41-133`).
- Rust runs an Axum HTTP server with static user list, no inbound/integrated trackers, no TLS, and no cache/load path (`crates/sb-core/src/services/ssmapi/server.rs:17-118`).
- Result: SSMAPI semantics diverge from Go’s managed server model.

### Audit coverage
- Inspected modules: Tailscale endpoint/outbound, DNS transports, TLS uTLS, Resolved, DERP, SSMAPI.
- Not revalidated in this pass: remaining protocol adapters, router, transport stack, docs/tests. “100% parity” statements remain unsubstantiated.

## Priority Gaps
1. Implement tsnet-equivalent Tailscale endpoint/outbound (control-plane auth, netstack, DNS hook, TCP+UDP data plane, routing filters).
2. Add active DHCP transport and finish tailscale/resolved DNS alignment (interface discovery, INFORM probes, IPv6, fallback parity).
3. Wire uTLS fingerprints into TLS handshakes (client/server, Reality/ShadowTLS) with selectable fingerprints.
4. Align DERP service with Go (mandatory TLS, DERP HTTP/2+WS handlers, verify-client mesh, tailscale client integration).
5. Align SSMAPI with managed inbounds (tracker hooks, TLS, cache persistence, per-server routing).
6. Re-audit remaining protocols/services with source-level comparisons and executable tests before claiming parity.
