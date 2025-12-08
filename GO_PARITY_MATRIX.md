# Go-Rust Parity Matrix (2025-12-08 Reality Check v1)

Objective: compare `singbox-rust` against Go reference `go_fork_source/sing-box-1.12.12` for functional, type, API, comment, and directory parity.

## Executive Summary

| Area | Status | Notes |
| --- | --- | --- |
| Tailscale endpoint/data plane | ❌ Not aligned | Go uses tsnet+gVisor stack; Rust stub control plane with system sockets only; no netstack/DNS hook |
| DNS transports | ◐ Partial | Active DHCP missing; MagicDNS minimal; resolved/tailscale gated and often stubbed |
| TLS uTLS | ◐ Partial | Fingerprints exist but not wired into TLS handshakes or outbound flows |
| Protocol/Service coverage claims | ⚠️ Unverified | Existing docs assert 100% parity without source/test evidence |

## Detailed Findings

### 1) Tailscale endpoint vs Go
- Go (`protocol/tailscale/endpoint.go`): `tsnet.Server` with gVisor stack (`gonet`), filter/netmon, DNS hook (`LookupHook`, `dnsConfigurator`), TCP+UDP handling, control plane auth, routing checks.
- Rust (`crates/sb-core/src/endpoint/tailscale.rs`): `StubControlPlane` fallback; `DaemonControlPlane` only hits `/localapi/v0/status` then dials/listens via OS sockets; no tsnet session, no netstack, UDP dial unsupported, DNS not integrated, limited inbound metadata updates.
- Result: Feature set far below Go; Tailnet connectivity and routing parity not achieved.

### 2) Tailscale outbound & MagicDNS
- Go uses the same tsnet stack plus MagicDNS transport (`protocol/tailscale/dns_transport.go`) bound to the Tailnet network.
- Rust outbound (`crates/sb-adapters/src/outbound/tailscale.rs`): mode selection (WireGuard/SOCKS/direct/Managed) but Managed mode depends on a `Coordinator` stub; WireGuard mode does not join the Tailnet; no tsnet-backed sockets.
- Rust MagicDNS (`crates/sb-transport/src/tailscale_dns.rs`): raw UDP client to `100.100.100.100` with hand-built parser; not tied to control-plane state, no IPv6, no fallback logic from Go.
- Result: Tailnet DNS and traffic routing diverge from Go implementation.

### 3) DNS transport matrix
- Go transports: UDP/TCP/DoT/DoH/DoQ/DoH3/FakeIP/Hosts/Local/Resolved/Tailscale/DHCP (active INFORM probe).
- Rust transports (`crates/sb-core/src/dns/transport`, `crates/sb-core/src/dns/upstream.rs`):
  - Implemented: UDP/TCP/DoT/DoH/DoQ/DoH3/Local/Hosts/FakeIP.
  - DHCP: `DhcpUpstream` only watches `resolv.conf`; no DHCP INFORM or interface probing (`dns/transport/dhcp/*.go` in Go).
  - Resolved/Tailscale: feature-gated; non-Linux falls back to `StubService` (`crates/sb-adapters/src/service/resolved_impl.rs`); tailscale upstream resolves static addrs only.
- Result: Transport parity is partial; active DHCP and full resolved/tailscale behaviour missing.

### 4) TLS uTLS integration
- Go (`common/tls/utls_client.go`, `common/tls/reality_*`): uTLS wired into TLS client/server, Reality server/client, ShadowTLS tests.
- Rust (`crates/sb-tls/src/utls.rs`): defines fingerprints/config API but never hooked into TLS connectors or outbound adapters; no ClientHello mutation path.
- Result: uTLS unsupported; REALITY/ShadowTLS parity not met when uTLS is required.

### 5) Resolved service
- Go (`service/resolved/service.go`): D-Bus server, link DNS/domain tracking, network monitor callbacks, per-link config application.
- Rust (`crates/sb-adapters/src/service/resolved_impl.rs`): Linux-only D-Bus implementation; uses system resolver for DNS listener; no network monitor callbacks; stub on non-Linux.
- Result: Partial parity and platform divergence.

### Audit coverage
- Inspected modules: Tailscale endpoint/outbound, DNS transports, TLS uTLS, Resolved service.
- Not revalidated in this pass: protocol adapters, DERP/SSMAPI, router, transport stack, documentation claims, test coverage. Current “100% parity” statements remain unsubstantiated.

## Priority Gaps
1. Implement tsnet-equivalent Tailscale endpoint/outbound (control plane auth, netstack, DNS hook, TCP+UDP data plane, routing filters).
2. Add active DHCP transport and interface discovery to match `dns/transport/dhcp`.
3. Wire uTLS fingerprints into TLS handshake (client/server, Reality/ShadowTLS) with selectable fingerprints.
4. Expand resolved/tailscale DNS integration and remove stub fallbacks where Go provides functionality.
5. Re-audit remaining protocols/services with source-level comparisons and real tests before claiming parity.
