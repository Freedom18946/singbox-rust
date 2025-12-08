# Next Steps (2025-12-08 Reality Check)

Parity Status: **Not aligned** with Go `go_fork_source/sing-box-1.12.12` in key areas (Tailscale, DNS transports, uTLS). The previous v7 notes claiming 100% parity are invalid.

## Immediate Actions
1) **Tailscale parity**  
   - Align `crates/sb-core/src/endpoint/tailscale.rs` and `crates/sb-adapters/src/outbound/tailscale.rs` with Go `protocol/tailscale/endpoint.go`. Implement tsnet-equivalent control plane (auth, state dir, hostname, routes), gVisor/netstack-style TCP/UDP handling, DNS hook, router/filter integration, and proper inbound metadata updates. Remove stub-only paths and ensure MagicDNS goes through the Tailnet stack.

2) **DNS transport completion**  
   - Implement active DHCP discovery (`dns/transport/dhcp/*.go`) instead of passive `resolv.conf` watching in `crates/sb-core/src/dns/upstream.rs`.  
   - Finish Tailscale/Resolved transports: integrate with control-plane state, IPv6, and avoid stub fallback in `crates/sb-adapters/src/service/resolved_impl.rs` and `crates/sb-transport/src/tailscale_dns.rs`.

3) **uTLS wiring**  
   - Connect `crates/sb-tls/src/utls.rs` into TLS client/server builders and outbound adapters (REALITY, ShadowTLS, TLS options) to match Go `common/tls/utls_client.go` and `reality_*`. Support fingerprint selection and ClientHello mutation.

4) **Validation sweep**  
   - Re-audit remaining protocol adapters, services (DERP/SSMAPI), router, and transports against Go sources. Replace inflated documentation/test claims with verified status and add targeted tests for each aligned module.
