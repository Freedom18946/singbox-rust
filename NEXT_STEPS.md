# Next Steps (2025-12-09 Reality Check)

Parity Status: **Not aligned** with Go `go_fork_source/sing-box-1.12.12` (see GO_PARITY_MATRIX.md). Actions below are ordered and must be verified (source + tests + config) with updates recorded in VERIFICATION_RECORD.md.

## Immediate Actions (priority order)
1) **Tailscale stack parity**  
   - Implement tsnet-equivalent control plane/netstack for endpoint/outbound: auth, state dir, hostname, routes, DNS hook, router/filter integration; TCP+UDP via netstack; bind MagicDNS to Tailnet context (replace raw 100.100.100.100 client).  
   - Files: `crates/sb-core/src/endpoint/tailscale.rs`, `crates/sb-adapters/src/outbound/tailscale.rs`, `crates/sb-transport/src/tailscale_dns.rs`.

2) **DNS transports completion**  
   - Add active DHCP probe/INFORM + interface discovery with tests; align resolved/tailscale transports with IPv6 and netmon callbacks; remove stub fallbacks.  
   - Files: `crates/sb-core/src/dns/upstream.rs`, `crates/sb-core/src/dns/transport`, `crates/sb-adapters/src/service/resolved_impl.rs`.

3) **DERP service parity**  
   - Enforce TLS; serve DERP over HTTP/2 + websocket; add verify-client hooks, STUN/latency probes, mesh PSK/peer support using tailscale client libs; add integration tests.  
   - Files: `crates/sb-core/src/services/derp/`.

4) **SSMAPI service parity**  
   - Bind Axum server to managed Shadowsocks inbounds; add traffic/user trackers, cache load/save, optional TLS, per-server routing; add end-to-end tests.  
   - Files: `crates/sb-core/src/services/ssmapi/`.

5) **uTLS wiring**  
   - Wire `crates/sb-tls/src/utls.rs` into TLS builders and Reality/ShadowTLS paths with fingerprint selection; add handshake tests.  
   - Files: TLS builders in sb-tls and adapters.

6) **Validation sweep & record**  
   - After each implementation, add targeted tests/config fixtures, run relevant crate/workspace tests, and log timestamped results in `VERIFICATION_RECORD.md`.  
   - Update `GO_PARITY_MATRIX.md` statuses only after source+tests+config pass.
