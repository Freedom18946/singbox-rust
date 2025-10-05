Sing-Box Parity Matrix (Baseline v1.12.4)

Status legend
- Full: Feature implemented and usable end-to-end
- Partial: Implemented with gaps or limited coverage (needs work)
- Stub: Present as placeholder but not functional
- Missing: Not implemented
- N/A: Not applicable to Rust implementation or intentionally out-of-scope

Baseline
- Upstream: SagerNet/sing-box v1.12.4 (docs and code fetched under `upstream-sing-box/`)
- Local: this repository (modules under `crates/`), config schema v2 (`crates/sb-config/src/validator/v2_schema.json`)
- Goal: CLI behavior and config surface compatible with upstream; functional parity prioritized by user impact

Inbounds
- anytls: Missing
- direct: Missing
- http: Full (crates/sb-adapters/src/inbound/http.rs)
- hysteria: Missing
- hysteria2: Missing
- mixed: Full (crates/sb-adapters/src/inbound/mixed.rs)
- naive: Full (crates/sb-adapters/src/inbound/naive.rs)
- redirect: Full (crates/sb-adapters/src/inbound/redirect.rs)
- shadowsocks: Full (crates/sb-adapters/src/inbound/shadowsocks.rs)
- shadowtls: Full (crates/sb-adapters/src/inbound/shadowtls.rs)
- socks: Full (crates/sb-adapters/src/inbound/socks/)
- tproxy: Full (crates/sb-adapters/src/inbound/tproxy.rs)
- trojan: Full (crates/sb-adapters/src/inbound/trojan.rs)
- tuic: Full (crates/sb-adapters/src/inbound/tuic.rs)
- tun: Full (crates/sb-adapters/src/inbound/tun*.rs)
- vless: Full (crates/sb-adapters/src/inbound/vless.rs)
- vmess: Full (crates/sb-adapters/src/inbound/vmess.rs)

Outbounds
- anytls: Missing
- block: Full (crates/sb-adapters/src/outbound/block.rs)
- direct: Full (crates/sb-adapters/src/outbound/direct.rs)
- dns: Full (crates/sb-adapters/src/outbound/dns.rs)
- http: Full (crates/sb-adapters/src/outbound/http.rs)
- hysteria: Missing
- hysteria2: Partial (crates/sb-adapters/src/outbound/hysteria2.rs is minimal; crates/sb-core/src/outbound/hysteria2.rs is larger; needs unification + tests)
- selector: Full (crates/sb-core/src/outbound/selector*.rs)
- shadowsocks: Full (crates/sb-adapters/src/outbound/shadowsocks.rs)
- shadowtls: Partial (present in crates/sb-core/src/outbound/shadowtls.rs; adapter integration pending)
- socks: Full (crates/sb-adapters/src/outbound/socks5.rs)
- ssh: Partial (feature `out_ssh`; implemented in `crates/sb-core/src/outbound/ssh_stub.rs`, config/IR + CLI wired for password auth via adapter bridge)
- tor: Missing
- trojan: Full (crates/sb-adapters/src/outbound/trojan.rs)
- tuic: Partial (crates/sb-adapters/src/outbound/tuic.rs minimal; crates/sb-core/src/outbound/tuic.rs larger; needs unification + tests)
- urltest: Full (selector/urltest implemented under crates/sb-core/src/outbound/*selector*.rs; config supports `urltest`)
- vless: Full (crates/sb-adapters/src/outbound/vless.rs)
- vmess: Full (crates/sb-adapters/src/outbound/vmess.rs)
- wireguard: Stub (crates/sb-core/src/outbound/wireguard_stub.rs)

Routing
- Rule engine: Full (domain/suffix/geoip/geosite/ipcidr/port/transport tcp|udp supported; crates/sb-core/src/router)
- Rule-Set (SRS): Full (local + remote fetch/cache; crates/sb-core/src/router/ruleset)
- Hot reload: Full (crates/sb-core/src/router/hot_reload*.rs)
- Explain/preview: Full (feature-gated; crates/sb-core/src/router/explain*)
- Sniff (TLS SNI/HTTP/QUIC): Missing (not present in inbounds or router conditions)
- Process-based routing: Partial (process router exists; platform coverage improving; crates/sb-core/src/router/process_router.rs, crates/sb-platform)

DNS
- Client: Full (UDP/TCP, cache, parallel; crates/sb-core/src/dns)
- DoT: Full (crates/sb-core/src/dns/dot.rs)
- DoH: Partial (basic POST implementation; crates/sb-core/src/dns/doh.rs)
- Fake-IP: Full (crates/sb-core/src/dns/fakeip.rs)
- DNS rule engine: Full (crates/sb-core/src/dns/rule_engine.rs)
- DNS rule-set integration: Full (uses router ruleset)
- Tailscale DNS server: Missing (upstream has server type `tailscale`)
- Hosts override/system hosts: Missing

TLS/Transport
- TLS (std): Full (crates/sb-transport/src/tls*.rs)
- REALITY: Partial (crates/sb-tls/src/reality/*; handshake integration not complete end-to-end)
- ECH: Partial (CLI keypair generation implemented; runtime handshake integration missing)
- uTLS (ClientHello mimic): Missing (Go-only upstream tag `with_utls`)
- QUIC: Full (crates/sb-transport/src/quic.rs)
- WebSocket/HTTPUpgrade/HTTP2: Full (crates/sb-transport/src/websocket.rs, httpupgrade.rs, http2.rs)
- gRPC tunnel: Full (crates/sb-transport/src/grpc.rs)
- Multiplex (yamux): Full (crates/sb-transport/src/multiplex.rs)
- UDP over TCP: Partial (tuic `udp_over_stream` supported; broader UoT not generalized across outbounds)

Services
- NTP service: Missing (config normalization present; no runtime service)
- DERP: Missing
- SSM API: Missing

APIs
- Clash API: Full (feature `clash-api`; crates/sb-api/src/clash/*)
- V2Ray API: Full (feature `v2ray-api`; crates/sb-api/src/v2ray/*)

CLI Parity
- run: Full (app/src/bin/run.rs)
- check: Full (app/src/bin/check.rs)
- version: Full (app/src/bin/version.rs and sb-version)
- format (config): Full (app/src/bin/format.rs)
- route (explain/trace helper): Full (app/src/bin/route.rs)
- rule-set: Partial (validate/info/format present; decompile and match added; compile/convert/merge/upgrade still missing; app/src/bin/ruleset.rs)
- generate reality-keypair: Full (app/src/cli/generate.rs)
- generate ech-keypair: Full (app/src/cli/generate.rs)
- generate tls/vapid/wireguard: Partial (tls-keypair implemented; vapid/wireguard missing)
- geosite commands: Missing
- geoip commands: Missing
- tools fetch/http3/connect: Partial (connect TCP/UDP + fetch HTTP/HTTPS implemented; http3 pending)
 - tools synctime: Partial (offset query implemented)
- merge (configs): Partial (app/src/bin/merge.rs; deep-merge + TLS/ECH/SSH path inlining; more edge-cases pending)

Platform/Adapters
- TUN: Full (macOS/Linux paths; enhanced variants present)
- TProxy/Redirect: Full (adapters implemented)
- WireGuard endpoint: Stub/Missing
- Tailscale endpoint: Missing

Notes
- Upstream features tagged `with_utls`, `with_wireguard`, or Tailscale-specific components are Go-ecosystem centric; Rust equivalents require separate libraries and may be prioritized based on demand.
- Some modules exist in both `sb-core` and `sb-adapters`; convergence is required to avoid duplication and ensure uniform configuration and behavior.
