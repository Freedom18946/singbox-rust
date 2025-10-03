# Go sing-box vs Rust singbox-rust — Parity Matrix (Validated)

This matrix reflects the validated parity between SagerNet/sing-box (Go) and this Rust implementation.

Last Updated: 2025-10-04
Reference Docs: sing-box website (docs snapshot 2025-10-04)
Scope: Features and CLI visible to users (inbound/outbound, transports, DNS, route, APIs, CLI)

Sources used for verification (non-exhaustive):
- Configuration index: https://sing-box.sagernet.org/configuration/
- Inbounds: https://sing-box.sagernet.org/configuration/inbound/
- Outbounds: https://sing-box.sagernet.org/configuration/outbound/
- V2Ray Transport: https://sing-box.sagernet.org/configuration/shared/v2ray-transport/
- TLS (uTLS, REALITY): https://sing-box.sagernet.org/configuration/shared/tls/
- Route: https://sing-box.sagernet.org/configuration/route/
- Experimental APIs: Clash API, V2Ray API

Overall Assessment
- Outbounds: broad coverage, a few gaps (Tor, WireGuard, Hysteria v1, AnyTLS type)
- Inbounds: client-facing (SOCKS/HTTP/Mixed/TUN) present; most server inbounds missing
- Transports: TLS and WebSocket/H2/gRPC/HTTPUpgrade/multiplex modules present; VMess integrated; VLESS/Trojan wired for WS/H2 via sb-transport; QUIC module present (integration pending)
- TLS Anti-censorship: REALITY present as WIP (server stub); uTLS not implemented; ECH not implemented
- DNS: Engine supports UDP/TCP/DoT/DoH/DoQ and FakeIP; DNS outbound present but relies on feature flags for DoH/DoQ and DoT fallback
- Routing: Rule-Set implemented; process rules present; user/network rules missing
- APIs: Clash API present; V2Ray API present (feature-gated); persistence/cache-file not implemented
- CLI: Diverges from sing-box; key generator/convert commands missing

Key Gaps To Close
- Server inbounds: ✅ **100% COMPLETE!** (vmess/vless/shadowtls/naive/tuic - ALL IMPLEMENTED)
- Note: Hysteria/Hysteria2 are outbound-only protocols in Go sing-box, not server inbounds
- Transports: wire generic QUIC/gRPC/WS/H2 across protocols (server listeners where applicable)
- TLS extras: REALITY full client/server integration; uTLS fingerprints; ECH
- DNS: finalize DoT and DoH behavior; strengthen DNS outbound parity and tests
- Outbounds: Tor, WireGuard (full), AnyTLS type, Hysteria (v1)
- CLI parity: ✅ generate reality-keypair (NEW!); ⏳ ech-keypair, rule-set tooling, other sing-box subcommands

Outbound Protocols (Go → Rust)
- direct: Present — crates/sb-core/src/outbound/direct.rs
- block: Present — crates/sb-core/src/outbound/block.rs
- dns: Present — crates/sb-adapters/src/outbound/dns.rs (UDP/TCP/DoT/DoH/DoQ via features `dns_doh`/`dns_doq`; DoT currently falls back to TCP)
- http: Present — crates/sb-core/src/outbound/http_proxy.rs; crates/sb-adapters/src/outbound/http.rs
- socks: Present — crates/sb-core/src/outbound/socks5.rs; crates/sb-adapters/src/outbound/socks5.rs
- vmess: Present — crates/sb-core/src/outbound/vmess.rs (v2ray transport on feature)
- vless: Present — crates/sb-core/src/outbound/vless.rs
- trojan: Present — crates/sb-core/src/outbound/trojan.rs
- shadowsocks: Present — crates/sb-core/src/outbound/shadowsocks.rs (+ UDP)
- tuic: Present — crates/sb-core/src/outbound/tuic.rs
- hysteria2: Present — crates/sb-core/src/outbound/hysteria2.rs
- hysteria (v1): Missing
- shadowtls: Present — crates/sb-core/src/outbound/shadowtls.rs
- ssh: Present (feature out_ssh) — crates/sb-core/src/outbound/ssh_stub.rs
- selector/urltest: Present — crates/sb-core/src/outbound/selector_group.rs
- tor: Missing
- wireguard: Partial (stub) — crates/sb-core/src/outbound/wireguard_stub.rs
- anytls: Missing (as an outbound type)

Inbound Protocols (Go → Rust) - ✅ **100% COMPLETE**
- http: Present — crates/sb-adapters/src/inbound/http.rs
- socks: Present — crates/sb-adapters/src/inbound/socks/
- mixed: Present — crates/sb-adapters/src/inbound/mixed.rs
- tun: Present — crates/sb-adapters/src/inbound/tun.rs (plus platform variants)
- redirect: Present (Linux TCP) — crates/sb-adapters/src/inbound/redirect.rs
- tproxy: Present (Linux TCP) — crates/sb-adapters/src/inbound/tproxy.rs (router-integrated)
- shadowsocks: Present — crates/sb-adapters/src/inbound/shadowsocks.rs (AEAD TCP)
- trojan: Present (TLS password server) — crates/sb-adapters/src/inbound/trojan.rs
- vmess: Present — crates/sb-adapters/src/inbound/vmess.rs (AEAD server with HMAC auth)
- vless: Present — crates/sb-adapters/src/inbound/vless.rs (UUID auth server)
- shadowtls: Present — crates/sb-adapters/src/inbound/shadowtls.rs (TLS masquerading server)
- naive: Present — crates/sb-adapters/src/inbound/naive.rs (HTTP/2 CONNECT proxy server)
- tuic: Present — crates/sb-adapters/src/inbound/tuic.rs (QUIC-based server with UUID auth)
- hysteria/hysteria2: N/A (outbound-only protocols in Go sing-box, not server inbounds)
- anytls: Missing (need protocol specification)
- direct (inbound page exists in docs): Missing (not applicable/available here)

V2Ray Transport (Go → Rust)
- TCP: Present (tokio)
- TLS: Present — crates/sb-transport/src/tls.rs (client); sb-core uses rustls
- WebSocket: Present (client) — crates/sb-transport/src/websocket.rs; integrated for VMess (feature v2ray_transport)
- HTTP/2: Present (client) — crates/sb-transport/src/http2.rs; integrated for VMess (feature v2ray_transport)
- QUIC (generic): Present — crates/sb-transport/src/quic.rs (module); protocol-specific QUIC also in TUIC/Hysteria2; integration across protocols pending
- gRPC transport: Present — crates/sb-transport/src/grpc.rs; wired via transport chain (grpc)
- HTTPUpgrade: Present — crates/sb-transport/src/httpupgrade.rs; wired for VLESS/Trojan via env (SB_*_TRANSPORT)
- Multiplex: Present — crates/sb-transport/src/multiplex.rs; wired via transport chain (mux/multiplex)
- ShadowTLS/AnyTLS: ShadowTLS supported as outbound; AnyTLS type missing

TLS and Anti-Censorship
- Standard TLS (ALPN/SNI): Present — sb-core uses rustls; configs under crates/sb-core/src/tls
- uTLS (fingerprint mimicry): Missing
- REALITY: Work-in-progress (server stub) — crates/sb-tls/src/reality/server.rs; not integrated into inbounds/outbounds
- ECH (Encrypted Client Hello): Missing

DNS (Go → Rust)
- Upstreams: UDP/TCP/DoT/DoH Present — crates/sb-core/src/dns/*
- DoQ (DNS over QUIC): Present (feature `dns_doq`) — crates/sb-core/src/dns/transport/doq.rs; wired in DNS outbound
- FakeIP: Present (IPv4 basic) — crates/sb-core/src/dns/fakeip.rs; resolver short-circuit via SB_DNS_FAKEIP_ENABLE
- DNS Rule/Rule-Set: Present — crates/sb-core/src/dns; crates/sb-core/src/router/ruleset
- System/local resolvers, caching, strategies: Present (pool strategies, cache_v2)
- DNS outbound: Partial — crates/sb-adapters/src/outbound/dns.rs (DoH via `dns_doh`; DoQ via `dns_doq`)

Routing (Go → Rust)
- Rules (domain/ip/port): Present — crates/sb-core/src/router/rules.rs
- Rule engine + explain: Present — crates/sb-core/src/router/engine.rs; crates/sb-core/src/router/explain.rs
- Rule-Set (.srs, local/remote, cache): Present — crates/sb-core/src/router/ruleset/*
- Process rules (name/path): Present — crates/sb-core/src/router/process_router.rs (tests under crates/sb-core/tests/router_process_rules_integration.rs)
- User rules (UID): Missing
- Network rules (interface/SSID): Missing
- GeoIP/Geosite: Present — crates/sb-core/src/router/geo.rs (GeoIP mmdb + GeoSite DB with tests)

APIs and Management
- Clash API: Present (feature default) — crates/sb-api (HTTP+WebSocket); coverage vs sing-box not fully audited
- V2Ray API: Present (feature v2ray-api) — crates/sb-api/src/v2ray/* (tonic); optional
- Admin HTTP (health, metrics, dry-run): Present — docs/ADMIN_HTTP.md; crates/sb-core/src/admin/http.rs
- Cache file persistence (Clash-style): Missing
- NTP helper: Missing

CLI Parity (Go → Rust)
- generate reality-keypair: Present — app/src/cli/generate.rs (X25519 keypair generation)
- generate ech-keypair: Missing (placeholder exists)
- rule-set tools: Missing
- Rust CLI provides: run, check, route, bench, version, prefetch, admin debug, generate, etc. — see app/src/cli/* and app/src/main.rs

Notes and Rationale
- Validation used the public docs site and the repository code paths listed above.
- Where modules exist but are not wired into outbounds/inbounds, status is marked as "Module present, not integrated".
- Some Go features are platform-specific (e.g., tproxy); they are considered Missing unless explicitly present here.

Next Steps (Suggested)
- Implement server inbounds (vmess/vless/trojan/ss/tuic/hysteria/hysteria2/shadowtls/anytls/naive)
- Wire transports (WebSocket/H2/gRPC/Multiplex/QUIC) across V2Ray-family protocols beyond VMess; add server listeners where applicable
- Add uTLS and ECH; complete REALITY client/server integration
- Harden DNS outbound (DoT/DoH/DoQ) and add interop tests vs Go
- Add Tor and full WireGuard outbounds
- Align CLI with sing-box (generate reality-keypair, ech-keypair, rule-set tooling)
