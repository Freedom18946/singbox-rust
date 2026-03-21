# Config Examples

Only files in this directory that still pass `cargo run -p app -- check -c ...` are kept.

## Inbounds

- `inbounds/minimal_http.json`: minimal HTTP inbound with direct outbound

## Outbounds

- `outbounds/shadowsocks.json`: Shadowsocks client outbound
- `outbounds/trojan-grpc.json`: Trojan over TLS + gRPC
- `outbounds/hysteria_v2.json`: Hysteria2 outbound

## Routing

- `routing/rules_demo.json`: current `when` / `to` rule syntax

## DNS

- `dns/doq-simple.yaml`: minimal DNS-over-QUIC example

## Security

- `security/ech_outbound.json`: ECH outbound example
- `security/reality_vless.json`: REALITY VLESS outbound example

## Advanced

- `advanced/ws0_smoke.json`: local smoke config
- `advanced/ws1_trojan_h2.json`: Trojan over TLS + HTTP/2
- `advanced/ws1_vmess_ws_tls.json`: VMess over TLS + WebSocket
