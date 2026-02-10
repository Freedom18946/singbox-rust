# L5 Compat Matrix (Go / GUI / Rust)

## P0 GUI->Clash API contract

| Surface | GUI call shape | Go reference | Rust reference | Status |
| --- | --- | --- | --- | --- |
| `GET /configs` | startup pull | `experimental/clashapi/configs.go` | `crates/sb-api/src/clash/handlers.rs` | wired |
| `PATCH /configs` | mode update | same | same | wired |
| `GET /proxies` | proxy list panel | `experimental/clashapi/proxies.go` | `handlers.rs` | wired |
| `GET /proxies/{name}/delay` | delay probe | same | `handlers.rs` | wired |
| `GET /connections` | connection panel | `experimental/clashapi/connections.go` | `handlers.rs` | wired |
| `DELETE /connections/{id}` | close connection | same | `handlers.rs` | wired |
| `WS /memory` | dashboard memory chart | `memory endpoint` | `websocket.rs` | wired |
| `WS /traffic` | dashboard traffic chart | `traffic endpoint` | `websocket.rs` | wired |
| `WS /connections` | live connection stream | same | `websocket.rs` | wired |
| `WS /logs` | live log stream | same | `websocket.rs` | wired |

## Subscription parser contract

| Input | GUI behavior reference | interop-lab rule |
| --- | --- | --- |
| JSON `outbounds` | `subscribes.ts` | parse `outbounds[]`, collect protocol from `type` |
| YAML `proxies` | `subscribes.ts` | parse `proxies[]`, collect protocol from `type` |
| Base64 | `subscribes.ts` | decode then re-run JSON/YAML/link-line parser |

## Data-plane simulation coverage

| Type | interop-lab service |
| --- | --- |
| HTTP echo | `upstream::HttpEcho` |
| TCP echo | `upstream::TcpEcho` |
| UDP echo | `upstream::UdpEcho` |
| WS echo | `upstream::WsEcho` |
| DNS stub | `upstream::DnsStub` |
| TLS echo | `upstream::TlsEcho` |
