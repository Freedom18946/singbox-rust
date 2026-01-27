# Transports

## Overview

Application-layer transports (WebSocket, HTTP/2, gRPC, HTTPUpgrade) sit on top of TCP/TLS.

## Key points

- Only one application-layer transport should be active per outbound.
- TLS may be inferred from transport hints (see transport defaults).
- Supported transports include WebSocket, HTTP/2, gRPC, and HTTPUpgrade.

## Transport object (recommended)

Use a `transport` object to define the transport type and its fields:

```yaml
outbounds:
  - type: vmess
    tag: vmess-ws
    server: vmess.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    tls:
      enabled: true
      sni: vmess.example.com
    transport:
      type: ws
      path: /ws
      headers:
        Host: vmess.example.com
```

## Common fields by transport

### WebSocket

- `transport.path`, `transport.headers.Host`
- Legacy shorthand: `ws_path`, `ws_host`

### HTTP/2

- `transport.path`, `transport.host`
- Legacy shorthand: `h2_path`, `h2_host`

### gRPC

- `transport.service_name`/`transport.service`, `transport.method_name`/`transport.method`
- `transport.authority`/`transport.host`, `transport.metadata`
- Legacy shorthand: `grpc_service`, `grpc_method`, `grpc_authority`, `grpc_metadata`

### HTTPUpgrade

- `transport.path`, `transport.headers`
- Legacy shorthand: `http_upgrade_path`, `http_upgrade_headers`

## Example (WebSocket)

```yaml
outbounds:
  - type: vmess
    tag: vmess-ws
    server: vmess.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    tls:
      enabled: true
      sni: vmess.example.com
    transport:
      type: ws
      path: /vmess
      headers:
        Host: vmess.example.com
```

## Related

- [Transport Defaults](../../04-development/transport-defaults.md)
- [Transport Strategy](../../TRANSPORT_STRATEGY.md)
