# VMess

## Overview

VMess is a flexible V2Ray protocol supporting multiple transports and optional TLS.

## When to use

- You need transport flexibility (WS/H2/gRPC)
- You already use VMess clients

## Minimal outbound example

```yaml
schema_version: 2

inbounds:
  - type: socks
    tag: socks-in
    listen: 127.0.0.1
    port: 1080

outbounds:
  - type: vmess
    tag: vmess-out
    server: vmess.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    tls:
      enabled: true
      sni: vmess.example.com

route:
  default: vmess-out
```

## Notes

- Use AEAD mode with `alter_id: 0` when required by your client/server.
- Transport selection must be mutually exclusive.
- If using WS/H2/gRPC, align TLS ALPN and transport hints.

## Related

- [TLS Configuration](../configuration/tls.md)
- [Transport Defaults](../../04-development/transport-defaults.md)
