# Hysteria (v1/v2)

## Overview

Hysteria is a high-performance QUIC-based protocol optimized for unstable networks.

## When to use

- You need better performance over lossy links
- You want QUIC-based transport

## Minimal outbound example (Hysteria2)

```yaml
schema_version: 2

inbounds:
  - type: socks
    tag: socks-in
    listen: 127.0.0.1
    port: 1080

outbounds:
  - type: hysteria2
    tag: hy2-out
    server: hysteria.example.com
    port: 443
    password: ${HY2_PASSWORD}
    up_mbps: 100
    down_mbps: 200
    tls:
      enabled: true
      sni: hysteria.example.com

route:
  default: hy2-out
```

## Notes

- Bandwidth fields are required for Hysteria2.
- QUIC uses TLS under the hood; trust settings are shared.
- Keep `up_mbps/down_mbps` aligned with real link capacity.

## Related

- [TLS Configuration](../configuration/tls.md)
- [Advanced Topics](../../06-advanced-topics/README.md)
