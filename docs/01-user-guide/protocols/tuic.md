# TUIC

## Overview

TUIC is a QUIC-based UDP-optimized protocol.

## When to use

- You need UDP-heavy workloads
- You want QUIC transport with reduced head-of-line blocking

## Minimal outbound example

```yaml
schema_version: 2

inbounds:
  - type: socks
    tag: socks-in
    listen: 127.0.0.1
    port: 1080

outbounds:
  - type: tuic
    tag: tuic-out
    server: tuic.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    token: ${TUIC_TOKEN}
    tls:
      enabled: true
      sni: tuic.example.com

route:
  default: tuic-out
```

## Notes

- `uuid` and `token` must match the server.
- QUIC uses TLS trust settings; set `tls.sni` correctly.

## Related

- [TLS Configuration](../configuration/tls.md)
- [Advanced Topics](../../06-advanced-topics/README.md)
