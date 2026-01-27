# VLESS

## Overview

VLESS is a lightweight V2Ray protocol often paired with TLS and REALITY.

## When to use

- You want lightweight protocol semantics
- You plan to use REALITY for camouflage

## Minimal outbound example

```yaml
schema_version: 2

inbounds:
  - type: socks
    tag: socks-in
    listen: 127.0.0.1
    port: 1080

outbounds:
  - type: vless
    tag: vless-out
    server: vless.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    tls:
      enabled: true
      sni: vless.example.com

route:
  default: vless-out
```

## Notes

- REALITY is configured under `tls.reality`.
- Keep `sni` consistent with your REALITY fallback target.

## Related

- [TLS Configuration](../configuration/tls.md)
- [REALITY](reality.md)
