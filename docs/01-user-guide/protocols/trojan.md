# Trojan

## Overview

Trojan is a TLS-based proxy protocol. TLS is required and provides transport encryption.

## When to use

- You want TLS-based camouflage
- You control a TLS-capable server

## Minimal outbound example

```yaml
schema_version: 2

inbounds:
  - type: socks
    tag: socks-in
    listen: 127.0.0.1
    port: 1080

outbounds:
  - type: trojan
    tag: trojan-out
    server: trojan.example.com
    port: 443
    password: ${TROJAN_PASSWORD}
    tls:
      enabled: true
      sni: trojan.example.com

route:
  default: trojan-out
```

## Minimal inbound example

```yaml
schema_version: 2

inbounds:
  - type: trojan
    tag: trojan-in
    listen: 0.0.0.0
    port: 443
    password: ${TROJAN_PASSWORD}
    tls:
      enabled: true
      cert: /etc/ssl/certs/fullchain.pem
      key: /etc/ssl/private/privkey.pem

outbounds:
  - type: direct
    tag: direct

route:
  default: direct
```

## Notes

- TLS certificate management is required.
- Do not disable certificate verification in production.
- Use a realistic `sni` that matches the server certificate.

## Related

- [TLS Configuration](../configuration/tls.md)
- [First Proxy](../../00-getting-started/first-proxy.md)
