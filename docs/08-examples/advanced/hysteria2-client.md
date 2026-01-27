# Hysteria2 Client Example

## Use case

QUIC-based proxy with bandwidth control.

## Config

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

## Related

- [Hysteria Protocol](../../01-user-guide/protocols/hysteria.md)
