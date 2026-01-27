# Multiplex Example

## Use case

Reduce handshake overhead by reusing a single connection.

## Config

```yaml
outbounds:
  - type: vmess
    tag: vmess-out
    server: vmess.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    tls:
      enabled: true
      sni: vmess.example.com
    multiplex:
      enabled: true
      max_streams: 8
```

## Related

- [Multiplex Feature](../../01-user-guide/features/multiplex.md)
