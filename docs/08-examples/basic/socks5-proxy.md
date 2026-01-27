# SOCKS5 Proxy Example

## Use case

Local SOCKS5 proxy for development or testing.

## Config

```yaml
schema_version: 2

inbounds:
  - type: socks
    tag: socks-in
    listen: 127.0.0.1
    port: 1080

outbounds:
  - type: direct
    tag: direct

route:
  default: direct
```

## Test

```bash
curl -x socks5h://127.0.0.1:1080 https://ifconfig.me
```

## Related

- [Getting Started](../../00-getting-started/README.md)
