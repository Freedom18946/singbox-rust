# Mixed Proxy Example

## Use case

Expose SOCKS5 and HTTP on one port.

## Config

```yaml
schema_version: 2

inbounds:
  - type: mixed
    tag: mixed-in
    listen: 127.0.0.1
    port: 7890

outbounds:
  - type: direct
    tag: direct

route:
  default: direct
```

## Related

- [Getting Started](../../00-getting-started/README.md)
