# HTTP Proxy Example

## Use case

Local HTTP CONNECT proxy.

## Config

```yaml
schema_version: 2

inbounds:
  - type: http
    tag: http-in
    listen: 127.0.0.1
    port: 8080

outbounds:
  - type: direct
    tag: direct

route:
  default: direct
```

## Related

- [Getting Started](../../00-getting-started/README.md)
