# Smart Routing Example

## Use case

Route by domain/IP with a direct and proxy split.

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
  - type: block
    tag: block
  - type: shadowsocks
    tag: proxy
    server: proxy.example.com
    port: 8388
    method: aes-256-gcm
    password: ${SS_PASSWORD}

route:
  rules:
    - domain_suffix: [doubleclick.net, googlesyndication.com]
      outbound: block
    - geoip: cn
      outbound: direct
  default: proxy
```

## Related

- [Custom Routing](../../06-advanced-topics/custom-routing.md)
