# REALITY Server Example

## Use case

VLESS inbound with REALITY enabled for camouflage.

## Config

```yaml
schema_version: 2

inbounds:
  - type: vless
    tag: vless-reality
    listen: 0.0.0.0
    port: 443
    users:
      - uuid: 00000000-0000-0000-0000-000000000000
        name: user1
    tls:
      enabled: true
      reality:
        enabled: true
        private_key: "your-private-key"
        short_ids: ["0123456789abcdef"]
        fallback_server: "www.microsoft.com"
        fallback_port: 443
      sni: www.microsoft.com

outbounds:
  - type: direct
    tag: direct

route:
  default: direct
```

## Related

- [REALITY Protocol](../../01-user-guide/protocols/reality.md)
