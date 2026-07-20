# REALITY Server Example

## Use case

VLESS inbound with REALITY enabled for camouflage.

## Config

```yaml
schema_version: 2

inbounds:
  - type: vless
    name: vless-reality
    listen: 0.0.0.0
    port: 443
    users:
      - uuid: 00000000-0000-0000-0000-000000000000
        name: user1
    tls:
      enabled: true
      server_name: www.microsoft.com
      reality:
        enabled: true
        private_key: "your-private-key"
        short_id: ["0123456789abcdef"]
        handshake:
          server: www.microsoft.com
          server_port: 443

outbounds:
  - type: direct
    name: direct

route:
  default: direct
```

## Related

- [REALITY Protocol](../../01-user-guide/protocols/reality.md)
