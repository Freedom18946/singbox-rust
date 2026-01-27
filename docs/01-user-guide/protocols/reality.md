# REALITY

## Overview

REALITY is a TLS camouflage mode used with VLESS to make traffic look like normal TLS to a target site.

## When to use

- You need censorship resistance
- You can manage key material on the server

## Client example

```yaml
outbounds:
  - type: vless
    tag: vless-reality
    server: reality.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    tls:
      enabled: true
      reality:
        enabled: true
        public_key: "your-public-key"
        short_id: "0123456789abcdef"
      sni: www.microsoft.com
```

## Server example

```yaml
inbounds:
  - type: vless
    tag: vless-reality-in
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
```

## Notes

- Client uses `public_key`; server uses `private_key`.
- Use stable, high-traffic domains for `sni` and fallback.
- `short_id` must match one of the server `short_ids`.

## Related

- [TLS Configuration](../configuration/tls.md)
- [Advanced Topics](../../06-advanced-topics/README.md)
