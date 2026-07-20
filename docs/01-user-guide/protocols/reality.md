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
      server_name: www.microsoft.com
      reality:
        enabled: true
        public_key: "your-public-key"
        short_id: "0123456789abcdef"
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
      server_name: www.microsoft.com
      reality:
        enabled: true
        private_key: "your-private-key"
        short_id: ["0123456789abcdef"]
        handshake:
          server: www.microsoft.com
          server_port: 443
```

## Notes

- Client uses `public_key`; server uses `private_key`.
- Use same `server_name` on client and server.
- Client `short_id` must match one server `short_id` entry.
- Current Rust VLESS server accepts exactly one inbound `users` entry.

## Related

- [TLS Configuration](../configuration/tls.md)
- [Advanced Topics](../../06-advanced-topics/README.md)
