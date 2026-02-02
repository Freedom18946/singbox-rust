# Inbounds

## Overview

Inbounds define local listeners that accept traffic. Each inbound has a `type` and a unique `tag`.

Common fields:

- `type`: inbound type (e.g., `socks`, `http`, `mixed`, `tun`, `trojan`)
- `tag` / `name`: unique identifier
- `listen`: bind address
- `port`: listen port

## Example: SOCKS inbound

```yaml
inbounds:
  - type: socks
    tag: socks-in
    listen: 127.0.0.1
    port: 1080
```

## Example: TUN inbound

```yaml
inbounds:
  - type: tun
    tag: tun-in
    address: [172.19.0.1/30]
    mtu: 1500
    auto_route: true
    stack: system
```

## Notes

- Some inbound types require extra protocol-specific fields.
- TUN requires elevated permissions on most platforms.
- Prefer `tag`; `name` is accepted for compatibility.
- Compatibility aliases for select fields are documented in the configuration overview.

## Related

- [Protocol Guides](../protocols/README.md)
- [Basic Configuration](../../00-getting-started/basic-configuration.md)
