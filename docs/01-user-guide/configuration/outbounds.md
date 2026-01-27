# Outbounds

## Overview

Outbounds define how traffic exits the proxy. Each outbound has a `type` and a unique `tag`.

Common fields:

- `type`: outbound type (e.g., `direct`, `block`, `shadowsocks`, `vmess`)
- `tag` / `name`: unique identifier
- `server`/`port`: remote address for proxy outbounds

## Example: direct + proxy

```yaml
outbounds:
  - type: direct
    tag: direct

  - type: shadowsocks
    tag: ss-out
    server: proxy.example.com
    port: 8388
    method: aes-256-gcm
    password: ${SS_PASSWORD}
```

## Notes

- Some outbounds support transport and TLS options.
- Selector/URLTest outbounds can route to other outbounds.
- Prefer `tag`; `name` is accepted for compatibility.

## Related

- [Protocol Guides](../protocols/README.md)
- [Transport Defaults](../../04-development/transport-defaults.md)
