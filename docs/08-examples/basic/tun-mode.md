# TUN Mode Example

## Use case

System-wide proxy via TUN.

## Config

```yaml
schema_version: 2

inbounds:
  - type: tun
    tag: tun-in
    address: [172.19.0.1/30]
    mtu: 1500
    auto_route: true
    stack: system

outbounds:
  - type: direct
    tag: direct

route:
  default: direct
```

## Notes

- Requires elevated permissions (CAP_NET_ADMIN on Linux).
- See `docs/UDP_SUPPORT.md` for UDP behavior.

## Related

- [UDP Support](../../UDP_SUPPORT.md)
