# Configuration Overview

## Overview

singbox-rust configuration files can be JSON or YAML. YAML is recommended for readability.

A configuration is composed of:

- `schema_version` (required)
- `log` (optional)
- `inbounds` (required)
- `outbounds` (required)
- `route` (required)
- `dns` (optional)
- `certificate` (optional)
- `admin` (optional)

## Minimal config

```yaml
schema_version: 2

inbounds:
  - type: socks
    tag: socks-in
    listen: 127.0.0.1
    port: 1080

outbounds:
  - type: direct
    tag: direct

route:
  default: direct
```

## Common sections

- **inbounds**: local listeners (SOCKS, HTTP, TUN, protocol inbounds)
- **outbounds**: upstream connectors (direct, proxy protocols, selectors)
- **route**: rule list + default outbound/final outbound
- **dns**: DNS servers, FakeIP, cache
- **certificate**: trust store additions
- **admin**: admin API and metrics exposure

## Notes

- Most objects support `tag` as the primary identifier. `name` is accepted as an alias.
- Route rules can reference outbounds by `tag`/`name` via `outbound` or `to`.
- Compatibility aliases are accepted for select fields (for example `user` for `username`, `auth_str` for Hysteria v1, URLTest `*_ms` timing keys, and selector/urltest `outbounds` as an alias for `members`).

## Related

- [Inbounds](inbounds.md)
- [Outbounds](outbounds.md)
- [Routing](routing.md)
- [DNS](dns.md)
- [TLS](tls.md)
- [Schema Migration](schema-migration.md)
