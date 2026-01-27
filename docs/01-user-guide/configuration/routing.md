# Routing

## Overview

Routing determines which outbound is used for each connection. Rules are evaluated in order; the first match wins.

Core fields:

- `route.rules`: ordered list of rules
- `route.default`: fallback outbound tag
- `route.final`: optional final outbound override

## Common rule keys

- `domain`, `domain_suffix`, `domain_keyword`
- `ip_cidr`
- `geoip`, `geosite`
- `port`, `protocol`
- `process_name`
- `inbound`

## Rule action fields

Rules can specify the outbound using either:

- `outbound: <tag>` (legacy-compatible)
- `to: <tag>` (schema v2 form)

## Example

```yaml
route:
  rules:
    - domain_suffix: [google.com, youtube.com]
      outbound: proxy
    - geoip: cn
      outbound: direct
  default: direct
```

## Example (when/to style)

```yaml
route:
  rules:
    - when:
        domain: google.com
      to: proxy
  default: direct
```

## Rule sets (SRS)

Reference local or remote rule sets:

```yaml
route:
  rule_set:
    - tag: ads
      type: local
      format: binary
      path: /etc/singbox/rules/ads.srs
  rules:
    - rule_set: ads
      outbound: block
```

## GeoIP/Geosite sources

Route can point to custom geodata paths:

```yaml
route:
  geoip:
    path: /etc/singbox/geoip.db
  geosite:
    path: /etc/singbox/geosite.db
```

## Notes

- Keep rules ordered by specificity.
- Use geodata for large domain sets.
- `route.default` is used when no rule matches.

## Related

- [Advanced Topics](../../06-advanced-topics/README.md)
- [Examples](../../08-examples/advanced/smart-routing.md)
