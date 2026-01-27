# FakeIP Example

## Use case

Enable FakeIP for TUN-based routing.

## Config

```yaml
dns:
  servers:
    - address: https://1.1.1.1/dns-query
      tag: cloudflare
  fakeip:
    enabled: true
    inet4_range: 198.18.0.0/15
    inet6_range: fc00::/18
```

## Related

- [DNS Configuration](../../01-user-guide/configuration/dns.md)
