# ECH (Encrypted Client Hello)

## Overview

ECH encrypts the TLS ClientHello, hiding SNI from observers.

## When to use

- You control or trust an ECH-enabled server
- You need additional privacy for TLS handshakes

## Client example

```yaml
outbounds:
  - type: trojan
    tag: trojan-ech
    server: trojan.example.com
    port: 443
    password: ${TROJAN_PASSWORD}
    tls:
      enabled: true
      ech:
        enabled: true
        config: "base64-encoded-ech-config"
      sni: trojan.example.com
```

## Notes

- ECH requires server-provided ECHConfigList.
- Not all TLS libraries support ECH; treat as experimental.

## Related

- [TLS Configuration](../configuration/tls.md)
- [Advanced Topics](../../06-advanced-topics/README.md)
