# Shadowsocks

## Overview

Shadowsocks is a lightweight proxy protocol using AEAD ciphers. It is widely supported and works well for most client/server deployments.

## When to use

- You want a simple, stable proxy protocol
- You need broad client compatibility
- You are OK with password-based authentication

## Minimal outbound example

```yaml
schema_version: 2

inbounds:
  - type: socks
    tag: socks-in
    listen: 127.0.0.1
    port: 1080

outbounds:
  - type: shadowsocks
    tag: ss-out
    server: proxy.example.com
    port: 8388
    method: aes-256-gcm
    password: ${SS_PASSWORD}

route:
  default: ss-out
```

## Minimal inbound example

```yaml
schema_version: 2

inbounds:
  - type: shadowsocks
    tag: ss-in
    listen: 0.0.0.0
    port: 8388
    method: aes-256-gcm
    password: ${SS_PASSWORD}

outbounds:
  - type: direct
    tag: direct

route:
  default: direct
```

## Notes

- Prefer AEAD ciphers (AES-GCM or ChaCha20-Poly1305).
- AEAD-2022 ciphers are supported when clients/servers match.
- Avoid embedding secrets in version control.

## Related

- [TLS Configuration](../configuration/tls.md)
- [Basic Configuration](../../00-getting-started/basic-configuration.md)
