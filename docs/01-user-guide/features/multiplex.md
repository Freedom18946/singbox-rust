# Multiplex

## Overview

Multiplexing allows multiple logical streams over a single transport connection (yamux).

## When to use

- You expect many short-lived connections
- You want fewer TCP/TLS handshakes

## Example

```yaml
outbounds:
  - type: vmess
    tag: vmess-out
    server: vmess.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    tls:
      enabled: true
      sni: vmess.example.com
    multiplex:
      enabled: true
      max_streams: 8
```

## Notes

- Not all protocols or transports support multiplexing.
- Tune `max_streams` based on latency and server capacity.
- If you observe head-of-line blocking, reduce `max_streams` or disable.

## Related

- [Transport Defaults](../../04-development/transport-defaults.md)
- [Advanced Topics](../../06-advanced-topics/README.md)
