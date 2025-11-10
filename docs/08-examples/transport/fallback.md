Transport Fallback Example (WS↔H2)

This example shows how to configure an outbound with both WebSocket and HTTP/2 hints, and enable automatic fallback attempts when the primary chain fails.

Example: VMess with TLS + WebSocket (primary) and HTTP/2 hint (fallback)

```yaml
schema_version: 2

outbounds:
  - type: vmess
    tag: vmess-ws-h2
    server: vmess.example.com
    port: 443
    uuid: 550e8400-e29b-41d4-a716-446655440000

    tls:
      enabled: true
      sni: vmess.example.com

    # Primary application-layer transport
    transport:
      - type: ws
        path: /vmess
        headers:
          Host: vmess.example.com

      # Hint for an alternate chain (HTTP/2)
      - type: h2
        path: /vmess
        host: vmess.example.com

route:
  default: vmess-ws-h2
```

Runtime toggle

- Set `SB_TRANSPORT_FALLBACK=1` to enable fallback attempts (default: enabled).

Metrics

- Attempts and outcomes: `transport_fallback_total{reason,mode,result}`
- Duration per attempt: `transport_fallback_ms{mode}`

Notes

- Fallback applies to VMess/VLESS/Trojan when built with `v2ray_transport`.
- The planner derives alternate chains based on hints; actual attempts occur only if the primary fails to dial/handshake.

