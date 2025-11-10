TUIC UDP over Stream Example

This example shows how to configure TUIC with UDP over stream enabled to relay UDP traffic via QUIC unidirectional streams.

```yaml
schema_version: 2

inbounds:
  - type: socks
    tag: socks-in
    listen: 127.0.0.1
    port: 1080

outbounds:
  - type: tuic
    tag: tuic-udp
    server: tuic.example.com
    port: 443
    uuid: 550e8400-e29b-41d4-a716-446655440000
    token: your-token

    # QUIC/TLS options
    tls:
      enabled: true
      sni: tuic.example.com

    # UDP relay configuration
    udp_relay_mode: native
    udp_over_stream: true
    zero_rtt_handshake: false

route:
  default: tuic-udp
```

Runtime metrics (when enabled)

- `udp_quic_send_total{proto=tuic}` / `udp_quic_send_bytes_total{proto=tuic}`
- `udp_quic_recv_total{proto=tuic}` / `udp_quic_recv_bytes_total{proto=tuic}`

Notes

- DNS traffic via SOCKS5 UDP associate will be relayed through TUIC when routing directs UDP to this outbound.
- For best results, ensure server supports UDP relay in TUIC v5.

