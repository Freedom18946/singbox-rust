DNS Configuration
=================

Overview
- Supports multiple upstream types: system, UDP, DoH, DoT, DoQ
- Pool and routing by tags (via `dns.rules`)
- TLS trust model integrates with top‑level `certificate` and per‑upstream fields

Upstream Syntax
- `system` — Use OS resolver
- `udp://host:port` — Plain UDP DNS (default port 53)
- `https://host/...` — DNS over HTTPS (DoH)
- `dot://host:port` — DNS over TLS (DoT, default port 853)
- `doq://host:port[@sni]` — DNS over QUIC (DoQ, default port 853), optional SNI override after `@`

Per‑Upstream TLS Fields (DoH/DoT/DoQ)
- `sni` — Override SNI for TLS verification (applicable to DoT/DoQ)
- `ca_paths` — Append CA files (PEM) for this upstream
- `ca_pem` — Append CA PEM (string or array)
- `skip_cert_verify` — Skip TLS verification (testing only)

Global trust
- Top‑level `certificate.ca_paths/ca_pem` append to the global root store and apply to all TLS usages
- Per‑upstream fields extend the trust store further for that upstream only

Example
```yaml
dns:
  servers:
    - tag: sys
      address: system

    - tag: dot1
      address: dot://1.1.1.1:853
      sni: cloudflare-dns.com
      ca_paths: [/etc/ssl/certs/custom-ca.pem]

    - tag: doq1
      address: doq://1.0.0.1:853@one.one.one.one
      ca_pem: |
        -----BEGIN CERTIFICATE-----
        ...
        -----END CERTIFICATE-----

    - tag: doh1
      address: https://1.1.1.1/dns-query
      skip_cert_verify: false
      # ca_pem may be provided to extend trust
      # ca_pem: ["-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----"]

    # Optional: EDNS0 Client Subnet (ECS) for this upstream
    - tag: geo-aware
      address: udp://8.8.8.8:53
      client_subnet: 1.2.3.0/24

  default: sys

  # Optional routing rules by tag (example)
  rules:
    - domain_suffix: ["internal.local"]
      server: dot1
    - keyword: ["video"]
      server: doq1
```

Notes
- Avoid `skip_cert_verify` in production
- When addressing IPs with TLS (DoT/DoQ), supply an appropriate `sni` for proper verification
- Combining global and per‑upstream CA additions allows flexible trust layering
- EDNS0 Client Subnet (ECS):
  - Global: set `dns.client_subnet: "1.2.3.0/24"` (or IPv6 prefix) to attach ECS to all queries
  - Per‑upstream: set `servers[].client_subnet` to override for a specific upstream
  - Environment override: `SB_DNS_CLIENT_SUBNET=1.2.3.0/24`

Adapter DNS helpers
--------------------

The Rust `adapter-dns` outbound kind can run a DNS-forwarding proxy tied to the upstreams
defined above. When you enable `adapter-dns` (and refer to `dns` from `sb-config::ir`), the
outbound builder honors additional IR fields described in `sb-config::ir::OutboundIR`:

- `dns_transport`: choose between `udp`, `tcp`, `dot`, `doh`, and `doq` (default `udp`).
- `dns_tls_server_name`: SNI for DoT/DoQ if the resolver is an IP address.
- `dns_timeout_ms` / `dns_query_timeout_ms`: dial/query timeouts in milliseconds.
- `dns_enable_edns0` / `dns_edns0_buffer_size`: control EDNS0 usage.
- `dns_doh_url`: when using DoH with a custom path, override the default endpoint.

These fields live beside the standard per-outbound options and are only applied when
`outbound.ty` is `dns`. Provide the upstream `server` as a literal IP (with optional `port`)
because the adapter interprets the field as a direct socket address rather than a DNS name.
