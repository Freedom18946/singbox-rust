# Configuration Reference

Complete reference for all singbox-rust configuration sections and fields.

---

## Top-Level Structure

```yaml
schema_version: 2          # Required

log:                        # Optional
  level: info

inbounds: []                # Required - local listeners
outbounds: []               # Required - upstream connectors
route:                      # Required - routing rules
  rules: []
  default: direct

dns:                        # Optional - DNS resolution
  servers: []
  rules: []

ntp:                        # Optional - NTP time sync
  enabled: false

certificate:                # Optional - global TLS trust
  ca_paths: []

endpoints: []               # Optional - WireGuard/Tailscale
services: []                # Optional - DERP/SSM/Resolved

experimental:               # Optional - Clash API, V2Ray API, cache
  clash_api: {}
```

---

## Inbounds

Each inbound defines a local listener. Common fields shared by all types:

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | (required) | Inbound type |
| `tag` / `name` | string | (optional) | Unique identifier for routing references |
| `listen` | string | `"0.0.0.0"` | Bind address (IP or IP:port) |
| `port` | u16 | (per type) | Listen port |
| `sniff` | bool | `false` | Enable protocol sniffing |
| `sniff_override_destination` | bool | `false` | Override destination with sniffed hostname |
| `udp` | bool | `false` | Enable UDP support |
| `udp_timeout` | string | - | UDP session timeout (e.g., `"5m"`) |
| `detour` | string | - | Detour to another inbound tag |
| `domain_strategy` | string | - | DNS resolution strategy |
| `set_system_proxy` | bool | `false` | Set OS system proxy |

### socks

SOCKS5 proxy inbound.

```yaml
inbounds:
  - type: socks
    tag: socks-in
    listen: "127.0.0.1:1080"
    # Optional authentication
    users:
      - username: user1
        password: pass1
```

### http

HTTP CONNECT proxy inbound.

```yaml
inbounds:
  - type: http
    tag: http-in
    listen: "127.0.0.1:8080"
    # Optional basic auth
    users:
      - username: user1
        password: pass1
```

### mixed

Combined SOCKS5 + HTTP proxy inbound (auto-detected by first byte).

```yaml
inbounds:
  - type: mixed
    tag: mixed-in
    listen: "0.0.0.0:1080"
```

### tun

TUN device inbound for transparent proxying.

```yaml
inbounds:
  - type: tun
    tag: tun-in
    tun:
      mtu: 1500
      auto_route: true
      strict_route: false
      stack: system             # system | gvisor | mixed
      inet4_address: "172.19.0.1/30"
      inet6_address: "fd00::1/126"
      exclude_routes: []
      include_routes: []
      endpoint_independent_nat: false
```

| Field | Type | Default | Description |
|---|---|---|---|
| `tun.mtu` | u32 | 1500 | Maximum transmission unit |
| `tun.auto_route` | bool | `false` | Automatically configure routes |
| `tun.auto_redirect` | bool | `false` | Auto redirect traffic |
| `tun.strict_route` | bool | `false` | Prevent traffic leaking |
| `tun.stack` | string | `"system"` | Network stack: `system`, `gvisor`, `mixed` |
| `tun.inet4_address` | string | - | IPv4 address/prefix for TUN interface |
| `tun.inet6_address` | string | - | IPv6 address/prefix for TUN interface |
| `tun.exclude_routes` | list | `[]` | Routes to exclude from TUN |
| `tun.include_routes` | list | `[]` | Routes to include in TUN |
| `tun.endpoint_independent_nat` | bool | `false` | Enable EI-NAT for UDP |

### redirect

Linux iptables REDIRECT transparent proxy.

```yaml
inbounds:
  - type: redirect
    tag: redirect-in
    listen: "0.0.0.0:1081"
```

### tproxy

Linux transparent proxy with IP_TRANSPARENT.

```yaml
inbounds:
  - type: tproxy
    tag: tproxy-in
    listen: "0.0.0.0:1082"
```

### shadowsocks (inbound)

Shadowsocks proxy server.

```yaml
inbounds:
  - type: shadowsocks
    tag: ss-in
    listen: "0.0.0.0:8388"
    method: aes-256-gcm
    password: server-password
    # Or multi-user:
    # users_shadowsocks:
    #   - name: user1
    #     password: pass1
```

### vmess (inbound)

VMess proxy server.

```yaml
inbounds:
  - type: vmess
    tag: vmess-in
    listen: "0.0.0.0:443"
    users_vmess:
      - name: user1
        uuid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        alter_id: 0
```

### vless (inbound)

VLESS proxy server.

```yaml
inbounds:
  - type: vless
    tag: vless-in
    listen: "0.0.0.0:443"
    users_vless:
      - name: user1
        uuid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        flow: xtls-rprx-vision
```

### trojan (inbound)

Trojan proxy server.

```yaml
inbounds:
  - type: trojan
    tag: trojan-in
    listen: "0.0.0.0:443"
    users_trojan:
      - name: user1
        password: trojan-pass
    # Optional fallback for non-Trojan traffic
    fallback: "127.0.0.1:80"
```

### hysteria2 (inbound)

Hysteria2 QUIC proxy server.

```yaml
inbounds:
  - type: hysteria2
    tag: hy2-in
    listen: "0.0.0.0:443"
    users_hysteria2:
      - name: user1
        password: hy2-pass
    congestion_control: bbr
    # Optional masquerade
    # masquerade:
    #   type: proxy
    #   proxy:
    #     url: "https://example.com"
```

### tuic (inbound)

TUIC QUIC proxy server.

```yaml
inbounds:
  - type: tuic
    tag: tuic-in
    listen: "0.0.0.0:443"
    users_tuic:
      - uuid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        token: user-token
```

---

## Outbounds

Each outbound defines an upstream connection strategy.

### direct

Connect directly to the destination (no proxy).

```yaml
outbounds:
  - type: direct
    name: direct
```

### block

Block/drop the connection.

```yaml
outbounds:
  - type: block
    name: block
```

### socks

SOCKS5 upstream proxy.

```yaml
outbounds:
  - type: socks
    name: socks-proxy
    server: proxy.example.com
    port: 1080
    credentials:
      username: user
      password: pass
```

### http

HTTP CONNECT upstream proxy.

```yaml
outbounds:
  - type: http
    name: http-proxy
    server: proxy.example.com
    port: 8080
    credentials:
      username: user
      password: pass
    tls:
      enabled: true
      sni: proxy.example.com
```

### shadowsocks

Shadowsocks upstream proxy.

| Field | Type | Default | Description |
|---|---|---|---|
| `server` | string | (required) | Server address |
| `port` | u16 | (required) | Server port |
| `method` | string | (required) | Encryption method |
| `password` | string | (required) | Password |
| `plugin` | string | - | SIP003 plugin name |
| `plugin_opts` | string | - | Plugin options |
| `udp_over_tcp` | bool | `false` | UDP over TCP transport |

```yaml
outbounds:
  - type: shadowsocks
    name: ss-out
    server: ss.example.com
    port: 8388
    method: aes-256-gcm
    password: ${SS_PASSWORD}
```

**Supported methods**: `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`, `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305`, `none`

### vmess

VMess upstream proxy.

| Field | Type | Default | Description |
|---|---|---|---|
| `server` | string | (required) | Server address |
| `port` | u16 | (required) | Server port |
| `uuid` | string | (required) | User UUID |
| `security` | string | `"auto"` | Encryption: `auto`, `aes-128-gcm`, `chacha20-poly1305`, `none` |
| `alter_id` | u8 | `0` | Legacy alterId (use 0 for AEAD) |
| `packet_encoding` | string | - | `packetaddr` or `xudp` |
| `transport` | object | - | Transport configuration |
| `tls` | object | - | TLS configuration |
| `multiplex` | object | - | Multiplex configuration |

```yaml
outbounds:
  - type: vmess
    name: vmess-out
    server: vmess.example.com
    port: 443
    uuid: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
    security: auto
    tls:
      enabled: true
      sni: vmess.example.com
    transport:
      type: ws
      path: /vmess
```

### vless

VLESS upstream proxy.

| Field | Type | Default | Description |
|---|---|---|---|
| `server` | string | (required) | Server address |
| `port` | u16 | (required) | Server port |
| `uuid` | string | (required) | User UUID |
| `flow` | string | - | Flow control: `xtls-rprx-vision` |
| `encryption` | string | `"none"` | Encryption mode |
| `packet_encoding` | string | - | `packetaddr` or `xudp` |
| `transport` | object | - | Transport configuration |
| `tls` | object | - | TLS configuration |

```yaml
outbounds:
  - type: vless
    name: vless-out
    server: vless.example.com
    port: 443
    uuid: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
    flow: xtls-rprx-vision
    tls:
      enabled: true
      reality:
        enabled: true
        public_key: "..."
        short_id: "..."
      sni: www.microsoft.com
```

### trojan

Trojan upstream proxy.

```yaml
outbounds:
  - type: trojan
    name: trojan-out
    server: trojan.example.com
    port: 443
    password: trojan-pass
    tls:
      enabled: true
      sni: trojan.example.com
```

### tuic

TUIC QUIC upstream proxy.

| Field | Type | Default | Description |
|---|---|---|---|
| `server` | string | (required) | Server address |
| `port` | u16 | (required) | Server port |
| `uuid` | string | (required) | User UUID |
| `token` | string | (required) | Authentication token |
| `congestion_control` | string | `"bbr"` | `bbr`, `cubic`, `new_reno` |
| `udp_relay_mode` | string | - | `native` or `quic` |
| `udp_over_stream` | bool | `false` | UDP over stream |
| `zero_rtt_handshake` | bool | `false` | QUIC 0-RTT |
| `skip_cert_verify` | bool | `false` | Skip TLS verification |

```yaml
outbounds:
  - type: tuic
    name: tuic-out
    server: tuic.example.com
    port: 443
    uuid: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
    token: secret-token
    congestion_control: bbr
    tls:
      sni: tuic.example.com
```

### hysteria2

Hysteria2 QUIC upstream proxy.

| Field | Type | Default | Description |
|---|---|---|---|
| `server` | string | (required) | Server address |
| `port` | u16 | (required) | Server port |
| `password` | string | (required) | Password |
| `up_mbps` | u32 | - | Upload bandwidth limit (Mbps) |
| `down_mbps` | u32 | - | Download bandwidth limit (Mbps) |
| `obfs` | string | - | Obfuscation key |
| `salamander` | string | - | Salamander obfuscation |

```yaml
outbounds:
  - type: hysteria2
    name: hy2-out
    server: hy2.example.com
    port: 443
    password: hy2-pass
    up_mbps: 100
    down_mbps: 100
    tls:
      sni: hy2.example.com
```

### ssh

SSH tunnel upstream proxy.

```yaml
outbounds:
  - type: ssh
    name: ssh-out
    server: ssh.example.com
    port: 22
    credentials:
      username: user
    ssh_private_key_path: /path/to/id_rsa
```

### selector

Manual selector (user picks which outbound to use via Clash API).

```yaml
outbounds:
  - type: selector
    name: manual-select
    members: [proxy-hk, proxy-jp, proxy-us]
    default: proxy-hk
    interrupt_exist_connections: false
```

### urltest

Automatic selector based on latency probing.

| Field | Type | Default | Description |
|---|---|---|---|
| `members` | list | (required) | Candidate outbound names |
| `test_url` | string | `http://www.gstatic.com/generate_204` | Probe URL |
| `test_interval_ms` | u64 | `60000` | Probe interval (ms) |
| `test_timeout_ms` | u64 | `5000` | Probe timeout (ms) |
| `test_tolerance_ms` | u64 | `50` | Switch only if latency diff exceeds this |
| `interrupt_exist_connections` | bool | `false` | Interrupt existing connections on switch |

```yaml
outbounds:
  - type: urltest
    name: auto-select
    members: [proxy-hk, proxy-jp, proxy-us]
    test_url: "http://www.gstatic.com/generate_204"
    test_interval_ms: 180000
    test_timeout_ms: 5000
    test_tolerance_ms: 50
```

### wireguard

WireGuard outbound (endpoint model in V2).

```yaml
endpoints:
  - type: wireguard
    tag: wg-out
    wireguard_private_key: "base64-private-key"
    wireguard_address: ["10.0.0.2/32"]
    wireguard_mtu: 1280
    wireguard_peers:
      - address: 1.2.3.4
        port: 51820
        public_key: "base64-public-key"
        allowed_ips: ["0.0.0.0/0"]
        persistent_keepalive_interval: 25
```

---

## Route

Controls which outbound handles each connection.

```yaml
route:
  rules: []
  rule_set: []
  default: direct               # Fallback outbound
  final: direct                 # Alias for default (Go compat)

  # Optional
  geoip_path: /path/to/geoip.db
  geosite_path: /path/to/geosite.db
  find_process: false
  auto_detect_interface: true
  default_interface: eth0
```

### Rule Fields

Rules are evaluated in order; first match wins.

```yaml
route:
  rules:
    # Match by domain
    - domain: [google.com, github.com]
      outbound: proxy

    # Match by domain suffix
    - domain_suffix: [".cn", ".internal"]
      outbound: direct

    # Match by keyword
    - domain_keyword: [video, stream]
      outbound: proxy

    # Match by GeoIP
    - geoip: cn
      outbound: direct

    # Match by Geosite
    - geosite: [category-ads-all]
      outbound: block

    # Match by IP CIDR
    - ipcidr: ["10.0.0.0/8", "172.16.0.0/12"]
      outbound: direct

    # Match by port
    - port: ["80", "443"]
      outbound: proxy

    # Match by process
    - process_name: [chrome, firefox]
      outbound: proxy

    # Match by network type
    - network: [tcp]
      outbound: proxy

    # Match by Clash API mode
    - clash_mode: [global]
      outbound: proxy

    # Logical rule (AND)
    - type: logical
      mode: and
      rules:
        - domain_suffix: [".google.com"]
        - network: [tcp]
      outbound: proxy

    # Rule action: sniff
    - action: sniff

    # Rule action: reject
    - domain_suffix: [".ads.example.com"]
      action: reject

    # Rule action: hijack-dns
    - port: ["53"]
      action: hijack-dns

    # Negation
    - not_domain_suffix: [".local"]
      outbound: proxy
```

### Rule Set

Reference local or remote rule sets:

```yaml
route:
  rule_set:
    - tag: ads
      type: local
      format: binary
      path: /etc/singbox/rules/ads.srs

    - tag: geoip-cn
      type: remote
      format: binary
      url: "https://example.com/geoip-cn.srs"
      download_detour: direct
      update_interval: "24h"

  rules:
    - rule_set: ads
      outbound: block
    - rule_set: geoip-cn
      outbound: direct
```

---

## DNS

```yaml
dns:
  servers:
    - tag: system-dns
      address: system

    - tag: google-doh
      address: "https://dns.google/dns-query"

    - tag: cloudflare-dot
      address: "dot://1.1.1.1:853"
      sni: cloudflare-dns.com

    - tag: quad9-doq
      address: "doq://9.9.9.9:853@dns.quad9.net"

  rules:
    - domain_suffix: [".internal.local"]
      server: system-dns

  default: google-doh
  strategy: prefer_ipv4
  disable_cache: false
  client_subnet: "1.2.3.0/24"          # EDNS0 ECS
  reverse_mapping: false
```

**DNS address schemes**: `system`, `udp://host:port`, `https://host/path` (DoH), `dot://host:port` (DoT), `doq://host:port[@sni]` (DoQ), `doh3://host:port[/path]` (DoH3), `dhcp://`, `tailscale://`, `resolved://`

---

## NTP

```yaml
ntp:
  enabled: true
  server: time.google.com
  server_port: 123
  interval_ms: 1800000          # 30 minutes
```

---

## Certificate (Global Trust)

```yaml
certificate:
  store: system                 # system | mozilla | none
  ca_paths:
    - /etc/ssl/certs/custom-ca.pem
  ca_pem:
    - |
      -----BEGIN CERTIFICATE-----
      ...
      -----END CERTIFICATE-----
```

---

## Log

```yaml
log:
  level: info                   # error | warn | info | debug | trace
  timestamp: true
  format: compact               # compact | json
  disabled: false
  output: stderr                # stdout | stderr | /path/to/file
```

---

## Experimental

### Clash API

```yaml
experimental:
  clash_api:
    external_controller: "127.0.0.1:9090"
    external_ui: /path/to/yacd
    secret: my-api-secret
    default_mode: rule
```

### V2Ray API

```yaml
experimental:
  v2ray_api:
    listen: "127.0.0.1:10085"
    stats:
      enabled: true
      inbounds: [socks-in]
      outbounds: [proxy]
```

### Cache File

```yaml
experimental:
  cache_file:
    enabled: true
    path: /var/lib/singbox/cache.db
    store_fakeip: true
    store_rdrc: true
```

---

## Transport Configuration

Used in VMess, VLESS, Trojan outbounds.

### WebSocket

```yaml
transport:
  type: ws
  path: /vmess
  headers:
    Host: example.com
```

### gRPC

```yaml
transport:
  type: grpc
  service_name: TunnelService
```

### HTTP Upgrade

```yaml
transport:
  type: httpupgrade
  path: /upgrade
  headers:
    Host: example.com
```

---

## TLS Configuration

See [TLS Documentation](tls.md) for full details.

```yaml
tls:
  enabled: true
  sni: example.com
  alpn: [h2, http/1.1]
  insecure: false                       # skip_cert_verify also accepted
  ca_paths: [/path/to/ca.pem]
  ca_pem: ["..."]
  reality:
    enabled: true
    public_key: "..."
    short_id: "..."
    server_name: www.microsoft.com
  ech:
    enabled: true
    config: "base64-ech-config"
```

---

## Multiplex Configuration

```yaml
multiplex:
  enabled: true
  protocol: yamux               # Only yamux supported
  max_connections: 4
  min_streams: 4
  max_streams: 16
  padding: false
  brutal:
    up: 100                     # Mbps
    down: 100
```

---

## Dialer Options (Per-Outbound)

Available on proxy outbounds:

| Field | Type | Description |
|---|---|---|
| `bind_interface` | string | Bind to specific interface |
| `inet4_bind_address` | string | IPv4 bind address |
| `inet6_bind_address` | string | IPv6 bind address |
| `routing_mark` | u32 | SO_MARK (Linux) |
| `reuse_addr` | bool | SO_REUSEADDR |
| `connect_timeout` | string | Connection timeout (e.g., `"5s"`) |
| `tcp_fast_open` | bool | TCP Fast Open |
| `tcp_multi_path` | bool | MPTCP |
| `udp_fragment` | bool | Allow UDP fragmentation |
| `domain_strategy` | string | DNS resolution strategy |
| `detour` | string | Dial through another outbound |

---

## Environment Variable Support

Credentials support environment variable references:

```yaml
outbounds:
  - type: shadowsocks
    name: ss-out
    server: ss.example.com
    port: 8388
    method: aes-256-gcm
    password: ${SS_PASSWORD}
    credentials:
      username_env: PROXY_USER     # Read from env var
      password_env: PROXY_PASS
```

DNS client subnet can also be set via environment:

```bash
export SB_DNS_CLIENT_SUBNET=1.2.3.0/24
```
