# Schema Migration: Go sing-box V1 to singbox-rust V2

## Overview

singbox-rust uses a **V2 schema** that is structurally different from Go sing-box V1.
The built-in migration tool handles most transformations automatically, but understanding
the differences helps when writing configs from scratch or debugging migration issues.

### Quick migration

```bash
singbox-rust check -c old-config.json --migrate --write-normalized --out config.v2.yaml
```

Always review the migrated output before deploying.

---

## Field Mapping Reference

### Top-Level Fields

| Go V1 field | Rust V2 field | Notes |
|---|---|---|
| `schema_version` (absent) | `schema_version: 2` | Required in V2 |
| `rules` (root level) | `route.rules` | Moved under `route` |
| `default_outbound` | `route.default` | Moved under `route` |
| `experimental` | `experimental` | Same location, same structure |

### Inbound Fields

| Go V1 field | Rust V2 field | Notes |
|---|---|---|
| `tag` | `tag` (or `name`) | Both accepted; `name` is the V2 canonical form |
| `listen` (IP only) | `listen` (IP:port string) | V2 merges IP and port into one field |
| `listen_port` | (merged into `listen`) | `"0.0.0.0"` + `listen_port: 1080` becomes `"0.0.0.0:1080"` |
| `sniff` | `sniff` | Same |
| `sniff_override_destination` | `sniff_override_destination` | Same |
| `domain_strategy` | `domain_strategy` | Same |
| `set_system_proxy` | `set_system_proxy` | Same |
| `users` | `users` | Same structure for SOCKS/HTTP auth |

**Supported inbound types**: `socks`, `http`, `mixed`, `tun`, `redirect`, `tproxy`, `direct`,
`shadowsocks`, `vmess`, `vless`, `trojan`, `naive`, `shadowtls`, `anytls`, `hysteria`, `hysteria2`, `tuic`, `dns`, `ssh`

### Outbound Fields

| Go V1 field | Rust V2 field | Notes |
|---|---|---|
| `tag` | `name` | Renamed; `tag` still accepted as alias |
| `server_port` | `port` | Renamed |
| `type: "socks5"` | `type: "socks"` | Normalized |
| `server` | `server` | Same |
| `uuid` | `uuid` | Same (VMess/VLESS/TUIC) |
| `password` | `password` | Same (Trojan/SS/Hysteria2) |
| `security` | `security` | Same (VMess cipher) |
| `alter_id` | `alter_id` | Same (VMess legacy) |
| `flow` | `flow` | Same (VLESS) |
| `method` | `method` | Same (Shadowsocks cipher) |
| `detour` | `detour` | Same (dial through another outbound) |

**Supported outbound types**: `direct`, `block`, `http`, `socks`, `shadowsocks`, `shadowtls`,
`selector`, `urltest`, `hysteria2`, `tuic`, `vless`, `vmess`, `trojan`, `ssh`, `dns`, `tor`,
`anytls`, `hysteria`, `wireguard`, `tailscale`, `shadowsocksr`

### Selector / URLTest Outbound Fields

| Go V1 field | Rust V2 field | Notes |
|---|---|---|
| `outbounds` | `members` (preferred) | `outbounds` accepted as alias |
| `default` | `default` | Default selected member |
| `url` | `test_url` | URLTest probe URL |
| `interval: "60s"` | `test_interval_ms: 60000` | **Duration string to milliseconds** |
| `timeout: "5s"` | `test_timeout_ms: 5000` | **Duration string to milliseconds** |
| `tolerance` | `test_tolerance_ms` | Milliseconds; Go uses duration strings |
| `interrupt_exist_connections` | `interrupt_exist_connections` | Same |

> **Compatibility note**: The `sb-config/outbound.rs` layer also accepts `interval`/`timeout`
> as integer seconds (e.g., `"interval": 60`) and `interval_ms`/`timeout_ms`/`tolerance_ms`
> for millisecond precision. Duration strings like `"3s"` are accepted in `interval`/`timeout`/`tolerance`.

### Route Rule Fields

| Go V1 field | Rust V2 field | Notes |
|---|---|---|
| `outbound` | `outbound` (or `to`) | `to` is the V2 canonical form |
| Flat conditions (e.g. `domain_suffix`) | Kept flat **or** wrapped in `when` | Both styles accepted |
| `domain` | `domain` | Same |
| `domain_suffix` | `domain_suffix` | Same |
| `domain_keyword` | `domain_keyword` | Same |
| `domain_regex` | `domain_regex` | Same |
| `geosite` | `geosite` | Same |
| `geoip` | `geoip` | Same |
| `ip_cidr` | `ipcidr` | Slight rename (underscore removed) |
| `source_ip_cidr` | `source` | Renamed |
| `port` | `port` | Same |
| `process_name` | `process_name` (alias: `process`) | Same |
| `network` | `network` | Same |
| `protocol` | `protocol` | Same |
| `clash_mode` | `clash_mode` | Same |
| `rule_set` | `rule_set` | Same |
| `type: "logical"` | `type: "logical"` | Same; use `mode: "and"/"or"` + `rules: [...]` |

**Rule actions**: `route` (default), `reject`, `reject-drop`, `hijack`, `hijack-dns`, `sniff`, `sniff-override`, `resolve`, `route-options`

**Negation**: Prefix any condition with `not_` to exclude (e.g., `not_domain_suffix`, `not_geoip`).

### DNS Fields

| Go V1 field | Rust V2 field | Notes |
|---|---|---|
| `dns.servers[].tag` | `dns.servers[].tag` | Same |
| `dns.servers[].address` | `dns.servers[].address` | Same scheme syntax |
| `dns.rules` | `dns.rules` | Same structure |
| `dns.final` | `dns.final` | Same |
| `dns.strategy` | `dns.strategy` | Same |
| `dns.disable_cache` | `dns.disable_cache` | Same |
| `dns.client_subnet` | `dns.client_subnet` | Same (EDNS0 ECS) |

**Supported DNS schemes**: `system`, `udp://`, `https://` (DoH), `dot://`/`tls://` (DoT),
`doq://`/`quic://` (DoQ), `doh3://`/`h3://` (DoH3), `dhcp://`, `tailscale://`, `resolved://`

### TLS Fields

| Go V1 field | Rust V2 field | Notes |
|---|---|---|
| `tls.enabled` | `tls.enabled` | Same |
| `tls.server_name` | `tls.sni` | Renamed in outbound config layer |
| `tls.insecure` | `tls.insecure` / `skip_cert_verify` | Both accepted |
| `tls.alpn` | `tls.alpn` | Same |
| `tls.reality` | `tls.reality` | Same sub-object |
| `tls.ech` | `tls.ech` | Same sub-object |

### Transport Fields

| Go V1 field | Rust V2 field | Notes |
|---|---|---|
| `transport.type: "ws"` | `transport.type: "ws"` | Same |
| `transport.type: "grpc"` | `transport.type: "grpc"` | Same |
| `transport.type: "httpupgrade"` | `transport.type: "httpupgrade"` | Same |
| `transport.path` | `transport.path` | Same (WS/HTTPUpgrade) |
| `transport.headers` | `transport.headers` | Same (WS/HTTPUpgrade) |
| `transport.service_name` | `transport.service_name` | Same (gRPC) |

### NTP Fields

| Go V1 field | Rust V2 field | Notes |
|---|---|---|
| `ntp.enabled` | `ntp.enabled` | Same |
| `ntp.server` | `ntp.server` | Same |
| `ntp.server_port` | `ntp.server_port` | Same |
| `ntp.interval` (duration) | `ntp.interval_ms` | **Duration to milliseconds** |

### Experimental Fields

| Go V1 field | Rust V2 field | Notes |
|---|---|---|
| `experimental.clash_api` | `experimental.clash_api` | Same |
| `experimental.v2ray_api` | `experimental.v2ray_api` | Same |
| `experimental.cache_file` | `experimental.cache_file` | Same |

---

## Duration Format Differences

Go sing-box uses Go-style duration strings (`"3s"`, `"5m"`, `"1h30m"`).
singbox-rust accepts both styles where applicable but prefers numeric values:

| Go V1 | Rust V2 (preferred) | Also accepted |
|---|---|---|
| `"60s"` | `60000` (ms field) or `60` (seconds field) | `"60s"` in some fields |
| `"5m"` | `300000` (ms field) | `"5m"` as string |
| `"1h"` | `3600000` (ms field) | `"1h"` as string |

**Fields using seconds** (integer): `interval`, `timeout` in URLTest outbound config.

**Fields using milliseconds** (integer): `test_interval_ms`, `test_timeout_ms`, `test_tolerance_ms`,
`interval_ms`, `timeout_ms`, `dns_timeout_ms`, `dns_query_timeout_ms` in the IR layer.

**Fields using duration strings**: `udp_timeout`, `connect_timeout`, `update_interval`, `sniff_timeout`.

---

## WireGuard Migration

WireGuard outbounds are migrated to the V2 **endpoint** model:

| Go V1 (outbound) | Rust V2 (endpoint) |
|---|---|
| `type: "wireguard"` (in `outbounds`) | `type: "wireguard"` (in `endpoints`) |
| `server` | `peers[0].address` |
| `port` / `server_port` | `peers[0].port` |
| `public_key` | `peers[0].public_key` |
| `pre_shared_key` | `peers[0].pre_shared_key` |
| `allowed_ips` | `peers[0].allowed_ips` |
| `reserved` | `peers[0].reserved` |
| `private_key` | `private_key` (top level) |
| `mtu` | `mtu` (top level) |
| `local_address` | `local_address` (top level) |

---

## Before / After Examples

### Example 1: Basic SOCKS proxy (Go V1 to Rust V2)

**Go V1**:
```json
{
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "0.0.0.0",
      "listen_port": 1080
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "socks5",
      "tag": "proxy",
      "server": "1.2.3.4",
      "server_port": 1080
    }
  ],
  "rules": [
    {
      "domain_suffix": [".google.com"],
      "outbound": "proxy"
    }
  ],
  "default_outbound": "direct"
}
```

**Rust V2**:
```yaml
schema_version: 2

inbounds:
  - type: mixed
    name: mixed-in
    listen: "0.0.0.0:1080"

outbounds:
  - type: direct
    name: direct

  - type: socks
    name: proxy
    server: 1.2.3.4
    port: 1080

route:
  rules:
    - domain_suffix: [".google.com"]
      outbound: proxy
  default: direct
```

### Example 2: VMess + WebSocket + TLS

**Go V1**:
```json
{
  "inbounds": [
    {
      "type": "socks",
      "tag": "socks-in",
      "listen": "127.0.0.1",
      "listen_port": 1080
    }
  ],
  "outbounds": [
    {
      "type": "vmess",
      "tag": "vmess-out",
      "server": "proxy.example.com",
      "server_port": 443,
      "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
      "security": "auto",
      "tls": {
        "enabled": true,
        "server_name": "proxy.example.com"
      },
      "transport": {
        "type": "ws",
        "path": "/vmess"
      }
    },
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "rules": [
      {
        "geosite": "cn",
        "outbound": "direct"
      }
    ],
    "final": "vmess-out"
  }
}
```

**Rust V2**:
```yaml
schema_version: 2

inbounds:
  - type: socks
    name: socks-in
    listen: "127.0.0.1:1080"

outbounds:
  - type: vmess
    name: vmess-out
    server: proxy.example.com
    port: 443
    uuid: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
    security: auto
    tls:
      enabled: true
      sni: proxy.example.com
    transport:
      type: ws
      path: /vmess

  - type: direct
    name: direct

route:
  rules:
    - geosite: cn
      outbound: direct
  final: vmess-out
```

### Example 3: URLTest auto-selection

**Go V1**:
```json
{
  "outbounds": [
    {
      "type": "urltest",
      "tag": "auto",
      "outbounds": ["proxy-hk", "proxy-jp", "proxy-us"],
      "url": "http://www.gstatic.com/generate_204",
      "interval": "3m",
      "tolerance": "50ms"
    }
  ]
}
```

**Rust V2**:
```yaml
outbounds:
  - type: urltest
    name: auto
    members: [proxy-hk, proxy-jp, proxy-us]
    test_url: "http://www.gstatic.com/generate_204"
    test_interval_ms: 180000    # 3 minutes
    test_tolerance_ms: 50
```

> **Shorthand also accepted**: `interval: 180` (seconds), `tolerance: 50` (ms) in the outbound layer.

---

## Common Migration Pitfalls

1. **Missing `schema_version: 2`**: V2 configs must include this field. The migrator adds it automatically, but hand-written configs sometimes omit it.

2. **`listen_port` not merged**: If you copy Go configs directly, remember to combine `listen` + `listen_port` into a single `listen: "IP:PORT"` string, or run the migrator.

3. **`tag` vs `name`**: Both work, but V2 prefers `name` for outbounds. The migrator renames `tag` to `name` automatically.

4. **`socks5` type**: Go uses `socks5` in some contexts; V2 normalizes to `socks`.

5. **Duration strings in timing fields**: Go uses `"3s"`, `"5m"`. The IR layer uses milliseconds (`test_interval_ms: 3000`). The outbound config layer accepts both integer seconds and duration strings for `interval`/`timeout`/`tolerance`.

6. **`server_port` to `port`**: Go uses `server_port` for outbound remote port; V2 uses `port`.

7. **Route rule `outbound` to `to`**: Both work; `to` is the V2 canonical form. The migrator renames automatically.

8. **Flat conditions vs `when` wrapper**: V2 supports both flat conditions (`domain_suffix: ...`) and the `when` wrapper style. The migrator wraps V1 conditions in `when`, but flat style is equally valid.

9. **WireGuard outbound to endpoint**: WireGuard has moved from `outbounds` to `endpoints` in V2. Peer fields are restructured into a `peers` array.

10. **Credential fields**: V2 accepts `user` as alias for `username` in SSH/HTTP/SOCKS outbounds, and `auth_str` for Hysteria V1.
