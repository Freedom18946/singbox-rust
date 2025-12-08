# Environment Variables Reference

Complete reference of all environment variables supported by singbox-rust.

**Total Variables**: 271+ (auto-discovered from source code)

---

## Core Settings

### General

| Variable        | Type   | Default | Description                                         |
| --------------- | ------ | ------- | --------------------------------------------------- |
| `SB_PRINT_ENV`  | bool   | `0`     | Print environment snapshot at startup (JSON format) |
| `SB_CONFIG`     | string | -       | Configuration file path                             |
| `SB_HARDEN`     | bool   | `0`     | Enable hardened mode (stricter security)            |
| `SB_FAILPOINTS` | string | -       | Enable fail points for chaos testing                |
| `SB_TRANSPORT_FALLBACK` | bool | `1` | Enable WS↔H2/Upgrade→WS fallback attempts (VMess/VLESS/Trojan with sb-transport) |
| `SB_TRANSPORT_SNI_FALLBACK` | bool | `1` | When TLS implied by hints (H2/gRPC) without SNI, use server host as SNI if it looks like a domain |

### Logging

| Variable           | Type   | Default | Description                                 |
| ------------------ | ------ | ------- | ------------------------------------------- |
| `RUST_LOG`         | string | `info`  | Log level filter (debug, info, warn, error) |
| `SB_LOG_LEVEL`     | string | `info`  | Alternative log level setting               |
| `SB_LOG_FORMAT`    | string | `compact`  | Log format: `compact` or `json`              |
| `SB_LOG_SAMPLE`    | bool   | `0`     | Enable log sampling                         |
| `SB_LOG_TIMESTAMP` | bool   | `1`     | Include timestamp in log output             |
| `SB_ACCESS_LOG`    | bool   | `0`     | Enable access logging                       |
| `SB_PANIC_LOG`     | bool   | `0`     | Log panics to file                          |
| `SB_PANIC_LOG_MAX` | int    | -       | Maximum panic log size                      |

---

## Admin API

### Admin Server

| Variable             | Type   | Default           | Description                        |
| -------------------- | ------ | ----------------- | ---------------------------------- |
| `SB_ADMIN_URL`       | string | `127.0.0.1:18088` | Admin HTTP server address          |
| `SB_ADMIN_IMPL`      | string | `core`            | Implementation: `core` or `debug`  |
| `SB_ADMIN_NO_AUTH`   | bool   | `0`               | Disable authentication (insecure!) |
| `SB_ADMIN_ALLOW_NET` | string | -                 | Allowed networks (CIDR)            |
| `SB_ADMIN_PORTFILE`  | string | -                 | Write listening port to file       |

### Admin Authentication

| Variable               | Type   | Default | Description                |
| ---------------------- | ------ | ------- | -------------------------- |
| `SB_ADMIN_TOKEN`       | string | -       | Admin API bearer token     |
| `SB_ADMIN_HMAC_SECRET` | string | -       | HMAC signature secret      |
| `SB_ADMIN_MTLS`        | bool   | `0`     | Enable mTLS authentication |
| `SB_ADMIN_TLS_CERT`    | string | -       | TLS certificate path       |
| `SB_ADMIN_TLS_KEY`     | string | -       | TLS private key path       |
| `SB_ADMIN_TLS_CA`      | string | -       | TLS CA certificate path    |

### Admin Rate Limiting

| Variable                         | Type   | Default | Description                    |
| -------------------------------- | ------ | ------- | ------------------------------ |
| `SB_ADMIN_RATE_LIMIT_ENABLED`    | bool   | `1`     | Enable rate limiting           |
| `SB_ADMIN_RATE_LIMIT_MAX`        | int    | `100`   | Maximum requests per window    |
| `SB_ADMIN_RATE_LIMIT_BURST`      | int    | `200`   | Burst capacity                 |
| `SB_ADMIN_RATE_LIMIT_WINDOW_SEC` | int    | `1`     | Rate limit window (seconds)    |
| `SB_ADMIN_RATE_LIMIT_STRATEGY`   | string | `fixed` | Strategy: `fixed` or `sliding` |

### Admin Timeouts

| Variable                        | Type | Default   | Description             |
| ------------------------------- | ---- | --------- | ----------------------- |
| `SB_ADMIN_FIRSTLINE_TIMEOUT_MS` | int  | `5000`    | First line read timeout |
| `SB_ADMIN_READ_TIMEOUT_MS`      | int  | `10000`   | Read timeout            |
| `SB_ADMIN_MAX_HEADER_BYTES`     | int  | `8192`    | Max header size         |
| `SB_ADMIN_MAX_BODY_BYTES`       | int  | `1048576` | Max body size (1MB)     |

### Admin URL Filtering

| Variable                   | Type   | Default | Description                            |
| -------------------------- | ------ | ------- | -------------------------------------- |
| `SB_ADMIN_URL_ALLOW_HOSTS` | string | -       | Allowed Host headers (comma-separated) |

---

## DNS Configuration

### DNS General

| Variable          | Type   | Default  | Description                                    |
| ----------------- | ------ | -------- | ---------------------------------------------- |
| `SB_DNS_ENABLE`   | bool   | `0`      | Enable DNS resolution features                 |
| `SB_DNS_MODE`     | string | `system` | DNS mode: `system`, `doh`, `dot`, `doq`, `udp` |
| `SB_DNS_SERVERS`  | string | -        | DNS servers (comma-separated)                  |
| `SB_DNS_CLIENT_SUBNET` | string | - | EDNS0 Client Subnet, e.g., `1.2.3.0/24` or `2001:db8::/56`; attaches ECS to queries |
| `SB_DNS_UPSTREAM` | string | -        | Upstream DNS server                            |
| `SB_DNS_IPV6`     | bool   | `1`      | Enable IPv6 DNS queries                        |
| `SB_DNS_FALLBACK` | string | -        | Fallback DNS server                            |
| `SB_DNS_STRATEGY` | string | -        | Query strategy                                 |

### DNS Pool

| Variable                   | Type   | Default | Description                                      |
| -------------------------- | ------ | ------- | ------------------------------------------------ |
| `SB_DNS_POOL`              | string | -       | DNS resolver pool (comma-separated)              |
| `SB_DNS_POOL_STRATEGY`     | string | `race`  | Pool strategy: `race`, `failover`, `round_robin` |
| `SB_DNS_POOL_MAX_INFLIGHT` | int    | `10`    | Max concurrent queries per pool                  |

### DNS Caching

| Variable                          | Type | Default | Description                |
| --------------------------------- | ---- | ------- | -------------------------- |
| `SB_DNS_CACHE_ENABLE`             | bool | `1`     | Enable DNS cache           |
| `SB_DNS_CACHE_SIZE`               | int  | `1024`  | Cache capacity             |
| `SB_DNS_CACHE_CAP`                | int  | `1024`  | Alternative cache capacity |
| `SB_DNS_CACHE_MAX`                | int  | `1024`  | Maximum cache entries      |
| `SB_DNS_DEFAULT_TTL_S`            | int  | `60`    | Default TTL (seconds)      |
| `SB_DNS_MIN_TTL_S`                | int  | `1`     | Minimum TTL                |
| `SB_DNS_MAX_TTL_S`                | int  | `600`   | Maximum TTL                |
| `SB_DNS_NEG_TTL_S`                | int  | `30`    | Negative response TTL      |
| `SB_DNS_NEGATIVE_TTL_S`           | int  | `30`    | Alternative negative TTL   |
| `SB_DNS_SYSTEM_TTL_S`             | int  | `60`    | System DNS result TTL      |
| `SB_DNS_CACHE_STALE_MS`           | int  | -       | Stale cache tolerance      |
| `SB_DNS_CACHE_CLEANUP_INTERVAL_S` | int  | -       | Cache cleanup interval     |

### DNS Timeouts

| Variable                  | Type | Default | Description               |
| ------------------------- | ---- | ------- | ------------------------- |
| `SB_DNS_TIMEOUT_MS`       | int  | `5000`  | Query timeout             |
| `SB_DNS_QUERY_TIMEOUT_MS` | int  | `5000`  | Alternative query timeout |
| `SB_DNS_UDP_TIMEOUT_MS`   | int  | `5000`  | UDP query timeout         |
| `SB_DNS_TCP_TIMEOUT_MS`   | int  | `5000`  | TCP query timeout         |
| `SB_DNS_DOH_TIMEOUT_MS`   | int  | `5000`  | DNS over HTTPS timeout    |
| `SB_DNS_DOT_TIMEOUT_MS`   | int  | `5000`  | DNS over TLS timeout      |
| `SB_DNS_DOQ_TIMEOUT_MS`   | int  | `5000`  | DNS over QUIC timeout     |

### DNS Retries

| Variable             | Type | Default | Description          |
| -------------------- | ---- | ------- | -------------------- |
| `SB_DNS_RETRIES`     | int  | `3`     | Query retry count    |
| `SB_DNS_UDP_RETRIES` | int  | `3`     | UDP-specific retries |

### DNS over HTTPS (DoH)

| Variable         | Type   | Default | Description      |
| ---------------- | ------ | ------- | ---------------- |
| `SB_DNS_DOH_URL` | string | -       | DoH endpoint URL |

### DNS over TLS (DoT)

| Variable          | Type   | Default | Description        |
| ----------------- | ------ | ------- | ------------------ |
| `SB_DNS_DOT_ADDR` | string | -       | DoT server address |

### DNS over QUIC (DoQ)

| Variable                 | Type   | Default | Description             |
| ------------------------ | ------ | ------- | ----------------------- |
| `SB_DNS_DOQ_ADDR`        | string | -       | DoQ server address      |
| `SB_DNS_DOQ_SERVER_NAME` | string | -       | DoQ server name for SNI |

### DNS Hosts & Static

| Variable              | Type   | Default | Description                         |
| --------------------- | ------ | ------- | ----------------------------------- |
| `SB_DNS_HOSTS_ENABLE` | bool   | `0`     | Enable hosts file                   |
| `SB_DNS_HOSTS_TTL_S`  | int    | `300`   | Hosts file TTL                      |
| `SB_DNS_STATIC`       | string | -       | Static DNS mappings (domain=ip,...) |
| `SB_DNS_STATIC_TTL_S` | int    | `300`   | Static entry TTL                    |

### FakeIP

| Variable               | Type   | Default      | Description          |
| ---------------------- | ------ | ------------ | -------------------- |
| `SB_DNS_FAKEIP_ENABLE` | bool   | `0`          | Enable FakeIP mode   |
| `SB_DNS_FAKEIP_TTL_S`  | int    | `60`         | FakeIP TTL           |
| `SB_DNS_FAKEIP_V6`     | bool   | `0`          | Enable IPv6 FakeIP   |
| `SB_FAKEIP_CAP`        | int    | `65536`      | FakeIP pool capacity |
| `SB_FAKEIP_V4_BASE`    | string | `198.18.0.0` | IPv4 base address    |
| `SB_FAKEIP_V4_MASK`    | int    | `15`         | IPv4 mask bits       |
| `SB_FAKEIP_V6_BASE`    | string | `fc00::`     | IPv6 base address    |
| `SB_FAKEIP_V6_MASK`    | int    | `18`         | IPv6 mask bits       |

### DNS Advanced

| Variable                      | Type   | Default | Description                      |
| ----------------------------- | ------ | ------- | -------------------------------- |
| `SB_DNS_PREFETCH`             | bool   | `0`     | Enable DNS prefetching           |
| `SB_DNS_PREFETCH_BEFORE_MS`   | int    | -       | Prefetch before expiry           |
| `SB_DNS_PREFETCH_CONCURRENCY` | int    | -       | Prefetch concurrency             |
| `SB_DNS_PARALLEL`             | bool   | `0`     | Parallel query mode              |
| `SB_DNS_PER_HOST_INFLIGHT`    | int    | `3`     | Max concurrent queries per host  |
| `SB_DNS_RACE_WINDOW_MS`       | int    | `50`    | Race window for parallel queries |
| `SB_DNS_HE_RACE_MS`           | int    | -       | Happy eyeballs race window       |
| `SB_DNS_HE_ORDER`             | string | -       | Happy eyeballs IP family order   |
| `SB_DNS_HE_DELAY_MS`          | int    | -       | Happy eyeballs delay             |
| `SB_DNS_HE_DISABLE`           | bool   | `0`     | Disable happy eyeballs           |
| `SB_DNS_QTYPE`                | string | -       | DNS query type                   |

---

## Router Configuration

### Router General

| Variable                   | Type   | Default | Description                  |
| -------------------------- | ------ | ------- | ---------------------------- |
| `SB_ROUTER_UDP`            | bool   | `1`     | Enable UDP routing           |
| `SB_ROUTER_UDP_RULES`      | string | -       | UDP-specific rules           |
| `SB_ROUTER_DNS`            | bool   | `1`     | Enable DNS routing           |
| `SB_ROUTER_DNS_TIMEOUT_MS` | int    | `5000`  | DNS query timeout in routing |
| `SB_ROUTER_HOT_RELOAD`     | bool   | `0`     | Enable hot reload            |
| `SB_ROUTER_OVERRIDE`       | string | -       | Override routing decision    |

### Router Rules

| Variable                          | Type   | Default | Description                 |
| --------------------------------- | ------ | ------- | --------------------------- |
| `SB_ROUTER_RULES`                 | string | -       | Routing rules (inline)      |
| `SB_ROUTER_RULES_FILE`            | string | -       | Rules file path             |
| `SB_ROUTER_RULES_TEXT`            | string | -       | Rules as text               |
| `SB_ROUTER_RULES_ENABLE`          | bool   | `1`     | Enable rule-based routing   |
| `SB_ROUTER_RULES_MAX`             | int    | `1000`  | Maximum rules               |
| `SB_ROUTER_RULES_REQUIRE_DEFAULT` | bool   | `1`     | Require default outbound    |
| `SB_ROUTER_RULES_MAX_DEPTH`       | int    | `10`    | Maximum rule nesting        |
| `SB_ROUTER_RULES_INCLUDE_DEPTH`   | int    | `10`    | Maximum include depth       |
| `SB_ROUTER_RULES_BASEDIR`         | string | `.`     | Base directory for includes |
| `SB_ROUTER_RULES_HOT_RELOAD_MS`   | int    | -       | Hot reload interval         |
| `SB_ROUTER_RULES_BACKOFF_MAX_MS`  | int    | -       | Hot reload backoff max      |
| `SB_ROUTER_RULES_JITTER_MS`       | int    | -       | Hot reload jitter           |
| `SB_ROUTER_RULES_FROM_JSON`       | bool   | `0`     | Parse rules from JSON       |

### Router Cache

| Variable                       | Type | Default | Description           |
| ------------------------------ | ---- | ------- | --------------------- |
| `SB_ROUTER_DECISION_CACHE`     | bool | `1`     | Enable decision cache |
| `SB_ROUTER_DECISION_CACHE_CAP` | int  | `1024`  | Cache capacity        |
| `SB_ROUTER_DECIDE_BUDGET_MS`   | int  | `100`   | Decision time budget  |

### Router Default Proxy

| Variable                       | Type   | Default | Description           |
| ------------------------------ | ------ | ------- | --------------------- |
| `SB_ROUTER_DEFAULT_PROXY`      | string | -       | Default proxy tag     |
| `SB_ROUTER_DEFAULT_PROXY_KIND` | string | -       | Default proxy type    |
| `SB_ROUTER_DEFAULT_PROXY_ADDR` | string | -       | Default proxy address |

### Router Domain Overrides

| Variable                     | Type   | Default | Description                 |
| ---------------------------- | ------ | ------- | --------------------------- |
| `SB_ROUTER_DOMAIN_OVERRIDES` | string | -       | Domain to outbound mappings |

### Router Optimization

| Variable                   | Type | Default | Description                   |
| -------------------------- | ---- | ------- | ----------------------------- |
| `SB_ROUTER_SUFFIX_TRIE`    | bool | `1`     | Use trie for suffix matching  |
| `SB_ROUTER_SUFFIX_STRICT`  | bool | `0`     | Strict suffix matching        |
| `SB_ROUTER_KEYWORD_AC_MIN` | int  | `5`     | Min keywords for Aho-Corasick |

### Router JSON

| Variable              | Type   | Default | Description             |
| --------------------- | ------ | ------- | ----------------------- |
| `SB_ROUTER_JSON_FILE` | string | -       | Router config JSON file |
| `SB_ROUTER_JSON_TEXT` | string | -       | Router config JSON text |

---

## Inbound Configuration

### SOCKS5 Inbound

| Variable                    | Type   | Default | Description                |
| --------------------------- | ------ | ------- | -------------------------- |
| `SB_SOCKS_TCP_ENABLE`       | bool   | `1`     | Enable SOCKS5 TCP          |
| `SB_SOCKS_TCP_ADDR`         | string | -       | SOCKS5 TCP listen address  |
| `SB_SOCKS_UDP_ENABLE`       | bool   | `0`     | Enable SOCKS5 UDP relay    |
| `SB_SOCKS_UDP_LISTEN`       | string | -       | SOCKS5 UDP listen address  |
| `SB_SOCKS_UDP_BIND`         | string | -       | SOCKS5 UDP bind address    |
| `SB_SOCKS_UDP_RELAY`        | bool   | `0`     | Enable UDP relay mode      |
| `SB_SOCKS_UDP_RESOLVE_BND`  | bool   | `0`     | Resolve BND address        |
| `SB_SOCKS_DISABLE_STOP`     | bool   | `0`     | Disable graceful stop      |
| `SB_SOCKS5_CTRL_TIMEOUT_MS` | int    | `5000`  | Control connection timeout |

### SOCKS5 UDP NAT

| Variable                             | Type | Default | Description                 |
| ------------------------------------ | ---- | ------- | --------------------------- |
| `SB_SOCKS_UDP_NAT_TTL_MS`            | int  | `60000` | UDP NAT session TTL         |
| `SB_SOCKS_UDP_PROXY_TIMEOUT_MS`      | int  | `10000` | UDP proxy timeout           |
| `SB_SOCKS_UDP_PROXY_FALLBACK_DIRECT` | bool | `1`     | Fallback to direct on error |

### HTTP Inbound

| Variable               | Type | Default | Description                |
| ---------------------- | ---- | ------- | -------------------------- |
| `SB_HTTP_DISABLE_STOP` | bool | `0`     | Disable graceful stop      |
| `SB_HTTP_LEGACY_WRITE` | bool | `0`     | Use legacy write mode      |
| `SB_HTTP_SMOKE_405`    | bool | `0`     | Return 405 for non-CONNECT |

### Mixed Inbound

| Variable                | Type | Default | Description           |
| ----------------------- | ---- | ------- | --------------------- |
| `SB_MIXED_DISABLE_STOP` | bool | `0`     | Disable graceful stop |

---

## Outbound Configuration

### TCP Proxy

| Variable                  | Type   | Default  | Description        |
| ------------------------- | ------ | -------- | ------------------ |
| `SB_TCP_PROXY_MODE`       | string | `direct` | TCP proxy mode     |
| `SB_TCP_PROXY_HTTP`       | string | -        | HTTP proxy address |
| `SB_TCP_PROXY_TIMEOUT_MS` | int    | `10000`  | TCP proxy timeout  |

### UDP Proxy

| Variable                   | Type   | Default       | Description                                 |
| -------------------------- | ------ | ------------- | ------------------------------------------- |
| `SB_UDP_PROXY_MODE`        | string | `direct`      | UDP proxy mode: `direct`, `proxy`, `socks5` |
| `SB_UDP_PROXY_ADDR`        | string | -             | UDP proxy address                           |
| `SB_UDP_SOCKS5_ADDR`       | string | -             | SOCKS5 server for UDP                       |
| `SB_UDP_SOCKS5_POOL`       | string | -             | SOCKS5 connection pool size                 |
| `SB_UDP_BALANCER_STRATEGY` | string | `round_robin` | UDP load balancing strategy                 |

### UDP NAT

| Variable         | Type | Default | Description                         |
| ---------------- | ---- | ------- | ----------------------------------- |
| `SB_UDP_NAT_MAX` | int  | `10000` | Max UDP NAT sessions                |
| `SB_UDP_NAT_TTL` | int  | `60`    | UDP NAT session TTL (seconds)       |
| `SB_UDP_TTL_MS`  | int  | `60000` | UDP session TTL (ms)                |
| `SB_UDP_GC_MS`   | int  | `10000` | UDP NAT garbage collection interval |

### UDP Rate Limiting

| Variable                  | Type | Default | Description            |
| ------------------------- | ---- | ------- | ---------------------- |
| `SB_UDP_OUTBOUND_PPS_MAX` | int  | -       | Max packets per second |
| `SB_UDP_OUTBOUND_BPS_MAX` | int  | -       | Max bytes per second   |

### SSH Outbound

| Variable             | Type   | Default              | Description          |
| -------------------- | ------ | -------------------- | -------------------- |
| `SB_SSH_KNOWN_HOSTS` | string | `~/.ssh/known_hosts` | SSH known hosts file |

### Proxy Pool

| Variable                 | Type   | Default | Description              |
| ------------------------ | ------ | ------- | ------------------------ |
| `SB_PROXY_POOL_JSON`     | string | -       | Proxy pool config (JSON) |
| `SB_PROXY_POOL_FILE`     | string | -       | Proxy pool config file   |
| `SB_PROXY_STICKY_TTL_MS` | int    | `60000` | Sticky session TTL       |
| `SB_PROXY_STICKY_CAP`    | int    | `1000`  | Sticky session capacity  |

### Proxy Health Check

| Variable                          | Type | Default | Description                      |
| --------------------------------- | ---- | ------- | -------------------------------- |
| `SB_PROXY_HEALTH_ENABLE`          | bool | `0`     | Enable health checks             |
| `SB_PROXY_HEALTH_INTERVAL_MS`     | int  | `30000` | Health check interval            |
| `SB_PROXY_HEALTH_TIMEOUT_MS`      | int  | `5000`  | Health check timeout             |
| `SB_PROXY_HEALTH_FALLBACK_DIRECT` | bool | `1`     | Fallback to direct on all failed |

---

## Protocol Configuration

### TLS

| Variable            | Type   | Default | Description                   |
| ------------------- | ------ | ------- | ----------------------------- |
| `SB_TLS_SNI`        | string | -       | TLS Server Name Indication    |
| `SB_TLS_ALPN`       | string | -       | TLS ALPN protocols            |
| `SB_TLS_MIN`        | string | `1.2`   | Minimum TLS version           |
| `SB_TLS_PIN_SHA256` | string | -       | Certificate pinning (SHA-256) |

### REALITY

| Variable                 | Type   | Default | Description                |
| ------------------------ | ------ | ------- | -------------------------- |
| `SB_REALITY_PUBLIC_KEY`  | string | -       | REALITY public key (hex)   |
| `SB_REALITY_SHORT_ID`    | string | -       | REALITY short ID           |
| `SB_REALITY_SERVER_NAME` | string | -       | REALITY target server name |
| `SB_REALITY_FINGERPRINT` | string | -       | TLS fingerprint            |
| `SB_REALITY_TARGET`      | string | -       | REALITY fallback target    |

### ECH (Encrypted Client Hello)

| Variable                                | Type   | Default | Description                   |
| --------------------------------------- | ------ | ------- | ----------------------------- |
| `SB_ECH_ENABLED`                        | bool   | `0`     | Enable ECH                    |
| `SB_ECH_CONFIG`                         | string | -       | ECH config (base64)           |
| `SB_ECH_PQ_ENABLED`                     | bool   | `0`     | Enable post-quantum ECH       |
| `SB_ECH_DYNAMIC_RECORD_SIZING_DISABLED` | bool   | `0`     | Disable dynamic record sizing |

### Trojan

| Variable                        | Type   | Default | Description                   |
| ------------------------------- | ------ | ------- | ----------------------------- |
| `SB_TROJAN_TRANSPORT`           | string | -       | Trojan transport type         |
| `SB_TROJAN_ALPN`                | string | -       | Trojan ALPN                   |
| `SB_TROJAN_SKIP_CERT_VERIFY`    | bool   | `0`     | Skip certificate verification |
| `SB_TROJAN_RESPONSE_TIMEOUT_MS` | int    | `10000` | Response timeout              |

### VMess

| Variable             | Type   | Default | Description          |
| -------------------- | ------ | ------- | -------------------- |
| `SB_VMESS_TRANSPORT` | string | -       | VMess transport type |

### VLESS

| Variable             | Type   | Default | Description          |
| -------------------- | ------ | ------- | -------------------- |
| `SB_VLESS_TRANSPORT` | string | -       | VLESS transport type |

### Hysteria2

| Variable                       | Type | Default | Description            |
| ------------------------------ | ---- | ------- | ---------------------- |
| `SB_HYSTERIA2_MAX_RETRIES`     | int  | `3`     | Max connection retries |
| `SB_HYSTERIA2_BACKOFF_MS_BASE` | int  | `100`   | Backoff base (ms)      |
| `SB_HYSTERIA2_BACKOFF_MS_MAX`  | int  | `5000`  | Backoff max (ms)       |

### Naive

| Variable                  | Type | Default | Description                |
| ------------------------- | ---- | ------- | -------------------------- |
| `SB_NAIVE_ALLOW_INSECURE` | bool | `0`     | Allow insecure connections |

### ShadowTLS

| Variable                | Type | Default | Description                |
| ----------------------- | ---- | ------- | -------------------------- |
| `SB_STL_ALLOW_INSECURE` | bool | `0`     | Allow insecure connections |

---

## Transport Configuration

### WebSocket

| Variable     | Type   | Default | Description           |
| ------------ | ------ | ------- | --------------------- |
| `SB_WS_PATH` | string | `/`     | WebSocket path        |
| `SB_WS_HOST` | string | -       | WebSocket Host header |

### HTTP/2

| Variable     | Type   | Default | Description        |
| ------------ | ------ | ------- | ------------------ |
| `SB_H2_PATH` | string | `/`     | HTTP/2 path        |
| `SB_H2_HOST` | string | -       | HTTP/2 Host header |

---

## Subscription

| Variable                    | Type   | Default  | Description               |
| --------------------------- | ------ | -------- | ------------------------- |
| `SB_SUBS_MAX_REDIRECTS`     | int    | `3`      | Max HTTP redirects        |
| `SB_SUBS_TIMEOUT_MS`        | int    | `4000`   | Fetch timeout             |
| `SB_SUBS_MAX_BYTES`         | int    | `524288` | Max response size (512KB) |
| `SB_SUBS_MAX_CONCURRENCY`   | int    | `8`      | Max concurrent fetches    |
| `SB_SUBS_RPS`               | int    | `4`      | Requests per second limit |
| `SB_SUBS_CACHE_CAP`         | int    | `64`     | Cache capacity            |
| `SB_SUBS_CACHE_TTL_MS`      | int    | `30000`  | Cache TTL                 |
| `SB_SUBS_CACHE_BYTES`       | int    | -        | Cache size limit (bytes)  |
| `SB_SUBS_CACHE_DISK`        | string | -        | Disk cache directory      |
| `SB_SUBS_MIME_ALLOW`        | string | -        | Allowed MIME types        |
| `SB_SUBS_MIME_DENY`         | string | -        | Denied MIME types         |
| `SB_SUBS_HEAD_PRECHECK`     | bool   | `0`      | HEAD request precheck     |
| `SB_SUBS_PRIVATE_ALLOWLIST` | string | -        | Private IP allowlist      |

### Subscription Circuit Breaker

| Variable             | Type  | Default | Description               |
| -------------------- | ----- | ------- | ------------------------- |
| `SB_SUBS_BR_WIN_MS`  | int   | `30000` | Circuit breaker window    |
| `SB_SUBS_BR_OPEN_MS` | int   | `15000` | Circuit breaker open time |
| `SB_SUBS_BR_FAILS`   | int   | `5`     | Failure threshold         |
| `SB_SUBS_BR_RATIO`   | float | `0.5`   | Failure ratio threshold   |

---

## Prefetch

| Variable              | Type | Default | Description             |
| --------------------- | ---- | ------- | ----------------------- |
| `SB_PREFETCH_ENABLE`  | bool | `0`     | Enable prefetch         |
| `SB_PREFETCH_CAP`     | int  | `256`   | Prefetch queue capacity |
| `SB_PREFETCH_WORKERS` | int  | `2`     | Prefetch worker threads |
| `SB_PREFETCH_RETRIES` | int  | `3`     | Prefetch retry count    |

---

## Performance & Limits

### Buffering

| Variable                      | Type | Default | Description              |
| ----------------------------- | ---- | ------- | ------------------------ |
| `SB_BUFFER_POOL_SIZE`         | int  | `2048`  | Buffer pool size (bytes) |
| `SB_BUFFER_POOL_MAX_CAPACITY` | int  | `32768` | Max buffer size          |

### Concurrency

| Variable                  | Type | Default | Description              |
| ------------------------- | ---- | ------- | ------------------------ |
| `SB_DIAL_MAX_CONCURRENCY` | int  | `100`   | Max concurrent dials     |
| `SB_DIAL_QUEUE_MS`        | int  | `100`   | Dial queue timeout       |
| `SB_OUT_MAX_CONCURRENCY`  | int  | `100`   | Max outbound concurrency |
| `SB_OUT_QUEUE_MS`         | int  | `100`   | Outbound queue timeout   |

### Circuit Breaker

| Variable                | Type | Default | Description                |
| ----------------------- | ---- | ------- | -------------------------- |
| `SB_CB_WINDOW_MS`       | int  | `30000` | Circuit breaker window     |
| `SB_CB_OPEN_TIMEOUT_MS` | int  | `15000` | Circuit breaker open time  |
| `SB_CB_FAILS`           | int  | `5`     | Failure threshold          |
| `SB_CB_COUNT_TIMEOUTS`  | bool | `1`     | Count timeouts as failures |
| `SB_CB_HALFOPEN_MAX`    | int  | `1`     | Half-open max requests     |

### Retry

| Variable           | Type  | Default | Description         |
| ------------------ | ----- | ------- | ------------------- |
| `SB_RETRY_MAX`     | int   | `3`     | Max retry attempts  |
| `SB_RETRY_BASE_MS` | int   | `100`   | Retry base delay    |
| `SB_RETRY_JITTER`  | float | `0.1`   | Retry jitter factor |

---

## Observability

### Metrics

| Variable          | Type   | Default | Description                |
| ----------------- | ------ | ------- | -------------------------- |
| `SB_METRICS_ADDR` | string | -       | Prometheus metrics address |
| `SB_OBS_UDP_IO`   | bool   | `0`     | Observe UDP I/O metrics    |

### Health Check

| Variable           | Type | Default | Description            |
| ------------------ | ---- | ------- | ---------------------- |
| `SB_HEALTH_ENABLE` | bool | `1`     | Enable health endpoint |

### Tracing

| Variable            | Type   | Default   | Description                |
| ------------------- | ------ | --------- | -------------------------- |
| `SB_TRACING_FORMAT` | string | `compact` | Tracing format             |
| `SB_TRACE_ID`       | string | -         | Fixed trace ID for testing |

---

## GeoIP & GeoSite

| Variable          | Type   | Default | Description         |
| ----------------- | ------ | ------- | ------------------- |
| `SB_GEOIP_ENABLE` | bool   | `0`     | Enable GeoIP lookup |
| `SB_GEOIP_MMDB`   | string | -       | MaxMind DB path     |
| `SB_GEOIP_CACHE`  | int    | `1024`  | GeoIP cache size    |
| `SB_GEOIP_TTL`    | int    | `3600`  | GeoIP cache TTL     |

---

## Development & Testing

### Testing

| Variable             | Type   | Default | Description              |
| -------------------- | ------ | ------- | ------------------------ |
| `SB_TEST_FORCE_ECHO` | bool   | `0`     | Force echo mode in tests |
| `SB_TEST_ECHO_GLUE`  | string | -       | Echo glue address        |

### Benchmarking

| Variable            | Type   | Default | Description            |
| ------------------- | ------ | ------- | ---------------------- |
| `SB_BENCH`          | bool   | `0`     | Enable benchmarking    |
| `SB_BENCH_N`        | int    | `1000`  | Number of requests     |
| `SB_BENCH_PAR`      | int    | `10`    | Parallel requests      |
| `SB_BENCH_RUNS`     | int    | `1`     | Benchmark runs         |
| `SB_BENCH_TCP`      | string | -       | TCP benchmark address  |
| `SB_BENCH_UDP`      | string | -       | UDP benchmark address  |
| `SB_BENCH_DNS`      | string | -       | DNS benchmark server   |
| `SB_BENCH_DNS_NAME` | string | -       | DNS benchmark domain   |
| `SB_BENCH_PAYLOAD`  | int    | `1024`  | Benchmark payload size |
| `SB_BENCH_CSV`      | string | -       | Benchmark CSV output   |

### Profiling

| Variable           | Type | Default | Description              |
| ------------------ | ---- | ------- | ------------------------ |
| `SB_PPROF`         | bool | `0`     | Enable pprof (set to `1` when `experimental.debug.listen` is provided) |
| `SB_PPROF_FREQ`    | int  | `100`   | Profiling frequency (Hz), auto-set when `experimental.debug.listen` is provided |
| `SB_PPROF_MAX_SEC` | int  | `60`    | Max profiling duration, auto-set when `experimental.debug.listen` is provided |
| `SB_DEBUG_ADDR`    | string | -     | Debug/pprof server address (populated from `experimental.debug.listen` when present) |

### Coverage & Debugging

| Variable           | Type   | Default | Description                   |
| ------------------ | ------ | ------- | ----------------------------- |
| `SB_COV_ADDR`      | string | -       | Coverage server address       |
| `SB_DEBUG_ADDR`    | string | -       | Debug server address          |
| `SB_RULE_COVERAGE` | bool   | `0`     | Enable rule coverage tracking |
| `SB_RUNTIME_DIFF`  | bool   | `0`     | Enable runtime diff           |

### DSL & Explain

| Variable                | Type   | Default | Description              |
| ----------------------- | ------ | ------- | ------------------------ |
| `SB_DSL_PLUS`           | string | -       | DSL+ rules file          |
| `SB_EXPLAIN_REBUILD_MS` | int    | -       | Explain rebuild interval |

### NTP

| Variable            | Type   | Default               | Description       |
| ------------------- | ------ | --------------------- | ----------------- |
| `SB_NTP_SERVER`     | string | `time.google.com:123` | NTP server        |
| `SB_NTP_INTERVAL_S` | int    | `1800`                | NTP sync interval |
| `SB_NTP_TIMEOUT_MS` | int    | `5000`                | NTP timeout       |

### Build Info

| Variable     | Type   | Default | Description                 |
| ------------ | ------ | ------- | --------------------------- |
| `SB_GIT_SHA` | string | -       | Git commit SHA (build time) |
| `SB_CLI_BIN` | string | -       | CLI binary path             |

### Guards

| Variable      | Type   | Default | Description                    |
| ------------- | ------ | ------- | ------------------------------ |
| `SB_GA_GUARD` | bool   | `0`     | Enable genetic algorithm guard |
| `SB_HUP_PATH` | string | -       | HUP signal file path           |

---

## Usage Examples

### Enable DNS with DoH

```bash
SB_DNS_ENABLE=1 \
SB_DNS_MODE=doh \
SB_DNS_DOH_URL=https://1.1.1.1/dns-query \
SB_DNS_IPV6=1 \
singbox-rust run -c config.yaml
```

### Enable Admin API with Auth

```bash
SB_ADMIN_URL=127.0.0.1:18088 \
SB_ADMIN_TOKEN=your-secret-token \
SB_ADMIN_RATE_LIMIT_ENABLED=1 \
SB_ADMIN_RATE_LIMIT_MAX=100 \
singbox-rust run -c config.yaml
```

### UDP with SOCKS5 Proxy

```bash
SB_UDP_PROXY_MODE=socks5 \
SB_UDP_SOCKS5_ADDR=127.0.0.1:1080 \
SB_UDP_NAT_MAX=10000 \
singbox-rust run -c config.yaml
```

### Enable Prefetch

```bash
SB_PREFETCH_ENABLE=1 \
SB_PREFETCH_CAP=256 \
SB_PREFETCH_WORKERS=4 \
singbox-rust run -c config.yaml
```

### Debug Mode with Full Logging

```bash
RUST_LOG=debug \
SB_PRINT_ENV=1 \
SB_LOG_FORMAT=json \
singbox-rust run -c config.yaml
```

---

## Notes

### Boolean Values

Boolean environment variables accept:

- **True**: `1`, `true`, `TRUE`, `yes`, `YES`, `on`, `ON`
- **False**: `0`, `false`, `FALSE`, `no`, `NO`, `off`, `OFF`, empty string

### Integer Values

Integer variables use default values if parsing fails. Invalid values are logged and ignored.

### Duration Values

Duration variables accept:

- Milliseconds: Variables ending in `_MS`
- Seconds: Variables ending in `_S` or `_SEC`
- Minutes: Variables ending in `_M` or `_MIN`

### Path Values

Path variables support:

- Absolute paths: `/path/to/file`
- Relative paths: `./config/file` (relative to working directory)
- Home expansion: `~/file` expands to user home directory

### List Values

List variables (comma-separated):

```bash
SB_DNS_POOL="system,udp:8.8.8.8:53,doh:https://1.1.1.1/dns-query"
```

---

## Validation

Test your environment variable configuration:

```bash
# Print all environment variables at startup
SB_PRINT_ENV=1 singbox-rust run -c config.yaml

# Validate configuration with env overrides
singbox-rust check -c config.yaml
```

---

## Related Documentation

- [CLI Reference](README.md) - Command-line interface
- [Configuration Guide](../01-user-guide/configuration/overview.md) - Configuration file reference
- [Operations Guide](../03-operations/) - Production deployment

---

**Auto-generated from source code analysis**  
**Last Updated**: 2025-11-23  
**Total Variables**: 271+

> ⚠️ **Note**: This list is automatically discovered from the codebase. Some variables may be experimental or deprecated. Refer to the source code for definitive behavior.
