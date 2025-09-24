# DNS Pool Examples

This example shows how to enable the DNS resolver pool with mixed upstreams. All features are disabled by default; enable only what you need.

Quick start (race strategy, A-first, with prefetch):

```
SB_ROUTER_DNS=1
SB_DNS_ENABLE=1
SB_DNS_POOL="system,udp:127.0.0.1:1053,doh:https://dns.example/dns-query,dot:1.1.1.1:853"
SB_DNS_POOL_STRATEGY=race
SB_DNS_HE_ORDER=A_FIRST
SB_DNS_HE_RACE_MS=30
SB_DNS_RACE_WINDOW_MS=50
SB_DNS_PREFETCH=1
SB_DNS_PREFETCH_BEFORE_MS=200
SB_DNS_PREFETCH_CONCURRENCY=4
```

Notes:
- Default path remains system-only unless `SB_DNS_ENABLE=1` and `SB_DNS_POOL` are set.
- Labels are normalized to keep cardinality bounded: `system`, `udp://ip:port`, `doh://host[:port]`, `dot://host[:port]`.
- For DoH/DoT in tests, you may need to accept local/self-signed certificates; never use insecure modes in production.

