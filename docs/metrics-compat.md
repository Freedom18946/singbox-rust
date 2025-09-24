# Metrics Compatibility (M1)

This crate exposes a minimal, stable set of counters and gauges intended for dashboards and alerting. All new paths are behind env/features and disabled by default. Building with `--features metrics` enables metrics collection.

## 指标字典 v1（最小可用集合）

> 约定：所有指标 behind `--features metrics`。Exporter 在 app 层按 `SB_METRICS_ADDR=host:port` 显式启用。

### 1. 入站
- `inbound_connections_total{protocol="http|socks", network="tcp|udp"}` 连接/会话数
- `inbound_error_total{proto="http|socks", class="reject|bad_method|parse|io|..."}`
- `http_respond_total{code="400|403|405|..."}`

### 2. 出站
- `outbound_connect_total{kind="direct|http|socks5|tls", phase="tcp_connect|proxy_handshake|tls_handshake", result="ok|err", class?="timeout|refused|reset|..."}`
- `outbound_connect_seconds_bucket{kind, phase, le="..."}`（阶段化直方图）
- `outbound_error_total{kind, phase, class}`（错误次数）
- `outbound_bytes_{in,out}_total{kind="direct|http|socks5"}`（若启用 metered 包装）

### 3. DNS
- `dns_query_total{backend="system|udp|dot|doh", qtype="a|aaaa|auto"}`
- `dns_rtt_seconds_bucket{backend,qtype}`
- `dns_error_total{backend,qtype,class}`
- `dns_cache_size`（gauge）
- `dns_cache_evict_total`
- `dns_cache_hit_total{kind="pos|neg|stale|miss|coalesced"}`
说明：
- `stale`：命中"过期但在 `SB_DNS_CACHE_STALE_MS` 窗口内"；同步返回旧值，后台刷新
- `coalesced`：并发合并的跟随请求
- `dns_inflight{scope="global|per_host"}`（若启并发闸门）
- `dns_resolve_error_total{code="timeout|blackhole|..."}`

### 4. UDP（SOCKS/直连统一口径）
- `udp_nat_size`（gauge）：当前 NAT 表会话数量
- `udp_nat_evicted_total`：TTL/GC 清理累计
- `udp_pkts_in_total` / `udp_pkts_out_total`：入/出方向报文数
- `udp_bytes_in_total` / `udp_bytes_out_total`：入/出方向字节数

### UDP（新实现指标）
- `udp_pkts_in_total` / `udp_pkts_out_total`
- `udp_bytes_in_total` / `udp_bytes_out_total`
- `udp_nat_size`（gauge）
- `udp_nat_evicted_total`
- `udp_nat_reject_total{reason="capacity"}`
- `udp_upstream_size`（gauge）
- `udp_upstream_evict_total`
- `udp_upstream_pkts_in_total` / `udp_upstream_pkts_out_total`
- `udp_upstream_bytes_in_total` / `udp_upstream_bytes_out_total`
- `udp_upstream_error_total{class="associate|capacity|select|send|recv|dst_unsupported"}`
- `socks_udp_error_total{class="bad_header|reject|nat_full|send_fail|return_fail|bad_addr|up_send_fail|up_select_none|proxy_kind_unsupported|up_dst_unsupported"}`

示例抓取（curl /metrics）：
```
udp_nat_size 3
udp_pkts_in_total 150
udp_pkts_out_total 150
udp_bytes_in_total 12000
udp_bytes_out_total 11800
```

#### 建议直方图桶（seconds）
- 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10

#### 聚合示例（PromQL）
- P50/P90 TCP 连接耗时（按 kind）：
  - `histogram_quantile(0.5, sum by (le,kind) (rate(outbound_connect_seconds_bucket{phase="tcp_connect"}[5m])))`
  - `histogram_quantile(0.9, sum by (le,kind) (rate(outbound_connect_seconds_bucket{phase="tcp_connect"}[5m])))`
- 代理握手失败率（按 kind/class）：
  - `sum by (kind,class) (increase(outbound_error_total{phase="proxy_handshake"}[15m]))`
- TLS 握手成功率（5分钟）：
  - `sum(increase(outbound_connect_total{kind="tls",phase="tls_handshake",result="ok"}[5m])) / sum(increase(outbound_connect_total{kind="tls",phase="tls_handshake"}[5m]))`
- TLS 握手P95耗时：
  - `histogram_quantile(0.95, sum by (le) (rate(outbound_connect_seconds_bucket{kind="tls",phase="tls_handshake"}[5m])))`

### 使用建议
- **endpoint label** 使用"`<池名>#<序号>`"，例如 `up#1`；禁止暴露原始地址，以降低基数并避免隐私泄露。
- **label 冻结**：v1 允许集见 `docs/metrics-labels-allowlist.json`，CI 可通过 `SB_VALIDATE_LABELS=1` 开启巡检。
- **兼容性承诺**：v1 指标名与 label key 集**不得修改**；如需新增维度，请新增**新指标**，而不是改旧指标的 label。
- 避免 host/domain 作为 label，防止指标基数爆炸；
- 建议用 Grafana 面板聚合展示 TCP/UDP 字节与包计数增长速率；
- 对 DNS 解析耗时（`dns_rtt_seconds_bucket{backend}`）做 P50/P90 趋势图，辅以 `dns_query_total{backend}`。

示例 PromQL：
```
histogram_quantile(0.9, sum by (le,backend) (rate(dns_rtt_seconds_bucket[5m])))
sum by (backend,class) (increase(dns_error_total[15m]))
```

### 说明
- TLS 握手建议 **单独看**，避免与代理握手混淆；
- 错误分类 `class` 复用 `telemetry/error_class.rs`，包括 `timeout|refused|tls_cert|tls_verify|handshake|...`

> 备注：label **不使用 host/domain**，避免高基数；错误类目统一映射在 `sb_core::telemetry` 与各模块内部。

## HTTP

- http_requests_total{method, code}: total requests by method and status code
  - method="CONNECT", code="200" for successful tunnel establishment
  - method!=CONNECT, code="405" for non-CONNECT methods
  - method="_parse_error", code="400" when request line parsing fails

## UDP

- udp_packets_out_total: number of UDP packets sent
- udp_bytes_out_total: total bytes sent over UDP
- udp_bytes_in_total: total bytes received over UDP
- udp_nat_size: current NAT association size (gauged periodically)
- inbound_error_total{proto="socks_udp", class}: inbound error classes
  - class ∈ {"parse","send","io","reject","capacity"}
- router_decide_total{proto="udp", decision}: UDP routing decisions
  - decision ∈ {"direct","proxy","reject"}
- outbound_drop_total{kind="udp", reason}: outbound drops
  - reason ∈ {"bps","pps","limit"} (limit used by current rate limiter)
- balancer_select_total{algo,mode}: upstream selection decisions for UDP proxy
  - algo ∈ {"rr","random","hash"}; mode ∈ {"single","pool"}
- outbound_error_total{kind="udp", class}: UDP outbound errors
  - class ∈ {"no_upstream","connect","send","recv"}
 - balancer_upstreams{upstream,state,degraded}: 1 for up, 0 for down; degraded indicates all-down selection
 - balancer_failures_total{upstream,reason}: failure counters per upstream and reason
 - udp_nat_reject_total{reason}: NAT association rejects, reason includes "capacity"

Notes:
- Counters follow additive semantics and are cheap to emit.
- Gauges are updated at a low cadence to avoid contention.

## PromQL Examples

- HTTP CONNECT success rate (5m):
  sum by () (increase(http_requests_total{method="CONNECT",code="200"}[5m]))
/
  sum by () (increase(http_requests_total{method="CONNECT"}[5m]))

- UDP router decision mix (1h):
  sum by (decision) (increase(router_decide_total{proto="udp"}[1h]))

- UDP NAT current size:
  avg_over_time(udp_nat_size[5m])

## DNS

- dns_query_total{hit,family,source,rcode}: DNS queries outcome
  - hit ∈ {"hit","miss"}; family ∈ {"A","AAAA","ANY"}; source ∈ {"static","system"}; rcode ∈ {"ok","nxdomain","nodata","error"}
- dns_error_total{class}: DNS errors by class
  - class ∈ {"timeout","resolve","empty"}
- dns_cache_size: current cache size (gauge)
- dns_cache_evictions_total: total cache evictions (counter)
- dns_upstream_select_total{strategy,upstream,kind}: upstream selection counters
- dns_query_latency_ms (histogram){upstream,kind}: query latency by upstream
- dns_pool_errors_total{upstream,reason}: pool/query errors by upstream
  - For DoH/DoT, reasons may include: `timeout|io|format|tls|handshake`
- dns_prefetch_total{reason}: prefetch actions (hit_stale|spawn|skip)
- dns_upstream_state{upstream,kind,state}: 1 for up, 0 for down (gauge)
- dns_pool_degraded_total{strategy,reason}: degraded pool events (e.g., all_down)
 
### DNS 指标（R16 补充）
- dns_timeout_total{kind=connect|read|write|resolve} —— 分类超时计数（可选接入）
- dns_blackhole_total —— 黑洞判定计数（上游不响应）
- dns_resolve_error_total{code} —— 解析失败计数（格式/拒绝/不存在等）
- dns_inflight{scope=global|host:example.com} —— 并发 gauge（已有的可沿用；此处口径统一）
 
## Router

- `router_decide_latency_ms_bucket`: decision latency (ms) histogram
  - Buckets: **Fibonacci** 0.5,1,2,3,5,8,13,21,34,55,89 (ms)
- `router_degrade_total{reason}`: decision degrade counters
  - `reason="budget"` **仅在"未定 → 默认"** 时增加一次；若规则已命中（exact/suffix/IP/GeoIP），**不计**预算降级
- `router_rules_invalid_total{reason}`: invalid/overflow rule counters at parse time
  - `reason ∈ {overflow, dup_exact, dup_suffix, dup_default, dup_port, bad_port, bad_transport, bad_portrange, bad_portset, empty_host, empty_decision, bad_geoip, invalid_cidr, invalid_char, unknown_kind, io}`
- `router_rules_include_total{result}`: include directive processing counters
  - `result ∈ {"success","error","cycle"}`; cycle indicates include cycle detection
- `router_rules_reload_total{result}`: 热重载结果计数
  - `result ∈ {"success","error","noop"}`；失败不切换旧索引；noop 表示内容无变化跳过重载
- `router_rules_footprint_bytes`: 估算的索引内存占用字节数（gauge）
- `router_rules_shadowed_total{kind}`: 规则遮蔽提示计数
  - `kind="exact_over_suffix"` 表示 exact 规则被 suffix 规则覆盖
- `router_rules_size{kind}`: 规则规模（gauge）
  - `kind ∈ {"exact","suffix","port","portset","transport","cidr4","cidr6","geoip"}`
- `router_rules_generation`: 当前激活索引的构建代号（gauge，单调递增）
- `router_rules_build_ms_bucket` / `router_rules_reload_ms_bucket`: 构建与热重载耗时（ms）直方图
- `router_dns_resolve_total{rcode}`: DNS 解析计数（只在 Router 决策链路使用时计）
  - `rcode ∈ {"ok","miss","error","timeout"}`
- `router_dns_resolve_ms_bucket`: DNS 解析耗时（ms）直方图
- `router_decision_cache_total{result}`: 决策缓存计数
  - `result ∈ {"hit","miss","invalidate"}`
- `router_decide_reason_total{kind}`: 按原因分解的决策计数
  - `kind ∈ {"cache","exact","suffix","ip","dns_ip","dns_geoip","port","portrange","transport","override","override_default","default"}`
- `router_json_bridge_errors_total{kind}`: JSON 桥接错误计数
  - `kind ∈ {"json_parse","unknown_rule_type","bad_ip_cidr","bad_port"}`
- `geoip_lookup_total{provider,rcode}`: GeoIP lookups; provider ∈ {`cidr`,`mmdb`}, rcode ∈ {`ok`,`miss`,`error`}
  - 错误细分：`error_io|error_format|error_not_found`

### Admin 输出（R14/R18/R22/R26）
- 输出仅用于排障与观测，保持“只读、默认关闭”。生产暴露请加 ACL/内网限制。
- cache 摘要不含明文键；推荐仅暴露 size/capacity/hit_ratio 等聚合字段（若后续接线）。
- analyze 输出建议在 CI/变更评审中使用（配合 `rules_tool` 生成可执行补丁）。
 - 在线补丁导出仅生成文本补丁；服务端不修改文件，无副作用。

PromQL examples:

- DNS success ratio (5m):
  sum by () (increase(dns_query_total{rcode="ok"}[5m])) / sum by () (increase(dns_query_total[5m]))
- DNS cache hit rate (1h):
  sum by () (increase(dns_cache_hit_total[1h])) / sum by () (increase(dns_query_total[1h]))
- DNS inflight 上下限观测（15m）：
  max_over_time(dns_inflight{scope="global"}[15m]) by ()
  , min_over_time(dns_inflight{scope="global"}[15m]) by ()

## NAT
- `nat_capacity_reject_total`：容量触顶拒绝次数
- `nat_entries_gauge`：当前 NAT 表条目数
- `nat_purge_total`：TTL 过期清理条数

### PromQL Examples
- 1h 拒绝率：increase(nat_capacity_reject_total[1h]) / (increase(nat_capacity_reject_total[1h]) + increase(nat_put_total[1h]))
- DNS by family and rcode (5m):
  sum by (family, rcode) (rate(dns_query_total[5m]))
 - DNS upstream p95 latency (5m):
   histogram_quantile(0.95, sum by (le) (rate(dns_query_latency_ms_bucket[5m])))
 - DNS pool errors by upstream (1h):
   sum by (upstream,reason) (increase(dns_pool_errors_total[1h]))
- Router inflight DNS gauges by scope:
  sum by (scope) (dns_inflight)
- Router p95 decision latency (5m):
  histogram_quantile(0.95, sum(rate(router_decide_latency_ms_bucket[5m])) by (le))
- Router degrade rate (15m):
  increase(router_degrade_total{reason="budget"}[15m])
- Router reload success rate (1h):
  sum(increase(router_rules_reload_total{result="success"}[1h]))
  /
  sum(increase(router_rules_reload_total[1h]))
- Router rules size trend (1h):
  max_over_time(router_rules_size[1h]) by (kind)
- Router generation (last):
  last_over_time(router_rules_generation[1h])
- Router DNS error rate (15m):
  sum(increase(router_dns_resolve_total{rcode=~"error|timeout"}[15m]))
  /
  sum(increase(router_dns_resolve_total[15m]))
- Router decision cache hit ratio (5m):
  sum(increase(router_decision_cache_total{result="hit"}[5m]))
  /
  sum(increase(router_decision_cache_total{result=~"hit|miss"}[5m]))
- Router decision reason mix (5m):
  sum by (kind) (increase(router_decide_reason_total[5m]))
- GeoIP 错误分布（1h）：
  sum by (rcode) (increase(geoip_lookup_total{provider="cidr"}[1h]))

## Proxy Health

- `proxy_up{kind="http|socks5"}` (gauge): 0/1 indicating proxy health status
- `proxy_check_total{kind="http|socks5", result="ok|fail"}`: Health check attempt counters
- `proxy_rtt_seconds_bucket{kind="http|socks5"}`: Health check response time histogram
- `router_route_fallback_total{from="proxy", to="direct", inbound="http|socks5"}`: Fallback event counters when proxy is unhealthy

### Proxy Selection P2 Metrics (optional, behind env)

- `proxy_select_total{pool,endpoint}`: Cumulative proxy selection counter per pool and endpoint
- `proxy_select_score{pool,endpoint}` (gauge): Current selection score for each endpoint
- `proxy_endpoint_rtt_ms{pool,endpoint}` (gauge): EMA RTT in milliseconds per endpoint
- `proxy_endpoint_halfopen_tokens{pool,endpoint}` (gauge): Current half-open circuit breaker tokens per endpoint

PromQL examples:
- Proxy uptime (5m):
  avg_over_time(proxy_up[5m]) by (kind)
- Proxy health check success rate (15m):
  sum(increase(proxy_check_total{result="ok"}[15m])) by (kind)
  /
  sum(increase(proxy_check_total[15m])) by (kind)
- Proxy health check P95 latency (5m):
  histogram_quantile(0.95, sum(rate(proxy_rtt_seconds_bucket[5m])) by (le, kind))
- Fallback rate (1h):
  sum(increase(router_route_fallback_total[1h])) by (inbound)
- Proxy selection distribution (1h):
  sum(increase(proxy_select_total[1h])) by (pool, endpoint)
- Proxy selection score distribution:
  avg(proxy_select_score) by (pool, endpoint)
- Proxy RTT tracking (5m):
  avg_over_time(proxy_endpoint_rtt_ms[5m]) by (pool, endpoint)

## R5/R6 新增特性

### R5 新增指标
- `router_rules_invalid_total{reason=bad_var_name|unknown_var|missing_default}` —— 规则构建期错误计数
- `router_rules_include_total{result=glob_success|glob_empty|glob_error}` —— include_glob 扩展结果
- `router_rules_reload_backoff_ms` —— 当前热重载退避毫秒（gauge）
- `router_rules_invalid_total{reason=include_depth_exceeded}` —— include_glob 深度超限
- （可选）在 CI/离线工具中读取 analyze 报告，统计遮蔽/冲突类型数量

### Bench 关注点（R11）
- 构建大规模 suffix/exact 表的 P50/P95 构建耗时对比
- strict on/off 差异（若启用严格后缀） —— 建议自定义规则集在本地 bench
- `criterion` 跑法：`cargo bench -p sb-core`
