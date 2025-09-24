## 编译与特性矩阵（R96–R99）

All features are disabled by default to avoid breaking existing deployments. Enable only what you need.

### CLI 子命令
- `singbox-rust check -c <file> [--format json|human] [--strict] [--schema] [--schema-dump] [--check-refs] [--max-ref-size N] [--fingerprint]`
  - **目标**：仅解析配置，不触 IO；输出结构化错误（JSON Pointer）与人类可读摘要。
  - **退出码**：0=通过；1=存在错误（`--strict` 下 warning 也算错误）。
  - `--schema`：启用 v1 JSON-Schema 校验（需 `--features check-schema` 编译）
  - `--schema-dump`：打印 v1 Schema 并退出（用于外部工具/审阅）
  - `--check-refs`：校验引用文件存在/可读/大小上限（仅本地文件）
  - `--max-ref-size`：引用文件大小上限，默认 262144（256 KiB）
  - `--fingerprint`：输出配置的 SHA256 指纹和规范化 JSON（用于配置变更检测）

### Bench 工具（`sb-bench`）
- `SB_BENCH=1`：显式开启基准工具（缺省拒绝运行以避免误触）。
- `SB_BENCH_N`：每项测试的迭代次数（默认 `200`，自动忽略非正整数）；兼容旧的 `SB_BENCH_RUNS`。
- `SB_BENCH_TCP` / `SB_BENCH_UDP` / `SB_BENCH_DNS`：覆盖各自目标地址，默认 `127.0.0.1:7` / `127.0.0.1:9099` / `127.0.0.1:53`。
- `SB_BENCH_DNS_NAME`：DNS 查询的 FQDN（默认 `example.com.`）。

### 场景运行
- `SB_PREFLIGHT_CHECK=1`：在启动前对 `runtime.yaml` 执行 `check` 并写入报告；`ok=false` 将导致退出（硬 gate）
- `SB_PREFLIGHT_SCHEMA=1` / `SB_PREFLIGHT_REFS=1`：为预检附加 Schema/引用检查
- `SB_FAILFAST=1`：等价 `SB_SCENARIO_GATES=strict-failfast`
- `PROFILE=release`：只跑发布前护栏（校验 + 冒烟 + 资源阈值）
- `SB_E2E_CHECK_CIDR_BAD=1`：启用 CIDR/域名格式负例测试
- `SB_PROC_SAMPLE_SEC`：进程资源采样间隔（秒）。默认 1；设置为 0 仅采样一次。
- `SB_PROC_PCTL`：资源分位数（默认 95）。仅在存在时序采样(`SB_PROC_SAMPLE_SEC>0`)时生效。
- `SB_FP_BASE=sha256:<hex>`：配置指纹基线；与预检指纹不一致时，在 strict/strict-failfast 模式 gate 失败；loose 模式仅记录。

### R136-R142 最新更新的 Admin 端点

- `/subs/preview_route_batch` - 批量预演路由，支持 B64 JSON 目标集，限制最多256个目标
- `/subs/merge` - 支持 `cache=1` 参数，返回 Provider 缓存统计（命中/未命中数）
- `/router/explain` - 在 meta 中添加 `cache` 字段显示缓存命中状态（"hit" | "miss"）
- `/trojan/dryrun` - 增强报告，meta 中包含 `kind`（"hello" | "tls_first"），支持 TLS 模式

### SS2022 和 Trojan 协议增强

- SS2022 核心离线构件：`proto_ss2022_core` 特性，提供统一字节布局
- Trojan 干运行报告：`proto_trojan_dry` 特性，统一报告格式和构造逻辑
- Router 缓存观测：`router_cache_explain` 特性，在 Explain 中显示缓存命中状态

## SOCKS/UDP

- SB_SOCKS_UDP_ENABLE: enable SOCKS5 UDP service when set to `1`/`true`.
- SB_SOCKS_UDP_LISTEN: comma or space separated UDP listen addresses, e.g. `0.0.0.0:11080, [::]:11080`.
- SB_SOCKS_UDP_BIND: optional local bind for upstream UDP sockets.
- SB_SOCKS_UDP_NAT_TTL_MS: optional NAT TTL (milliseconds). When set, NAT entries are purged periodically.

### SOCKS5 UDP（运行态）

- `SB_SOCKS_UDP_ENABLE`: `1` 启用运行态 UDP 服务（默认 `0`）
- `SB_SOCKS_UDP_LISTEN`: 监听地址列表，如 `127.0.0.1:11080` 或 `127.0.0.1:11080,::1:11080`
  - 运行态会以列表**首个地址**作为 `UDP ASSOCIATE` 的回包 `BND.ADDR`；必须与监听实际一致。
- `SB_UDP_NAT_MAX`: NAT 表最大会话数（默认内部值，详见 `sb-core/src/net/datagram.rs`）

### 新增特性环境变量

- `SB_PROM_OFF=1`：关闭 PROM 断言解析（默认开启，若未开启 /metrics 则自动降级为 note）。
- `SB_SCHEMA_V2=1`：构建时开启 `schema-v2` 特性（也可用 cargo features 控制）。
- `SB_SOCKS_UDP_NAT_TTL_MS`: NAT 会话空闲 TTL（毫秒；默认内部值）；开启 TTL 时会后台周期清理。

### SOCKS5 UDP（新实现）
- `SB_SOCKS_UDP_ENABLE=1`：启用 SOCKS5 UDP 服务（默认关闭）
- `SB_SOCKS_UDP_LISTEN="127.0.0.1:11080[,::1:11080]"`：监听地址（逗号分隔）
- `SB_SOCKS_UDP_NAT_TTL_MS=30000`：NAT 空闲 TTL（毫秒）
- `SB_UDP_NAT_MAX=65536`：NAT 容量上限（>0 启用；满载拒绝）
- `SB_SOCKS_UDP_UP_TTL_MS=30000`：上游 SOCKS5 UDP 会话 TTL（毫秒；默认等于 NAT TTL）
- `SB_SOCKS_UDP_PROXY_TIMEOUT_MS=800`：上游 UDP Associate/回包短超时（毫秒）
- `SB_SOCKS_UDP_PROXY_FALLBACK_DIRECT=1`：上游不可用时回落 Direct（默认开启，关闭则直接丢弃）
- `SB_UDP_NAT_TTL`：UDP NAT 映射的 TTL（默认 30s）。
- `SB_UDP_NAT_MAX`：UDP NAT 最大容量（默认 4096）。
- `SB_DNS_ENABLE`：启用内置 DNS 客户端与缓存（默认关闭）。
- `SB_DNS_MIN_TTL` / `SB_DNS_MAX_TTL`：DNS TTL 钳制（默认 5s / 600s），用于正/负缓存。
- `SB_UDP_UPSTREAM_MAX`：上游会话容量上限（超过即拒绝新建；默认不限）
- `SB_SOCKS_UDP_UP_RECV_TASK=1`：开启每会话独立收包协程（默认 0）。开启后 `recv_once()` 从队列取包，降低窗口丢包概率。
- `SB_SOCKS_UDP_UP_RECV_CH=256`：协程收包队列容量（1~16384，默认 256）。
- `SB_SOCKS_UDP_RESOLVE_BND=1`：允许解析 ASSOC 回复中的域名 BND（默认 0）。启用后对 `ATYP=DOMAIN` 使用系统解析；失败仍回落 loopback。
> 仅当路由判定为 `proxy(:name?)` 且选中 **SOCKS5** 上游时才会透传；HTTP 上游会按 `SB_SOCKS_UDP_PROXY_FALLBACK_DIRECT` 选择回落或丢弃。

## Router (behind env; disabled by default)

- SB_ROUTER_UDP: enable UDP routing when `1`.
- SB_ROUTER_UDP_RULES: rules string; supports `exact:...=...`, `suffix:...=...`, and `default=...` decisions.
  - decision ∈ {`direct`,`proxy`,`reject`}
  - example: `exact:example.com=proxy,suffix:.internal=reject,default=direct`

### Router Rules（运行态切换）
- `SB_ROUTER_RULES_ENABLE=1`：启用**文本/文件**规则（`SB_ROUTER_RULES_FILE` / `SB_ROUTER_RULES_TEXT`）
- **Phase 2（本轮新增）**：JSON 桥接（默认关闭）
  - `SB_ROUTER_RULES_FROM_JSON=1`：启用 JSON→规则引擎
  - `SB_ROUTER_JSON_FILE=/path/to/router.json` 或 `SB_ROUTER_JSON_TEXT='{"rules":[...]}'`
  - 生效原则：**谁先安装谁生效**（JSON/文本互斥，不混合）

### Router Default Proxy（ENV 桥接）
- `SB_ROUTER_DEFAULT_PROXY`：
  - `direct`（默认）
  - `http://host:port`
  - `socks5://host:port`
- 或：
  - `SB_ROUTER_DEFAULT_PROXY_KIND=http|socks5|direct`
  - `SB_ROUTER_DEFAULT_PROXY_ADDR=host:port`

### Proxy Health Check（默认关闭）
- `SB_PROXY_HEALTH_ENABLE=1`：启用周期健康检查（仅对默认代理生效）
- `SB_PROXY_HEALTH_INTERVAL_MS=3000`：健康检查周期（毫秒）
- `SB_PROXY_HEALTH_TIMEOUT_MS=800`：单次健康检查超时（毫秒）
- `SB_PROXY_HEALTH_FALLBACK_DIRECT=1`：当代理不健康时，路由判定为 Proxy 的流量**自动回落 Direct**
> 行为安全：不开此开关，路由不改；开启后也只会"降级为直连"，不破坏用户空间。

### Named Proxy Pool v1（多代理池 / 加权选择 / 粘滞亲和 / 健康熔断联动）
- `SB_PROXY_POOL_JSON`：内联 JSON 配置代理池，格式见下方示例
- `SB_PROXY_POOL_FILE`：代理池 JSON 配置文件路径
- `SB_PROXY_STICKY_TTL_MS=10000`：粘滞亲和 TTL（毫秒，按 client_ip+target 缓存选择结果）
- `SB_PROXY_STICKY_CAP=4096`：粘滞亲和缓存容量（条目数）

#### 代理池 JSON 格式示例
```json
[
  {
    "name": "poolA",
    "policy": "weighted_rr",
    "sticky_ttl_ms": 10000,
    "sticky_cap": 4096,
    "endpoints": [
      {
        "kind": "http",
        "addr": "proxy1.example.com:8080",
        "weight": 3,
        "max_fail": 3,
        "open_ms": 5000,
        "half_open_ms": 1000
      },
      {
        "kind": "socks5",
        "addr": "proxy2.example.com:1080",
        "weight": 1,
        "max_fail": 3,
        "open_ms": 5000,
        "half_open_ms": 1000
      }
    ]
  }
]
```

> 路由语法：使用 `proxy:poolA` 指向命名代理池，`proxy` 仍走默认代理。池不存在或全熔断时按健康回退开关处理。

### Router Rules 2.0 (compiled index; file+env)

- SB_ROUTER_RULES: additional rules appended after file rules; DSL supports
  - `exact:host=decision`, `suffix:.tail=decision`, `port:443=decision`, `portset:80,443,8443=decision`, `portrange:1000-2000=decision`, `transport:tcp=decision`, `cidr4:x.x.x.x/len=decision`, `cidr6:xxxx::/len=decision`, `geoip:CC=decision`, and `default=decision`.
- SB_ROUTER_RULES_FILE: rules file path; one rule per line; allows `#` comments and empty lines.
  - File rules are loaded first; `SB_ROUTER_RULES` is applied as an incremental append.
  - Supports `include path/to/file.rules` and `@include path/to/file.rules` directives for recursive file inclusion.
- SB_ROUTER_RULES_HOT_RELOAD_MS: when >0, periodically checks file mtime and hot-swaps the compiled index on change. Default: `0` (off).
- SB_ROUTER_RULES_MAX: maximum number of parsed rules from sources. Default: `8192`. Overflow rules are ignored and counted.
- SB_ROUTER_RULES_INCLUDE_DEPTH: maximum include depth for recursive file inclusion. Default: `4`.

Common pitfalls (lint logged at parse time):
- Duplicate `exact` rules for the same host: last-wins; deduped; reported as `dup_exact`.
- `suffix` starting with a leading dot: allowed; normalized (logged as hint).
- `geoip` country codes must be two-letter uppercase (ISO-3166-1 alpha-2). Invalid entries are ignored and counted as `bad_geoip`.
- Empty host or invalid CIDR will be ignored and counted as `empty_host` / `invalid_cidr` respectively.

## DNS (behind env; disabled by default)

- SB_DNS_ENABLE=1: enable DNS subsystem for resolvers and metrics (default: 0)
- SB_DNS_CACHE_SIZE: LRU capacity (default: 1024)
- SB_DNS_MIN_TTL_S: minimum TTL clamp in seconds (default: 1)
- SB_DNS_MAX_TTL_S: maximum TTL clamp in seconds (default: 600)
- SB_DNS_NEG_TTL_S: negative-cache TTL in seconds (default: 30)
- SB_DNS_DEFAULT_TTL_S: default TTL when system resolver returns none (default: 60)
- SB_DNS_STATIC: static mapping table before system lookup. Format: `example.com=1.2.3.4;::1,foo.local=10.0.0.1`
- SB_DNS_STATIC_TTL_S: TTL for static entries (default: 300)
- SB_DNS_TIMEOUT_MS: on-demand resolve timeout for router path (default: 300)
- SB_DNS_IPV6: include IPv6 results (default: 1)

### DNS Resolver Pool (behind env)

- SB_DNS_POOL: comma-separated upstreams, e.g. `system,udp:127.0.0.1:1053,udp:127.0.0.1:2053`
- DoH/DoT examples: `doh:https://resolver.example/dns-query`, `dot:1.1.1.1:853` (features `dns_doh`/`dns_dot` must be enabled)
- SB_DNS_POOL_STRATEGY: `race|sequential|fanout` (default: `race`)
- SB_DNS_RACE_WINDOW_MS: per-upstream race staggering window (default: 50)
- SB_DNS_HE_ORDER: `A_FIRST|AAAA_FIRST` (default: `A_FIRST`)
- SB_DNS_HE_RACE_MS: family race window in ms (default: 30)
- SB_DNS_UDP_TIMEOUT_MS: UDP DNS per-query timeout in ms (default: 200; tests only)

### DNS Prefetch (behind env)

- SB_DNS_PREFETCH=1: enable near-expiry background refresh (default: 0)
- SB_DNS_PREFETCH_BEFORE_MS: spawn prefetch when remaining TTL <= this window (default: 200)
- SB_DNS_PREFETCH_CONCURRENCY: max concurrent prefetch tasks (default: 4)

### DNS Resolver Bridge (behind env)

- `SB_DNS_CACHE_ENABLE`:
  - `0` (default): 使用系统解析（`tokio::lookup_host`），行为与旧版一致；
  - `1`: 统一走内部 `sb_core::dns::resolve::resolve_all()`，启用轻量缓存、并发闸门、可选 prefetch（其余阈值见本文件前文 DNS 章节）。
  - 说明：这是**运行态桥接开关**；不修改调用方代码即可切换解析实现，遵守"Never break userspace"。

### DNS 选择与回退
- `SB_DNS_MODE`：`system`（默认）| `udp` | `dot` | `doh` | `auto`
- `SB_DNS_TIMEOUT_MS`：单次请求超时，默认 1500
- `SB_DNS_QTYPE`：查询类型，`auto`（默认，并发 A/AAAA 并合并）| `a` | `aaaa`
- `SB_DNS_UDP_SERVER`：UDP 服务器（默认 `1.1.1.1:53`）
- `SB_DNS_DOT_ADDR`：DoT 服务器（默认 `1.1.1.1:853`）
- `SB_DNS_DOH_URL`：DoH URL（默认 `https://cloudflare-dns.com/dns-query`）
> 注：`dns_dot`/`dns_doh` 需对应 feature 开启；TLS 校验遵循 `SB_TLS_NO_VERIFY`。

### DNS 缓存（默认关闭；需 `--features dns_cache`）
- `SB_DNS_CACHE_ENABLE=1`：启用缓存（正/负/stale）
- `SB_DNS_CACHE_CAP=4096`：容量上限（条目数）
- `SB_DNS_CACHE_TTL_SEC=60`：正向缓存 TTL（秒），当后端未携带 TTL 时采用
- `SB_DNS_CACHE_NEG_TTL_MS=20000`：负缓存 TTL（毫秒）
- `SB_DNS_CACHE_STALE_MS=0`：stale-while-revalidate 窗口（毫秒，0=禁用）
> 说明：缓存按查询类型（A/AAAA）分别存储，后续版本会自动使用后端提供的真实 TTL（取最小值）；未提供时回落 `SB_DNS_CACHE_TTL_SEC`。

### DNS Health / Backoff

- Lightweight per-upstream health with exponential backoff on failures: 100ms * 2^n (capped at 2s). Down upstreams are avoided; if all are down, pool degrades and continues while recording dns_pool_degraded_total{reason="all_down"}.

## Router DNS (on-demand)

- SB_ROUTER_DNS=1: enable on-demand resolve for cidr4 rules in UDP path. Only triggers when there is at least one `cidr4:` rule; failure or timeout does not override existing host rules.
 - Supports `cidr6:` rules as well; IPv6 results are considered when `SB_DNS_IPV6` is enabled (default: 1).
 
## GeoIP (behind env)

- SB_GEOIP_ENABLE=1: enable GeoIP matching (default: 0)
- SB_GEOIP_PROVIDER: `cidr|mmdb` (default: `cidr`)
- SB_GEOIP_CIDR_PATH: file path for `CIDR,CC` lines when provider=`cidr`
- SB_GEOIP_MMDB_PATH: path to MaxMind mmdb (feature `geoip_mmdb` must be enabled)
- `SB_GEOIP_MMDB`：启用 MMDB GeoIP 数据库（feature=geoip_mmdb）；设置为 `.mmdb` 文件路径即开启。
- `SB_GEOIP_MMDBS`：多库 MMDB 路径，使用 `:` 分隔，按顺序命中（feature=geoip_mmdb）。
- `SB_GEOIP_CACHE`：GeoIP LRU 缓存容量（默认 8192）。
- `SB_GEOIP_TTL`：GeoIP 缓存 TTL（默认 600s，例如 `10m`）。
- `SB_CHECK_ANALYZE`：开启规则分析扩展，输出 `ConflictRule` 与 `UnreachableOutbound`（默认关闭）。
 
## DNS Pool Concurrency (behind env)
 
- SB_DNS_POOL_MAX_INFLIGHT: global concurrent resolve limit (default: 64)
- SB_DNS_PER_HOST_INFLIGHT: per-host concurrent resolve limit (default: 2)
 
## Router Budget (behind env)
 
- SB_ROUTER_DECIDE_BUDGET_MS: decision time budget in milliseconds (default: 5)

### 选择策略（P2，可选）
  - `SB_SELECT_RTT_BIAS=1`：启用基于 EMA-RTT 的选择偏置（默认 0）
- `SB_SELECT_RTT_ALPHA=0.5`：RTT 偏置强度 α，score = weight / (1 + α * rtt_ms / N)
- `SB_SELECT_RTT_NORM_MS=100`：RTT 归一化基准 N（毫秒）
- `SB_SELECT_RTT_HALF_LIFE_MS=3000`：EMA 半衰期（毫秒）
- `SB_SELECT_HALF_OPEN=1`：启用半开阀，失败到阈值后仅用少量 token 探测（默认 0）
- `SB_SELECT_HALF_OPEN_TOKENS=2`：每端点初始半开 token 数（1~128）
- `SB_SELECT_FAIL_OPEN_THRESHOLD=3`：进入半开状态的失败阈值

### 选择器 P3（behind env）
- `SB_SELECT_P3=1`：启用 P3 评分选择器（默认关闭，不影响现有选择逻辑）。
- `SB_P3_ALPHA=0.2`：EMA 衰减系数（double）。
- `SB_P3_EPS=0.15`：抖动阈值 epsilon（double）。
- `SB_P3_COOLDOWN_MS=3000`：切换冷却窗（毫秒）。
- `SB_P3_BIAS_COLD=0.2`：冷启动偏置（样本不足时增加分数以抑制切换）。
- `SB_P3_EXPLORE`：P3 探索模式；`epsilon:<p>`（如 `epsilon:0.05`）或 `softmax:<tau>`（如 `softmax:0.5`）。默认关闭。
- `SB_P3_MIN_DWELL_MS`：最小驻留时间（默认 1500）。
- `SB_P3_MIN_SAMPLES`：候选最小样本数（默认 3）。
- `SB_P3_EMA_HALFLIFE_MS`：错误 EMA 半衰时间（默认 5000）。
- `SB_CHECK_ANALYZE_LEVEL`：`warn|error`（默认 `error`），只影响 Conflict 类。

指标（开启 metrics 时导出）：
- `proxy_select_score{outbound="<pool#idx>"}`
- `proxy_select_switch_total{reason="jitter|cooldown|score"}`
- `proxy_select_explore_total{mode="epsilon|softmax"}`

### Explain（旁路调试，仅编译时启用）
- `feature=explain`：开启路由 Explain 旁路（JSON/DOT），不进入数据路径；默认关闭。

### 观测（可选）
  - `SB_OBS_UDP_IO=1`：对 SOCKS5-UDP relay 的 send/recv 做轻量观测（默认 0）。不改变数据通路，仅辅助 EMA 收敛更快；真正的选择反馈已通过 `with_observation()` 在建链处完成。

## UDP Proxy Mode / Balancer

- SB_UDP_PROXY_MODE: `direct|socks5` (default: `direct`).
- SB_UDP_PROXY_ADDR: `host:port` for upstream SOCKS5 when using proxy mode.
  - alias: `SB_UDP_SOCKS5_ADDR` (legacy docs); code uses `SB_UDP_PROXY_ADDR`.
- SB_UDP_SOCKS5_POOL: comma-separated `host:port` list for upstream pool.
- SB_UDP_BALANCER_STRATEGY: `rr|random|hash` (default: `rr`).

## UDP NAT Limits

- SB_UDP_NAT_TTL_MS: NAT entry TTL in milliseconds (default: 60000).
- SB_UDP_NAT_MAX: maximum number of NAT entries (default: 65536).
  - When capacity is reached, new associations are rejected and `udp_nat_reject_total{reason="capacity"}` increments.


## Metrics

- Build with `--features metrics` to enable metrics collection.
- See `docs/metrics-compat.md` for the exact metric names and labels.

### Metrics 导出
- 构建：`cargo build --features metrics` 打包指标宏与导出器。
- 运行：仅当设置 `SB_METRICS_ADDR="127.0.0.1:9090"` 时才会监听 HTTP `/metrics`（默认关闭）。
- CI 等待：`NEED_METRICS=1 SB_METRICS_ADDR=127.0.0.1:9090 scripts/run-scenarios` 将强制等待 `/metrics` 就绪。
- 门限：`SB_SCENARIO_GATES=loose|strict`（默认 loose）。`loose` 仅 gate 标注 `gate=1` 的断言；`strict` 对全部断言生效。
- `SB_VALIDATE_LABELS=1`：开启 `/metrics` label 允许集校验；发现违规将标红并可 gate
- `SB_LABEL_GATES=loose|strict`：label 校验 gate 策略（默认 loose）
- `SB_E2E_ARCHIVE=1`：将报告/面板/allowlist 打进归档
- 建议在本地/CI 中配合 `scripts/e2e_dns_cache.zsh`、`scripts/e2e_udp_metrics.zsh` 做烟测。
- 拨号指标验证：`scripts/e2e_dial_metrics.zsh`（默认直连 `example.com:80`，可覆写 `HOST/PORT/CNT`）

### Router rules (compiled index + hot-reload)
- `SB_ROUTER_RULES` : inline rules text (optional)
- `SB_ROUTER_RULES_FILE` : external rules file path
- `SB_ROUTER_RULES_HOT_RELOAD_MS` : when > 0, watch file mtime and rebuild index; **only swap on success**
- `SB_ROUTER_RULES_MAX` : max accepted rules (default 8192)
- `SB_ROUTER_RULES_INCLUDE_DEPTH` : maximum include depth for recursive file inclusion (default 4)

#### Hot Reload Enhancements
- **Content Hashing**: Uses blake3 to detect actual content changes; identical content skips reload (metrics: `reload_total{result="noop"}`)
- **Include Cycle Protection**: Detects and breaks include cycles using canonicalized path tracking (metrics: `router_rules_include_total{result="cycle"}`)
- **Memory Footprint**: Estimates index memory usage (metrics: `router_rules_footprint_bytes`)
- **Shadowing Detection**: Warns when exact rules are covered by suffix rules (metrics: `router_rules_shadowed_total{kind="exact_over_suffix"}`)

## 决策缓存（可选）

- `SB_ROUTER_DECISION_CACHE`（`1` 开启，默认关闭）
  对 host（经规范化后）→ 决策结果做 LRU 缓存；在 Router 索引 **generation 改变** 时自动失效，保证与热切换一致。

- `SB_ROUTER_DECISION_CACHE_CAP`（默认 `1024`）
  LRU 容量（条目数）。观测：
  - `router_decision_cache_total{result∈hit|miss|invalidate}`

### Host 规范化
- 缺省仅做 **ASCII 小写**；开启 `idna` feature 时，额外做 **IDNA** punycode 规范化（失败容错为原文小写）。
- `SB_ROUTER_SUFFIX_STRICT=1`：启用**严格后缀模式** —— 仅使用基于标签边界的 `suffix_map` 直查；禁用无边界 `ends_with` 线扫兜底（默认关闭）

### Explain 调试（开发态）
- 提供只读调试接口而非开关：
  - `decide_http_explain(target: &str) -> DecisionExplain`
  - `decide_udp_async_explain(handle: &RouterHandle, host: &str) -> DecisionExplain`
  返回命中路径与原因字符串与 `reason_kind`（exact/suffix/ip/dns_ip/dns_geoip/port/portrange/transport/default），**不建议在热路径频繁调用**。

### 运行时覆盖（仅调试）
- `SB_ROUTER_OVERRIDE`：以逗号或分号分隔的小型规则集（支持 `exact:host=...`、`suffix:.tail=...`、`port:<u16>=...`、`portset:80,443=...`、`portrange:1000-2000=...`、`transport:{tcp|udp}=...`、`default=...`）。
- 覆盖仅在决策路径生效，不改变索引与热重载；命中计 `router_decide_reason_total{kind="override"}` / 覆盖 default 计 `"override_default"`。

### 快照摘要导出
- `router_snapshot_summary() -> String`：返回当前 Router 索引的摘要（feature `json` 时为 JSON 字符串），包含 generation、checksum_hex、各类规模与 footprint 估计，便于调试与工单排障。

### GeoIP Provider 安全化
- 全局 Provider 通过 `set_global_provider(Arc<dyn Provider>)` 注入；内部使用 `OnceCell<Arc<_>>`，无 `static mut`，线程安全。

## Debug / Boot Diagnostics

- SB_PRINT_ENV=1: print a single-line JSON of relevant environment values at startup.

## R5/R6 Enhanced Features

### R5 新增环境变量
- `SB_ROUTER_RULES_REQUIRE_DEFAULT`：R5 守门。设为 `1/true` 时，规则必须显式 `default:...`，否则热重载构建失败且不切换。
- `SB_ROUTER_RULES_BACKOFF_MAX_MS`：R5 退避上限（默认 10000ms）。热重载失败时指数退避（250ms 起，×2 直至上限）。
- `SB_ROUTER_RULES_BASEDIR`：R5 include_glob 基准目录。缺省为进程工作目录。
- `SB_ROUTER_RULES_MAX_DEPTH`：R10 include_glob 预展开最大深度（默认 3）。超限直接拒绝切换。
- `SB_ROUTER_RULES_JITTER_MS`：R9/R10 热重载 tick 额外随机抖动（毫秒，默认 0=关闭）。
- `SB_ADMIN_DEBUG_ADDR`：R6/R9 管理只读端口监听地址（如 `127.0.0.1:18088`）。默认未设置=不启用。
  - features：`rules_capture` 启用规则文本捕获（只读）。`analyze_json` 启用 `/router/analyze` JSON 输出（否则输出 minijson JSON）。`cache_stats` 允许缓存实现注册统计 Provider，`/router/cache` 输出实化字段；`cache_stats_hot` 允许注册热点 Provider；`geoip_provider` 允许外部注册 GeoIP 快查 Provider。

### 新增 DSL
- `let:NAME=value` —— R5 变量定义。`NAME` 必须匹配 `[A-Z][A-Z0-9_]{0,31}`；在后续行中可用 `$NAME` 展开（模式与 RHS 均生效）。
- `include_glob:pattern` —— R5 批量包含。`pattern` 基于 `SB_ROUTER_RULES_BASEDIR` 展开，按路径排序后内联拼接。允许 `$NAME` 变量。
- `${NAME:-default}` —— R10 变量默认值占位；当 `NAME` 未定义或为空时采用 `default`。

### Admin 只读端点
- `GET /router/snapshot` —— JSON，返回 `router_snapshot_summary()` 结果
- `GET /router/explain?target=...&proto={tcp|udp}` —— JSON，包含 `proto`/`decision`/`reason_kind`/`explain`
- `GET /router/health` —— 纯文本 `"ok"`，可用于探针
- `GET /version` —— 纯文本构建信息（不暴露敏感配置）
- `GET /router/cache` —— JSON，决策缓存摘要（若禁用则返回 `{"disabled":true}`）
- `GET /router/geoip?ip=1.2.3.4` —— JSON，返回国家码或 `unavailable`
- `GET /help` —— 列出可用只读端点
- `GET /router/analyze[?inline=base64]` —— 基于文本进行规则分析；未提供 `inline` 时，且启用 `rules_capture` 则使用捕获文本
 - `GET /router/analyze/patch?kind={portrange_merge|suffix_shadow_cleanup}[&inline=base64]` —— 在线导出 CLI 补丁文本（需 `rules_tool`）
 - `GET /subs/fetch?url=...` —— 拉取订阅（只读，限长；需 `subs_http`）
 - `GET /subs/parse?format=clash|singbox&inline=base64` —— 解析并返回 `{rules,outbounds}` 计数（需 `subs_clash`/`subs_singbox`）
 - `GET /subs/plan?format=...&inline=base64&kinds=...` —— 对解析到的规则执行 normalize+plan（JSON；需 `sbcore_rules_tool`）
 - `GET /subs/convert?format=...&inline=base64[&mode=keyword|suffix]` —— 返回规范化后的 Router DSL 文本（只读）
   - mode=suffix（默认）：`DOMAIN-KEYWORD` 近似为 `suffix:*kw*`
   - mode=keyword（需 `router_keyword`）：输出 `keyword:kw=decision`

### 决策驻留（intern）
- 内部通过驻留池去重存储各类决策字符串，避免分散泄漏。
- 需要 `'static` 的旧接口（例如关键词匹配路径）从池里取值；Explain 路径仍返回 `String`。
- 观测：后续可在 Admin 加只读端点暴露驻留大小（本轮不暴露）。

### 订阅映射补完
- Clash 规则映射：
  - `NETWORK,TCP/UDP,...` → `transport:{tcp|udp}=...`
  - `IP-CIDR` / `IP-CIDR6` → `cidr:...=...`
- sing-box 规则映射：
  - `ip_cidr` / `ip_cidr6` → `cidr:...=...`
  - `network: tcp|udp` → `transport:{tcp|udp}=...`

### Keyword AC 阈值
- `SB_ROUTER_KEYWORD_AC_MIN`：关键词数量达到阈值才构建 AC（默认 **64**）；否则走顺扫，降低小规模规则的构建成本。

### TLS Builder 环境预览
- 只读端点：`GET /tls/config` 返回
  - `sni`: 取自 `SB_TLS_SNI`（可空）
  - `alpn`: 取自 `SB_TLS_ALPN`（逗号分隔，如 `h2,http/1.1`）
- 该端点**不改变**运行时 Dialer，仅用于观测与调试（Never break userspace）。
- 有效端点：`GET /tls/effective` 展示通过 `TlsDialer::from_env(...)` 注入后的 SNI/ALPN（仅展示，不建连）

### 决策驻留池
- 只读端点：`GET /router/intern` → `{"pool_size": <u64>}`
- 用于观测驻留池大小；驻留池避免到处泄漏 `'static` 决策字符串。

### 基准
- `sb-core/benches/keyword_bench.rs`（需 features=`bench,router_keyword`；AC 编译需再加 `router_keyword_ac`）
- 比较 64/1k/8k 关键词下构建+匹配的开销，为阈值选择提供参考。

### 订阅 RULE-SET/GEOSITE 合并（只读）
- 端点：`GET /subs/merge?format=clash&inline=base64[&ruleset.NAME=base64][&geosite.NAME=base64]`
- 不发起网络请求；上层需显式提供各集合内容（base64）
- 解析逻辑：
  - `RULE-SET,NAME,DECISION`：集合内容逐行按 Clash 规则语法映射到 DSL，并套用 DECISION
  - `GEOSITE,NAME,DECISION`：集合内容逐行当作后缀 `suffix:...=DECISION`
- 默认行为未变（`/subs/convert` 仍保留旧近似）；Never break userspace。

### Trojan 最小握手构造（可选 feature）
- `sb-proto/proto_trojan_min`：提供 `TrojanHello {password,host,port}.to_bytes()`
- 仅生成字节序列，后续与 `sb-transport` 组合拨号时再进入 TLS/IO 层

### Trojan 出站（最小）
- feature: `app/proto_trojan_min` & `sb-proto/proto_trojan_min`
- 端点：`GET /trojan/dryrun?host=...&port=...&pass=...` → `{"hex":"...","len":N}`（只读，无网络）

### Admin 网络守门
- `SB_ADMIN_ALLOW_NET=1` 才允许 `/trojan/dryrun_connect` 发起最小连通尝试（默认关闭）
- 尝试仅在**超时窗口**内进行（默认 100ms），且不发送业务数据以外的首包

### /subs/convert_json 视图增强
- feature: `app/subs_view_hash` 以启用 blake3 哈希字段
- 输出：`rules_hash`、`outbounds_hash`（禁用时为 `"disabled"` 字符串）
- R82: 新增 `sample_rules`（≤10 规则示例）和 `kinds_count`（出站类型统计直方图）
- 用途：CI 缓存命中、增量对比、配置去抖、快速预览

### 路由决策缓存热点分析（R81）
- 端点：`GET /router/cache/hot?limit=N` → JSON，返回缓存热点 Top-N 项目
- feature: `cache_stats_hot` 启用热点统计功能
- 输出格式：`{"items": [{"hash_prefix": "xxxxxxxx", "hits": N}, ...]}`
- hash_prefix: 使用 blake3 前8位十六进制匿名化
- 用途：缓存优化、热点调优、性能分析

### Transport 超时工具（R83）
- `sb-transport/util` 模块新增超时包装器：
  - `dial_with_timeout(dialer, target, timeout_ms)` - 解析 host:port 格式并带超时拨号
  - `connect_with_timeout(dialer, host, port, timeout_ms)` - 直接指定 host+port 带超时连接
  - `dial_with_timeout_future(...)` - 返回 Future 的异步版本
- 超时时使用 `DialError::Timeout` 错误类型
- tokio 的 time feature 已内置启用

### 传输层错误兼容（R84）
- `DialError::Timeout` 已标记 **deprecated**；工具函数与 Harness 统一将超时映射为 `Other("timeout")`
- 若你已有对 `Timeout` 的匹配，不受影响；建议改为判断 `Other("timeout")` 文本或使用工具函数返回

### Trojan 连通报告（R85）
- `/trojan/dryrun_connect?...` 现在返回：`{"ok":true|false,"path":"tcp|tls","elapsed_ms":N}`
- 仍受 `SB_ADMIN_ALLOW_NET=1` 守门与 `timeout_ms` 控制，默认 100ms

### 路由缓存 Provider 接线（R86）
- feature: `sb-core/cache_stats_wire`
- 在 Router 初始化完成后调用：
  - `register_router_decision_cache_adapter(&ADAPTER)`
  - `register_router_hot_adapter(&HOT)`
- 默认不自动注册，避免隐性副作用；仅提供"显式接线"入口

### 订阅 JSON 视图再增强（R87）
- 新增：`outbound_kinds_count`（按出站类型聚合的直方图）
- 现有：`rules_hash/outbounds_hash`、`sample_rules`、`kinds_count`

特性说明：
- `sb-core/router_keyword`：启用 Router 关键词索引；默认关闭
- `sb-core/router_keyword_ac`：启用关键词 Aho-Corasick 加速（与 `router_keyword` 同时启用）
- `sb-transport/transport_tls`：启用 TLS；提供 `webpki_roots_config()`（生产）与 `smoke_empty_roots_config()`（测试）；`TlsDialer` 支持 `sni_override` 与 `alpn`

### SS2022 最小 dryrun（只读）
- feature: `app/proto_ss2022_min` + `sb-proto/proto_ss2022_min`
- 端点：`GET /ss2022/dryrun?host=...&port=...&method=2022-blake3-aes-256-gcm&pass=...`
- 仅返回首包 hex/len；不发起网络连接
- 注意：TLS 未实现，tls=1 时返回错误

### Outbound Registry（最小）
- feature: `app/outbound_registry` + `sb-proto/outbound_registry`
- 用于将"出站名→协议种类"映射为可 dryrun 的最小 connector；当前支持 `trojan`/`ss2022`

### 按出站名 dryrun（只读）
- 端点：`GET /outbound/test?name=...&host=...&port=...&tls=0|1&timeout_ms=100`
- 仅写入首包（trojan），受 `SB_ADMIN_ALLOW_NET=1` 守门；ss2022 返回首包 hex（不联网）

### 订阅出站绑定 JSON
- 端点：`GET /subs/bindings?format=clash|singbox&inline=base64`

## Admin 端点 JSON 统一口径（R126）

所有返回含 hash 的端点在 meta 里加 hashes:boolean；含排序提示的加 ordered:boolean；normalize 生效与否显式化：

### /subs/convert_full
```
curl -s "http://127.0.0.1:18088/subs/convert_full?format=clash&inline=BASE64&normalize=1"
```
返回包含 meta.hashes、meta.ordered、meta.normalized

### /subs/diff_full
```
curl -s "http://127.0.0.1:18088/subs/diff_full?format=clash&lhs=BASE64&rhs=BASE64&normalize=1"
```
返回包含 meta.hashes、meta.ordered、meta.normalized

### /subs/lint
```
curl -s "http://127.0.0.1:18088/subs/lint?format=clash&inline=BASE64&normalize=1"
```
返回包含 meta.hashes、meta.ordered、meta.normalized

### /subs/preview_patch
```
curl -s "http://127.0.0.1:18088/subs/preview_patch?format=clash&inline=BASE64&kinds=portrange_merge,lint_autofix"
```
返回包含 meta.hashes、meta.ordered、meta.normalized、meta.unknown_kinds

### /router/explain
```
curl -s "http://127.0.0.1:18088/router/explain?target=example.com&proto=tcp"
```
返回包含 meta.block（固定 false）

### /tls/config 和 /tls/effective
```
curl -s "http://127.0.0.1:18088/tls/config"
curl -s "http://127.0.0.1:18088/tls/effective"
```
返回包含 meta.hashes、meta.ordered、meta.normalized

## Cache Hot JSON 稳定形状（R128）

/router/cache/hot 的 JSON 固定为：
```json
{"limit":N,"count":M,"items":[{"hash_prefix":"...","hits":H},...]}
```

无 provider 时输出：
```json
{"disabled":true,"limit":N,"count":0,"items":[]}
```

```
curl -s "http://127.0.0.1:18088/router/cache/hot?limit=64"
```

## 规划 kinds 白名单（R127）

/subs/preview_patch 支持 kinds 白名单：["portrange_merge","suffix_shadow_cleanup","port_aggregate","lint_autofix"]

输出 unknown_kinds 数组；plan_summary 透传；即使空计划也用 lint_autofix 兜底产生 "+/-"

## SS2022 连通 harness（R123）

```
export SB_ADMIN_ALLOW_NET=1
curl -s "http://127.0.0.1:18088/ss2022/dryrun_connect?host=example.com&port=443&tls=0&timeout_ms=100"
```

返回结构：
```json
{"ok":true|false,"path":"tcp|tls","elapsed_ms":N}
```

## 编译 Feature 矩阵

### R121-124 决策缓存与 SS2022 harness
```bash
# 最小检查
cargo check -q --workspace

# 决策缓存接线（演示 LRU）
cargo check -q -p sb-core --features router_cache_lru_demo
cargo test -q -p sb-core --features router_cache_lru_demo,cache_stats_hot --test cache_wire_snapshot -- --nocapture
cargo test -q -p sb-core --features router_cache_lru_demo,cache_stats_hot --test cache_hot_json -- --nocapture

# Admin 热点/摘要（只读）
cargo check -q -p singbox-rust --features router_cache_lru_demo

# SS2022 harness（形状测试）
cargo check -q -p sb-proto --features proto_ss2022_min
cargo test -q -p sb-proto --features proto_ss2022_min --test ss2022_harness_test -- --nocapture

# Admin SS2022 dryrun（守门）
cargo check -q -p singbox-rust --features proto_ss2022_min
```

### R125-129 清理与验收
```bash
# 清理+编译
cargo check -q --workspace

# sb-core：热点输出稳定、LRU 演示
cargo test -q -p sb-core --features "router_cache_lru_demo,cache_stats_hot" --test cache_wire_snapshot -- --nocapture
cargo test -q -p sb-core --features "router_cache_lru_demo,cache_stats_hot" --test cache_hot_json -- --nocapture

# sb-proto：ss2022 harness 形状
cargo test -q -p sb-proto --features "proto_ss2022_min" --test ss2022_harness_test -- --nocapture

# sb-subscribe：full/diff/lint/preview_plan
cargo test -q -p sb-subscribe --features "subs_full,subs_clash" -- --nocapture
cargo test -q -p sb-subscribe --features "subs_diff,subs_clash" --test diff_full_test -- --nocapture
cargo test -q -p sb-subscribe --features "subs_lint,subs_lint_patch,subs_clash" --test lint_basic -- --nocapture
cargo test -q -p sb-subscribe --features "subs_preview_plan,subs_clash" --test preview_plan_test -- --nocapture

# app（只编译，端点在运行时可 curl）
cargo check -q -p singbox-rust --features "router_cache_lru_demo,subs_full,subs_diff,subs_lint,subs_lint_patch,subs_preview_plan,subs_clash"
```

## 重要约定

- 全部 behind features；默认关闭；失败回退占位 JSON
- read-only / 守门 / 不写磁盘
- 错误可观测
- 输出：`{"outbounds":[{"name":"...","kind":"trojan|ss2022|..."}]}`

## TLS

- `SB_TLS_NO_VERIFY`:
  - `0`（默认）：使用 WebPKI 根进行证书校验
  - `1`：跳过证书校验（测试/内网）
  - 生效面：`TlsClient::from_env()` 与使用该客户端的路径（如 DoT）

### 路由沙盒 Dry-Run（R92-R95）
- feature: `app/route_sandbox` + `outbound_registry` + `proto_trojan_min` + `proto_ss2022_min`
- 端点：`GET /route/dryrun?target=...&proto=tcp|udp[&connect=1][&tls=0|1][&timeout_ms=100][&pass=...][&method=...]`
- 工作流：Router 决策 → 推断出站类型（tro*/ss2*/direct/reject）→ 生成首包或最小连通
- 出站名推断：前缀 `tro*` → trojan，前缀 `ss2*` → ss2022，`direct`/`reject` → 内建
- 参数化：`connect=1` 仅在 `SB_ADMIN_ALLOW_NET=1` 时尝试最小连通；`tls=0|1`、`timeout_ms`、`pass`/`method`
- 环境变量回退：`SB_OUTBOUND_DEFAULT_PASS`、`SB_SS2022_METHOD`
- 最小路由规则安装：需预置 Router 规则（如 `default=direct`）或运行时规则以便决策推断
# Environment Variables (M1 Minimal)
 
## 编译与特性矩阵（R96–R99）
- 最小通过：`cargo check -q --workspace`
- 常用组合：
  - 订阅视图：`-p singbox-rust --features subs_view,subs_clash`（JSON 视图）
  - 订阅绑定：`--features subs_bindings,subs_clash`
  - TLS：`--features tls_env`（不会默认引入 rustls）
  - 路由沙盒：`--features route_sandbox`（仅只读；connect=1 需 `SB_ADMIN_ALLOW_NET=1`）

## /route/dryrun 参数与守门
- `connect=1` 仅在 `SB_ADMIN_ALLOW_NET=1` 时生效；否则返回 501
- `tls/timeout_ms/pass/method` 仅作用于 trojan/ss2022 分支；direct/reject 永远离线返回
- 端点 behind `app/route_sandbox`；禁用时不编译相关逻辑
### /subs/convert_full（R100–R101）
- feature: `app/subs_full` + 解析器特性（`subs_clash` 或 `subs_singbox`）
- 调用：`GET /subs/convert_full?format=clash|singbox&inline=base64[&mode=keyword|suffix][&normalize=1]`
- 返回：minijson 对象，包含：
  - `dsl`（可选 normalize 后的 Router DSL 文本）
  - `dsl_hash`（如启用 `subs_hash`，否则为 `"disabled"`）
  - `view`（与 `/subs/convert_json` 字段一致）
  - `bindings`（与 `/subs/bindings` 一致）

- 增量（R100–R103）
  - full：`cargo check -q -p singbox-rust --features subs_full,subs_clash`
  - keyword 模式：`--features router_keyword`（仅影响 DSL/视图映射）
  - 仍然只读、无网络；`connect=1` 相关逻辑仅在 `/route/dryrun` 且 `SB_ADMIN_ALLOW_NET=1`
### /subs/diff_full（R104–R105）
- feature: `app/subs_diff` + 至少一个解析器（`subs_clash` 或 `subs_singbox`）
- 调用：`GET /subs/diff_full?format=clash|singbox&lhs=base64&rhs=base64[&mode=keyword|suffix][&normalize=1]`
- 返回：minijson
  - `kinds_count_lhs/rhs`：规则种类直方图
  - `outbound_kinds_lhs/rhs`：出站类型直方图
  - `dsl_patch`：行级最小补丁（`-old` / `+new`），基于（可选）归一化后 DSL
  - 仅离线；不联网不落盘；默认关闭
  
  - 增量（R104–R107）
    - diff：`cargo check -q -p singbox-rust --features subs_diff,subs_clash`
    - diff 测试：`cargo test -q -p sb-subscribe --features subs_diff,subs_clash --test diff_full_test`

### /subs/lint（R108–R110）
- feature: `app/subs_lint`（可选 `app/subs_lint_patch` 以返回 `patch`）
- 调用：`GET /subs/lint?format=clash|singbox&inline=base64[&mode=keyword|suffix][&normalize=1][&patch=1]`
- 返回（minijson）：
  - `totals`：empty_decision / dup_rule / reversed_portrange / shadow_suffix_over_exact / unknown_outbound
  - `issues`：逐项列表；`can_autofix`：是否存在安全自动修复项
  - `patch`（可选）：CLI 风格行级补丁，仅包含安全修改（删除重复、反向区间修正）
- 纯离线、只读；默认关闭特性

### /subs/diff_full 说明（补充）
- 增加字段：`ordered:false` —— 行级差分基于集合，未保留顺序（建议配合 `normalize=1`）

### 编译矩阵（增量）
- lint：`cargo check -q -p singbox-rust --features subs_lint,subs_clash`
- lint+patch：`cargo check -q -p singbox-rust --features subs_lint,subs_lint_patch,subs_clash`
- 测试：`cargo test -q -p sb-subscribe --features subs_lint,subs_clash --test lint_basic`

### /subs/preview_route（S13 R113–R116）
- features: `app/subs_preview_route` + `app/subs_full` + 解析器（`subs_clash` 或 `subs_singbox`）
- GET `/subs/preview_route?format=clash|singbox&inline=base64&targets=base64[&mode=keyword|suffix][&normalize=1][&proto=tcp|udp][&connect=1]`
- `targets`：base64 编码、按行列出 `host[:port]`；`proto` 默认 tcp
- 默认离线：`connect=1` 仅在 `SB_ADMIN_ALLOW_NET=1` 时生效；且仅对 direct/trojan/ss2022 提供最小探测
- 响应（minijson）：`{ ok, meta{...}, dsl_hash, results:[{target, decision, reason_kind, explain, connect?}] }`
- 行为不写磁盘、不污染全局索引；Never break userspace

### 编译矩阵（增量）
- 预览（clash）：`cargo check -q -p singbox-rust --features subs_preview_route,subs_full,subs_clash`
- 预览测试（库）：`cargo check -q -p sb-core --features preview_route`
### /subs/preview_patch（S14 R117–R120）
- features: `app/subs_preview_plan`（可选 `app/subs_preview_apply` 返回 `dsl_out`）
- GET `/subs/preview_patch?format=clash|singbox&inline=base64[&mode=keyword|suffix][&normalize=1][&kinds=a,b][&apply=1]`
- `kinds` 默认：`port_aggregate,portrange_merge,suffix_shadow_cleanup,lint_autofix`
- 返回（minijson）：
  - `meta`：`normalized` / `ordered:false` / `apply` / `kinds`
  - `lint`：离线报告（与 `/subs/lint` 一致）
  - `plan_summary`：计划摘要
  - `patch`：CLI 风格补丁（行级）
  - `dsl_in_hash`（`subs_hash` 开启时），以及 `dsl_out/_hash`（`apply=1` 时）
- 只读、离线；不写文件、不改全局索引；建议开启 `normalize=1` 获取稳定补丁
### 编译矩阵（增量）
- 预览计划：`cargo check -q -p singbox-rust --features subs_preview_plan,subs_full,subs_clash`
- dry-run 应用：`cargo check -q -p singbox-rust --features subs_preview_apply,subs_preview_plan,subs_full,subs_clash`
- 测试：`cargo test -q -p sb-subscribe --features subs_preview_plan,subs_clash --test preview_plan_test`

### R130-R135 增强功能

#### Router Cache Admin Controls (R132)
- features: `app/router_cache_admin` + `sb-core/router_cache_admin`
- Admin 端点：
  - `POST /router/cache/reset`: 清空路由决策缓存（需 `SB_ADMIN_ALLOW_ADMIN=1`）
  - `GET /router/cache/stats`: 返回缓存统计信息（大小、容量、命中率等）
- 编译验收：`cargo check -q -p singbox-rust --features "router_cache_lru_demo,router_cache_admin"`

#### SS2022 TLS First Packet Builder (R133)
- features: `app/proto_ss2022_tls_first` + `sb-proto/proto_ss2022_tls_first`
- 功能：SS2022 协议的 TLS 握手首包构造（只读预览）
- API：
  - `build_tls_first_packet(payload: &[u8], sni: Option<&str>) -> Vec<u8>`
  - `preview_tls_first_packet(payload: &[u8]) -> String` - 十六进制格式化输出
- 编译验收：`cargo check -q -p sb-proto --features "proto_ss2022_tls_first"`
- 测试：`cargo test -q -p sb-proto --features "proto_ss2022_tls_first" --test ss2022_tls_test`

#### Subscription Outbound Binding Enhancement (R134)
- features: `app/subs_bindings_dry` + `sb-subscribe/subs_bindings_dry`
- 增强功能：订阅出站绑定的干运行连接测试
- API：
  - `dry_connect_test(profile, target) -> String` - 对所有出站进行模拟连接测试
  - `bindings_enhanced_minijson(profile, test_connect, target) -> String` - 增强的绑定信息，可选连接测试
- 特点：
  - 仅模拟 DNS 解析和基本检查，不进行实际网络连接
  - 支持不同出站类型的差异化检查（trojan, shadowsocks, direct, block）
  - 返回连接状态、耗时和错误信息
- 编译验收：`cargo check -q -p sb-subscribe --features "subs_bindings_dry"`
- 测试：`cargo test -q -p sb-subscribe --features "subs_clash,subs_bindings_dry" --test bindings_test`

#### Tests and Documentation (R135)
新增测试文件：
- `crates/sb-core/tests/router_cache_wire_test.rs` - 路由缓存功能测试
- `crates/sb-proto/tests/ss2022_tls_test.rs` - SS2022 TLS 首包构造测试
- `crates/sb-subscribe/tests/bindings_test.rs` - 订阅绑定增强测试（已扩展）

#### 综合验证命令
```bash
# R130-R135 完整验证
cargo check -q --workspace
cargo test -q -p sb-core --features "router_cache_lru_demo,router_cache_admin" --test router_cache_wire_test
cargo test -q -p sb-proto --features "proto_ss2022_tls_first" --test ss2022_tls_test
cargo test -q -p sb-subscribe --features "subs_clash,subs_bindings_dry" --test bindings_test
```

### 特性依赖图

#### 缓存相关
- `router_cache_wire` → `cache_stats` + `cache_stats_hot` + `cache_stats_wire`
- `router_cache_lru_demo` → `router_cache_wire` + `dep:lru`
- `router_cache_admin` → `router_cache_wire`

#### 协议相关
- `proto_ss2022_tls_first` → `proto_ss2022_min` + `sb-transport/transport_tls`

#### 订阅相关
- `subs_bindings_dry` → `subs_bindings` + `dep:tokio` + `sb-core/dns_udp`
- #### 接入示例（闭环用法）
  在进行上游拨号/会话创建时：
  ```rust
  use sb_core::outbound::observe::with_observation;
  use sb_core::outbound::selector::PoolSelector;
  // 假设已有: let selector: &PoolSelector = sticky_selector();
  if let Some((idx, ep)) = selector.select_with_index(&pool, client, target, &health) {
      let mut sess = with_observation(selector, &pool.name, idx, || UpSocksSession::create(ep.clone(), timeout_ms)).await?;
      if std::env::var("SB_OBS_UDP_IO").ok().as_deref() == Some("1") { sess.bind_observation(pool.name.clone(), idx); }
      // 后续使用 sess ...
  }
  ```
  > 默认未启用 P2 时，上报不改变选择结果；启用后将影响后续选路概率与半开阀放量。
