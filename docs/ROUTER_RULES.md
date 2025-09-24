## Router Rules (Phase 2.4)

`Rule` fields:

```rust
pub struct Rule {
  pub host_suffix: Option<String>,
  pub transport:   Option<String>,
  pub inbound:     Option<String>,
  pub user:        Option<String>,
  pub target:      Arc<dyn Outbound>,
}
```

### From JSON

```json
{
  "route": {
    "rules": [
      { "host_suffix": ["example.com",".ads"], "outbound": "block" },
      { "transport": "tcp", "outbound": "direct" }
    ],
    "final": "direct"
  }
}
```

Multiple suffixes → multiple `Rule`s. Empty rule (no constraints) is ignored.

### From Environment

- `SBR_BLOCK_SUFFIXES="example.com,.ads"`
- `SBR_DIRECT_SUFFIXES="internal.local,corp.net"`

The app builds these into rules targeting `block`/`direct`.

# Router 规则最小全集（v1）

**优先级（从高到低，短路生效）**：
1. `exact:example.com` / `domain:example.com`
2. `suffix:.example.com`
3. `keyword:foo`
4. `ip_cidr:192.168.0.0/16` / `ip_cidr:2001:db8::/32`
5. `transport:udp|tcp` + `port:80|443|...`（可合并 portset）
6. `default:direct|proxy|reject`

匹配结果：`outbound = direct|proxy|proxy:poolName|reject`（Named Proxy Pool v1 扩展）

**注**：`proxy:poolName` 语法指向命名代理池；若池不存在或全熔断，按健康回退开关处理。

语法扩展：
- `port:N` 单端口；`portrange:A-B` 闭区间；`portset:P1,P2,...` 去重后集合；
- `keyword:xxx` 对 domain 子串做 ASCII 不区分大小写匹配；
- `suffix:` 与 `exact:` 推荐使用小写（内部按 ASCII 小写进行比较）。

示例：
```ini
exact:download.example.com = direct
suffix:.example.com       = proxy:poolA
keyword:tracker           = reject
ip_cidr:10.0.0.0/8        = direct
transport:udp,port:53     = direct
portset:80,443,8443       = proxy:poolA
default                   = proxy
```

## JSON → 规则引擎桥接
最小 JSON 形态：
```json
{
  "rules": [
    { "type": "domain",         "value": "download.example.com", "outbound": "direct" },
    { "type": "domain_suffix",  "value": ".example.com",         "outbound": "proxy:poolA"  },
    { "type": "domain_keyword", "value": "tracker",              "outbound": "reject" },
    { "type": "ip_cidr",        "value": "10.0.0.0/8",           "outbound": "direct" },
    { "type": "port",           "value": 53,                     "transport": "udp",  "outbound": "direct" },
    { "type": "portset",        "values": [80,443,8443],         "outbound": "proxy:poolA"  }
  ],
  "default": "proxy"
}
```
字段别名支持：
- `type`: `domain|exact|domain_exact|host|domain_suffix|suffix|domain_keyword|keyword|ip_cidr|ip-cidr|ipcidr|port|portrange|port_range|portset|port_set|ports|default`
- `value/values`: 单值或数组均可；`portrange` 支持 `"A-B"` 或 `[A,B]`

### 指标
- `router_match_total{rule="exact|suffix|keyword|ip_cidr|transport|port|default", decision}`
- `router_decide_total{decision="direct|proxy|reject"}`
- `router_json_bridge_errors_total{kind="json_parse|unknown_rule_type|bad_ip_cidr|bad_port"}`
> 注：**不包含 host/domain 级 label**，避免高基数。