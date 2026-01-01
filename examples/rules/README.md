# Routing Rules / 路由规则

Pre-made routing rule sets and templates for common use cases.

常见用例的预制路由规则集和模板。

---

## 📋 Available Rule Files

### basic-router.rules

**Description**: Minimal routing rule set demonstrating all matcher types.

**最小路由规则集** - 展示所有匹配器类型。

**Contents**:

```
exact:download.example.com = direct
suffix:.example.com       = proxy
keyword:tracker           = reject
ip_cidr:10.0.0.0/8        = direct
transport:udp,port:53     = direct
portset:80,443,8443       = proxy
default                   = direct
```

**Use Cases**:

- Learning routing syntax
- Template for custom rules
- Quick testing

---

### router.json

**Description**: JSON format routing configuration with detailed rules.

**JSON 格式路由配置** - 详细规则。

**Features**:

- Domain suffix matching
- Transport-based rules
- Multiple rule evaluation

**Usage**:

```bash
cargo run -p app -- run -c examples/rules/router.json
```

---

## 📂 Rule Snippets

**Directory**: `snippets/`

Reusable rule fragments that can be included in larger rule sets.

### block-ads.dsl

**Description**: Common ad and tracker blocking rules.

**广告与追踪器拦截规则**。

**Contents**:

```
suffix:ads.example.com=reject
suffix:tracker.example.com=reject
```

**Usage**:

Include in your main rule file:

```
include:examples/rules/snippets/block-ads.dsl
# Your other rules...
```

---

## 📝 Rule Templates (Coming Soon)

**Directory**: `templates/`

Complete rule sets for specific scenarios:

### home-network.rules (Planned)

**Scenario**: Home network with local services and streaming.

**Features**:

- Local network direct routing
- Streaming service rules
- Ad blocking
- IoT device handling

---

### office-network.rules (Planned)

**Scenario**: Corporate network with compliance requirements.

**Features**:

- Internal domain direct routing
- Corporate proxy chaining
- Security policy enforcement
- Audit logging rules

---

### travel-mode.rules (Planned)

**Scenario**: Mobile/travel with unreliable connections.

**Features**:

- Aggressive failover
- Minimal DNS queries
- Connection pooling
- Battery-efficient routing

---

## 🔧 Rule Syntax

### Basic Format

```
<matcher>:<pattern>=<outbound>
```

### Matcher Types

| Matcher      | Description       | Example                      |
| ------------ | ----------------- | ---------------------------- |
| `exact:`     | Exact match       | `exact:example.com=direct`   |
| `suffix:`    | Domain suffix     | `suffix:.cn=direct`          |
| `keyword:`   | Contains keyword  | `keyword:ads=reject`         |
| `ip_cidr:`   | IP CIDR range     | `ip_cidr:10.0.0.0/8=direct`  |
| `cidr:`      | Alias for ip_cidr | `cidr:192.168.0.0/16=direct` |
| `transport:` | Protocol type     | `transport:udp=direct`       |
| `port:`      | Port number       | `port:80=proxy`              |
| `portset:`   | Multiple ports    | `portset:80,443,8080=proxy`  |
| `default:`   | Default rule      | `default:direct`             |

### Advanced Matchers

| Matcher         | Platform              | Description      |
| --------------- | --------------------- | ---------------- |
| `process_name:` | macOS, Windows        | Process name     |
| `process_path:` | macOS, Windows, Linux | Full path        |
| `geoip:`        | All                   | GeoIP code       |
| `geosite:`      | All                   | GeoSite category |

---

## 🎯 Common Patterns

### 1. Block Ads and Trackers

```
keyword:ads=reject
keyword:tracker=reject
keyword:analytics=reject
suffix:.doubleclick.net=reject
suffix:googleadservices.com=reject
```

### 2. China Direct Routing

```
geoip:cn=direct
geosite:cn=direct
suffix:.cn=direct
```

### 3. Private Network Direct

```
cidr:10.0.0.0/8=direct
cidr:172.16.0.0/12=direct
cidr:192.168.0.0/16=direct
cidr:127.0.0.0/8=direct
```

### 4. DNS Direct Routing

```
transport:udp,port:53=direct
transport:tcp,port:53=direct
```

### 5. Process-Based Routing (macOS/Windows)

```
process_name:Terminal=direct
process_name:Chrome=proxy
process_path:/Applications/Mail.app=direct
```

---

## 🔄 Converting Formats

### DSL to JSON

**DSL**:

```
suffix:.cn=direct
keyword:ads=reject
default:proxy
```

**JSON**:

```json
{
  "route": {
    "rules": [
      {
        "when": { "domain_suffix": [".cn"] },
        "to": "direct"
      },
      {
        "when": { "domain_keyword": ["ads"] },
        "to": "reject"
      }
    ],
    "default": "proxy"
  }
}
```

### JSON to DSL

Use the conversion tool:

```bash
cargo run -p app -- convert-rules --from json --to dsl \
  -i rules.json -o rules.dsl
```

---

## 💡 Best Practices

### 1. Rule Order Matters

More specific rules should come first:

✅ **Good**:

```
exact:api.example.com=proxy
suffix:.example.com=direct
default:proxy
```

❌ **Bad**:

```
suffix:.example.com=direct
exact:api.example.com=proxy  # Never reached!
default:proxy
```

### 2. Use Comments

Document your rules:

```
# Block advertising networks
keyword:ads=reject
keyword:tracker=reject

# Direct routing for local networks
cidr:192.168.0.0/16=direct

# Default to proxy
default:proxy
```

### 3. Test Your Rules

Use the explain command:

```bash
cargo run -p app -- route -c config.json \
  --dest tracker.example.com:443 --explain
```

### 4. Keep It Simple

Start with basic rules, add complexity as needed:

```
# Phase 1: Basic routing
suffix:.cn=direct
default:proxy

# Phase 2: Add blocking (later)
keyword:ads=reject
suffix:.cn=direct
default:proxy

# Phase 3: Add process rules (later)
process_name:Terminal=direct
keyword:ads=reject
suffix:.cn=direct
default:proxy
```

---

## 📖 Examples

### Minimal Rules

```
default:direct
```

### Basic Split Routing

```
suffix:.cn=direct
cidr:10.0.0.0/8=direct
cidr:192.168.0.0/16=direct
default:proxy
```

### Advanced with Ad Blocking

```
# Block ads
keyword:ads=reject
keyword:tracker=reject
keyword:analytics=reject

# Local networks
cidr:10.0.0.0/8=direct
cidr:192.168.0.0/16=direct

# China direct
geoip:cn=direct
geosite:cn=direct

# DNS direct
transport:udp,port:53=direct

# Default proxy
default:proxy
```

---

## 🔗 Related Documentation

- [DSL Syntax](../dsl/README.md)
- [Routing Configuration](../configs/routing/)
- [Router Rules](../../docs/ROUTER_RULES.md)

---

## 🧪 Testing Rules

### 1. Validate Syntax

```bash
cargo run -p app -- check -c config-with-rules.json
```

### 2. Explain Routing

```bash
# Test domain routing
cargo run -p app -- route -c config.json \
  --dest example.com:443 --explain

# Test IP routing
cargo run -p app -- route -c config.json \
  --dest 1.2.3.4:80 --explain
```

### 3. Dry Run

```bash
# Enable dry-run mode in debug admin
cargo run -p app -- run -c config.json --admin-impl debug
```

---

**Contributions Welcome**: Submit your rule templates via pull request!

---

**Last Updated**: 2026-01-01
