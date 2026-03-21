# DSL Routing Rules / DSL 路由规则

Domain-Specific Language (DSL) for expressing routing rules in singbox-rust.

singbox-rust 的领域特定语言（DSL），用于表达路由规则。

---

## 📖 Basic Syntax

DSL provides a concise way to define routing rules:

```
<matcher>:<pattern>=<outbound>
```

### Example

```
exact:example.com=direct
suffix:.cn=proxy
keyword:ads=reject
cidr:192.168.0.0/16=direct
default:proxy
```

---

## 🎯 Matchers

### Domain Matchers

| Matcher    | Description         | Example                    |
| ---------- | ------------------- | -------------------------- |
| `exact:`   | Exact domain match  | `exact:example.com=direct` |
| `suffix:`  | Domain suffix match | `suffix:.cn=direct`        |
| `keyword:` | Contains keyword    | `keyword:ads=reject`       |

### Network Matchers

| Matcher    | Description    | Example                         |
| ---------- | -------------- | ------------------------------- |
| `cidr:`    | IP CIDR range  | `cidr:10.0.0.0/8=direct`        |
| `ip_cidr:` | Alias for cidr | `ip_cidr:192.168.0.0/16=direct` |

### Protocol Matchers

| Matcher      | Description    | Example                        |
| ------------ | -------------- | ------------------------------ |
| `transport:` | Protocol type  | `transport:udp,port:53=direct` |
| `port:`      | Port number    | `port:80,443=proxy`            |
| `portset:`   | Multiple ports | `portset:80,443,8080=proxy`    |

### Default Rule

| Matcher    | Description   | Example          |
| ---------- | ------------- | ---------------- |
| `default:` | Fallback rule | `default:direct` |

---

## 📝 Examples

### basic-routing.dsl

Simple routing rules for common use cases:

```
exact:example.com=direct
suffix:shop.com=proxyA
keyword:ads=reject
default:proxyB
```

Use these files as DSL reference material and test inputs for the DSL tooling in this repository.

---

### advanced-routing.dsl

Advanced patterns with CIDR and multiple matchers:

```
exact:example.com=direct
suffix:shop.com=proxyC
keyword:tracker=reject
cidr:192.168.0.0/16=direct
default:proxyB
```

**Features**:

- Private IP ranges
- Keyword-based blocking
- Domain suffix routing

---

## 📚 DSL Versions

### DSL v1 (`v1-examples.txt`)

Original DSL syntax with basic matchers.

### DSL v2 (`v2-examples.txt`)

Enhanced syntax with:

- Process matching (platform-specific)
- GeoIP/GeoSite support
- Rule set references

### DSL+ (`plus-syntax.txt`)

Extended syntax with:

- Logical operators (AND, OR, NOT)
- Rule priorities
- Include directives

---

## 🔧 Advanced Features

### Include Directive

Split rules into reusable snippets:

```
# Main rule file
include:snippets/block_ads.dsl
suffix:.cn=direct
default:proxy
```

**Snippet** (`snippets/block_ads.dsl`):

```
# Block ad domains
suffix:ads.example.com=reject
suffix:tracker.example.com=reject
```

---

### Combined Matchers

Use multiple conditions:

```
transport:udp,port:53=direct
transport:tcp,port:80,443=proxy
```

---

## 🎓 Learning Path

1. **Start Simple**: Review `basic-routing.dsl`
2. **Add Complexity**: Study `advanced-routing.dsl`
3. **Learn Extensions**: Read `plus-syntax.txt`
4. **Version Differences**: Compare `v1-examples.txt` vs `v2-examples.txt`

---

## 🔄 Converting to JSON

DSL rules can be converted to JSON format:

**DSL**:

```
suffix:.cn=direct
default:proxy
```

**Equivalent JSON**:

```json
{
  "route": {
    "rules": [
      {
        "when": {
          "domain_suffix": [".cn"]
        },
        "to": "direct"
      }
    ],
    "default": "proxy"
  }
}
```

---

## 💡 Tips

1. **Order Matters**: Rules are evaluated top-to-bottom
2. **Specificity**: More specific rules should come before general ones
3. **Testing**: Use `cargo run -p app -- route --explain` to debug
4. **Comments**: Use `#` for comments in DSL files

---

## 📖 Related Documentation

- [DSL Rules](../../docs/06-advanced-topics/dsl-rules.md)
- [Configuration Examples](../configs/)
- [Routing Examples](../configs/routing/)

---

## 🧩 Rule Snippets

See `snippets/` directory for reusable rule fragments:

- `block_ads.dsl` - Common ad/tracker blocking rules

More snippets coming soon!

---

**Note**: DSL syntax is continuously evolving. Check version-specific files for compatibility.
