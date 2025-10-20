# Advanced Topics

Deep dives into advanced features and use cases.

---

## Available Topics

### Anti-Censorship Protocols

- **[REALITY Deployment](reality-deployment.md)** - Production REALITY setup and best practices
- **[ECH Deployment](ech-deployment.md)** - Encrypted Client Hello configuration and testing
- **[Protocol Camouflage](protocol-camouflage.md)** - Traffic disguise strategies

### Routing & Traffic Management

- **[Custom Routing Strategies](custom-routing.md)** - Advanced routing patterns and techniques
- **[GeoIP/GeoSite Rules](geoip-geosite.md)** - Geographic routing and domain categories
- **[Process-Based Routing](process-routing.md)** - Route by application (native APIs)
- **[Rule DSL](dsl-rules.md)** - Domain-specific language for complex rules

### Subscription System

- **[Subscription Management](subscription-system.md)** - Remote subscription and auto-update
- **[Node Selection](node-selection.md)** - Automatic node selection strategies
- **[Health Checks](health-checks.md)** - URLTest and health monitoring

### Performance & Optimization

- **[Zero-Breakage Guarantees](zero-breakage.md)** - Backward compatibility strategy
- **[Multiplexing](multiplexing.md)** - yamux stream multiplexing for efficiency
- **[Connection Pooling](connection-pooling.md)** - Reusing connections

### Integration

- **[Scenarios](scenarios.md)** - Real-world deployment scenarios
- **[Chaos Engineering](chaos-engineering.md)** - Resilience testing
- **[Migration from sing-box](migration.md)** - Migrating from Go implementation

---

## REALITY Deep Dive

### What Makes REALITY Special?

**Traditional TLS proxies** are detectable because:

- Predictable TLS fingerprints
- Certificate SNI can be censored
- Active probing reveals proxy servers

**REALITY solves this** by:

1. **Masquerading**: Traffic looks identical to legitimate sites
2. **Fallback**: Failed auth connects to real target (no detection)
3. **X25519 Auth**: Client proves identity without revealing intent

### Production REALITY Setup

```yaml
# Server configuration
inbounds:
  - type: vless
    tag: reality-in
    listen: 0.0.0.0
    port: 443
    users:
      - uuid: user-uuid-here
        name: client1
    tls:
      enabled: true
      reality:
        enabled: true
        private_key: "server-private-key-64-hex"
        short_ids:
          - "0123456789abcdef"
          - "fedcba9876543210"
        fallback_server: "www.microsoft.com"
        fallback_port: 443
      sni: www.microsoft.com

# Client configuration
outbounds:
  - type: vless
    tag: reality-out
    server: your-server-ip
    port: 443
    uuid: user-uuid-here
    tls:
      enabled: true
      reality:
        enabled: true
        public_key: "server-public-key-64-hex"
        short_id: "0123456789abcdef"
      sni: www.microsoft.com
```

**Key decisions**:

- **Target domain**: Choose stable, popular sites (Microsoft, Apple, Cloudflare)
- **Port**: Use 443 (standard HTTPS) for least suspicion
- **Multiple short_ids**: Allow rotation without downtime

See [REALITY Deployment Guide](reality-deployment.md).

---

## Advanced Routing Patterns

### Pattern 1: Split Tunneling by Process

Route only specific applications through proxy:

```yaml
route:
  rules:
    # Browser through proxy
    - process_name: [chrome, firefox, safari]
      outbound: proxy

    # Terminal apps direct
    - process_name: [Terminal, iTerm2]
      outbound: direct

  default: direct
```

**Performance**: Native process matching is 149x faster on macOS!

### Pattern 2: Geo-Based Load Balancing

```yaml
outbounds:
  # US servers
  - type: urltest
    tag: us-group
    outbounds: [us-1, us-2, us-3]
    url: https://www.google.com/generate_204
    interval: 300s

  # EU servers
  - type: urltest
    tag: eu-group
    outbounds: [eu-1, eu-2, eu-3]

route:
  rules:
    # US services → US servers
    - domain_suffix: [netflix.com, hulu.com]
      outbound: us-group

    # EU services → EU servers
    - domain_suffix: [bbc.co.uk, arte.tv]
      outbound: eu-group
```

### Pattern 3: Time-Based Routing

Use external scripts to switch routing based on time/conditions:

```bash
#!/bin/bash
# switch-proxy.sh

HOUR=$(date +%H)

if [ $HOUR -ge 9 ] && [ $HOUR -le 17 ]; then
    # Work hours: use work proxy
    PROXY="work-proxy"
else
    # Off hours: use personal proxy
    PROXY="personal-proxy"
fi

# Update selector via Admin API
curl -X POST http://127.0.0.1:18088/admin/select \
  -d "{\"selector\": \"auto-select\", \"outbound\": \"$PROXY\"}"
```

See [Custom Routing](custom-routing.md).

---

## DSL Rules

Write complex rules using domain-specific language:

```
# dsl-rules.txt

# Block ads
domain_suffix(.doubleclick.net) => block
domain_suffix(.googlesyndication.com) => block

# China direct
geoip(cn) => direct
geosite(cn) => direct

# Streaming services
domain_keyword(netflix) => us-proxy
domain_keyword(youtube) => proxy

# Fallback
* => direct
```

**Compile to rule-set**:

```bash
singbox-rust rule-set compile dsl-rules.txt --out rules.srs
```

**Use in config**:

```yaml
route:
  rule_sets:
    - path: rules.srs
      tag: custom-rules
```

See [DSL Rules Guide](dsl-rules.md).

---

## Subscription System

### Auto-Update Subscriptions

```yaml
subscriptions:
  - url: https://example.com/subscription
    tag: main-sub
    auto_update: true
    update_interval: 24h
    user_agent: "singbox-rust/0.2.0"
```

### Node Filtering

```yaml
subscriptions:
  - url: https://example.com/subscription
    filters:
      # Only keep nodes with "US" in name
      - type: regex
        pattern: "US.*"

      # Exclude free nodes
      - type: exclude
        pattern: ".*free.*"
```

### Health-Based Selection

```yaml
outbounds:
  - type: urltest
    tag: auto-best
    subscription: main-sub
    url: https://www.google.com/generate_204
    interval: 300s
    tolerance: 50ms # Switch if difference > 50ms
```

See [Subscription System Guide](subscription-system.md).

---

## Zero-Breakage Guarantees

singbox-rust follows strict compatibility rules:

### ✅ We Will NEVER

1. **Remove config fields** - Only deprecate with warnings
2. **Change default behavior** - Without explicit opt-in
3. **Break CLI interfaces** - Commands stay stable
4. **Change JSON APIs** - Response format is stable

### ✅ We WILL

1. **Add new features** - Via opt-in flags
2. **Improve performance** - Without API changes
3. **Fix bugs** - Even if it changes behavior
4. **Deprecate gracefully** - With migration guides

### Migration Strategy

**V1 → V2 Migration**:

```bash
# Automatic migration
singbox-rust check -c v1-config.json --migrate --out v2-config.yaml

# Both versions supported side-by-side
```

**Deprecation Process**:

1. Mark as deprecated (1-2 releases)
2. Show warnings (2-3 releases)
3. Remove (major version bump only)

See [Zero-Breakage Guarantees](zero-breakage.md).

---

## Real-World Scenarios

### Scenario 1: Remote Team VPN

**Requirements**:

- All traffic through company proxy
- Split tunneling for local resources
- Process-based routing for security tools

**Solution**: [VPN Scenario](scenarios.md#remote-team-vpn)

### Scenario 2: Streaming Service Unblocking

**Requirements**:

- US proxy for US content
- JP proxy for JP content
- Direct for local content

**Solution**: [Streaming Scenario](scenarios.md#streaming-unblock)

### Scenario 3: Development Proxy

**Requirements**:

- localhost always direct
- API calls through proxy
- Browser through system proxy

**Solution**: [Dev Proxy Scenario](scenarios.md#development-proxy)

See [Scenarios Guide](scenarios.md) for complete examples.

---

## Topics Index

| Topic               | Difficulty   | Documentation                   |
| ------------------- | ------------ | ------------------------------- |
| REALITY Deployment  | Advanced     | [Guide](reality-deployment.md)  |
| ECH Configuration   | Advanced     | [Guide](ech-deployment.md)      |
| Custom Routing      | Intermediate | [Guide](custom-routing.md)      |
| Process Matching    | Intermediate | [Guide](process-routing.md)     |
| DSL Rules           | Intermediate | [Guide](dsl-rules.md)           |
| Subscription System | Intermediate | [Guide](subscription-system.md) |
| Multiplexing        | Intermediate | [Guide](multiplexing.md)        |
| Zero-Breakage       | Reference    | [Guide](zero-breakage.md)       |
| Scenarios           | Practical    | [Guide](scenarios.md)           |

---

## Related Documentation

- **[User Guide](../01-user-guide/)** - Basic configuration
- **[Protocols](../01-user-guide/protocols/)** - Protocol details
- **[Operations](../03-operations/)** - Production deployment
- **[Development](../04-development/)** - Contributing
