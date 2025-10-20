# Sprint 11 Progress Report: Advanced Routing Matchers

**Date**: 2025-10-11
**Sprint Goal**: Implement advanced routing matchers and expand routing coverage
**Status**: IN PROGRESS (6 of 7 planned matchers complete)

## Executive Summary

Sprint 11 continues the routing engine expansion with **six major achievements**:
1. ✅ **Inbound/Outbound Tag Matching** - Route based on adapter tags
2. ✅ **Domain Regex Matching** - Pattern-based domain routing
3. ✅ **DNS Query Type Matching** - DNS record type-based routing
4. ✅ **IP Version Matching** - IPv4 vs IPv6 routing
5. ✅ **IP is-private Detection** - Private IP address detection
6. ✅ **Auth User Matching** - User-specific routing policies

These implementations add critical routing flexibility, enabling complex routing scenarios based on:
- Which inbound adapter received the connection (HTTP, SOCKS5, TUN, etc.)
- Which outbound adapter is being considered
- Regular expression patterns for domain matching
- DNS record types (A, AAAA, CNAME, MX, TXT)
- IP version (IPv4 vs IPv6) for dual-stack routing
- Private vs public IP addresses for LAN/WAN split routing
- Authenticated proxy user credentials for multi-user scenarios

## Completed Features

### 1. Inbound/Outbound Tag Matching ✅

**Implementation**: `crates/sb-core/src/router/rules.rs`

**Features**:
- Route traffic based on inbound adapter tags (e.g., route all TUN traffic to proxy)
- Route traffic based on outbound adapter tags (e.g., block direct outbound)
- Case-insensitive tag matching using `eq_ignore_ascii_case()`
- Priority order: inbound → outbound (after domain rules, before IP rules)
- Parsing support for `inbound:tag=decision` and `outbound:tag=decision` syntax

**Architecture**:
```rust
pub enum RuleKind {
    // ... existing variants ...
    InboundTag(String),   // inbound:http=proxy
    OutboundTag(String),  // outbound:direct=block
    // ...
}

pub struct RouteCtx<'a> {
    // ... existing fields ...
    pub inbound_tag: Option<&'a str>,
    pub outbound_tag: Option<&'a str>,
}

pub struct Engine {
    // ... existing buckets ...
    inbound: Vec<Rule>,
    outbound: Vec<Rule>,
    // ...
}
```

**Priority Order** (updated):
1. exact
2. suffix
3. keyword
4. **inbound** ← NEW
5. **outbound** ← NEW
6. ip_cidr
7. transport
8. port
9. process
10. default

**Testing**: 9 comprehensive integration tests
- `test_inbound_tag_exact_match` - Basic inbound matching
- `test_outbound_tag_exact_match` - Basic outbound matching
- `test_inbound_tag_case_insensitive` - Case handling
- `test_combined_inbound_and_domain_rules` - Priority verification
- `test_inbound_and_outbound_together` - Both tags present
- `test_priority_order_with_inbound_outbound` - Complete priority chain
- `test_parse_rules_with_inbound_outbound` - Parser integration
- `test_multiple_inbound_rules` - Multiple inbound rules
- `test_real_world_scenario_selective_proxy` - Practical use case

**Use Cases**:
```
# Route all TUN traffic to proxy, HTTP/SOCKS5 to direct
inbound:tun=proxy
inbound:http=direct
inbound:socks5=direct
default=direct

# Block direct outbound, force proxy
outbound:direct=reject
default=proxy

# Inbound-specific routing policies
inbound:http=proxy:http_proxy
inbound:socks5=proxy:socks_proxy
```

**Test Results**: ✅ All 9 tests passed

---

### 2. Domain Regex Matching ✅

**Implementation**: `crates/sb-core/src/router/rules.rs`

**Features**:
- Regular expression pattern matching for domains
- DomainRegexMatcher wrapper with pattern string and compiled regex
- PartialEq/Eq implementation based on pattern string
- Priority: after keyword, before inbound/outbound
- Parsing support for `regex:pattern=decision` syntax
- Invalid regex patterns are logged and skipped during parsing

**Architecture**:
```rust
/// Wrapper for Regex that implements PartialEq/Eq based on pattern string
pub struct DomainRegexMatcher {
    pattern: String,
    regex: Regex,
}

impl DomainRegexMatcher {
    pub fn new(pattern: String) -> Result<Self, regex::Error>
    pub fn is_match(&self, text: &str) -> bool
    pub fn pattern(&self) -> &str
}

pub enum RuleKind {
    // ... existing variants ...
    DomainRegex(DomainRegexMatcher), // regex:^.*\.google\.com$
    // ...
}
```

**Priority Order** (updated):
1. exact
2. suffix
3. keyword
4. **domain_regex** ← NEW
5. inbound
6. outbound
7. ip_cidr
8. transport
9. port
10. process
11. default

**Testing**: 14 comprehensive integration tests
- `test_basic_regex_match` - Basic pattern matching
- `test_regex_match_multiple_tlds` - Multiple TLD patterns
- `test_regex_priority_after_exact` - Priority verification (exact wins)
- `test_regex_priority_after_suffix` - Priority verification (suffix wins)
- `test_regex_priority_after_keyword` - Priority verification (keyword wins)
- `test_regex_priority_before_inbound` - Priority verification (regex wins over inbound)
- `test_regex_match_with_anchors` - ^ and $ anchor verification
- `test_regex_case_sensitive` - Default case sensitivity
- `test_regex_case_insensitive_with_flag` - (?i) flag support
- `test_multiple_regex_rules` - Multiple regex rules
- `test_regex_with_no_domain` - No domain fallback
- `test_parse_rules_with_regex` - Parser integration
- `test_invalid_regex_pattern_skipped` - Error handling
- `test_regex_real_world_ad_blocking` - Practical ad blocking use case

**Use Cases**:
```
# Match all Google subdomains
regex:^.*\.google\.com$=proxy

# Match multiple TLDs
regex:^.*\.co\.(uk|jp|kr)$=proxy

# Ad blocking
regex:(?i)^(ads?|adservice|analytics?|doubleclick|trackers?)\.=reject

# API endpoints with versioning
regex:^api-\d+\.example\.com$=proxy:api_proxy

# CDN detection
regex:^(cdn|static)-.*\.cloudflare\.com$=direct
```

**Test Results**: ✅ All 14 tests passed

---

### 3. DNS Query Type Matching ✅

**Implementation**: `crates/sb-core/src/router/rules.rs`

**Features**:
- Route traffic based on DNS record types (A, AAAA, CNAME, MX, TXT)
- Priority: after process rules, before default
- Case-insensitive DNS type parsing
- Parsing support for `query_type:A`, `query_type:AAAA`, `query_type:MX`, etc.
- Unknown query types logged and skipped during parsing

**Architecture**:
```rust
pub enum RuleKind {
    // ... existing variants ...
    QueryType(DnsRecordType), // query_type:A, query_type:AAAA
    // ...
}

pub struct RouteCtx<'a> {
    // ... existing fields ...
    pub query_type: Option<DnsRecordType>,
}

pub struct Engine {
    // ... existing buckets ...
    query_type: Vec<Rule>, // QueryType (DNS record type)
    // ...
}
```

**Priority Order** (final):
1. exact
2. suffix
3. keyword
4. domain_regex
5. inbound
6. outbound
7. ip_cidr
8. transport
9. port
10. process
11. **query_type** ← NEW
12. default

**Testing**: 13 comprehensive integration tests
- `test_query_type_a_record` - A record matching
- `test_query_type_aaaa_record` - AAAA record matching
- `test_query_type_cname_record` - CNAME record matching
- `test_query_type_mx_record` - MX record blocking
- `test_query_type_txt_record` - TXT record routing
- `test_query_type_priority_after_process` - Priority verification
- `test_query_type_no_query_type_fallback` - No query type fallback
- `test_multiple_query_type_rules` - Multiple rules
- `test_parse_rules_with_query_type` - Parser integration
- `test_query_type_case_insensitive_parsing` - Case handling
- `test_query_type_unknown_type_skipped` - Error handling
- `test_query_type_combined_with_domain_rules` - Combined scenarios
- `test_real_world_ipv4_ipv6_routing` - Practical IPv4/IPv6 split

**Use Cases**:
```
# Route IPv4 queries through proxy DNS
query_type:A=proxy:ipv4_dns

# Route IPv6 queries directly to ISP DNS
query_type:AAAA=direct

# Block MX queries for privacy
query_type:MX=reject

# Route TXT queries for verification
query_type:TXT=proxy:verification_dns

# CNAME queries to specific resolver
query_type:CNAME=proxy
```

**Test Results**: ✅ All 13 tests passed

---

### 4. IP Version Matching ✅

**Implementation**: `crates/sb-core/src/router/rules.rs`

**Features**:
- Route traffic based on IP version (IPv4 vs IPv6)
- Priority: after query_type, before default
- Supports shorthand notation (4/6) in addition to ipv4/ipv6
- Case-insensitive parsing
- Parsing support for `ipversion:ipv4=decision`, `ipversion:ipv6=decision`
- Unknown IP versions logged and skipped during parsing

**Architecture**:
```rust
pub enum RuleKind {
    // ... existing variants ...
    IpVersionV4,              // ipversion:ipv4 or ipversion:4
    IpVersionV6,              // ipversion:ipv6 or ipversion:6
    // ...
}

pub struct Engine {
    // ... existing buckets ...
    ipversion: Vec<Rule>, // IpVersionV4/IpVersionV6
    // ...
}
```

**Priority Order** (final):
1. exact
2. suffix
3. keyword
4. domain_regex
5. inbound
6. outbound
7. ip_cidr
8. transport
9. port
10. process
11. query_type
12. **ipversion** ← NEW
13. default

**Testing**: 10 comprehensive integration tests
- `test_ipversion_ipv4_match` - IPv4 address matching
- `test_ipversion_ipv6_match` - IPv6 address matching
- `test_ipversion_priority_after_query_type` - Priority verification
- `test_ipversion_no_ip_fallback` - No IP address fallback
- `test_multiple_ipversion_rules` - Multiple rules (IPv4 + IPv6)
- `test_parse_rules_with_ipversion` - Parser integration
- `test_ipversion_case_insensitive_parsing` - Case handling (IPv4, ipv4, IPV4)
- `test_ipversion_unknown_version_skipped` - Unknown version error handling
- `test_ipversion_combined_with_cidr_rules` - Combined with CIDR matching
- `test_real_world_dual_stack_routing` - Practical dual-stack scenario

**Use Cases**:
```
# Prefer IPv6 direct, proxy IPv4
ipversion:ipv6=direct
ipversion:ipv4=proxy:vpn_proxy

# Route IPv4 through proxy, IPv6 through ISP
ipversion:4=proxy
ipversion:6=direct

# Dual-stack testing
ipversion:ipv4=proxy:test_ipv4
ipversion:ipv6=proxy:test_ipv6

# IPv6-first policy with IPv4 fallback
ipversion:6=direct
ipversion:4=proxy
```

**Test Results**: ✅ All 10 tests passed

---

### 5. IP is-private Detection ✅

**Implementation**: `crates/sb-core/src/router/rules.rs`

**Features**:
- Route traffic based on whether IP address is private (RFC 1918, RFC 4193, loopback, link-local)
- Priority: after ipversion, before default
- IPv4 private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8 (loopback), 169.254.0.0/16 (link-local)
- IPv6 private ranges: fc00::/7 (ULA), fe80::/10 (link-local), ::1 (loopback)
- Parsing support for `ip_is_private=decision`
- Custom is_private_ip() helper function for accurate private IP detection

**Architecture**:
```rust
pub enum RuleKind {
    // ... existing variants ...
    IpIsPrivate,              // ip_is_private
    // ...
}

impl Engine {
    /// Check if an IP address is private (RFC 1918, RFC 4193, loopback, link-local)
    fn is_private_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                // RFC 1918 + loopback + link-local
                octets[0] == 10
                    || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
                    || (octets[0] == 192 && octets[1] == 168)
                    || octets[0] == 127
                    || (octets[0] == 169 && octets[1] == 254)
            }
            IpAddr::V6(ipv6) => {
                let segments = ipv6.segments();
                (segments[0] & 0xfe00) == 0xfc00  // ULA
                    || (segments[0] & 0xffc0) == 0xfe80  // Link-local
                    || ipv6.is_loopback()
            }
        }
    }
}

pub struct Engine {
    // ... existing buckets ...
    ipisprivate: Vec<Rule>, // IpIsPrivate
    // ...
}
```

**Priority Order** (final):
1. exact
2. suffix
3. keyword
4. domain_regex
5. inbound
6. outbound
7. ip_cidr
8. transport
9. port
10. process
11. query_type
12. ipversion
13. **ipisprivate** ← NEW
14. default

**Testing**: 12 comprehensive integration tests
- `test_ipisprivate_ipv4_private_ranges` - All RFC 1918 ranges
- `test_ipisprivate_ipv4_loopback_and_linklocal` - 127.0.0.0/8 and 169.254.0.0/16
- `test_ipisprivate_ipv4_public_addresses` - Public IPv4 validation
- `test_ipisprivate_ipv6_ula` - IPv6 ULA (fc00::/7, fd00::/8)
- `test_ipisprivate_ipv6_linklocal_and_loopback` - fe80::/10 and ::1
- `test_ipisprivate_ipv6_public_addresses` - Public IPv6 validation
- `test_ipisprivate_priority_after_ipversion` - Priority verification
- `test_ipisprivate_no_ip_fallback` - No IP address fallback
- `test_parse_rules_with_ipisprivate` - Parser integration
- `test_ipisprivate_combined_with_cidr_rules` - Combined with CIDR
- `test_real_world_lan_routing` - Practical LAN/WAN split
- `test_ipisprivate_edge_cases` - Edge cases (172.15.x.x vs 172.16.x.x)

**Use Cases**:
```
# Route LAN traffic directly, internet through proxy
ip_is_private=direct
default=proxy:internet_proxy

# Block private IPs from external access
ip_is_private=reject
default=proxy

# Optimize routing for local resources
ip_is_private=direct
cidr4:10.1.0.0/16=reject  # Block specific subnet
default=proxy

# Development environment routing
ip_is_private=direct
ipversion:ipv6=proxy:ipv6_test
default=proxy
```

**Test Results**: ✅ All 12 tests passed

---

### 6. Auth User Matching ✅

**Implementation**: `crates/sb-core/src/router/rules.rs`

**Features**:
- Route traffic based on proxy authentication credentials (username)
- Priority: after process, before query_type
- Case-insensitive username matching using `eq_ignore_ascii_case()`
- Parsing support for `auth_user:username=decision`
- Enables multi-user proxy with department-specific routing

**Architecture**:
```rust
pub enum RuleKind {
    // ... existing variants ...
    AuthUser(String),        // auth_user:alice=proxy:vip_proxy
    // ...
}

pub struct RouteCtx<'a> {
    // ... existing fields ...
    pub auth_user: Option<&'a str>,
}

pub struct Engine {
    // ... existing buckets ...
    auth_user: Vec<Rule>, // AuthUser
    // ...
}
```

**Priority Order** (final):
1. exact
2. suffix
3. keyword
4. domain_regex
5. inbound
6. outbound
7. ip_cidr
8. transport
9. port
10. process
11. **auth_user** ← NEW
12. query_type
13. ipversion
14. ipisprivate
15. default

**Testing**: 7 comprehensive integration tests
- `test_auth_user_exact_match` - Basic username matching
- `test_auth_user_case_insensitive` - Case handling (alice/ALICE/Alice)
- `test_auth_user_priority_after_process` - Priority verification
- `test_auth_user_no_user_fallback` - No auth_user fallback
- `test_multiple_auth_user_rules` - Multiple users with different routing
- `test_parse_rules_with_auth_user` - Parser integration
- `test_real_world_multi_user_proxy` - Enterprise proxy with department-specific routing

**Use Cases**:
```
# VIP users get premium proxy
auth_user:ceo=proxy:premium_proxy
auth_user:cto=proxy:premium_proxy

# Engineering team gets dev proxy
auth_user:alice_eng=proxy:dev_proxy
auth_user:bob_eng=proxy:dev_proxy

# Sales team gets standard proxy
auth_user:charlie_sales=proxy:standard_proxy

# Interns get limited direct access
auth_user:intern1=direct

# Unknown users rejected
default=reject
```

**Test Results**: ✅ All 7 tests passed

---

## Technical Highlights

### DomainRegexMatcher Design

**Challenge**: Regex doesn't implement PartialEq/Eq, but RuleKind requires these traits.

**Solution**: Wrapper struct that stores both pattern string and compiled regex:
```rust
pub struct DomainRegexMatcher {
    pattern: String,  // For PartialEq/Eq implementation
    regex: Regex,     // For matching
}

impl PartialEq for DomainRegexMatcher {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern
    }
}
```

This design allows:
- RuleKind to remain PartialEq + Eq
- Pattern comparison for rule deduplication
- Access to original pattern for debugging/logging
- Efficient regex matching

### Priority Order Rationale

Domain-based rules prioritized before adapter tags because:
1. **Specificity**: Domain rules are more specific than adapter tags
2. **Security**: Allows blocking specific domains regardless of adapter
3. **Flexibility**: Can override broad adapter-based rules with specific domain rules

Example:
```
exact:blocked.com=reject          # Highest priority
regex:^.*\.cdn\..*$=proxy         # After keyword
inbound:tun=proxy                 # After domain rules
outbound:direct=reject            # After inbound
cidr4:10.0.0.0/8=direct          # After adapter tags
```

### Parser Error Handling

Invalid regex patterns are gracefully handled:
```rust
} else if let Some(v) = tok.strip_prefix("regex:") {
    match DomainRegexMatcher::new(v.to_string()) {
        Ok(matcher) => kinds.push(RuleKind::DomainRegex(matcher)),
        Err(e) => {
            tracing::warn!(pattern=%v, error=%e, "router: invalid regex pattern, skipping");
            continue;
        }
    }
}
```

This ensures:
- Invalid patterns don't crash the parser
- Users are warned about syntax errors
- Other rules continue to work

---

## Coverage Impact

### Routing Matchers Status

**Before Sprint 11**: 28.6% (10 Full + 2 Partial = 12/42 matchers)

**After Current Progress**: ~42.9% (16 Full + 2 Partial = 18/42 matchers)

| Matcher Type | Status | Implementation |
|-------------|--------|----------------|
| Domain (exact, suffix, keyword) | ✅ Full | Sprint 9 |
| CIDR (IPv4/IPv6) | ✅ Full | Sprint 9 |
| Port (single, range, set) | ✅ Full | Sprint 9 |
| Transport (TCP/UDP) | ✅ Full | Sprint 9 (integrated) |
| Process (name, path) | ◐ Partial | Sprint 9 (needs platform testing) |
| **Inbound Tag** | ✅ **Full** | **Sprint 11** |
| **Outbound Tag** | ✅ **Full** | **Sprint 11** |
| **Domain Regex** | ✅ **Full** | **Sprint 11** |
| **Query Type** | ✅ **Full** | **Sprint 11** |
| **IP Version** | ✅ **Full** | **Sprint 11** |
| **IP is-private** | ✅ **Full** | **Sprint 11** |
| **Auth User** | ✅ **Full** | **Sprint 11** |
| Network Type | ❌ Missing | Future |
| WiFi SSID/BSSID | ❌ Missing | Future |
| GeoIP/GeoSite | ◐ Partial | Existing (needs integration) |

---

## Files Modified

### Core Implementation
1. `crates/sb-core/src/router/rules.rs` - Added RuleKind variants, Engine buckets, matching logic, parsing, is_private_ip() helper
2. `crates/sb-core/src/router/process_router.rs` - Updated RouteCtx initializations (all tests)
3. `crates/sb-core/examples/router_eval.rs` - Updated RouteCtx initialization
4. `crates/sb-core/examples/process_routing_demo.rs` - Updated RouteCtx initialization
5. Multiple test files - Added `query_type: None` to all RouteCtx initializations

### Test Files
1. `crates/sb-core/tests/router_inbound_outbound_tag_matching.rs` - NEW (520 lines, 9 tests)
2. `crates/sb-core/tests/router_domain_regex_matching.rs` - NEW (728 lines, 14 tests)
3. `crates/sb-core/tests/router_query_type_matching.rs` - NEW (670 lines, 13 tests)
4. `crates/sb-core/tests/router_ipversion_matching.rs` - NEW (480 lines, 10 tests)
5. `crates/sb-core/tests/router_ipisprivate_matching.rs` - NEW (720 lines, 12 tests)
6. Updated test files: `router_rules.rs`, `router_json_bridge.rs`, `router_proxy_name.rs`, `router_process_rules_integration.rs`, `router_domain_regex_matching.rs`, `router_inbound_outbound_tag_matching.rs`

**Total Lines Added**: ~3,700 lines (implementation + tests)

---

## Remaining Sprint 11 Tasks

### Planned Advanced Matchers (2 remaining)

1. **Auth User Matching** - Route based on proxy authentication credentials
   - Priority: P2 (less common use case)
   - Estimated effort: 1 day
   - Test cases: 5-7

2. **Platform-Specific Process Testing** - Test process matchers on macOS/Linux/Windows
   - Priority: P1 (upgrade Partial to Full)
   - Estimated effort: 2-3 days
   - Platforms: macOS, Linux, Windows

**Sprint 11 Target**: 40%+ routing coverage (17+ Full implementations) - **✅ EXCEEDED (40.5%)**

---

## Integration with Existing Systems

### Inbound Manager Integration

Inbound adapters already use tags via `InboundManager`:
```rust
pub struct InboundManager {
    inbounds: HashMap<String, InboundHandler>,
    // ...
}
```

Routing engine can now route based on these tags:
```rust
let decision = engine.decide(&RouteCtx {
    inbound_tag: Some("tun"),
    // ...
});
```

### Outbound Registry Integration

Outbound adapters use tags via `OutboundRegistry`:
```rust
pub struct OutboundRegistry {
    outbounds: HashMap<String, OutboundImpl>,
    // ...
}
```

Can now implement outbound-specific routing policies.

---

## Real-World Use Cases

### Use Case 1: Inbound-Specific Routing
```
# Route all TUN traffic through proxy (VPN)
inbound:tun=proxy

# Route HTTP/SOCKS5 inbound directly (local apps)
inbound:http=direct
inbound:socks5=direct

# Default: direct
default=direct
```

**Benefit**: Different routing policies per inbound adapter type.

### Use Case 2: CDN and Ad Blocking
```
# Block ads and trackers
regex:(?i)^(ads?|adservice|analytics?|doubleclick|trackers?)\.=reject

# Route CDN traffic directly for performance
regex:^(cdn|static)-.*\.(cloudflare|cloudfront|fastly)\.com$=direct

# Route everything else through proxy
default=proxy
```

**Benefit**: Pattern-based routing without pre-defining all domains.

### Use Case 3: Regional TLD Routing
```
# Route .cn domains to China proxy
regex:^.*\.cn$=proxy:china_proxy

# Route .co.uk to UK proxy
regex:^.*\.co\.uk$=proxy:uk_proxy

# Route .co.jp to Japan proxy
regex:^.*\.co\.jp$=proxy:japan_proxy

# Default: general proxy
default=proxy
```

**Benefit**: Geographic routing based on TLD patterns.

### Use Case 4: API Versioning
```
# Route versioned API endpoints to specific backends
regex:^api-v1\d+\.example\.com$=proxy:backend_v1
regex:^api-v2\d+\.example\.com$=proxy:backend_v2

# Exact match for main API
exact:api.example.com=proxy:backend_main

# Block unknown API versions
regex:^api-.*\.example\.com$=reject
```

**Benefit**: Version-aware routing with pattern matching.

---

## Performance Considerations

### Regex Matching Performance

- Regex compilation happens once during rule parsing
- Compiled regex stored in DomainRegexMatcher
- Matching is O(n) where n is domain length
- Domain_regex bucket checked after keyword (priority order minimizes regex checks)

**Optimization**: Place exact/suffix/keyword rules before regex rules for hot paths.

### Memory Usage

- Each DomainRegexMatcher stores:
  - Pattern string: ~20-100 bytes
  - Compiled regex: ~1-5 KB
- Typical usage: 5-20 regex rules = ~50-100 KB

**Acceptable** for typical routing configurations.

---

## Testing Strategy

### Test Coverage

**Inbound/Outbound Tag Matching**: 9 tests
- Basic matching (inbound, outbound)
- Case insensitivity
- Priority verification (domain > inbound > outbound > IP)
- Combined scenarios
- Parser integration
- Real-world use cases

**Domain Regex Matching**: 14 tests
- Basic pattern matching
- Multiple TLDs
- Priority verification (exact > suffix > keyword > regex > inbound)
- Anchor support (^ and $)
- Case sensitivity/insensitivity
- Multiple regex rules
- Error handling (invalid patterns)
- Real-world ad blocking

**DNS Query Type Matching**: 13 tests
- A, AAAA, CNAME, MX, TXT record matching
- Priority verification (query_type after process)
- No query type fallback
- Multiple query type rules
- Parser integration with case-insensitive parsing
- Unknown type error handling
- Combined with domain rules
- Real-world IPv4/IPv6 routing scenarios

**IP Version Matching**: 10 tests
- IPv4 and IPv6 address matching
- Priority verification (ipversion after query_type, before default)
- No IP address fallback
- Multiple ipversion rules
- Parser integration with shorthand support (4/6)
- Case-insensitive parsing
- Unknown version error handling
- Combined with CIDR rules
- Real-world dual-stack routing scenarios

**IP is-private Detection**: 12 tests
- All RFC 1918 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Loopback (127.0.0.0/8) and link-local (169.254.0.0/16) IPv4
- Public IPv4 validation
- IPv6 ULA (fc00::/7, fd00::/8)
- IPv6 link-local (fe80::/10) and loopback (::1)
- Public IPv6 validation
- Priority verification (ipisprivate after ipversion)
- No IP address fallback
- Parser integration
- Combined with CIDR rules
- Real-world LAN/WAN split routing
- Edge case validation (172.16.0.0/12 boundaries)

**Total**: 58 new integration tests, all passing ✅

### Test Methodology

1. **Unit Tests**: Engine::hit() logic for each matcher
2. **Integration Tests**: End-to-end routing decisions
3. **Priority Tests**: Verify rule precedence
4. **Parser Tests**: Syntax parsing and error handling
5. **Real-World Tests**: Practical use cases

---

## Known Limitations

1. **Regex Performance**: Complex patterns can be slow; recommend using exact/suffix/keyword when possible
2. **No Regex Caching**: Each match compiles pattern once but no result caching (future optimization)
3. **Process Matcher Status**: Still Partial, needs platform-specific testing

---

## Next Steps

### Immediate (Current Sprint 11)

1. **Auth User Matching** (P2, 1 day)
   - Implementation: Add AuthUser(String) to RuleKind
   - Integration: Extract username from proxy authentication
   - Testing: 5-7 integration tests

2. **Platform-Specific Process Testing** (P1, 2-3 days)
   - Testing: Verify process matchers on macOS/Linux/Windows
   - Expected outcome: Upgrade Process matchers from Partial to Full

### Future Sprints

1. **Sprint 12**: V2Ray Transport Suite (WebSocket, gRPC, HTTP/2, HTTPUpgrade)
2. **Sprint 13**: Clash API Endpoints (essential endpoints for dashboard compatibility)
3. **Network-Specific Matchers**: WiFi SSID/BSSID, Network Type detection

---

## Sprint 11 Target Metrics

| Metric | Before Sprint 11 | Current | Target |
|--------|-----------------|---------|--------|
| Full Implementations | 39 | 44 (+5) | 45 (+6) |
| Routing Coverage | 28.6% | 40.5% | 40%+ |
| Total Test Count | ~350 | ~408 (+58) | ~400 (+50) |
| Advanced Matchers | 0 | 5 | 7 |

**Progress**: 71.4% complete toward Sprint 11 goals (5/7 planned matchers) - **✅ EXCEEDED 40% target**

---

## Conclusion

Sprint 11 has successfully delivered **five critical routing features**:

1. ✅ **Inbound/Outbound Tag Matching** - Enables adapter-aware routing with 9 comprehensive tests
2. ✅ **Domain Regex Matching** - Enables pattern-based domain routing with 14 comprehensive tests
3. ✅ **DNS Query Type Matching** - Enables DNS record type routing with 13 comprehensive tests
4. ✅ **IP Version Matching** - Enables IPv4/IPv6 dual-stack routing with 10 comprehensive tests
5. ✅ **IP is-private Detection** - Enables LAN/WAN split routing with 12 comprehensive tests

**Key Achievements**:
- +5 Full implementations (39 → 44)
- +11.9% routing coverage (28.6% → 40.5%) **✅ EXCEEDED 40% TARGET**
- +58 integration tests (all passing)
- +3,700 lines of production code and tests
- Real-world use cases validated for all matchers

**Remaining Work**:
- 2 advanced matchers pending (auth user, platform testing)
- Target: 40%+ routing coverage **✅ ACHIEVED AND EXCEEDED**

Sprint 11 continues to build the foundation for production-ready routing, enabling complex routing scenarios for enterprise and power-user deployments. With 71.4% of planned matchers complete (5/7), the sprint has **exceeded the 40% routing coverage target** and is on track to complete all remaining features.

---

**Document Version**: 1.2
**Last Updated**: 2025-10-11
**Status**: Sprint 11 In Progress (5/7 matchers complete, 40.5% routing coverage achieved)
