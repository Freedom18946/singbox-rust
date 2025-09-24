# DNS Integration in Routing Decision Chain

This document describes the implementation of DNS system integration into the routing decision chain, completing task 7 from the singbox-rust completion specification.

## Overview

The DNS integration allows the router to resolve domain names and use the resolved IP addresses for routing decisions. This enables domain-based routing rules to work correctly with proper upstream selection.

## Implementation Components

### 1. DNS Bridge (`dns_bridge.rs`)

The DNS bridge provides adapters to connect the DNS module's `Resolver` trait with the router's `DnsResolve` trait:

- **`DnsResolverBridge`**: Adapts DNS module resolvers to work with the router engine
- **`EnhancedDnsResolver`**: Provides additional metrics and monitoring for DNS operations

### 2. Router Engine Integration (`engine.rs`)

Enhanced the `RouterHandle` with DNS integration:

- **`with_dns_resolver()`**: Convenience method to inject DNS module resolvers
- **`has_dns_resolver()`**: Check if DNS resolver is configured
- **Enhanced metrics**: DNS cache hit/miss tracking in `resolve_with_fallback()`

### 3. DNS Integration Utilities (`dns_integration.rs`)

Provides convenient functions for setting up DNS-enabled routing:

- **`setup_dns_routing()`**: Set up DNS-enabled routing with default configuration
- **`setup_dns_routing_with_config()`**: Custom configuration support
- **`validate_dns_integration()`**: Validation of DNS integration setup

### 4. Comprehensive Testing (`router_dns_integration.rs`)

Complete test suite covering:

- Domain resolution with IP-based routing rules
- Exact match priority over DNS resolution
- Timeout and error handling
- IPv6 support
- Multiple IP address handling
- DNS integration enable/disable functionality

## Key Features Implemented

### ✅ Router Accepts DNS Client Dependency

The `RouterHandle` now accepts DNS resolvers through:
```rust
pub fn with_dns_resolver(mut self, resolver: Arc<dyn crate::dns::Resolver>) -> Self
```

### ✅ Domain Resolution in Routing Decision Process

The routing engine integrates DNS resolution in the decision chain:
1. Exact/suffix rules (highest priority)
2. Literal IP rules
3. **DNS resolution → IP rules** (new integration)
4. GeoIP matching (if enabled)
5. Transport/port rules
6. Default fallback

### ✅ DNS Cache Hit/Miss Metrics and Monitoring

Enhanced metrics tracking:
- `dns_cache_hit_total{kind="hit"}` - Cache hits
- `dns_cache_hit_total{kind="miss"}` - Cache misses
- `dns_resolve_duration_ms` - Resolution timing
- `dns_resolve_total{result="success|error"}` - Resolution outcomes

### ✅ Tests for DNS-Based Routing Rule Evaluation

Comprehensive test coverage including:
- Domain resolution with CIDR rule matching
- Priority handling (exact > DNS+IP)
- Error and timeout scenarios
- IPv6 support validation
- Multiple IP address handling

### ✅ DNS Integration with Existing Routing Logic

The DNS integration preserves existing routing behavior:
- DNS resolution only occurs when enabled (`SB_ROUTER_DNS=1`)
- Existing exact/suffix/IP rules maintain priority
- Fallback behavior unchanged
- Performance impact minimized through caching

## Configuration

### Environment Variables

- `SB_ROUTER_DNS=1` - Enable DNS resolution in routing
- `SB_ROUTER_DNS_TIMEOUT_MS=5000` - DNS resolution timeout
- `SB_GEOIP_ENABLE=1` - Enable GeoIP matching after DNS resolution

### Usage Example

```rust
use sb_core::router::{setup_dns_routing, DnsIntegrationConfig};

// Simple setup with defaults
let router = setup_dns_routing();

// Custom configuration
let config = DnsIntegrationConfig {
    enabled: true,
    timeout_ms: 3000,
    enhanced_metrics: true,
    resolver_name: "custom".to_string(),
};
let router = setup_dns_routing_with_config(config);

// With custom resolver
let custom_resolver = Arc::new(MyDnsResolver::new());
let router = setup_dns_routing_with_resolver(custom_resolver, config);
```

## Architecture Integration

The DNS integration follows the existing architecture patterns:

1. **Separation of Concerns**: DNS logic separated from routing logic
2. **Interface Abstraction**: Bridge pattern for trait compatibility
3. **Metrics Integration**: Consistent with existing metrics patterns
4. **Error Handling**: Graceful degradation on DNS failures
5. **Performance**: Minimal impact on non-DNS routing paths

## Verification

The implementation satisfies all requirements from task 7:

- ✅ Router accepts DNS client dependency
- ✅ Domain resolution implemented in routing decision process
- ✅ DNS cache hit/miss metrics and monitoring added
- ✅ Comprehensive tests for DNS-based routing rule evaluation
- ✅ DNS integration works with existing routing logic
- ✅ Requirements 3.1 and 3.5 addressed

## Future Enhancements

Potential improvements for future iterations:

1. **DNS Rule Caching**: Cache routing decisions based on DNS results
2. **Health Checking**: Monitor DNS upstream health
3. **Load Balancing**: Distribute queries across multiple DNS upstreams
4. **Advanced Metrics**: Per-domain resolution statistics
5. **Configuration Hot Reload**: Dynamic DNS configuration updates

## Conclusion

The DNS integration successfully bridges the DNS module with the routing engine, enabling domain-based routing rules to work correctly while maintaining compatibility with existing functionality and providing comprehensive monitoring capabilities.