# Route Test Vectors

This directory contains minimal configuration samples for route explain testing.

## Test Cases

### direct.json
- **Scenario**: Direct connection (localhost bypass)
- **Expected**: dest → DIRECT
- **Rule**: domain match for localhost/127.0.0.1

### blackhole.json
- **Scenario**: Block specific domains (ads filtering)
- **Expected**: ads.example.com → BLOCK
- **Rule**: domain match → blackhole outbound

### selector.json
- **Scenario**: Tag-based selection
- **Expected**: *.example.com → SELECT (which chooses from proxy1/proxy2)
- **Rule**: domain_suffix match → selector outbound

### geoip.json
- **Scenario**: GeoIP-based routing
- **Expected**: CN/private IP → DIRECT, others → PROXY
- **Rule**: geoip match

## Usage in Tests

```rust
#[test]
fn route_vector_direct() {
    let config = include_str!("route_vectors/direct.json");
    // Parse, explain, assert dest/matched_rule/outbound
}
```

## Compatibility Note

These vectors are designed for:
- Structural stability testing (field presence, types)
- Cross-implementation comparison (Go vs Rust)
- Regression detection (output format changes)

Do not compare exact `matched_rule` values across implementations unless rule hashing is standardized.

