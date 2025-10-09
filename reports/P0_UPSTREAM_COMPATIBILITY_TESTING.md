# P0 Upstream Compatibility Testing Guide

This document explains how to run upstream compatibility tests for P0 protocols.

## Overview

The P0 upstream compatibility tests verify that the Rust implementation of sing-box is compatible with the upstream Go implementation. These tests check:

1. **Config file compatibility**: Configs accepted by Go should be accepted by Rust
2. **Schema compatibility**: Field names and types should match
3. **Protocol compatibility**: Both implementations should understand the same protocol parameters

## Test Coverage

The compatibility test suite covers:

- **REALITY TLS**: Client/server config compatibility
- **ECH (Encrypted Client Hello)**: TLS extension config compatibility
- **Hysteria v1**: Protocol and authentication config compatibility
- **Hysteria v2**: Protocol, obfuscation, and authentication config compatibility
- **SSH**: Outbound config compatibility
- **TUIC**: Protocol and congestion control config compatibility
- **Mixed configs**: Complex configurations with multiple P0 protocols

## Prerequisites

### 1. Build or Download Upstream sing-box

You need the upstream Go sing-box binary. You can either:

**Option A: Download from releases**
```bash
# Download latest release from https://github.com/SagerNet/sing-box/releases
# For example:
wget https://github.com/SagerNet/sing-box/releases/download/v1.12.4/sing-box-1.12.4-linux-amd64.tar.gz
tar xzf sing-box-1.12.4-linux-amd64.tar.gz
export GO_SINGBOX_BIN=$(pwd)/sing-box-1.12.4-linux-amd64/sing-box
```

**Option B: Build from source**
```bash
cd upstream-sing-box
go build -o sing-box ./cmd/sing-box
export GO_SINGBOX_BIN=$(pwd)/sing-box
```

### 2. Set Environment Variable

The tests require the `GO_SINGBOX_BIN` environment variable to point to the upstream binary:

```bash
export GO_SINGBOX_BIN=/path/to/upstream/sing-box
```

If this variable is not set, the tests will skip with a message indicating the binary is not available.

## Running the Tests

### Run all compatibility tests

```bash
export GO_SINGBOX_BIN=/path/to/upstream/sing-box
cargo test --test p0_upstream_compatibility
```

### Run specific protocol tests

```bash
# Test REALITY compatibility
cargo test --test p0_upstream_compatibility test_reality_config_compatibility

# Test ECH compatibility
cargo test --test p0_upstream_compatibility test_ech_config_compatibility

# Test Hysteria v2 compatibility
cargo test --test p0_upstream_compatibility test_hysteria2_config_compatibility

# Test SSH compatibility
cargo test --test p0_upstream_compatibility test_ssh_config_compatibility

# Test TUIC compatibility
cargo test --test p0_upstream_compatibility test_tuic_config_compatibility
```

### Generate compatibility report

```bash
export GO_SINGBOX_BIN=/path/to/upstream/sing-box
cargo test --test p0_upstream_compatibility test_document_compatibility_results
```

This will create a report at `reports/p0_upstream_compatibility.md` documenting the test results.

## Test Behavior

### When GO_SINGBOX_BIN is set

- Tests will run config validation against both Rust and Go implementations
- Tests verify that both implementations accept/reject configs consistently
- Any mismatches will cause test failures with detailed output

### When GO_SINGBOX_BIN is not set

- Tests will skip with message: "Skipping test: GO_SINGBOX_BIN not set"
- This is expected behavior for CI environments without upstream binary
- Tests will still pass (skipped tests don't fail the build)

## Interpreting Results

### Success

When tests pass, it means:
- Config schemas are compatible between Rust and Go
- Field names and types match
- Validation logic is consistent

### Failure

If tests fail, check:
1. **Config format differences**: Field names or structure may differ
2. **Validation differences**: One implementation may be stricter
3. **Version mismatch**: Upstream version may have changed schema

Example failure output:
```
Config compatibility mismatch:
Go: Config validation passed
Rust: Error: unknown field 'new_field'
```

## Known Limitations

### What these tests DO verify

✅ Config file format compatibility  
✅ Schema field compatibility  
✅ Config validation consistency  
✅ Parameter naming and types  

### What these tests DO NOT verify

❌ **Wire protocol compatibility**: Actual network protocol behavior  
❌ **Runtime interoperability**: Rust client ↔ Go server communication  
❌ **Performance parity**: Speed and resource usage  
❌ **Edge case handling**: Unusual network conditions  

### Why runtime tests are not included

Full runtime interoperability tests would require:
1. Starting actual protocol servers (REALITY, Hysteria, etc.)
2. Network connectivity between test processes
3. TLS certificates and keys
4. Longer test execution time
5. Platform-specific networking setup

These are better suited for manual integration testing or dedicated E2E test environments.

## Manual Interoperability Testing

For production deployment, we recommend manual testing:

### Test Rust client → Go server

1. Start upstream Go sing-box server:
```bash
$GO_SINGBOX_BIN run -c server-config.json
```

2. Connect with Rust client:
```bash
cargo run -- run -c client-config.json
```

3. Verify traffic flows correctly

### Test Go client → Rust server

1. Start Rust server:
```bash
cargo run -- run -c server-config.json
```

2. Connect with upstream Go client:
```bash
$GO_SINGBOX_BIN run -c client-config.json
```

3. Verify traffic flows correctly

## Continuous Integration

### GitHub Actions Example

```yaml
- name: Download upstream sing-box
  run: |
    wget https://github.com/SagerNet/sing-box/releases/download/v1.12.4/sing-box-1.12.4-linux-amd64.tar.gz
    tar xzf sing-box-1.12.4-linux-amd64.tar.gz
    echo "GO_SINGBOX_BIN=$(pwd)/sing-box-1.12.4-linux-amd64/sing-box" >> $GITHUB_ENV

- name: Run compatibility tests
  run: cargo test --test p0_upstream_compatibility
```

### Local Development

Add to your shell profile:
```bash
# ~/.bashrc or ~/.zshrc
export GO_SINGBOX_BIN=/usr/local/bin/sing-box
```

## Troubleshooting

### Tests skip with "GO_SINGBOX_BIN not set"

**Solution**: Set the environment variable:
```bash
export GO_SINGBOX_BIN=/path/to/sing-box
```

### Tests fail with "No such file or directory"

**Solution**: Verify the binary path is correct:
```bash
ls -la $GO_SINGBOX_BIN
```

### Tests fail with "Permission denied"

**Solution**: Make the binary executable:
```bash
chmod +x $GO_SINGBOX_BIN
```

### Config compatibility mismatches

**Solution**: Check upstream version:
```bash
$GO_SINGBOX_BIN version
```

Ensure you're testing against the same version documented in the codebase (v1.12.4 stable).

## Updating Tests

When upstream sing-box releases new versions:

1. Update test configs to match new schema
2. Add tests for new protocol features
3. Update version references in this document
4. Re-run full test suite
5. Document any breaking changes

## Related Documentation

- [P0 Production Parity Spec](.kiro/specs/p0-production-parity/)
- [GO Parity Matrix](../GO_PARITY_MATRIX.md)
- [P0 Completion Summary](../P0_COMPLETION_SUMMARY.md)
- [Upstream sing-box Documentation](https://sing-box.sagernet.org/)

## Contact

For questions or issues with compatibility testing:
- Check existing test output for detailed error messages
- Review upstream sing-box documentation
- Compare config schemas between implementations
