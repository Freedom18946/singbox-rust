# Schema v2 Error Format Implementation

This document describes the implementation of the Schema v2 error format system for singbox-rust, which provides structured error reporting with precise location information and issue classification.

## Overview

The Schema v2 error format system implements the following requirements:

1. **IssueCode enum** with variants: UnknownField, InvalidType, OutOfRange, MissingRequired, DuplicateTag
2. **RFC6901 JSON pointer** implementation for precise error location
3. **CLI integration** with `--schema-v2-validate` flag
4. **Structured error reporting** using existing ErrorReport
5. **SHA256 fingerprint generation** for error patterns

## CLI Integration

### Command Line Flag

The `--schema-v2-validate` flag has been added to the `singbox check` command:

```bash
singbox check -c config.yaml --schema-v2-validate
```

### Automatic Activation

Schema v2 validation is automatically enabled when using the `--deny-unknown` flag:

```bash
singbox check -c config.yaml --deny-unknown
```

### Output Format

The error output follows the structured format:

```json
{
  "ok": false,
  "file": "config.yaml",
  "issues": [
    {
      "kind": "config",
      "code": "UnknownField",
      "ptr": "/unknown_field",
      "msg": "schema v2 validation error: unknown field `unknown_field`",
      "hint": "Remove unknown field or check spelling"
    }
  ],
  "summary": {
    "errors": 1,
    "warnings": 0,
    "strict": false
  },
  "fingerprint": "sha256:a1b2c3d4e5f6..."
}
```

## Implementation Details

### Core Error System

The error system is implemented in `crates/sb-core/src/error.rs`:

- `SbError` enum with Config variant for schema errors
- `IssueCode` enum with all required variants
- `ErrorReport` struct with issues and fingerprint
- `Issue` struct with kind, code, ptr, msg, and hint fields

### CLI Integration

The CLI integration is implemented in `app/src/cli/check.rs`:

- `--schema-v2-validate` flag definition
- `validate_schema_v2()` function for validation logic
- Error classification and JSON pointer extraction
- Integration with existing error reporting system

### Fingerprint Generation

Fingerprints are generated using SHA256 of error patterns:

- Only `code` and `ptr` fields are used for fingerprint calculation
- Message content does not affect the fingerprint
- Deterministic generation ensures consistent results

## Testing

### Unit Tests

Unit tests are implemented in `crates/sb-core/src/test_integration.rs`:

- Error system integration tests
- Fingerprint generation correctness tests
- Requirements compliance verification

### Integration Tests

Integration tests are implemented in `app/tests/check_cli.rs`:

- CLI flag functionality tests
- Error format validation tests
- Fingerprint generation tests
- Feature availability tests

### Test Configurations

Test configurations are provided:

- `test_schema_v2_valid.yaml` - Valid configuration for positive tests
- `test_schema_v2_invalid.yaml` - Invalid configuration with unknown fields

## Usage Examples

### Basic Validation

```bash
# Validate configuration with schema v2
singbox check -c config.yaml --schema-v2-validate

# Output JSON format with fingerprint
singbox check -c config.yaml --schema-v2-validate --format json --fingerprint
```

### Error Detection

The system detects various types of schema errors:

1. **Unknown Fields**: Fields not defined in the schema
2. **Type Mismatches**: Wrong data types for fields
3. **Out of Range**: Values outside acceptable ranges
4. **Missing Required**: Required fields not present
5. **Duplicate Tags**: Duplicate identifiers

### Error Messages

Each error includes:

- **Kind**: Type of error (config, network, timeout, capacity)
- **Code**: Specific error code from IssueCode enum
- **Pointer**: RFC6901 JSON pointer to error location
- **Message**: Human-readable error description
- **Hint**: Optional suggestion for fixing the error

## Feature Flags

The implementation uses the following feature flags:

- `schema-v2`: Enables schema v2 generation and validation
- `error-v2`: Enables structured error reporting (optional)

Build with schema v2 support:

```bash
cargo build --features schema-v2
```

## Compatibility

The implementation maintains backward compatibility:

- Existing error handling continues to work
- New structured errors are opt-in via CLI flags
- Feature flags allow building without schema v2 support
- Graceful degradation when features are disabled

## Future Enhancements

Potential future improvements:

1. More detailed JSON pointer extraction from serde errors
2. Additional error classification for specific schema violations
3. Improved hint generation based on error context
4. Performance optimizations for large configuration files