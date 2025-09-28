# CLI JSON Schema Contract

This document defines the JSON schema contracts for CLI commands and the stability policies that govern them.

## Overview

CLI commands that output JSON data follow strict schema contracts to ensure API stability for programmatic consumers. Any changes to these schemas are considered breaking changes and must follow semantic versioning practices.

## Contracted Commands

### `version --format json`

**Schema Contract:**
```json
{
  "name": "string",
  "version": "string", 
  "commit": "string",
  "date": "string",
  "features": ["string"]
}
```

**Field Descriptions:**
- `name`: Application name (always "singbox-rust")
- `version`: Semantic version string (e.g., "0.1.0")
- `commit`: Git commit hash (8+ characters)
- `date`: Build timestamp in ISO 8601 format
- `features`: Array of enabled cargo features (sorted alphabetically)

**Stability Policy:**
- All fields are required and must maintain their types
- New fields may be added as optional fields only
- Field names and types cannot be changed
- The `features` array must always be sorted

### `check --format json`

**Schema Contract:**
```json
{
  "ok": "boolean",
  "file": "string", 
  "issues": [
    {
      "kind": "error|warning",
      "ptr": "string",
      "msg": "string",
      "code": "string",
      "hint": "string?"
    }
  ],
  "summary": {
    "total_issues": "number",
    "errors": "number", 
    "warnings": "number"
  },
  "fingerprint": "string?",
  "canonical": "object?"
}
```

**Field Descriptions:**
- `ok`: Overall validation result (true = passed, false = failed)
- `file`: Path to the config file that was checked
- `issues`: Array of validation issues found
- `issues[].kind`: Issue severity ("error" or "warning")
- `issues[].ptr`: JSON Pointer (RFC 6901) to the problematic field
- `issues[].msg`: Human-readable error message
- `issues[].code`: Machine-readable error code (uppercase snake_case)
- `issues[].hint`: Optional suggestion for fixing the issue
- `summary`: Aggregate statistics about issues found
- `fingerprint`: Optional SHA256-8 hash of normalized config
- `canonical`: Optional normalized config object

**Issue Codes:**
The following issue codes are part of the stable contract:
- `SCHEMA_VIOLATION`: General schema validation failure
- `MISSING_FIELD`: Required field missing
- `TYPE_MISMATCH`: Wrong data type for field
- `UNKNOWN_FIELD`: Unexpected field in configuration
- `OUT_OF_RANGE`: Value outside acceptable range
- `PORT_CONFLICT`: Port numbers conflict
- `EMPTY_RULE_MATCH`: Routing rule has no match conditions

**Stability Policy:**
- Core fields (`ok`, `file`, `issues`, `summary`) cannot be removed or changed
- Issue code values are stable and cannot be changed
- New issue codes may be added
- Optional fields (`fingerprint`, `canonical`) may be present or absent

### `route --explain --format json`

**Schema Contract:**
```json
{
  "dest": "string",
  "matched_rule": "string",
  "chain": ["string"],
  "outbound": "string", 
  "rule_id": "string",
  "reason": "string",
  "trace": "object?"
}
```

**Field Descriptions:**
- `dest`: Destination address (host:port or IP:port)
- `matched_rule`: Human-readable name of the matched rule
- `chain`: Array of match conditions that applied
- `outbound`: Name of the selected outbound
- `rule_id`: SHA256-8 hash of the rule for stable identification
- `reason`: Human-readable explanation of the routing decision
- `trace`: Optional detailed trace information (when --trace flag used)

**Field Constraints:**
- `rule_id`: Must be exactly 8 lowercase hexadecimal characters
- `chain`: Array of strings in format "type:value" (e.g., "geoip:US")
- `dest`: May include port or be just hostname/IP

**Stability Policy:**
- All core fields are required and cannot be removed
- Field types cannot be changed
- The `trace` field is optional and may be extended
- Rule ID format (SHA256-8) is stable

## Contract Testing

### Test Strategy

Each command has dedicated contract tests that:
1. Execute the actual CLI command
2. Parse and validate the JSON output 
3. Assert the presence and types of all required fields
4. Verify field constraints and formats
5. Ensure no unexpected fields are added

### Test Files

- `app/tests/version_contract.rs`: Version command schema tests
- `app/tests/check_schema_v2.rs`: Check command schema tests  
- `app/tests/route_explain.rs`: Route explain command schema tests

### Continuous Integration

Contract tests run on every commit to catch breaking changes early. Any schema changes that break these tests require:
1. Explicit documentation of the breaking change
2. Version bump according to semantic versioning
3. Migration guide for consumers

## Stability Policies

### Semantic Versioning

Schema changes follow semantic versioning:
- **MAJOR**: Breaking changes (field removal, type changes, required field additions)
- **MINOR**: Backward-compatible additions (new optional fields)
- **PATCH**: No schema changes, only implementation fixes

### Deprecation Process

When fields need to be removed:
1. Mark field as deprecated in documentation
2. Add deprecation warning in next minor version
3. Remove field in next major version
4. Provide migration period of at least 6 months

### Error Handling

JSON output must always be valid JSON, even in error conditions:
- Parsing errors return valid error JSON with appropriate fields
- Network failures are handled gracefully
- Invalid arguments produce structured error responses

## Consumer Guidelines

### Parsing Best Practices

For robust consumption of CLI JSON output:

```bash
# Always validate JSON before processing
if ! jq empty <<< "$output" 2>/dev/null; then
  echo "Invalid JSON output" >&2
  exit 1
fi

# Check for required fields
if ! jq -e '.ok' <<< "$output" >/dev/null; then
  echo "Missing required 'ok' field" >&2
  exit 1  
fi
```

### Forward Compatibility

Write consumers to be tolerant of:
- New optional fields
- Extended arrays with additional elements
- Additional enum values in string fields

### Error Handling

Always check the `ok` field in structured responses:
```bash
if jq -e '.ok == false' <<< "$output" >/dev/null; then
  # Handle validation failures
  jq -r '.issues[] | "\(.kind): \(.msg)"' <<< "$output"
  exit 1
fi
```

## Migration Guide

### Version 0.1.x to Future Versions

This section will be updated as breaking changes are introduced. Current version (0.1.x) establishes the initial contract baseline.

## Implementation Notes

### JSON Formatting

All JSON output uses:
- Pretty printing with 2-space indentation
- Consistent field ordering
- UTF-8 encoding
- No trailing newlines in JSON content

### Performance Considerations

JSON serialization is optimized for:
- Minimal memory allocation
- Fast serialization of large config files
- Streaming output for large datasets

### Security

JSON output avoids:
- Sensitive data exposure (credentials, keys)
- Path traversal information
- Internal implementation details
