# CLI Schema Contract

JSON output fields for CLI and admin API responses.

## Common Fields

| Field | Type | Description |
|-------|------|-------------|
| `fingerprint` | string | Build version (e.g. `"0.1.0"`), always present |
| `config_fingerprint` | string | SHA256-8 of canonical config (sorted keys, no comments) |

## config_fingerprint Semantics

- **Computation**: `sha256(canonical_json)[0:8]` where canonical JSON has sorted keys and `//`/`#` comment keys removed
- **Presence**:
  - ✓ Startup JSON (`event: "started"`)
  - ✓ Reload success (`event: "reload", ok: true`)
  - ✓ Reload internal error (`event: "reload", ok: false, error.code: "internal"`)
  - ✗ Reload parse/validation errors (config wasn't valid)

## Example Outputs

### Startup
```json
{"event":"started","pid":1234,"config_fingerprint":"a1b2c3d4","fingerprint":"0.1.0"}
```

### Reload Success
```json
{"event":"reload","ok":true,"config_fingerprint":"a1b2c3d4","changed":{...},"fingerprint":"0.1.0","t":123}
```

### Reload Internal Error
```json
{"event":"reload","ok":false,"config_fingerprint":"a1b2c3d4","error":{"code":"internal","message":"..."},"fingerprint":"0.1.0","t":123}
```

### Reload Parse Error (no config_fingerprint)
```json
{"event":"reload","ok":false,"error":{"code":"parse_error","message":"..."},"fingerprint":"0.1.0","t":123}
```
