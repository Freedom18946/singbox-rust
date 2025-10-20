# JSON Schemas / JSON 模式定义

JSON Schema files for configuration validation and IDE autocompletion.

用于配置验证和 IDE 自动补全的 JSON Schema 文件。

---

## 📋 Available Schemas

### config.schema.json

**Purpose**: Main configuration file schema for singbox-rust.

**Validates**:

- Inbound configurations
- Outbound configurations
- Routing rules
- DNS settings
- Log configuration

**Usage in IDE**:

**VS Code** - Add to `.vscode/settings.json`:

```json
{
  "json.schemas": [
    {
      "fileMatch": ["config*.json", "**/configs/**/*.json"],
      "url": "./examples/schemas/config.schema.json"
    }
  ]
}
```

**JetBrains IDEs** (IntelliJ, WebStorm, etc.):

1. Open Settings → Languages & Frameworks → Schemas and DTDs → JSON Schema Mappings
2. Add new mapping:
   - Schema file: `examples/schemas/config.schema.json`
   - File pattern: `config*.json`

---

### subs.schema.json

**Purpose**: Subscription format schema.

**Validates**:

- Subscription source configuration
- Node list format
- Auto-update settings
- Probe configuration

**Usage**:

```json
{
  "json.schemas": [
    {
      "fileMatch": ["subs*.json", "subscription*.json"],
      "url": "./examples/schemas/subs.schema.json"
    }
  ]
}
```

---

### schema.map.json

**Purpose**: Schema mapping file for version-specific schemas.

**Contents**:

- Schema version mappings
- Compatibility information
- Migration guides

---

## 🔧 Using Schemas

### Command-Line Validation

Validate configuration against schema:

```bash
# Using app's built-in validator
cargo run -p app -- check -c config.json

# Using external tools (e.g., ajv-cli)
npm install -g ajv-cli
ajv validate -s examples/schemas/config.schema.json -d config.json
```

---

### IDE Integration

#### VS Code

1. Install "JSON Schema Validator" extension (optional, built-in support exists)
2. Configure in workspace settings:

```json
{
  "json.schemas": [
    {
      "fileMatch": [
        "config*.json",
        "**/examples/**/*.json",
        "**/configs/**/*.json"
      ],
      "url": "./examples/schemas/config.schema.json"
    },
    {
      "fileMatch": ["subs*.json"],
      "url": "./examples/schemas/subs.schema.json"
    }
  ]
}
```

**Benefits**:

- ✅ Autocompletion
- ✅ Real-time validation
- ✅ Inline documentation
- ✅ Error highlighting

---

#### IntelliJ IDEA / WebStorm

1. Open Settings
2. Navigate to: Languages & Frameworks → Schemas and DTDs → JSON Schema Mappings
3. Click "+" to add new schema
4. Configure:
   - Name: `singbox-rust config`
   - Schema file or URL: `<project>/examples/schemas/config.schema.json`
   - Schema version: `JSON Schema version 7`
   - File path pattern: `config*.json`

---

### Programmatic Validation

**Rust** (using `jsonschema` crate):

```rust
use jsonschema::JSONSchema;
use serde_json::json;

fn validate_config(config: &serde_json::Value) -> Result<(), String> {
    let schema = json!({
        // Load from config.schema.json
    });

    let compiled = JSONSchema::compile(&schema)
        .map_err(|e| format!("Schema compilation failed: {}", e))?;

    compiled.validate(config)
        .map_err(|errors| {
            errors.map(|e| e.to_string()).collect::<Vec<_>>().join(", ")
        })?;

    Ok(())
}
```

**JavaScript/TypeScript**:

```typescript
import Ajv from "ajv";
import configSchema from "./examples/schemas/config.schema.json";

const ajv = new Ajv();
const validate = ajv.compile(configSchema);

const config = {
  // Your configuration
};

if (!validate(config)) {
  console.error("Validation errors:", validate.errors);
}
```

---

## 📖 Schema Structure

### Top-Level Properties

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "singbox-rust Configuration",
  "type": "object",
  "properties": {
    "schema_version": { "type": "number" },
    "log": { "$ref": "#/definitions/LogConfig" },
    "inbounds": { "type": "array" },
    "outbounds": { "type": "array" },
    "route": { "$ref": "#/definitions/RouteConfig" },
    "dns": { "$ref": "#/definitions/DnsConfig" }
  },
  "required": ["inbounds", "outbounds"]
}
```

### Definitions

Schemas use `$ref` to reference reusable definitions:

```json
{
  "definitions": {
    "InboundConfig": {
      /* ... */
    },
    "OutboundConfig": {
      /* ... */
    },
    "RouteRule": {
      /* ... */
    },
    "DnsServer": {
      /* ... */
    }
  }
}
```

---

## 🔄 Schema Versioning

Schemas follow singbox-rust version numbers:

- **v0.1.x**: Initial schema (legacy)
- **v0.2.x**: Current schema (stable)
- **v0.3.x**: Next schema (development)

### Version Migration

When upgrading, use the format command:

```bash
# Migrate and format to latest schema
cargo run -p app -- format -c old-config.json -o new-config.json
```

---

## 🛠️ Extending Schemas

To add custom properties:

1. Create a copy of the schema
2. Add your custom definitions
3. Update `additionalProperties` if needed

**Example**:

```json
{
  "properties": {
    "custom_field": {
      "type": "string",
      "description": "My custom field"
    }
  }
}
```

---

## 💡 Tips

1. **Use $schema property**: Add `"$schema"` to your config files for IDE hints

   ```json
   {
     "$schema": "../examples/schemas/config.schema.json",
     "inbounds": [...]
   }
   ```

2. **Validate before deploy**: Always validate configs before deploying:

   ```bash
   cargo run -p app -- check -c config.json
   ```

3. **Check examples**: All example configs in `examples/` conform to schemas

4. **Report issues**: If schema validation conflicts with actual behavior, report a bug

---

## 📚 Related Documentation

- [Configuration Examples](../configs/)
- [JSON Schema Specification](https://json-schema.org/)
- [Main Examples README](../README.md)

---

## 🔗 External Tools

### Validation Tools

- **ajv-cli**: `npm install -g ajv-cli`
- **jsonschema (Python)**: `pip install jsonschema`
- **check-jsonschema**: `pip install check-jsonschema`

### Schema Editors

- [JSON Schema Editor](https://json-schema-editor.tangramjs.com/)
- [JSON Schema Lint](https://jsonschemalint.com/)

### Testing

```bash
# Validate all example configs
find examples/configs -name "*.json" -exec \
  cargo run -p app -- check -c {} \;
```

---

**Note**: Schemas are actively maintained and updated with new features. Always use the latest schema version from the repository.
