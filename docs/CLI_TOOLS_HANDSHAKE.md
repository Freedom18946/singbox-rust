# sb-check：配置校验工具

用于对 singbox-rust 配置文件进行基本结构校验和 JSON Schema 验证。

```bash
# Basic configuration validation
cargo run -q -p singbox-rust --bin sb-check -- --config ./examples/config.sample.json

# Schema validation with expected failure sample (EXPECTED_FAIL_SAMPLE)
cargo run -q -p singbox-rust --bin sb-check --features "config_schema" -- \
  --config ./examples/config.bad.json \
  --config-schema ./examples/config.schema.json 2>&1 || echo "Expected failure with bad config"

# Schema validation with valid config
cargo run -q -p singbox-rust --bin sb-check --features "config_schema" -- \
  --config ./examples/config.sample.json \
  --config-schema ./examples/config.schema.json
```

The `config.bad.json` file contains intentionally malformed configuration for testing:
- Invalid port types
- Missing required fields
- Unknown inbound/outbound types
- Invalid IP addresses
