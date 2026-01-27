# CLI Reference

Complete command-line interface documentation for singbox-rust.

---

## Overview

The `singbox-rust` binary provides a unified CLI for running the proxy server and managing configurations.

```bash
singbox-rust <COMMAND> [OPTIONS]
```

---

## Common Commands

### `run` - Start Proxy Server

Start the proxy server with specified configuration:

```bash
singbox-rust run -c config.yaml
```

**Options**:

- `-c, --config <FILE>` - Configuration file path (required)
- `--admin-impl <IMPL>` - Admin implementation: `core` or `debug` (default: `core`)
- `--admin-listen <ADDR>` - Admin API listen address (default: `127.0.0.1:18088`)

**Examples**:

```bash
# Basic usage
singbox-rust run -c config.yaml

# With debug admin API
singbox-rust run -c config.yaml --admin-impl debug --admin-listen 127.0.0.1:8088

# With environment variables
RUST_LOG=info SB_ADMIN_ENABLE=1 singbox-rust run -c config.yaml
```

See [run command](run.md) for details.

### `check` - Validate Configuration

Validate configuration file syntax and semantics:

```bash
singbox-rust check -c config.yaml
```

**Options**:

- `-c, --config <FILE>` - Configuration file to validate
- `--format <FORMAT>` - Output format: `text`, `json` (default: `text`)
- `--migrate` - Migrate V1 config to V2
- `--write-normalized` - Write normalized config
- `--out <FILE>` - Output file path (with `--write-normalized`)

**Exit codes**:

- `0` - Valid configuration
- `1` - Warnings (still usable)
- `2` - Errors (cannot run)

**Examples**:

```bash
# Basic validation
singbox-rust check -c config.yaml

# JSON output
singbox-rust check -c config.yaml --format json

# Migrate V1 to V2
singbox-rust check -c old-v1-config.json --migrate --write-normalized --out new-v2-config.yaml
```

See [check command](check.md) and [Exit Codes](exit-codes.md).

### `version` - Show Version Info

Display version, build info, and feature flags:

```bash
singbox-rust version
```

**Options**:

- `--format <FORMAT>` - Output format: `text`, `json` (default: `text`)

**Example output**:

```
singbox-rust v0.2.0
Rust: 1.90.0
Build: 2025-10-18T12:34:56Z
Commit: abc123def456
Features: acceptance,metrics,router,tls,quic
```

### `route` - Test Routing Decision

Explain routing decisions for a destination (stable schema):

```bash
singbox-rust route -c config.yaml --dest example.com:443 --explain
```

**Options**:

- `-c, --config <FILE>` - Configuration file
- `--dest <ADDR>` - Destination address (host:port)
- `--explain` - Show detailed explanation
- `--format <FORMAT>` - Output format: `text`, `json`
- `--trace` - Enable trace-level logging

**Example (JSON output fields)**:

```bash
singbox-rust route -c config.yaml --dest google.com:443 --explain --format json

# Output keys (stable):
# {
#   "dest": "google.com:443",
#   "matched_rule": "ab12cd34",    // sha256-8 of matched rule
#   "chain": ["domain:google.com", "geoip:US"],
#   "outbound": "proxy-us",
#   "trace": { ... }                // present only with --with-trace
# }
```

See [route-explain command](route-explain.md).

---

## Configuration Management

### `format` - Format Configuration File

Format and normalize configuration files:

```bash
singbox-rust format -c config.yaml -w
```

**Options**:

- `-c, --config <FILE>` - Configuration file
- `-w, --write` - Write changes back to file
- `--indent <NUM>` - Indentation spaces (default: 2)

**Example**:

```bash
# Format and print to stdout
singbox-rust format -c config.yaml

# Format and write back
singbox-rust format -c config.yaml -w
```

See [format command](format.md).

### `merge` - Merge Configuration Files

Merge multiple configuration files:

```bash
singbox-rust merge -c base.yaml -c override.yaml output.yaml
```

**Options**:

- `-c, --config <FILE>` - Configuration files (can be repeated)
- Last argument: output file path

**Example**:

```bash
# Merge base + prod overrides
singbox-rust merge -c config.base.yaml -c config.prod.yaml config.final.yaml
```

See [CLI Tools](https://github.com/sing-box/sing-box/blob/dev-next/docs/configuration/merge.md) for merge behavior (upstream reference).

---

## Data Management

### `geoip` - GeoIP Database Tools

Manage GeoIP databases:

```bash
# List all countries
singbox-rust geoip --file geoip.db list

# Lookup IP address
singbox-rust geoip --file geoip.db lookup 8.8.8.8

# Export country to SRS
singbox-rust geoip --file geoip.db export cn --out cn.srs
```

**Commands**:

- `list` - List all country codes
- `lookup <IP>` - Lookup IP address country
- `export <CODE>` - Export country to SRS format

See [geoip-geosite command](geoip-geosite.md).

### `geosite` - Geosite Database Tools

Manage geosite (domain category) databases:

```bash
# List all categories
singbox-rust geosite --file geosite.db list

# Lookup domain
singbox-rust geosite --file geosite.db lookup netflix.com

# Export category to SRS
singbox-rust geosite --file geosite.db export netflix --out netflix.srs
```

**Commands**:

- `list` - List all site categories
- `lookup <DOMAIN>` - Lookup domain categories
- `export <CATEGORY>` - Export category to SRS format

See [geoip-geosite command](geoip-geosite.md).

### `rule-set` - Rule Set Management

Manage rule-set files (SRS binary format):

```bash
# Compile rules to SRS
singbox-rust rule-set compile rules.json --out rules.srs

# Validate SRS file
singbox-rust rule-set validate rules.srs

# Convert formats
singbox-rust rule-set convert rules.json --out rules.srs

# Merge multiple rule-sets
singbox-rust rule-set merge file1.srs file2.srs --out merged.srs
```

**Commands**:

- `compile <FILE>` - Compile JSON rules to SRS binary
- `validate <FILE>` - Validate SRS file
- `convert <FILE>` - Convert between formats
- `merge <FILES...>` - Merge multiple rule-sets

See [rule-set command](rule-set.md).

---

## Code Generation

### `generate` - Generate Keypairs and Configs

Generate cryptographic keys and configurations:

```bash
# REALITY keypair
singbox-rust generate reality-keypair

# ECH keypair
singbox-rust generate ech-keypair

# WireGuard keypair
singbox-rust generate wireguard-keypair

# UUID
singbox-rust generate uuid

# TLS self-signed certificate
singbox-rust generate tls-cert \
  --domain example.com \
  --org "My Org" \
  --out-cert cert.pem \
  --out-key key.pem
```

**Commands**:

- `reality-keypair` - Generate X25519 keypair for REALITY
- `ech-keypair` - Generate ECH config and keys
- `wireguard-keypair` - Generate WireGuard keys
- `uuid` - Generate random UUID v4
- `tls-cert` - Generate self-signed TLS certificate

**Example output (reality-keypair)**:

```json
{
  "private_key": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "public_key": "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"
}
```

See [generate command](generate.md).

---

## Utility Tools

### `tools` - Network Utilities

Various network testing tools:

```bash
# TCP connect test
singbox-rust tools connect example.com:443 -c config.yaml

# HTTP(S) fetch test
singbox-rust tools fetch https://example.com -c config.yaml

# Sync system time via NTP
singbox-rust tools sync-time --server time.google.com:123
```

**Commands**:

- `connect <ADDR>` - Test TCP connection through routing
- `fetch <URL>` - Fetch URL through configured outbounds
- `sync-time` - Synchronize system time via NTP

**Options**:

- `-c, --config <FILE>` - Use configuration for routing
- `--outbound <TAG>` - Use specific outbound
- `--timeout <DURATION>` - Connection timeout

See [CLI Tools Handshake](CLI_TOOLS_HANDSHAKE.md) for integration.

---

## Benchmark Tools

### `bench` - Performance Benchmarks

Run I/O benchmarks:

```bash
singbox-rust bench io --url https://example.com --requests 100 --concurrency 10
```

**Options**:

- `--url <URL>` - Target URL
- `--requests <NUM>` - Number of requests (0 = unlimited)
- `--concurrency <NUM>` - Concurrent connections
- `--h2` - Use HTTP/2
- `--json` - JSON output

**Note**: Requires `reqwest` feature flag.

See [Operations Guide](../03-operations/README.md) for performance and runtime notes.

---

## Completion Generation

### `gen-completions` - Shell Completions

Generate shell completion scripts:

```bash
# Generate for all shells
singbox-rust gen-completions --all --dir completions/

# Generate for specific shell
singbox-rust gen-completions --shell bash --dir completions/
```

**Options**:

- `--shell <SHELL>` - Shell type: `bash`, `zsh`, `fish`, `powershell`, `elvish`
- `--all` - Generate for all shells
- `--dir <DIR>` - Output directory

**Installation**:

```bash
# Bash
cp completions/singbox-rust.bash /etc/bash_completion.d/

# Zsh
cp completions/_singbox-rust /usr/local/share/zsh/site-functions/

# Fish
cp completions/singbox-rust.fish ~/.config/fish/completions/
```

---

## Global Options

These options work with all commands:

| Option          | Description        | Example                  |
| --------------- | ------------------ | ------------------------ |
| `-h, --help`    | Show help message  | `singbox-rust --help`    |
| `-V, --version` | Show version       | `singbox-rust --version` |
| `-v, --verbose` | Increase verbosity | `singbox-rust -vvv run`  |
| `-q, --quiet`   | Decrease verbosity | `singbox-rust -q run`    |

---

## Environment Variables

Common environment variables:

| Variable          | Description          | Default           |
| ----------------- | -------------------- | ----------------- |
| `RUST_LOG`        | Log level filter     | `info`            |
| `RUST_BACKTRACE`  | Show backtraces      | `0`               |
| `SB_PRINT_ENV`    | Print env snapshot   | `0`               |
| `SB_DNS_ENABLE`   | Enable DNS features  | `0`               |
| `SB_DNS_MODE`     | DNS backend mode     | `system`          |
| `SB_ADMIN_ENABLE` | Enable admin API     | `0`               |
| `SB_ADMIN_LISTEN` | Admin listen address | `127.0.0.1:18088` |

See [Environment Variables](environment-variables.md) for complete list.

---

## Exit Codes

Standard exit codes across all commands:

| Code | Meaning    | Example                       |
| ---- | ---------- | ----------------------------- |
| `0`  | Success    | Valid config, successful run  |
| `1`  | Warnings   | Config valid but has warnings |
| `2`  | Errors     | Invalid config, runtime error |
| `3`  | Regression | Benchmark regression detected |

See [Exit Codes](exit-codes.md) for detailed explanations.

---

## Usage Examples

### Development Workflow

```bash
# 1. Create config
cat > config.yaml <<EOF
schema_version: 2
inbounds:
  - type: socks
    tag: socks-in
    listen: 127.0.0.1
    port: 1080
outbounds:
  - type: direct
    tag: direct
route:
  default: direct
EOF

# 2. Validate
singbox-rust check -c config.yaml

# 3. Test routing
singbox-rust route -c config.yaml --dest google.com:443 --explain

# 4. Format
singbox-rust format -c config.yaml -w

# 5. Run
singbox-rust run -c config.yaml
```

### Production Deployment

```bash
# 1. Validate production config
singbox-rust check -c config.prod.yaml --format json

# 2. Generate required keys
singbox-rust generate reality-keypair > keys.json

# 3. Run with systemd (see ops guide)
sudo systemctl start singbox-rust

# 4. Check logs
journalctl -u singbox-rust -f

# 5. Health check
curl http://127.0.0.1:18088/__metrics
```

### Migration from V1

```bash
# 1. Backup old config
cp config.json config.json.bak

# 2. Migrate to V2
singbox-rust check -c config.json \
  --migrate \
  --write-normalized \
  --out config.v2.yaml

# 3. Validate new config
singbox-rust check -c config.v2.yaml

# 4. Test with new config
singbox-rust run -c config.v2.yaml
```

---

## Command Reference

| Command                             | Purpose            | Quick Example                                             |
| ----------------------------------- | ------------------ | --------------------------------------------------------- |
| [`run`](run.md)                     | Start proxy server | `singbox-rust run -c config.yaml`                         |
| [`check`](check.md)                 | Validate config    | `singbox-rust check -c config.yaml`                       |
| [`version`](version.md)             | Show version       | `singbox-rust version`                                    |
| [`route`](route-explain.md)         | Test routing       | `singbox-rust route -c config.yaml --dest google.com:443` |
| [`format`](format.md)               | Format config      | `singbox-rust format -c config.yaml -w`                   |
| [`merge`](merge.md)                 | Merge configs      | `singbox-rust merge -c a.yaml -c b.yaml out.yaml`         |
| [`geoip`](geoip-geosite.md)         | GeoIP tools        | `singbox-rust geoip --file geoip.db list`                 |
| [`geosite`](geoip-geosite.md)       | Geosite tools      | `singbox-rust geosite --file geosite.db list`             |
| [`rule-set`](rule-set.md)           | Rule-set tools     | `singbox-rust rule-set compile rules.json`                |
| [`generate`](generate.md)           | Generate keys      | `singbox-rust generate reality-keypair`                   |
| [`tools`](tools.md)                 | Network utils      | `singbox-rust tools connect example.com:443`              |
| [`tools geodata-update`](tools.md#geodata-update) | Download geodata | `singbox-rust tools geodata-update --dest ./data`         |
| [`gen-completions`](completions.md) | Shell completions  | `singbox-rust gen-completions --all`                      |

---

## Getting Help

- **Per-command help**: `singbox-rust <command> --help`
- **User Guide**: [Configuration docs](../01-user-guide/README.md)
- **Examples**: [Example configurations](../08-examples/README.md)
- **Troubleshooting**: [Common issues](../TROUBLESHOOTING.md)

---

**Related Documentation**:

- [Environment Variables](environment-variables.md)
- [Exit Codes](exit-codes.md)
- [User Guide](../01-user-guide/README.md)
- [Operations Guide](../03-operations/README.md)
