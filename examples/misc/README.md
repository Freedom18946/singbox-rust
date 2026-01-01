# Miscellaneous / 杂项文件

Additional helper files, legacy examples, and testing utilities.

额外的辅助文件、旧版示例和测试工具。

---

## 📋 File Inventory

### Testing & Profiling

#### chaos.profiles.json

**Purpose**: Chaos testing profiles for resilience testing.

**混沌测试配置** - 用于弹性测试。

**Contents**:

- Network failure scenarios
- Latency injection profiles
- Packet loss simulation
- Connection disruption patterns

**Usage**:

```bash
# Run with chaos profile (if implemented)
cargo run -p app -- run -c config.json --chaos-profile examples/misc/chaos.profiles.json
```

---

### Environment & Configuration

#### dns_pool_example.env

**Purpose**: Example environment variables for DNS pool configuration.

**DNS 池配置环境变量示例**。

**Contents**:

```bash
SB_DNS_ENABLE=1
SB_DNS_POOL="system,udp:127.0.0.1:1053,doh:https://cloudflare-dns.com/dns-query"
SB_DNS_POOL_STRATEGY=race
```

**Usage**:

```bash
# Load and run
source examples/misc/dns_pool_example.env
cargo run -p app -- run -c config.json
```

See [docs/ENV_VARS.md](../../docs/ENV_VARS.md) for all variables.

---

### Target Lists

#### targets.sample.txt

**Purpose**: Sample target list for testing and benchmarking.

**测试和基准测试的目标列表**。

**Format**:

```
example.com:443
google.com:80
1.1.1.1:53
```

**Usage**:

```bash
# Bulk connectivity test (if implemented)
cargo run -p app -- test-targets -c config.json -t examples/misc/targets.sample.txt
```

---

#### targets.auto.txt

**Purpose**: Auto-generated target list for continuous testing.

**自动生成的目标列表** - 用于持续测试。

**Usage**: Same as `targets.sample.txt`.

---

### Subscription Examples

#### subs.nodes.sample.json

**Purpose**: Sample subscription node list format.

**订阅节点列表示例格式**。

**Structure**:

```json
{
  "nodes": [
    {
      "type": "shadowsocks",
      "server": "example.com",
      "port": 8388,
      "method": "aes-256-gcm",
      "password": "password"
    }
  ]
}
```

**Usage**: Template for subscription implementations.

---

#### subs.bad.json

**Purpose**: Invalid subscription format for error testing.

**无效订阅格式** - 用于错误测试。

**Usage**: Validate error handling:

```bash
cargo run -p app -- check -c examples/misc/subs.bad.json
# Should return validation errors
```

---

### Legacy Configurations

#### v1_minimal.yml

**Purpose**: Legacy schema version 1 minimal configuration.

**旧版 schema v1 最小配置**。

**Note**: Kept for backward compatibility testing. New configs should use v2 format.

**Migration**:

```bash
cargo run -p app -- format -c examples/misc/v1_minimal.yml -o v2_config.json
```

---

#### v1_proxy.yml

**Purpose**: Legacy v1 proxy configuration example.

**旧版 v1 代理配置示例**。

**Features**:

- Old-style routing syntax
- Legacy DNS configuration
- Deprecated field names

**Status**: Use for testing migration tools only.

---

#### tuic_example.json

**Purpose**: Legacy TUIC configuration (before moving to `configs/outbounds/`).

**旧版 TUIC 配置** - 移动到 `configs/outbounds/` 前的版本。

**Note**: See `../configs/outbounds/tuic_outbound.json` for current version.

---

#### config.bad.json

**Purpose**: Intentionally malformed configuration for testing error handling.

**故意错误的配置** - 用于测试错误处理。

**Contains**:

- Invalid JSON syntax
- Missing required fields
- Type mismatches
- Invalid values

**Usage**:

```bash
# Should fail gracefully
cargo run -p app -- check -c examples/misc/config.bad.json
```

---

### Historical Scenarios

#### hs.scenarios.json

**Purpose**: Historical test scenarios (legacy).

**历史测试场景** (旧版)。

**Note**: Migrated to `../code-examples/testing/scenarios/`. Kept for reference.

---

## 🔧 Usage Patterns

### Testing Error Handling

```bash
# Test with invalid config
cargo run -p app -- check -c examples/misc/config.bad.json 2>&1 | grep "error"

# Test with bad subscription
cargo run -p app -- check -c examples/misc/subs.bad.json
```

### Environment Variable Testing

```bash
# Load DNS pool env
source examples/misc/dns_pool_example.env
env | grep SB_

# Run with loaded env
cargo run -p app -- run -c config.json
```

### Legacy Format Migration

```bash
# Migrate v1 to v2
cargo run -p app -- format \
  -c examples/misc/v1_minimal.yml \
  -o migrated_v2.json \
  --output-format json

# Validate migration
cargo run -p app -- check -c migrated_v2.json
```

---

## 💡 Tips

### 1. Don't Use in Production

These files are for **testing and development only**:

- ❌ Don't copy directly to production
- ❌ Don't rely on bad.json for actual configs
- ✅ Use as reference for testing
- ✅ Learn from legacy migration patterns

### 2. Environment Variables

Copy `dns_pool_example.env` and customize:

```bash
cp examples/misc/dns_pool_example.env .env.local
# Edit .env.local with your settings
source .env.local
```

### 3. Target Lists

Create your own target lists:

```bash
# Generate from monitoring
cat <<EOF > my-targets.txt
production.example.com:443
backup.example.com:443
dns.example.com:53
EOF

# Test connectivity
cargo run -p app -- test-targets -t my-targets.txt
```

---

## 🗂️ File Categories

### For Testing

- `config.bad.json` - Error handling
- `subs.bad.json` - Invalid subscription
- `chaos.profiles.json` - Resilience testing
- `targets.sample.txt` - Connectivity testing

### For Reference

- `v1_minimal.yml` - Legacy format
- `v1_proxy.yml` - Migration reference
- `tuic_example.json` - Historical example
- `hs.scenarios.json` - Old test scenarios

### For Configuration

- `dns_pool_example.env` - Environment variables
- `subs.nodes.sample.json` - Subscription format

---

## 🔗 Related Documentation

- [Environment Variables](../../docs/ENV_VARS.md)
- [Subscription Format](../../docs/SUBS_AUTOPROBE.md)
- [Testing Guide](../../docs/testing/)
- [Migration Guide](../../docs/NORMALIZE_SCHEMA.md)

---

## 📦 Archival Notice

Some files in this directory are kept for:

- **Backward compatibility** testing
- **Migration tool** validation
- **Error handling** test cases
- **Historical reference**

For current, production-ready examples, see:

- `../quick-start/` - Getting started
- `../configs/` - Protocol configurations
- `../code-examples/` - Integration examples

---

## 🧹 Cleanup Guidelines

When cleaning up old configs:

1. **Check dependencies**: Ensure no tests rely on these files
2. **Document changes**: Update CHANGELOG.md
3. **Archive if needed**: Move to `docs/archive/` if historically significant
4. **Update references**: Search for file references in code and docs

---

**Note**: This directory will shrink over time as legacy examples are migrated or deprecated.

---

**Last Updated**: 2026-01-01
