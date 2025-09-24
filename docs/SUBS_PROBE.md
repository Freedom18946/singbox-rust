# sb-subs probe：本地订阅文件加载与体检（离线）

`probe` 用于**只读**本地订阅文件，进行**结构与关键字段体检**；不访问网络。

## 1. 用法
```bash
# YAML/JSON 自动识别；数组/对象均可
cargo run -q -p singbox-rust --bin sb-subs --features "subs_clash subs_singbox" -- \
  probe --file ./examples/subs.nodes.sample.json --fmt pretty --top 20 --out ./target/subs.probe.json

# 严格模式（发现问题即非零退出）
cargo run -q -p singbox-rust --bin sb-subs --features "subs_clash subs_singbox" -- \
  probe --file ./examples/subs.nodes.sample.json --strict

# 表格模式
cargo run -q -p singbox-rust --bin sb-subs --features "subs_clash subs_singbox" -- \
  probe --file ./examples/subs.nodes.sample.json --fmt table --field tag,type,server,server_port,tls.enabled --colmax 28

# 规范化导出
cargo run -q -p singbox-rust --bin sb-subs --features "subs_clash subs_singbox" -- \
  probe --file ./examples/subs.nodes.sample.json --dedup server_port \
  --export ./target/subs.filtered.singbox.json --normalize sing_box --stats-only
cargo run -q -p singbox-rust --bin sb-subs --features "subs_clash subs_singbox" -- \
  probe --file ./examples/subs.nodes.sample.json --dedup tag \
  --export ./target/subs.filtered.clash.json --normalize clash --stats-only
```

## 2. 体检项
- **结构识别**：根数组 / 对象字段 `proxies|outbounds|nodes`；
- **关键字段**：`server`、`server_port|port`、`type`；
- **TLS 概览**：`enabled/insecure/server_name` 分布；
- **重复与冲突**：`tag` 重复、`server:port` 重复；
- **问题列表**：缺失字段或类型错误的条目索引；
- **样例列表**：去敏的字段子集，便于人工排查。

## 3. 输出示例
```json
{
  "kind": "array",
  "items_total": 128,
  "by_type": { "trojan": 128 },
  "tls": { "enabled": 128, "insecure": 128, "missing_sni": 0 },
  "tags": { "duplicated": [["🇭🇰 HK | 香港 01", 2]] },
  "servers_top": [["sc6f40.kfsnuf.xyz:24105", 8], ["03047c.onndcm.xyz:24301", 3]],
  "problems": ["[77] 缺失 server 或 port/server_port"],
  "samples": [
    { "tag": "🇭🇰 HK | 香港 01", "type": "trojan", "server": "sc6f40.kfsnuf.xyz", "server_port": 24105,
      "tls": { "enabled": true, "server_name": "example.com", "insecure": true } }
  ]
}
```

### 表格示例（等宽裁剪）
```
tag    | type   | server      | server_port | port | tls.enabled
-------+--------+-------------+-------------+------+------------
HK 01  | trojan | example.hk  | 24105       |      | true
JP 01  | trojan | example.jp  |             | 24301| true
```

### 规范化导出（sing-box）
```json
[
  {"tag":"HK 01","type":"trojan","server":"example.hk","server_port":24105,"tls":{"enabled":true,"server_name":"hk.example"}},
  {"tag":"JP 01","type":"trojan","server":"example.jp","server_port":24301,"tls":{"enabled":true,"server_name":"jp.example"}}
]
```

### 规范化导出（clash 最小形）
```json
[
  {"name":"HK 01","type":"trojan","server":"example.hk","port":24105,"tls":true,"servername":"hk.example"},
  {"name":"JP 01","type":"trojan","server":"example.jp","port":24301,"tls":true,"servername":"jp.example"}
]
```

### 外部 Schema 映射导出（schema）
```json
[
  {"name":"HK 01","type":"trojan","server":"example.hk","server_port":24105,"tls":{"enabled":true}},
  {"name":"JP 01","type":"trojan","server":"example.jp","server_port":24301,"tls":{"enabled":true}}
]
```

## 5. Schema validation (optional)

When exporting subscription nodes with `--export`, you can optionally validate the output against a JSON Schema using the `--schema-validate` flag. This feature requires the `subs_schema` feature to be enabled.

```bash
# Schema validation with strict mode (fails on validation errors)
cargo run -q -p singbox-rust --bin sb-subs --features "subs_clash subs_singbox subs_schema" -- \
  probe --file ./examples/subs.nodes.sample.json --fmt json --dedup server_port \
  --export ./target/subs.filtered.json --normalize sing_box \
  --schema-validate ./examples/subs.schema.json --stats-only --strict

# Schema validation with warning mode (continues on validation errors)
cargo run -q -p singbox-rust --bin sb-subs --features "subs_clash subs_singbox subs_schema" -- \
  probe --file ./examples/subs.nodes.sample.json --fmt json --dedup server_port \
  --export ./target/subs.filtered.json --normalize sing_box \
  --schema-validate ./examples/subs.schema.json --stats-only
```

### Schema validation behavior

- **Only applies when `--export` is used**: Schema validation only validates exported items, not the probe analysis itself
- **Validation against normalized output**: Items are validated after applying `--normalize` and `--schema-map` transformations
- **Error handling with `--strict`**:
  - With `--strict`: Exits with non-zero code on validation errors
  - Without `--strict`: Prints warnings but continues processing
- **Error reporting**: Shows up to 5 validation errors with details, summarizes if more errors exist

### Example schema file

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Subscription Node Schema",
  "type": "object",
  "required": ["type", "server"],
  "properties": {
    "type": {
      "type": "string",
      "enum": ["trojan", "vmess", "vless", "shadowsocks", "socks", "http", "direct"]
    },
    "server": {
      "type": "string",
      "format": "hostname"
    },
    "server_port": {
      "type": "integer",
      "minimum": 1,
      "maximum": 65535
    }
  },
  "additionalProperties": false
}
```

### Expected failure samples

For testing schema validation and error handling, you can use the provided bad sample files:

```bash
# Test with intentionally malformed subscription data (EXPECTED_FAIL_SAMPLE)
cargo run -q -p singbox-rust --bin sb-subs --features "subs_clash subs_singbox subs_schema" -- \
  probe --file ./examples/subs.bad.json --fmt json --strict \
  --export ./target/subs.bad.export.json --normalize sing_box \
  --schema-validate ./examples/subs.schema.json 2>&1 || echo "Expected failure: $?"

# This should produce validation errors and exit with non-zero code when --strict is used
```

The `subs.bad.json` file contains intentionally malformed entries for testing:
- Missing required `type` field
- Missing `server` field
- Invalid field types
- Empty objects
- Unknown protocol types

## 6. 与远程订阅的关系
`probe` 是**离线体检**。远程订阅（HTTP/HTTPS 下载、鉴权、加密/混淆/握手）等能力将在**握手/加密完成后**再考虑接入，避免"半拉子"破坏用户预期。

## 7. 兼容性与稳定性
- 输出结构稳定、字段名固定；可在 CI 中长期快照对比；
- 对未知字段保持**忽略**策略，永不因新增字段而失败（Never break userspace）。
- 表格模式仅影响 stdout 呈现；`--out` 持续写 JSON 报告，脚本兼容性不变。
- Schema 验证为**可选**；未指定时行为不变。
- 导出为数组 JSON，字段按 `--normalize` 规范化处理，默认仅在缺失 `server_port` 时回填 `port`。