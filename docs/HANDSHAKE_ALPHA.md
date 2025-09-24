# Handshake Alpha (离线握手测试工具)

**特性门控**: `handshake_alpha`
**用途**: 协议握手的离线形状与长度自测，不做真实网络连接与完整加密验证。

## 概述

`sb-handshake` 是一个用于离线测试协议握手包的工具，支持以下协议：
- Trojan
- VMess

工具提供多种模式用于握手包的生成、验证、回环测试和指标分析。

## 基本命令

### 1. encode - 生成握手包

生成协议的初始握手包并保存到文件：

```bash
cargo run -q -p singbox-rust --features "handshake_alpha" --bin sb-handshake -- \
  encode --proto trojan --host example.com --port 443 --seed 42 --out handshake.bin
```

### 2. roundtrip - 自洽性验证

测试 encode → decode 的自洽性（仅静态校验）：

```bash
cargo run -q -p singbox-rust --features "handshake_alpha" --bin sb-handshake -- \
  roundtrip --proto vmess --seed 42 --out roundtrip.bin
```

### 3. inspect - 包结构检查

生成握手包的结构信息（长度、头部、尾部）：

```bash
cargo run -q -p singbox-rust --features "handshake_alpha" --bin sb-handshake -- \
  inspect --proto trojan --host example.com --port 443 --seed 42 --out inspect.json
```

输出示例：
```json
{
  "proto": "Trojan",
  "len": 78,
  "head16": "474554202f20485454502f312e310d0a486f73743a20",
  "tail16": "0d0a0d0a"
}
```

## 高级功能

### 4. loopback - 回环测试

执行完整的回环测试，包含帧级日志记录：

```bash
# 基本回环测试
cargo run -q -p singbox-rust --features "handshake_alpha" --bin sb-handshake -- \
  loopback --proto vmess --host example.com --port 443 --seed 42 --out session.jsonl

# 带XOR混淆的回环测试
cargo run -q -p singbox-rust --features "handshake_alpha" --bin sb-handshake -- \
  loopback --proto vmess --host example.com --port 443 --seed 42 \
  --out session.jsonl --obf xor:aa
```

生成的 JSONL 文件包含帧级别的元数据：
```json
{"ts_ms":1674123456789,"dir":"tx","len":78,"head8_hex":"474554202f","tail8_hex":"0d0a0d0a"}
{"ts_ms":1674123456790,"dir":"rx","len":32,"head8_hex":"c7c5c42f","tail8_hex":"8c8a8d8f"}
```

### 5. metrics - 指标分析

从 JSONL 会话日志生成统计指标：

```bash
cargo run -q -p singbox-rust --features "handshake_alpha" --bin sb-handshake -- \
  metrics --from session.jsonl --out metrics.json --head8-top 3
```

输出示例：
```json
{
  "frames": 2,
  "tx": 78,
  "rx": 32,
  "head8_modes": [
    {"hex": "474554202f", "count": 1},
    {"hex": "c7c5c42f", "count": 1}
  ]
}
```

### 6. replay - 重放验证

从 JSONL 日志重放解码验证（仅处理 RX 帧）：

```bash
# 宽松模式（报告错误但不中断）
cargo run -q -p singbox-rust --features "handshake_alpha" --bin sb-handshake -- \
  replay --proto vmess --host example.com --port 443 --from session.jsonl

# 严格模式（遇到错误立即退出）
cargo run -q -p singbox-rust --features "handshake_alpha" --bin sb-handshake -- \
  replay --proto vmess --host example.com --port 443 --from session.jsonl --strict
```

## 本机 IO α（IoLocal）

> 特性门控：`--features "handshake_alpha,io_local_alpha"`
> 仅允许 `127.0.0.1` / `::1`，**不做 DNS**，不出网。

### 内置 Echo + XOR（可选）
```bash
cargo run -q -p singbox-rust --features "handshake_alpha,io_local_alpha" --bin sb-handshake -- \
  io-local --proto trojan --port 0 --seed 42 \
  --spawn-echo --obf-xor aa \
  --out ./target/hs.session.jsonl
```
随后可复用：
```bash
cargo run -q -p singbox-rust --features "handshake_alpha" --bin sb-handshake -- \
  metrics --from ./target/hs.session.jsonl --out ./target/hs.metrics.json --head8-top 3
cargo run -q -p singbox-rust --features "handshake_alpha" --bin sb-handshake -- \
  replay --proto trojan --host localhost --port 443 --from ./target/hs.session.jsonl --strict
```

### 进阶：Chaos 注入（延迟/丢包/截断/篡改）

```bash
# 注入 50ms 写延迟、20ms 读延迟；丢弃前 4 字节；截断到 16 字节；对回包再 XOR 0xaa
cargo run -q -p singbox-rust --features "handshake_alpha,io_local_alpha" --bin sb-handshake -- \
  io-local --proto trojan --port 0 --seed 42 --spawn-echo --obf-xor aa \
  --delay-tx-ms 50 --delay-rx-ms 20 --rx-drop 4 --rx-trim 16 --rx-xor aa \
  --out ./target/hs.session.iolocal.chaos.jsonl

# 度量（Top-3 head8）
cargo run -q -p singbox-rust --features "handshake_alpha" --bin sb-handshake -- \
  metrics --from ./target/hs.session.iolocal.chaos.jsonl --out ./target/hs.metrics.chaos.json --head8-top 3
```

### Chaos 预设与外部文件
支持三种来源，优先级：`--chaos-from` 外部 JSON > `--chaos-profile` 预设 > 零散 flags。

**内置预设**
- `none`：无注入（默认）
- `slowloss`：轻微时延 + 轻丢弃 + 截断 24B
- `evil`：强时延 + 丢弃 4B + 截断 16B + XOR AA
- `mobile3g`：模拟 3G 移动网络（延迟 120/180ms，轻丢包）
- `edge`：模拟边缘网络（延迟 250/350ms，中等丢包）
- `wifi_bad`：模拟不佳 WiFi（延迟 40/60ms，轻丢包）

**外部 JSON 示例（字段全部可选）**
```json
{ "delay_tx_ms": 25, "delay_rx_ms": 40, "rx_drop": 2, "rx_trim": 24, "rx_xor": "aa" }
```
用法：
```bash
cargo run -q -p singbox-rust --features "handshake_alpha,io_local_alpha" --bin sb-handshake -- \
  io-local --proto trojan --port 0 --spawn-echo --chaos-profile slowloss \
  --out ./target/hs.slowloss.jsonl
cargo run -q -p singbox-rust --features "handshake_alpha,io_local_alpha" --bin sb-handshake -- \
  io-local --proto trojan --port 0 --spawn-echo --chaos-from ./examples/chaos.profiles.json \
  --out ./target/hs.custom.jsonl
```

### JSONL 验证与阈值断言
```bash
# 验证（写报告）
cargo run -q -p singbox-rust --features "handshake_alpha" --bin sb-handshake -- \
  verify-jsonl --from ./target/hs.session.jsonl --out ./target/hs.verify.json

# 断言（最小帧/流量 + 最大乱序 + 长度阈值 + 片段频次）
cargo run -q -p singbox-rust --features "handshake_alpha" --bin sb-handshake -- \
  assert-metrics --from ./target/hs.session.jsonl \
  --min-frames 2 --min-tx 8 --min-rx 8 --max-disorder 0 \
  --len-min 8 --len-max 2048 --max-span-ms 8000 \
  --expect-head8 0b6578616d706c65:1 --expect-head8 deadbeef
```

### JSONL 切片（Slice）
```bash
# 仅保留 RX 帧，限制 10 行，且 head8 以 "0b65" 开头，写到新文件
cargo run -q -p singbox-rust --features "handshake_alpha" --bin sb-handshake -- \
  slice --from ./target/hs.session.jsonl --out ./target/hs.session.rx10.jsonl \
  --dir rx --limit 10 --head8-prefix 0b65
```

**不变性**：
- 默认关闭，参数层加法，不影响既有命令；
- 仅 localhost，路由层仍然**零 IO**，符合架构文档"路由不做 IO"。

## 场景驱动（RunScenarios）
把一系列命令固化为 JSON 场景文件，便于一键重放 + 断言。

**示例：examples/hs.scenarios.json**
```json
{
  "name": "alpha-smoke",
  "stop_on_fail": true,
  "steps": [
    { "action":"loopback", "proto":"trojan", "host":"example.com", "port":443, "seed":42, "out":"target/hs.loop.jsonl" },
    { "action":"verify_jsonl", "from":"target/hs.loop.jsonl", "out":"target/hs.loop.verify.json" },
    { "action":"assert_metrics", "from":"target/hs.loop.jsonl", "expect": { "min_frames":2, "min_tx":8, "min_rx":8, "max_disorder":0 } },
    { "action":"io_local", "proto":"vmess", "port":0, "seed":42, "out":"target/hs.iolocal.jsonl", "spawn_echo":true, "chaos_profile":"slowloss" },
    { "action":"verify_jsonl", "from":"target/hs.iolocal.jsonl", "out":"target/hs.iolocal.verify.json" }
  ]
}
```
运行（含默认 seed / 输出目录 / 变量注入）：
```bash
cargo run -q -p singbox-rust --features "handshake_alpha,io_local_alpha" --bin sb-handshake -- \
  run-scenarios --from ./examples/hs.scenarios.json \
  --default-seed 42 --out-dir ./target \
  --var RUN_ID=202501 --var SUITE=smoke \
  --out ./target/hs.${RUN_ID}.${SUITE}.summary.json \
  --report ./target/hs.${RUN_ID}.${SUITE}.report.json
```
输出包含每步结果与汇总，通过/失败一目了然。

### 场景：展开审阅（dry-run）

```bash
cargo run -q -p singbox-rust --features "handshake_alpha,io_local_alpha" --bin sb-handshake -- \
  run-scenarios --from ./examples/hs.scenarios.json \
  --default-seed 42 --out-dir ./target \
  --vars-from ./examples/scenarios/vars.dev.json \
  --var RUN_ID=2025Q1 --var SUITE=smoke \
  --dry-run --out ./target/hs.scenarios.expanded.json
```

### include / defaults / vars
- `include`: 在场景顶层添加 `include: ["./examples/scenarios/loopback.smoke.json", ...]`，会在当前 `steps` 前展开。
- `defaults.seed`: 允许 step 中写 `seed: 0`，由缺省值替代（保证数字类型不被字符串模板污染）。
- `defaults.out_dir`: 统一的输出根目录。相对 `from/out` 会拼接到该目录。
- `vars`: 仅用于字符串/路径字段（`out/from/chaos_from`）中的 `${KEY}` 模板替换；不会影响数值字段。

### 新的 chaos 预设
`mobile3g / edge / wifi_bad` 三档预设加入，便于快速模拟移动/边缘/WiFi 不佳环境；参数保守，**仅用于离线测试**。

## 混淆支持

当前支持的混淆方式：
- `xor:XX` - XOR混淆，其中XX为十六进制字节（如 `xor:aa`）

混淆仅在 loopback 模式下生效，用于测试不同的数据变换场景。

## CI 集成示例

```bash
# 生成测试会话
cargo run -q -p singbox-rust --features "handshake_alpha" --bin sb-handshake -- \
  loopback --proto vmess --host example.com --port 443 --seed 42 \
  --out ./target/hs.session.jsonl --obf xor:aa

# 生成指标
cargo run -q -p singbox-rust --features "handshake_alpha" --bin sb-handshake -- \
  metrics --from ./target/hs.session.jsonl --out ./target/hs.metrics.json --head8-top 3

# 验证重放（严格模式）
cargo run -q -p singbox-rust --features "handshake_alpha" --bin sb-handshake -- \
  replay --proto vmess --host example.com --port 443 --from ./target/hs.session.jsonl --strict
```

## 注意事项

1. **离线工具**: 不会进行真实的网络连接
2. **形状验证**: 主要用于包结构的一致性检查
3. **种子可控**: 使用固定种子确保测试结果可复现
4. **特性门控**: 必须启用 `handshake_alpha` 特性才能使用
5. **CI 友好**: 所有输出都遵循 `HS_OK:` 前缀格式，便于脚本解析

## 输出格式说明

- 所有成功操作都以 `HS_OK:` 开头
- JSON 输出使用 pretty 格式便于阅读
- JSONL 格式每行一个完整的 JSON 对象
- 错误时返回非零退出码