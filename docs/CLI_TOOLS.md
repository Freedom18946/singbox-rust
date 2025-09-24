# CLI 工具链（离线）

## sb-preview（路由预演）
构建**临时 RouterIndex**，对目标 host[:port] 做 explain（无需运行主服务）。支持 DSL+（include/macro），通过环境变量开启：
`SB_DSL_PLUS=1`。

```bash
cargo run -q -p singbox-rust --bin sb-preview --features preview_route -- \
  --dsl ./examples/dsl.sample.txt --target "www.shop.com:443" --proto tcp --fmt json
```

输出（示例）：

```json
{"decision":"proxyA","reason":"suffix matched host=www.shop.com","reason_kind":"suffix"}
```

**输出格式**
- `--fmt=min`：仅 `decision`
- `--fmt=json`：紧凑 JSON
- `--fmt=pretty`：美化 JSON
**DSL+（可选）**
- 启用：`SB_DSL_PLUS=1`；否则按标准 DSL 解析
- 能力：`include "<file>"`、`@macro NAME { ... }` / `use NAME`
- 仅做文本展开，不改变路由语义

**常见错误**
- DSL 语法错误 → `构建路由索引失败`
- target 缺失端口（在需要时）→ 由 preview 函数返回 reason_kind=bad_target

## sb-subs（订阅工具链：预览/差异/加载体检）

```bash
# 预览订阅计划（离线）
cargo run -q -p singbox-rust --bin sb-subs --features "subs_preview_plan" -- preview-plan --fmt pretty

# 订阅差异（离线）
cargo run -q -p singbox-rust --bin sb-subs --features "subs_diff" -- diff-full --fmt json

# 新增：本地订阅文件体检（不触网；JSON/YAML 自动识别）
cargo run -q -p singbox-rust --bin sb-subs --features "subs_clash subs_singbox" -- \
  probe --file ./examples/subs.nodes.sample.json --fmt pretty --top 20 --out ./target/subs.probe.json
# 若要对你的文件进行体检（例如你提供的 JSON），路径替换为你的文件：
# probe --file /path/to/79d98cb1-f1e2-41fd-886f-2fada3047a1c.json --fmt pretty --top 20 --out ./target/subs.probe.json
# 严格模式：发现问题则以非零码退出
cargo run -q -p singbox-rust --bin sb-subs --features "subs_clash subs_singbox" -- \
  probe --file ./examples/subs.nodes.sample.json --fmt json --strict

# 表格输出 + 列选择 + 裁剪
cargo run -q -p singbox-rust --bin sb-subs --features "subs_clash subs_singbox" -- \
  probe --file ./examples/subs.nodes.sample.json --fmt table --field tag,type,server,server_port,tls.enabled --colmax 24

# Schema validation with expected failure sample (EXPECTED_FAIL_SAMPLE)
cargo run -q -p singbox-rust --bin sb-subs --features "subs_clash subs_singbox subs_schema" -- \
  probe --file ./examples/subs.bad.json --fmt json --strict \
  --export ./target/subs.bad.export.json --normalize sing_box \
  --schema-validate ./examples/subs.schema.json 2>&1 || echo "Expected failure with bad schema"

# 筛选与限制输出条目
cargo run -q -p singbox-rust --bin sb-subs --features "subs_clash subs_singbox" -- \
  probe --file ./examples/subs.nodes.sample.json --fmt table \
  --field tag,type,server,server_port,tls.enabled --colmax 28 --grep HK --limit 50

### probe —— 导出与规范化

```bash
# 规范化为 sing-box
cargo run -q -p singbox-rust --bin sb-subs --features "subs_clash subs_singbox" -- \
  probe --file ./examples/subs.nodes.sample.json --fmt json --dedup server_port \
  --export ./target/subs.filtered.singbox.json --normalize sing_box --stats-only

# 规范化为 clash
cargo run -q -p singbox-rust --bin sb-subs --features "subs_clash subs_singbox" -- \
  probe --file ./examples/subs.nodes.sample.json --fmt json --dedup tag \
  --export ./target/subs.filtered.clash.json --normalize clash --stats-only

# 外部 Schema 映射：rename/coalesce/set/delete
cargo run -q -p singbox-rust --bin sb-subs --features "subs_clash subs_singbox" -- \
  probe --file ./examples/subs.nodes.sample.json --fmt json --dedup server_port \
  --export ./target/subs.filtered.custom.json --normalize schema \
  --schema-map ./examples/schema.map.json --stats-only
```

# 启用 AutoProbe（缺省关闭；不会触网）：
# 1) 显式一次性：--autoprobe <路径>
cargo run -q -p singbox-rust --bin sb-subs --features "subs_clash subs_singbox" -- \
  --autoprobe ./examples/subs.nodes.sample.json preview-plan --fmt json
# 2) 默认模式 + 环境变量（全局开关）：
SB_SUBS_AUTOPROBE=./examples/subs.nodes.sample.json \
  cargo run -q -p singbox-rust --bin sb-subs --features "subs_clash subs_singbox" -- \
  --autoprobe-default --autoprobe-fmt pretty --autoprobe-top 5 preview-plan
# 3) 默认模式 + 内置候选路径（若存在即体检）：
#    ./sub.json 或 /Users/bob/Desktop/Projects/ING/sing/singbox-rust/sub.json
cargo run -q -p singbox-rust --bin sb-subs --features "subs_clash subs_singbox" -- \
  --autoprobe-default preview-plan
```

### 说明

* `--diff-sample-mode random --seed` 保证可复现；`--cluster-by` 让样本覆盖更均衡。
* `--normalize schema` 仅影响导出文件；stdout/--out 的统计 JSON 不变。

## sb-dsl（DSL+ 工具）
纯离线工具，用于 **expand/lint/pack**：
```bash
# 展开 include/macro，打印标准 DSL
cargo run -q -p singbox-rust --bin sb-dsl --features "dsl_plus preview_route" -- \
  expand -i ./examples/dsl.plus.txt

# 校验并输出统计
cargo run -q -p singbox-rust --bin sb-dsl --features "dsl_plus preview_route" -- \
  lint -i ./examples/dsl.plus.txt --show

# 打包展开后的 DSL 到文件
cargo run -q -p singbox-rust --bin sb-dsl --features "dsl_plus preview_route" -- \
  pack -i ./examples/dsl.plus.txt -o ./target/expanded.dsl
```

**语法速览**
- 注释/空行：整行 `#` 或空白会被忽略
- `include "path/to/file.dsl"`：相对当前文件目录
- 宏：
  ```text
  @macro COMMON {
    suffix:shop.com=proxyA
    suffix:cdn.shop.com=direct
  }
  use COMMON
  ```

## sb-route（批量预演 / 对比 / 派生覆盖集）
```bash
# 批量预演（统计 reason_kind / decision 聚合）
cat examples/targets.sample.txt | \
  cargo run -q -p singbox-rust --bin sb-route --features "preview_route dsl_analyze dsl_derive" -- \
  explain-batch --dsl ./examples/dsl.sample.txt --proto tcp --fmt json

# 仅输出 summary（大集跑分降噪），并将 summary 落地
cat examples/targets.sample.txt | \
  cargo run -q -p singbox-rust --bin sb-route --features "preview_route dsl_analyze dsl_derive" -- \
  explain-batch --dsl ./examples/dsl.sample.txt --emit summary_only --fmt pretty \
  --out-summary ./target/explain.summary.json

# DSL 分析 —— 影子/遮蔽规则专用输出
cargo run -q -p singbox-rust --bin sb-route --features "preview_route dsl_analyze" -- \
  analyze --dsl ./examples/dsl.sample.txt --emit shadow_only --top 20 --fmt pretty \
  --out-shadow ./target/analyze.shadow.json

# 对比两份 DSL 的决策一致性（自动派生目标集上限 2000）
cargo run -q -p singbox-rust --bin sb-route --features "preview_route dsl_analyze dsl_derive" -- \
  compare --dsl-a ./examples/a.dsl --dsl-b ./examples/b.dsl --auto-limit 2000 --fmt pretty --diff-sample 50

# 从 DSL 自动派生覆盖性目标集（可用于上面 explain-batch）
cargo run -q -p singbox-rust --bin sb-route --features "preview_route dsl_analyze dsl_derive" -- \
  cover --dsl ./examples/a.dsl --output ./target/cover.targets --limit 5000
```
### Compare（差异对比）—— 抽样 + 聚类
```bash
# 按簇均匀抽样（reason_kind），随机且可复现 - 输出纯数组
cargo run -q -p singbox-rust --bin sb-route --features "preview_route dsl_analyze dsl_derive" -- \
  compare --dsl-a ./examples/a.dsl --dsl-b ./examples/b.dsl \
  --emit samples_only --fmt json \
  --diff-sample 64 --diff-sample-mode random --seed 42 \
  --cluster-by reason_kind --max-per-cluster 8 \
  > ./target/compare.samples.json

# 获取完整输出（含sample_meta内嵌）
cargo run -q -p singbox-rust --bin sb-route --features "preview_route dsl_analyze dsl_derive" -- \
  compare --dsl-a ./examples/a.dsl --dsl-b ./examples/b.dsl \
  --emit full --fmt json \
  --diff-sample 32 --cluster-by reason_kind --max-per-cluster 6

# 将sample_meta写入单独文件
cargo run -q -p singbox-rust --bin sb-route --features "preview_route dsl_analyze dsl_derive" -- \
  compare --dsl-a ./examples/a.dsl --dsl-b ./examples/b.dsl \
  --emit samples_only --fmt json \
  --diff-sample 32 --cluster-by reason_kind --max-per-cluster 6 \
  --out-sample-meta ./target/compare.sample_meta.json \
  > ./target/compare.samples.json

# 仅矩阵（样本 0）
cargo run -q -p singbox-rust --bin sb-route --features "preview_route dsl_analyze dsl_derive" -- \
  compare --dsl-a ./examples/a.dsl --dsl-b ./examples/b.dsl --emit matrix_only --diff-sample 0 --fmt json
```

### DSL 分析（新增 stats_only / pointer / out-analyze）
```bash
# 完整 JSON（pretty）
cargo run -q -p singbox-rust --bin sb-route --features "preview_route dsl_analyze dsl_derive" -- \
  analyze --dsl ./examples/dsl.sample.txt --fmt pretty

# 仅通用统计（结构无关），Top-20
cargo run -q -p singbox-rust --bin sb-route --features "preview_route dsl_analyze dsl_derive" -- \
  analyze --dsl ./examples/dsl.sample.txt --emit stats_only --top 20 --fmt pretty

# 用 JSON Pointer 抽取子树再做统计；并落地产物
cargo run -q -p singbox-rust --bin sb-route --features "preview_route dsl_analyze dsl_derive" -- \
  analyze --dsl ./examples/dsl.sample.txt --pointer '/rules' --emit stats_only \
  --out-analyze ./target/analyze.rules.stats.json --fmt pretty

# 仅影子规则（若存在），并落地报告
cargo run -q -p singbox-rust --bin sb-route --features "preview_route dsl_analyze" -- \
  analyze --dsl ./examples/dsl.sample.txt --emit shadow_only --top 15 \
  --out-shadow ./target/analyze.shadow.json --fmt json

# 键频 + 深度分布（结构无关），并落地 keys 报告
cargo run -q -p singbox-rust --bin sb-route --features "preview_route dsl_analyze" -- \
  analyze --dsl ./examples/dsl.sample.txt --emit keys_only --top 20 \
  --out-keys ./target/analyze.keys.json --fmt pretty
```
> 说明：`--pointer` 遵循 RFC6901（`/a/b/0` 指向对象 `a.b[0]`）。未命中时会给出告警并返回完整 JSON。

### 期望输出片段（示例）
> 形状示例，键名与计数取决于 DSL 与输入集；用于帮助新手理解输出结构。
```json
// explain-batch --emit summary_only
{
  "total": 12345,
  "elapsed_ms": 987,
  "per_sec": 12500,
  "reason_kind": { "suffix": 8000, "exact": 3345 },
  "decisions": { "direct": 12000, "proxy": 345 }
}
```
```json
// compare --emit samples_only (纯数组输出)
[
  { "target": "example.com", "a": { "decision": "direct", "reason_kind": "suffix" }, "b": { "decision": "proxy", "reason_kind": "exact" } },
  { "target": "api.shop.com", "a": { "decision": "proxy", "reason_kind": "suffix" }, "b": { "decision": "direct", "reason_kind": "cidr" } }
]
```
```json
// compare --emit full (包含sample_meta)
{
  "total": 2048,
  "equal": 1980,
  "diff": 68,
  "elapsed_ms": 420,
  "per_sec": 4876,
  "matrix": { "direct": { "direct": 1800, "proxy": 10 }, "proxy": { "direct": 5, "proxy": 233 } },
  "samples": [ { "target": "example.com", "a": { "decision": "direct" }, "b": { "decision": "proxy" } } ],
  "sample_meta": { "clusters": [{"key": "all", "size": 68, "picked": 50}] }
}
```
```json
// analyze --emit stats_only --top 3
{
  "summary": {
    "total_keys": 812,
    "rules_len": 128,
    "shadowed_len": 23
  },
  "top": {
    "reason_kind": [["suffix", 540], ["exact", 220], ["cidr", 52]],
    "decisions": [["direct", 700], ["proxy", 90], ["reject", 22]],
    "arrays_by_key": [["rules", 128], ["shadowed", 23], ["something_list", 5]]
  }
}
```

**ExplainBatch 输出**
- 行级：min（decision）/ json（目标+解释）/ pretty
- 可附加 `--summary` 聚合 `{ total, elapsed_ms, per_sec, reason_kind{*}, decisions{*} }`

**Compare 输出**
- 汇总：`{ total, equal, diff, elapsed_ms, per_sec }`
- `matrix`：混淆矩阵（决策 A → 决策 B 的计数）
- `samples`：最多 N 条差异样本（含 reason / reason_kind）
- `sample_meta`：仅出现在 `--emit full` 或通过 `--out-sample-meta` 写入文件

**重要**：`--emit samples_only` 输出纯数组格式 `[...]`，不包含 `sample_meta`。要获取聚类元信息，使用 `--emit full` 或 `--out-sample-meta`。

**Cover 输出**
- 将自动派生的目标集（exacts 优先，suffix 次之）写入文件或打印，用于后续 explain-batch。

### 字段说明（以实际实现为准）
- `dsl_in`: 解析与规范化后的输入 DSL
- `dsl_out`: 计划/补丁应用后的输出 DSL（当 `--apply` 为 true）
- `ordered`: 是否保持原条目相对顺序
- `normalize`: 是否进行归一化处理

### 常见问题（FAQ）
1. **为什么我拿不到 `dsl_out`？**
   - 检查是否加了 `--apply`，否则只会生成计划不落地。
2. **`--field` 返回空行**
   - 说明该字段不存在或为空，这是预期行为，脚本可用 `|| true` 忽略。
3. **Clash 与 sing-box 的差别**
   - `--format clash|singbox` 仅影响解析器与字段映射，不影响输出契约。

### Smoke & CI 提示

* 运行 `sb-check` 的最小示例（**推荐 JSON**，也支持 YAML 自动识别）：

  ```bash
  # JSON
  cargo run -q -p singbox-rust --bin sb-check -- --config ./examples/config.min.json
  # YAML
  cargo run -q -p singbox-rust --bin sb-check -- --config ./examples/config.min.yaml

  # 配置 schema 验证（需要 config_schema feature）
  cargo run -q -p singbox-rust --bin sb-check --features "config_schema" -- \
    --config ./examples/config.min.json --config-schema ./examples/config.schema.json
  ```

#### 配置 Schema 验证

`sb-check` 支持可选的 JSON Schema 验证功能，用于对配置文件进行结构验证：

- **Auto-detect format**: 自动识别配置文件的 JSON 或 YAML 格式
- **Schema validation**: 使用提供的 JSON Schema 文件验证配置结构
- **Error reporting**: 验证失败时显示前 5 个错误详情
- **Exit behavior**: 验证失败时以非零码退出

```bash
# Schema validation example
cargo run -q -p singbox-rust --bin sb-check --features "config_schema" -- \
  --config ./examples/config.min.json \
  --config-schema ./examples/config.schema.json
```

**注意**: `--config-schema` 功能需要启用 `config_schema` feature。如果未启用该 feature 但使用了 `--config-schema` 标志，工具将显示警告并退出。

### Smoke & CI 提示 (continued)

- 运行 `sb-route` 示例所需 features：

  * `explain-batch` 需要：`--features "preview_route dsl_analyze"`
  * `compare` 需要：`--features "preview_route dsl_analyze dsl_derive"`
  * `analyze` 需要：`--features "preview_route dsl_analyze"`
  * `analyze --emit shadow_only` 同上
- `sb-subs` 的 **AutoProbe** 缺省关闭；如需启用，请使用：
  * `--autoprobe <路径>`（一次性）或
  * `--autoprobe-default` + `SB_SUBS_AUTOPROBE=<路径>`（全局）；或依赖内置候选（存在才读取）。


### Handshake alpha（可选）
见 `docs/HANDSHAKE_ALPHA.md`。该特性默认关闭；开启后可用于离线 shape/长度自测，不做真实网络与加密。

**快速验证**:
```bash
# 生成测试会话
cargo run -q -p singbox-rust --features "handshake_alpha" --bin sb-handshake -- \
  loopback --proto vmess --host example.com --port 443 --seed 42 \
  --out ./target/hs.session.jsonl --obf xor:aa

# 生成指标（限制前3个head8模式）
cargo run -q -p singbox-rust --features "handshake_alpha" --bin sb-handshake -- \
  metrics --from ./target/hs.session.jsonl --out ./target/hs.metrics.json --head8-top 3

# 严格模式重放验证
cargo run -q -p singbox-rust --features "handshake_alpha" --bin sb-handshake -- \
  replay --proto vmess --host example.com --port 443 --from ./target/hs.session.jsonl --strict
```

所有操作均为离线，适用于 CI 环境中的形状一致性检查。
