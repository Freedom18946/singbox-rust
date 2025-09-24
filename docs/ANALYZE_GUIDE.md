# sb-route analyze 增强指南（stats_only / shadow_only / keys_only / pointer / out-analyze）

本页解释 `sb-route analyze` 新增能力：**结构无关统计**、**JSON Pointer 子树抽取**、**产物落地**。借助这些能力，你可以把 DSL 静态分析的结果直接纳入自动化 Pipeline，与 `compare` / `explain-batch` 输出一起形成可diff、可追踪的三件套产物。

---

## 1. 为什么要做“结构无关”的统计？
分析器返回的 JSON 会随着核心升级而演化，但我们关注的指标大多是“常青”的：

- `reason_kind`：出现了哪些命中类型（suffix / exact / cidr / keyword / …）
- `decision`：最终路由决策分布（direct / proxy / reject / …）
- `rules_len`：DSL 中规则数组的规模
- `shadowed_len`：影子规则数量（键名中包含 `shadow` 的数组会被累计）
- `arrays_by_key`：每个数组键的体量（辅助定位超大集合）
- `total_keys`：对象键总数，用于粗略评估复杂度

因此我们通过一个递归遍历器对任意 JSON 做聚合统计——不依赖内部 schema，只要字段名称沿用上一代惯例就能自动感知。

> 这意味着“stats_only”模式可以在未来版本中保持稳定，即使核心再增删字段也不会崩。

---

## 2. 用法速览（命令行示例）

下面所有指令均假定在仓库根目录执行，并使用示例 DSL `./examples/dsl.sample.txt`：

```bash
# 2.1 完整 JSON（搭配 --fmt pretty 更易读）
cargo run -q -p singbox-rust --bin sb-route --features "preview_route dsl_analyze dsl_derive" -- \
  analyze --dsl ./examples/dsl.sample.txt --fmt pretty

# 2.2 仅输出结构无关统计，Top-10（默认 top=20，top=0 表示全量）
cargo run -q -p singbox-rust --bin sb-route --features "preview_route dsl_analyze dsl_derive" -- \
  analyze --dsl ./examples/dsl.sample.txt --emit stats_only --top 10 --fmt pretty

# 2.3 抽取 /rules 子树再做统计，并把结果写入文件（用于回归对比）
cargo run -q -p singbox-rust --bin sb-route --features "preview_route dsl_analyze dsl_derive" -- \
  analyze --dsl ./examples/dsl.sample.txt --pointer '/rules' --emit stats_only \
  --out-analyze ./target/analyze.rules.stats.json --fmt pretty

# 2.4 只抽取 JSON 子树（不做统计），并输出紧凑 JSON（默认 --emit full）
cargo run -q -p singbox-rust --bin sb-route --features "preview_route dsl_analyze dsl_derive" -- \
  analyze --dsl ./examples/dsl.sample.txt --pointer '/analysis/warnings/0'

# 影子/遮蔽规则（若 JSON 中存在相关数组/字段）
cargo run -q -p singbox-rust --bin sb-route --features "preview_route dsl_analyze" -- \
  analyze --dsl ./examples/dsl.sample.txt --emit shadow_only --top 20 --fmt pretty \
  --out-shadow ./target/analyze.shadow.json
```

> 所有示例均使用 `--features "preview_route dsl_analyze dsl_derive"`（二进制 `required-features` 要求），别忘了带上！

---

## 3. 输出示例与字段说明

### 3.1 `--emit full`（默认）
保留核心返回的原始 JSON。若指定 `--pointer`，则仅输出子树。

```json
{
  "analysis": {
    "rules": [
      { "line": 12, "kind": "suffix", "value": "shop.com", "decision": "proxy" },
      { "line": 30, "kind": "suffix", "value": "cdn.shop.com", "decision": "direct" }
    ],
    "shadowed": [
      { "victim": "suffix:foo.com", "winner": "suffix:*.com" }
    ],
    "warnings": []
  }
}
```

### 3.2 `--emit stats_only --top 3`
产出与结构解耦的统计汇总，适合做 diff。

```json
{
  "summary": {
    "total_keys": 812,
    "rules_len": 128,
    "shadowed_len": 23
  },
  "top": {
    "reason_kind": [["suffix", 540], ["exact", 220], ["cidr", 52]],
    "decisions": [["direct", 700], ["proxy", 90], ["reject", 22]],
    "arrays_by_key": [["rules", 128], ["shadowed", 23], ["targets", 12]]
  }
}
```

字段释义：

| 字段 | 类型 | 说明 |
| ---- | ---- | ---- |
| `summary.total_keys` | number | 所有对象键总和（粗视复杂度） |
| `summary.rules_len` | number | 存在 `rules` 数组时的长度，否则为 0 |
| `summary.shadowed_len` | number | 所有键名包含 `shadow` 的数组长度之和 |
| `top.reason_kind` | array | 命中理由字符串频次，按降序 Top-N |
| `top.decisions` | array | 决策字符串频次，按降序 Top-N |
| `top.arrays_by_key` | array | 各数组键累计长度（洞察大集合），按降序 Top-N |

Top-N 的语义：`--top N` 会在排序后截断，只保留前 N 个；`--top 0` 则表示不截断，可能生成很长的数组，需自行取舍。

### shadow_only 形状（示例）
```json
{
  "summary": { "shadow_arrays": 3, "shadow_items": 23 },
  "top_arrays": [["shadowed", 23], ["shadow_rules", 0]],
  "samples": [
    { "rule": "r42", "decision": "direct", "reason_kind": "suffix" }
  ]
}
```

### keys_only 形状（示例）
```json
{
  "keys_top": [["reason_kind", 540], ["decision", 700], ["rules", 1]],
  "depth": {
    "max": 6,
    "objects": [[0,1],[1,5],[2,9]],
    "arrays":  [[1,1],[2,2]],
    "values":  [[3,40],[4,120]]
  }
}
```

---

## 4. JSON Pointer 的行为

- 遵循 [RFC6901](https://www.rfc-editor.org/rfc/rfc6901)，例如 `/rules/0/decision`
- 若用户传入未带 `/` 的指针（例如 `rules/0`），CLI 会自动补上前缀 `/`
- 指针未命中时会打印告警并退回完整 JSON，再根据 `--emit` 决定输出内容
- 指针命中数组时，`stats_only` 会基于命中的数组重新统计（Top-N 只针对子树）

常见用途：

1. 针对 `analysis.rules` 做单独统计，观察规则体量变化
2. 分析 `analysis.shadowed` 子树，快速查看影子数是否激增
3. 针对 `warnings` 节点提取字符串列表，做监控或告警

---

## 5. 产物落地：`--out-analyze`

任何 `--emit` 生成的最终 JSON 均可通过 `--out-analyze PATH` 写入磁盘；输出始终为 pretty JSON，方便直接纳入 Git diff。

执行成功后会打印一条 recap：

```
ANALYZE_OUT: path='target/analyze.rules.stats.json' emit=StatsOnly pointer=/rules top=20
```

你可以借此在脚本中确认文件是否写入成功、命中的 pointer、截断阈值等信息。

---

## 6. 与其他 CLI 的组合姿势

1. **吞吐 + 对比 + 统计**：
   - `explain-batch --emit summary_only --out-summary` → 吞吐 & 聚合
   - `compare --emit matrix_only --out-matrix` → 路由矩阵对比
   - `analyze --emit stats_only --out-analyze` → DSL 结构与命中概览
   - 这三份 JSON 可以直接入库、入 Git 或统一送入告警系统

2. **Pointer + stats_only**：
   - 抽取 `/analysis/shadowed`，观察影子规则的数量
   - 抽取 `/analysis/duplicates`，辅助开发排查大规模重复项

3. **自定义 Top-N**：
   - 小规模 DSL 可以设 `--top 0` 输出全量
   - 大规模生产 DSL 建议设 `--top 20` 或更小，避免日志噪音

---

## 7. 设计取舍 & 注意事项

- **稳定性**：依赖键名而非 schema，一旦出现新的关键字段（例如未来引入 `reason_detail`），只需在遍历器里新增几行统计即可。
- **顺序可预测**：`BTreeMap` 确保同类项按键排序，diff 不会跳动。
- **性能**：遍历器是一次 DFS，复杂度与 JSON 大小线性；即使大型 DSL 也能在毫秒级完成。
- **扩展空间**：未来可根据真实需求继续补充特定字段的聚合（例如 shadow 样本 Top-N），而不会破坏现有 CLI 契约。

---

## 8. 常见问题（FAQ）

> **Q0. 为什么compare的`samples_only`输出没有`sample_meta`，在哪里能找到聚类信息？**
> A0. 这是userspace兼容性设计：`samples_only`输出纯数组`[...]`，便于scripts直接处理。聚类元信息(`sample_meta`)可通过以下方式获取：
>   - 使用`--emit full`，`sample_meta`会内嵌到完整JSON输出中
>   - 使用新增的`--out-sample-meta`参数将其写入单独文件
>   - 这确保现有工作流不受影响，同时提供可选的元信息访问方式

> **Q1. Pointer 输入了 `/analysis/rules`，结果还提示未命中？**
> A1. 请确认 `analysis_to_json` 的根结构是否含有 `analysis`；不同版本可能直接把 `rules` 放在顶层。如果不确定，可以先 `--emit full` 看结构。

> **Q2. `arrays_by_key` 中出现了陌生键名，是什么？**  
> A2. 统计器会把所有数组的键记录下来，帮助你定位谁是“最大的集合”。陌生键通常代表核心新增的数组结构，正好可以提醒关注。

> **Q3. 想对 `shadowed` 列表做更细致的排查怎么办？**
> A3. 已提供 `--emit shadow_only`：按键名包含 `shadow` 的数组进行聚合，并输出 Top-N 与样本；若不存在相关结构，`summary.shadow_arrays=0`。

> **Q4. keys_only 的用途？**
> A4. 当你拿到陌生版本分析 JSON 时，先用 `keys_only` 探查"键面"与"深度"，再决定抽样策略与派生目标集。

> **Q5. Compare 样本量太大怎么办？**
> A5. 用 `--diff-sample-mode random --seed 42` 取可复现子集；或 `--diff-sample 0` 仅看矩阵。

> **Q6. 可以直接把统计结果喂进 Prometheus / Loki 吗？**
> A6. 可以。`stats_only` 输出就是标准 JSON，可以配合 `jq` 转换成 key-value 或 metrics 格式。也可以在 CI 中直接比较上一版的 `summary.total_keys`、`rules_len` 差异。

---

## 9. 下一步：与 compare / explain 的协作

- **compare**：使用 `--emit matrix_only` 落地矩阵，搭配 `stats_only` 可以判断“差异发生在哪些决策 + 规则规模是否变化”。
- **explain-batch**：使用 `--emit summary_only` 跑吞吐，结合 `stats_only` 衡量“命中类型”是否偏移。
- **subs 工具链**：未来可将 `sb-subs plan` 产生的 DSL 直接送入 `analyze`，生成统计产物，从而构成“订阅 → DSL → 分析 → 回归”链路。

---

> Tips：搭配 `make ci-local` 或本文档给出的 GitHub Actions 片段，可以在 CI 中落地 `analyze.stats.json`，把 DSL 规模变化第一时间呈现给评审者。

---

## 10. JSON Pointer 速查表

| 目标 | Pointer 写法 | 说明 |
| ---- | ------------- | ---- |
| 全量规则列表 | `/analysis/rules` | 直接定位规则数组，用于统计规模或导出原始 DSL 片段 |
| 第一条规则的决策 | `/analysis/rules/0/decision` | 典型结构为 `{ "decision": "proxy" }`
| 影子规则列表 | `/analysis/shadowed` | 多数版本均输出数组，可搭配 `--emit stats_only` 观测规模 |
| 重复规则列表 | `/analysis/duplicates` | 若核心分析器提供重复检测，这里可快速定位 |
| 告警首条信息 | `/analysis/warnings/0/message` | 输出 warning 文本，可用于 CI 提醒 |
| 自定义节点 | `/custom/path/here` | 任何存在于 JSON 中的路径都可以指向；若含 `~` 或 `/`，请按 RFC6901 转义 |

> RFC6901 转义规则：`
>   `/` 在路径中表示层级分隔，若键名本身含 `/`，请写成 `~1`
>   `~` 则写成 `~0`
> 举例：键名 `foo/bar~baz` 的 pointer 写法为 `/foo~1bar~0baz`

---

## 11. Pipeline 模板（Makefile + GitHub Actions）

### 11.1 Makefile 片段

```make
.PHONY: analyze-stats
analyze-stats:
	cargo run -q -p singbox-rust --bin sb-route --features "preview_route dsl_analyze dsl_derive" -- \
	  analyze --dsl ./examples/dsl.sample.txt --emit stats_only --top 20 \
	  --fmt pretty --out-analyze ./target/analyze.stats.json
```

### 11.2 GitHub Actions 片段

```yaml
- name: sb-route analyze
  run: |
    set -eux
    cargo run -q -p singbox-rust --bin sb-route --features "preview_route dsl_analyze dsl_derive" -- \
      analyze --dsl ./examples/dsl.sample.txt --emit stats_only --top 20 \
      --fmt json --out-analyze ./target/analyze.stats.json
    cat ./target/analyze.stats.json
```

> 建议配合 `actions/upload-artifact` 将 `target/analyze.stats.json` 作为流水线附件，便于评审下载。

---

## 12. 搭配 jq / dasel 的范式

### 12.1 jq 取出 Top-3 reason

```bash
jq '.top.reason_kind[:3]' ./target/analyze.stats.json
```

### 12.2 jq 计算 shadowed 长度增量

```bash
prev=$(jq '.summary.shadowed_len' ./baseline/analyze.stats.json)
next=$(jq '.summary.shadowed_len' ./target/analyze.stats.json)
echo "shadowed diff: $((next - prev))"
```

### 12.3 dasel 将数组展开成表格

```bash
dasel -r json -f ./target/analyze.stats.json -p json -w table -m '.top.arrays_by_key'
```

---

## 13. Troubleshooting Checklist

1. **命令报错 `target requires features ...`**
   - 请确认始终带上 `--features "preview_route dsl_analyze dsl_derive"`
   - 若你使用自定义构建流程，可在 `Cargo.toml` 中为 `sb-route` 指定 `required-features`
2. **Pointer 命中为空数组**
   - 核心模块可能未输出该字段；建议回退 `--emit full` 观察结构
3. **stats_only 输出全是 0**
   - 很可能 Pointer 指向了不存在的节点或返回了标量，请检查路径写法
4. **落地文件未生成**
   - `ANALYZE_OUT` 会输出 recap；若未出现，说明写入前就失败了（例如路径不存在）
5. **CI 中 diff 太噪音**
   - 调整 `--top`；或在落地后使用 `jq 'del(.top.arrays_by_key[2:])'` 做裁剪

---

## 14. 与 compare/explain 的集成仪表板思路

| 产物 | 命令 | 主要指标 | 建议渲染 |
| ---- | ---- | -------- | -------- |
| `explain.summary.json` | `explain-batch --emit summary_only` | total / per_sec / reason_kind | 折线图 + 环形图 |
| `compare.matrix.json` | `compare --emit matrix_only` | 混淆矩阵（A→B） | 热力图 + Top-N 差异列表 |
| `analyze.stats.json` | `analyze --emit stats_only` | total_keys / rules_len / shadowed_len / top 场景 | 条形图 + 趋势折线 |

落地到监控平台的最小流程：

1. 在 CI 中生成三份 JSON，并上传为构建附件；
2. 监听主干合并事件，下载附件并解析关键指标；
3. 推送到 TSDB / Prometheus，或生成 Markdown 报告附在 Pull Request；
4. 针对指标阈值设定告警，如 shadowed_len 激增、rules_len 暴涨等。

---

## 15. 扩展路线（Roadmap）

- [x] `--emit shadow_only`：提取影子规则样本，为人工审计提供线索；
- [ ] `--emit warnings_only`：对 `warnings` 数组做结构化导出，方便 CI fail-fast；
- [ ] 与 `sb-subs` 对接：直接分析订阅生成的 DSL，计算策略覆盖度；
- [ ] 提供 `--format markdown`，输出 Markdown 表格，便于报告；
- [ ] 支持自定义统计器插件，例如 `--stats-config ./stats.lua` 动态定义聚合逻辑。

欢迎在 Issue 中继续补充想法，我们会根据 CLI 工具链的定位逐步解锁。

---

## 16. 完整命令速查（Cheat Sheet）

```text
sb-route --features "preview_route dsl_analyze dsl_derive" analyze \
  --dsl ./examples/dsl.sample.txt \
  --emit stats_only \
  --pointer '/analysis/rules' \
  --top 25 \
  --fmt pretty \
  --out-analyze ./target/analyze.rules.stats.json
```

```text
sb-route --features "preview_route dsl_analyze dsl_derive" analyze \
  --dsl ./examples/dsl.sample.txt \
  --emit full \
  --pointer '/analysis/warnings/0' \
  --fmt json
```

```text
sb-route --features "preview_route dsl_analyze dsl_derive" analyze \
  --dsl ./examples/dsl.sample.txt \
  --emit stats_only \
  --top 0 \
  --fmt json
```

这些模板可直接复制粘贴，在此基础上调整 DSL 路径、Pointer 与输出文件名即可。

---

## 17. 附录：完整样本输出（来自 examples/dsl.sample.txt）

以下为一次真实执行 `sb-route analyze --emit stats_only --top 5 --fmt pretty` 的截断输出，便于快速比对：

```json
{
  "summary": {
    "total_keys": 42,
    "rules_len": 5,
    "shadowed_len": 0
  },
  "top": {
    "reason_kind": [
      ["suffix", 3],
      ["exact", 1],
      ["default", 1]
    ],
    "decisions": [
      ["direct", 4],
      ["proxyA", 1]
    ],
    "arrays_by_key": [
      ["rules", 5],
      ["warnings", 0],
      ["shadowed", 0]
    ]
  }
}
```

如需将该 JSON 转换为 Markdown 表格，可执行：

```bash
jq -r '.top.reason_kind | ("rank,reason,count"), (.[] | @csv)' ./target/analyze.stats.json
```

---

## 18. 附录：与 `sb-preview` 联动示例

1. 使用 `sb-subs plan` 生成候选 DSL：
   ```bash
   cargo run -q -p singbox-rust --bin sb-subs --features "subs_preview_plan subs_diff subs_clash subs_singbox" -- \
     plan --format clash --mode keyword --input ./docs/samples/clash.yaml --normalize --apply --fmt json \
     --field dsl_out > ./target/snapshot.dsl
   ```
2. 对生成结果运行 `sb-route analyze`：
   ```bash
   cargo run -q -p singbox-rust --bin sb-route --features "preview_route dsl_analyze dsl_derive" -- \
     analyze --dsl ./target/snapshot.dsl --emit stats_only --fmt pretty --out-analyze ./target/snapshot.analyze.json
   ```
3. 将统计结果与基线比较：
   ```bash
   diff -u ./baseline/snapshot.analyze.json ./target/snapshot.analyze.json || true
   ```
4. 若差异过大，可以再用 `sb-preview` 对关键目标做 explain：
   ```bash
   cargo run -q -p singbox-rust --bin sb-preview --features preview_route -- \
     --dsl ./target/snapshot.dsl --target "www.shop.com:443" --proto tcp --fmt pretty
   ```

---

## 19. 附录：常用故障的诊断脚本

```bash
#!/usr/bin/env bash
set -euo pipefail
OUT=./target/analyze.diagnose.json
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

cargo run -q -p singbox-rust --bin sb-route --features "preview_route dsl_analyze dsl_derive" -- \
  analyze --dsl ./examples/dsl.sample.txt --emit full --fmt json > "$TMP"

if ! jq empty "$TMP" >/dev/null 2>&1; then
  echo "[ERROR] analyze 输出不是合法 JSON" >&2
  exit 1
fi

jq '{\
  summary: {\
    rules_len: (.analysis.rules | length),\
    shadowed_len: (.analysis.shadowed | length),\
    warnings: (.analysis.warnings | length)\
  }\
}' "$TMP" > "$OUT"

echo "诊断结果已写入 $OUT"
```

该脚本先确认 analyze 输出的 JSON 结构，再生成一个最小诊断摘要，适合在 CI 中快速定位问题。

---

## 20. 附录：术语对照表

| 术语 | 含义 | 备注 |
| ---- | ---- | ---- |
| reason_kind | 命中理由类型 | 与 `sb-core` 引擎返回一致，如 suffix/exact/default |
| decision | 路由决策标签 | 例如 direct / proxyA / reject |
| shadowed | 影子规则 | 通常表示被上层规则遮蔽的条目 |
| duplicates | 重复规则 | 若分析器有实现则会出现该数组 |
| arrays_by_key | 数组规模排行 | 用于快速找出“最大的集合” |
| total_keys | 对象键总数 | 粗略衡量 JSON 复杂度 |

---

## 21. 附录：Quick Commands（仅命令，不带说明）

```text
cargo run -q -p singbox-rust --bin sb-route --features "preview_route dsl_analyze dsl_derive" -- analyze --dsl ./examples/dsl.sample.txt --fmt json
cargo run -q -p singbox-rust --bin sb-route --features "preview_route dsl_analyze dsl_derive" -- analyze --dsl ./examples/dsl.sample.txt --emit stats_only --top 10 --fmt pretty
cargo run -q -p singbox-rust --bin sb-route --features "preview_route dsl_analyze dsl_derive" -- analyze --dsl ./examples/dsl.sample.txt --pointer '/analysis/rules/0' --emit full --fmt pretty
cargo run -q -p singbox-rust --bin sb-route --features "preview_route dsl_analyze dsl_derive" -- analyze --dsl ./examples/dsl.sample.txt --pointer '/analysis/shadowed' --emit stats_only --fmt json
```

> 如果你希望在 shell 历史中快速复制粘贴，可以把这些命令保存为 `docs/snippets/analyze.cmds`。

---

## 22. 附录：差异审阅清单（Code Review Checklist）

- [ ] 分析统计产物是否存档（`ANALYZE_OUT` 日志存在）
- [ ] `summary.total_keys` 与基线差值是否在预期范围内
- [ ] `summary.rules_len` 是否存在异常陡增（>20%）
- [ ] `top.reason_kind` 是否出现陌生命中类型（如新增 `geoip` / `query`）
- [ ] `top.decisions` 是否出现异常决策（如误入 `block`）
- [ ] `top.arrays_by_key` 是否出现新的巨大集合（提示核心结构变化）

将上述检查点嵌入 PR 模板，可显著缩短评审时间。

---

## 23. 附录：FAQ 扩展版

- **Pointer 是否可指向根？** 可以，使用 `/` 或留空（CLI 会自动补 `/`）。
- **是否支持多 Pointer？** 暂不支持。若需要多个子树，可多跑几次或配合 `jq` 拆分。
- **Top-N 的排序是否稳定？** 同值时按键名升序，以便 diff 对齐。
- **能否追加自定义统计项？** 目前可通过修改 `collect_stats`，保持向后兼容性即可。
- **stats_only 会不会漏掉深层键？** 不会，递归遍历所有对象、数组，统计逻辑与层级无关。

---

## 24. 结语

`sb-route analyze` 从“只打印 JSON”升级到“可统计 / 可抽取 / 可落地”，意味着我们具备了 DSL 变更的最小可观测性。将其纳入 CI 与日常回归中，可以在功能上线前及时识别规则规模失衡、影子条目激增等问题，也为后续影子提取、覆盖率分析打下基础。

下一步，我们将继续围绕 CLI 工具链补齐“影子样本导出、订阅对比表格化、告警统一化”等能力，敬请期待。
