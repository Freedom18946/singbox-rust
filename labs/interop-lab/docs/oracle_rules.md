# L5 Oracle Rules

## Normalization Principles

1. 比较语义结果，不比较字段顺序。
2. HTTP 比较 `status` + `body_hash`。
3. WS 比较 `frame_count + frame_hash`（按 path）。
4. `traffic_results` 比较 action `success` 语义。
5. 计数器允许抖动：`oracle.tolerate_counter_jitter=true` 时，`|rust-go| <= oracle.counter_jitter_abs` 视为可接受。

## Oracle 字段定义

| 字段 | 类型 | 默认值 | 语义 |
| --- | --- | --- | --- |
| `ignore_http_paths` | `string[]` | `[]` | 命中的 HTTP path 差异计入 ignored，不计 mismatch |
| `ignore_ws_paths` | `string[]` | `[]` | 命中的 WS path 差异计入 ignored，不计 mismatch |
| `tolerate_counter_jitter` | `bool` | `false` | 是否启用计数器抖动容忍 |
| `counter_jitter_abs` | `int` | `0` | 抖动绝对阈值 |

备注：`ignore_*` 支持精确匹配和 `prefix*` 前缀匹配。

## Diff Output

`case diff <id>` 会生成：

- `diff.json`
- `diff.md`

主字段：

- `http_mismatches`
- `ws_mismatches`
- `subscription_mismatches`
- `traffic_mismatches`
- `ignored_http_count`
- `ignored_ws_count`
- `ignored_counter_jitter_count`
- `gate_score`

`gate_score = mismatch 总数`，不包含 ignored 项。

## 断言算子（L6.2.1）

支持：`eq` `ne` `exists` `not_exists` `gt` `gte` `lt` `lte` `contains` `regex`。

扩展键空间：

- `ws.<name>.frame_count`
- `errors.count`
- `subscription.node_count`
- `traffic.<name>.detail.*`

## 环境分级策略（L5.3.1）

- `strict`：可进入 PR smoke，默认阻断。
- `env_limited`：默认不阻断 PR；nightly 记录趋势与失败归因。
