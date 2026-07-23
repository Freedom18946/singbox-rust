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
| `ignore_memory_ratio_on_non_linux` | `bool` | `false` | 非 Linux 主机忽略 RSS（Rust）与 Go heap 的不可比峰值比率；Linux 仍执行 2x gate |

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
- `connection_mismatches` — 连接数 + downloadTotal/uploadTotal（L10.2.1）
- `memory_mismatches` — 内存峰值比率 >2x 时报警（L10.2.1）
- `ignored_http_count`
- `ignored_ws_count`
- `ignored_counter_jitter_count`
- `ignored_memory_ratio_count`
- `gate_score`

`gate_score = http + ws + subscription + traffic + connection + memory mismatch 总数`，不包含 ignored 项。

## 断言算子（L6.2.1）

支持：`eq` `ne` `exists` `not_exists` `gt` `gte` `lt` `lte` `contains` `regex`，以及
reference 比较 `eq_ref` `ne_ref` `gt_ref` `gte_ref`。断言可用 `kernel: rust|go` 锁定 S4
差异。

## Case outcome

- `PASS`：断言通过，无 S4 标签。
- `DIV-COVERED`：断言通过，且 `covered_divergences` 非空。
- `ENV-LIMITED`：环境受限 case 的失败全部完成环境归因，或精确匹配其
  `expected_env_failures` kernel/stage allowlist；额外失败仍阻断。
- `FAIL`：其余失败；验收阻断。

扩展键空间：

- `ws.<name>.frame_count`
- `errors.count`
- `subscription.node_count`
- `traffic.<name>.detail.*`

## 环境分级策略（L5.3.1）

- `strict`：可进入 PR smoke，默认阻断。
- `env_limited`：默认不阻断 PR；nightly 记录趋势与失败归因。
