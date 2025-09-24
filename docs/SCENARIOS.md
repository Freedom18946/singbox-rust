## 场景矩阵与断言

`scripts/run-scenarios` 会从 `scripts/scenarios.d/` 读取子场景脚本，每个脚本输出一行 JSON：
`{"name":"<case>","ok":0|1,"msg":"..."}`。

聚合器在执行前后各抓取一次 `/metrics`，对关键指标做增量断言，并汇总为：
- `target/e2e/CLEAN_REPORT.json`：包含 `build/scenarios/metrics.slice/ok/log_tail/timestamp`
- 失败时进程非零退出，控制台给出最小定位。

### 断言 DSL（场景头部注释）
每个 `scripts/scenarios.d/*.zsh` 可声明若干断言行，例如：

```
# ASSERT:
# METRIC key=http_respond_total label='code="405"' min=1 gate=1
```

字段含义：
- `key`：Prometheus 指标名；
- `label`：匹配该指标行的子串正则（如 `code="405"`、`backend="dot"`），留 `'.*'` 表示不筛选；
- `min`：期望的增量最小值（AFTER-BEFORE）；
- `gate`：`1` 表示该断言在 `SB_SCENARIO_GATES=loose` 下也会 gate；`0` 仅在 `strict` 模式下 gate。

#### COMPARE 语法
```
# COMPARE key=proxy_select_total left='pool="up",endpoint="up#1"' right='pool="up",endpoint="up#2"' op='>' gap=10 gate=1
```
- 含义：比较**左右两组 label** 的**增量**，按 `op` 和 `gap` 判定（例如快端选择增量 >= 慢端 + 10）。
- `left/right`：分别匹配左侧和右侧指标的 label 正则。
- `op`：比较操作符，支持 `>`, `>=`, `==`, `<`, `<=`。
- `gap`：期望的最小差异值。
- `gate`：同 METRIC 语义；`loose` 模式下仅 gate=1 的断言生效；`strict` 全部生效。

#### VALUE 语法
```
# VALUE key=udp_upstream_map_size label='.*' op='<=' value=512 gate=1
```
- 含义：读取 AFTER 时刻该指标当前值，与阈值比较（适合 **gauge 上限** 护栏）。
- `op`：比较操作符，支持 `>`, `>=`, `==`, `<`, `<=`。
- `value`：期望的阈值。
- `gate`：同 METRIC 语义；未启 metrics 时降级为 note，不影响 ok。

### 进程资源护栏（PROC_VALUE）
- 在 `docs/metrics-gates.json` 添加 `proc_values[]`：
  - `key`: `rss_mib|fd|threads`
  - `op`: `>,>=,==,<,<=`
  - `value`: 数值阈值
  - `gate`: 1 则纳入 gating
- Runner 会在进程稳定后采样一次（或长稳场景按已有循环），并把断言写回各场景 `asserts[]`。

### 布尔归一化与解释
- `--why`：在不可达/冗余时输出维度原因（proto/domain/cidr）。
- `--rule-graph`：输出 DOT（遮蔽/覆盖边）。示例：`singbox-rust check -c conf.yaml --rule-graph | dot -Tpng > rules.png`

### Schema v2
- 构建特性：`schema-v2`；命令：`singbox-rust check --schema --schema-dump v2`
- 来源：Rust 类型经 `schemars` 自动导出，避免手写 schema 漂移。

### PromQL 快照断言（离线）
- 在场景脚本头加入 `# PROM expr='rate(metric[30])' op='>' value='0' gate=1 owner=xxx severity=error`
- 支持：`sum(metric{...})`、`rate(metric[W])`、`increase(metric[W])`、`absent(metric{...})`、`sum by(label)(metric{...})`
- 数据源为用例前/后的两次 `/metrics` 抓取。
- 示例：
  ```bash
  # PROM expr='sum by(code)(http_respond_total{code=~"4.."})' op='>=' value='10' gate=1 owner=route severity=error
  # PROM expr='absent(proxy_circuit_state_total{state="open"})' op='==' value='1' gate=1 owner=health severity=error
  # PROM expr='increase(udp_upstream_pkts_in_total[30])' op='>' value='0' gate=1 owner=udp severity=error
  ```

### 逐组 PromQL 断言
- `gate_group=1`：对 `sum by(...)` 的**每个组**单独 gate；任一组失败则场景失败。
- 示例：
  ```bash
  # PROM expr='sum by(code)(http_respond_total{code=~"4.."})' op='>=' value='10' gate=1 owner=route severity=error gate_group=1
  ```
- 作用：当需要确保每个错误码组都达到最小次数时使用，而不是所有错误码的总和。

### 稳定 RuleID 与配置对比
- `singbox-rust check --with-rule-id --why`：问题定位包含 `[rid]`，与 DOT 节点一致。
- `singbox-rust check --diff-config old.yaml new.yaml`：输出 `{added,removed,moved}`（基于 RuleID）。
- 示例：
  ```bash
  # 检查时附加 RuleID
  ./target/release/singbox-rust check -c good.yaml --with-rule-id --why

  # 配置对比
  ./target/release/singbox-rust check --diff-config base.yaml new.yaml | jq
  ```
- 作用：**RuleID 稳定映射**让 SARIF/报告/DOT 在重排/最小化之后仍能对齐"同一条规则"。

### 规则最小化与计划应用
- `--minimize-rules`：输出剔除冗余后的最小规则集（仅 stdout）。
- `--apply-plan`：从 stdin 读 JSON-Patch（由 `--autofix-plan` 生成）应用于内存配置并打印，不写文件。
- 示例：
  ```bash
  # 生成最小集
  singbox-rust check -c config.yaml --minimize-rules > minimized.json
  # 生成计划并应用
  singbox-rust check -c config.yaml --autofix-plan > plan.json
  cat plan.json | singbox-rust check -c config.yaml --apply-plan > patched.json
  ```

### 全过程资源最大值护栏（PROC_MAX）
- 环境变量：
  - `SB_PROC_SAMPLE_SEC`：资源采样间隔秒（默认 `1`；设 `0` 表示仅单点快照）
- 在 `docs/metrics-gates.json` 添加 `proc_max[]`：
  - `key`: `rss_mib|fd|threads`
  - `op`: `>,>=,==,<,<=`
  - `value`: 数值阈值
  - `gate`: 1 则纳入 gating
- Runner 会在后台持续采样并记录最大值，用于对 RSS/FD/threads 的**全过程最大值**设定阈值。

### 规则覆盖分析（升级）
`singbox-rust check -c <file> --schema --fingerprint --explain`
- 启用 `--fingerprint` 同时进行覆盖分析，新增基于 EXACT/SUFFIX 与 CIDR 前缀的"包含判定"。
- 在开启 `check-net` 特性时，CIDR 使用 `ipnet` 做包含判断；未开启时回退到启发式。
- 新增 IssueCode:
  - `UnreachableRule`：被前序更广匹配规则完全覆盖；
  - `ShadowedBy`：前序 any/proto_all 对后续产生遮蔽风险（告警）。

### 指纹基线对比
- `SB_FP_BASE=sha256:<hex>`：将预检 `--fingerprint` 与基线对比，写入 `CLEAN_REPORT.json.fingerprint_match`。
- 归档包含 `config.canonical.json`、`fingerprint.txt` 与 `fp.compare.txt`（若不匹配）。
- CI 可用指纹不一致作为配置漂移红线，受 `SB_SCENARIO_GATES` 约束。

### 资源护栏：分位数
- `SB_PROC_PCTL`：默认 95（p95）。gates 支持 `proc_pctl[]`，键为 `rss_mib|fd|threads`。
- 在 `docs/metrics-gates.json` 添加 `proc_pctl[]`：
  - `key`: `rss_mib|fd|threads`
  - `op`: `>,>=,==,<,<=`
  - `value`: 数值阈值
  - `gate`: 1 则纳入 gating
- 基于时序 CSV 采样计算分位数，比 `proc_max[]` 更稳健（减少锯齿干扰）。

### 资源护栏：窗口分位
- `proc_pctl_window[]`：对 CSV 时序按 `window_sec` 切片计算 `pctl`（如 95），逐窗断言，能发现间歇尖峰。
- 需 `SB_PROC_SAMPLE_SEC>0`。
- 在 `docs/metrics-gates.json` 添加 `proc_pctl_window[]`：
  - `key`: `rss_mib|fd|threads`
  - `pctl`: 分位数值（如 95）
  - `window_sec`: 窗口秒数
  - `op`: `>,>=,==,<,<=`
  - `value`: 数值阈值
  - `gate`: 1 则纳入 gating
  - `owner`: 责任小组（如 "runtime"）
  - `severity`: 严重程度（"error"/"warn"/"info"）

### 可执行修复（autofix）
- `singbox-rust check --autofix-plan -c config.yaml`：输出 JSON Patch 风格 `move/replace`，不落盘。
- `--normalize`：打印规范化配置（预览），不改文件。
- `--summary`：快速统计（入/出站数量、规则数、池名集合、BIND 端口集合），便于人眼审阅与 CI 附件。

### failfast
- `SB_SCENARIO_GATES=strict-failfast` 或设置 `SB_FAILFAST=1`：任一 gate 失败立即退出，控制台打印 `<scene>/proc/<key> ...` 最小定位。

聚合器会在运行前后各抓一次 `/metrics` 并计算 delta，并把断言合并回对应场景对象的 `asserts[]` 字段，例如：
另外，当 `SB_VALIDATE_LABELS=1` 时，会对 `/metrics` 的**label 允许集**做巡检，结果写入 `CLEAN_REPORT.json.labels`，并在控制台打印违规最小定位。
```json
{
  "name": "socks5_udp_direct",
  "ok": true,
  "asserts": [
    {"name":"udp_upstream_pkts_in_total","label":".*","before":10,"after":12,"delta":2,"min":1,"ok":true}
  ]
}
```
当 `NEED_METRICS=0` 或未设置 `SB_METRICS_ADDR` 时，断言降级为 note，不影响 `ok`；场景对象仍包含 `asserts[]` 以便离线审阅。

当前内置场景（可扩展）：
- `check_good`：生成最小合法配置并执行 `singbox-rust check -c ...`，期望 0 退出
- `check_bad`：生成典型错误配置（端口越界、proto 非数组、DNS 模式非法），期望非 0
- `http_405`：HTTP 根路径返回 405
- `socks5_tcp_connect`：SOCKS5 CONNECT 到 example.com 成功
- `socks5_udp_direct`：SOCKS5-UDP 直连探测包成功返回
- `dns_udp`：系统或备用 DNS 解析 `example.com` 成功

### `--check` 场景
- `check_good`：生成最小合法配置并执行 `singbox-rust check -c ...`，期望 0 退出。
- `check_bad`：生成典型错误配置（端口越界、proto 非数组、DNS 模式非法），期望非 0。
- `check_schema_bad`：`SB_E2E_CHECK_SCHEMA_BAD=1` 启用；构造非数组 inbounds 触发 Schema 错误，验证解析器与 Gate。
两场景**不依赖 metrics**，可用于 smoke 阶段。

### 预检 Gate（可选）
- 当 `SB_PREFLIGHT_CHECK=1` 时，`run-scenarios` 会在主进程启动前执行 `check`，并将结果写入 `CLEAN_REPORT.json.preflight`。
- 失败时控制台输出 `preflight:<code>//<ptr>//<msg>` 的最小定位行。
 
可选扩展场景（需显式开启 ENV，默认跳过）：
- `dns_dot`：`SB_TEST_DOT=1` 时，验证与公共 DoT 端点的 TLS 握手（openssl）
- `dns_doh`：`SB_TEST_DOH=1` 时，对 Cloudflare DoH 发送一次查询（期望 `Status:0`）
- `dns_dot_internal`：需要 `SB_E2E_DNS_DOT=1`，通过**内部 dot backend** 处理查询；断言 `dns_query_total{backend="dot"}` 的增量 **min=1, gate=1**
- `dns_doh_internal`：需要 `SB_E2E_DNS_DOH=1`，通过**内部 doh backend** 处理查询；断言 `dns_query_total{backend="doh"}` 的增量 **min=1, gate=1**
- `socks5_udp_upstream`：需要 `SB_E2E_UDP_UPSTREAM=1`，自管上游实例生命周期，验证主实例经**上游 SOCKS5** 的 UDP 查询；断言 `udp_upstream_pkts_in_total` 的增量 **min=1, gate=1**
- `selector_p2_trend`：`SB_E2E_P2_TREND=1` 启用。脚本内起两套 SOCKS5 桩（快/慢），主实例 UDP 走命名池 `up`，启用 RTT 偏置；断言快端选择增量显著大于慢端（METRIC + COMPARE）。
- `selector_p2_recovery`：`SB_E2E_P2_RECOVERY=1` 启用。独立池 `up2`，倒置快慢，验证收敛能自恢复（`COMPARE` 反向断言新快端 > 新慢端）。
- `udp_upstream_longrun`：`SB_E2E_UDP_LONGRUN=1` 启用。循环发起 UDP 请求，断言 `udp_upstream_*` 增量达到门限；可在门限表中为 `udp_upstream_map_size` 增加上限 gate。
- `udp_upstream_stability`：`SB_E2E_UDP_STABILITY=1` 启用。开启上游协程接收，长稳 60s；断言 `udp_upstream_*` 增量达标，且 `udp_upstream_map_size <= 512`（可通过 `UDP_MAP_MAX` 调整）。

指标断言策略：
- 存在性：`http_respond_total` 必须出现
- 增量：`proxy_select_total` 计算前后 delta 并记录（默认不设阈值）
 - 降级：未启用 metrics（无 `SB_METRICS_ADDR` 或未带特性构建）时，断言以 note 记录但不影响 `ok`

### 运行建议
- 默认：不开启任何可选场景，矩阵只含最小链路
- 带指标 gating：`--features metrics` + `NEED_METRICS=1 SB_METRICS_ADDR=127.0.0.1:9090`
- 内部 DNS：按需开启 `SB_E2E_DNS_DOT=1`/`SB_E2E_DNS_DOH=1`
- 上游 UDP：`SB_E2E_UDP_UPSTREAM=1`，必要时调整 `UP_SOCKS/UP_HTTP` 端口变量
- 配置化上游路由：`SB_E2E_UP_CONF=1` 让主实例的 `runtime.yaml` 声明 `outbounds: up#1` 并将 UDP 路由至 `proxy:up#1`，场景 `socks5_udp_upstream_conf` 会对 `proxy_select_total{pool="up#1"}` 做增量 gate

### 参数
- `--scenes "a,b,c"` 或 `SCENES=a,b,c`：仅运行子集
- `--duration N`：长稳模式，循环 N 秒
- `--report path`：自定义报告路径
- `--profile release`：只跑发布前硬护栏（config 校验 + 短冒烟 + 资源阈值）
- `SB_E2E_ARCHIVE=1`：生成 `report-<ts>.tar.gz`，包含报告、运行配置、Grafana 四页 JSON、label allowlist

### 断言来源：Gates-only
- 设置 `SB_GATES_ONLY=1` 后，`run-scenarios` **仅**使用 `docs/metrics-gates.json` 中的断言（metrics/compares/values/prom）。
- 场景脚本内的 `# METRIC/...` 注释仅用于可读性，**不参与**执行，避免漂移。

### Enhanced Prometheus Diagnostic Reporting
- 新增 `PROM` 断言类型，支持 PromQL 查询与诊断报告
- 格式：`# PROM expr='<promql>' op='<operator>' value=<number> owner='<owner>' severity='<level>' gate=<0|1>`
- 支持的操作符：`eq`/`==`, `gt`/`>`, `gte`/`>=`, `lt`/`<`, `lte`/`<=`
- 自动记录查询来源：`http`（成功）、`offline`（离线快照）、`__PROM_HTTP_FAIL__:<reason>`（HTTP 失败）
- 环境变量：
  - `SB_PROM_HTTP`：Prometheus HTTP API 端点
  - `SB_PROM_TIMEOUT_MS`：HTTP 查询超时（默认 2000ms）
- 失败时自动降级到离线快照，确保测试连续性

### 检查器 P4 选项

```bash
singbox-rust check -c <file|-> [--schema] [--deny-unknown] [--allow-unknown /path/prefix,/other] [--check-refs] [--rules-dir DIR] [--format human|json|sarif] [--explain] [--enforce-apiversion]
```

- `-c -` 支持从 stdin 读取配置。
- `--deny-unknown` 将 Schema 置为 `additionalProperties:false`，拒绝未知字段。
- `--allow-unknown /experimental,/custom` 允许指定 JSON Pointer 前缀下的未知字段。
- `--rules-dir DIR` 作为 `rules_*` 与 `*file/*path` 的解析根。
- `--format sarif` 输出 SARIF 2.1.0，便于 CI/安服平台摄取。
- `--explain` 在 human 输出中附简短修复建议。
- `--enforce-apiversion` 强制检查 apiVersion/kind 字段的存在性和有效性。

#### 新增语义校验
- **重复名称/端口冲突**：outbound.name 重复、inbound listen+port 冲突
- **CIDR/域名格式**：route.when.cidr 和 route.when.domain 的语法校验
- **apiVersion/kind**：建议设置为 `singbox/v1` 和 `Config`

### 门限表
- `docs/metrics-gates.json` 提供每个场景的指标门限；聚合器自动合并
- 若同时在场景头部 DSL 与门限表声明同一指标，**取并集**（两者都执行）

约束与默认：
- 所有开关 behind env；默认运行态不变（never break userspace）
- 脚本自管进程生命周期，不脏化环境
- HTTP 场景现已包含三次重试逻辑，消除偶发连接失败
