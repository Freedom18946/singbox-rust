## CI 场景矩阵（v1）

### Phase A · Smoke（无指标）
- 构建：`cargo build --bin singbox-rust`
- 运行：`--profile smoke`（check_good, check_bad, http_405, socks5_tcp_connect）
- 断言：配置校验与基础连通性；不触 /metrics
- 新增：`check_schema_bad`，可选 `check_schema_bad` 用于 Schema 冒烟（开启 `--features check-schema` 构建时）

### Phase B · Metrics（带指标 + label 校验）
- 构建：`cargo build --features metrics --bin singbox-rust`
- 运行：`--scenes http_405,socks5_udp_direct,dns_udp`
- 断言：DSL + `SB_VALIDATE_LABELS=1`（loose）

### Phase C · Internal Link（可选全开）
- `SB_CI_FULL=1` 时启用：dot/doh 内部、上游路由、P2 趋势/恢复、UDP 稳定性
- 断言：DSL + 门限表合并 + label 校验

### Phase B/C 预检 Gate（可选）
- 可在运行器中启用 `SB_PREFLIGHT_CHECK=1` 与 `SB_PREFLIGHT_SCHEMA=1`，将配置校验作为**硬护栏**。

### Gates-only
- CI 各阶段均可设置 `SB_GATES_ONLY=1`，确保阈值以 `docs/metrics-gates.json` 为唯一真理源。

### 预检组合
- `SB_PREFLIGHT_CHECK=1 SB_PREFLIGHT_SCHEMA=1 SB_PREFLIGHT_REFS=1`：在启动前硬 gate 配置。

### 产物
- `target/ci/*.json`：各阶段报告（含版本/平台三元组）
- `target/ci/junit.xml`：JUnit 汇总（可被 CI 平台收集）
- `target/e2e/report-*.tar.gz`：归档（报告/配置/面板/allowlist）

> 门限的**唯一真相源**：`docs/metrics-gates.json`，脚本自动合并 DSL（若存在）。

### RC 出包
- `scripts/run-rc`：全自动跑 profile=full + strict-failfast + 归档；输出 `target/rc/rc-<ts>.tar.gz`。
- 包含：CLEAN_REPORT.json、归档报告、gates/allowlist、Grafana 面板。

#### RC 包增强审计追踪
- **环境快照**：`environment-<ts>.txt` - 系统信息、构建环境、Git状态、配置变量
- **配置指纹**：`fingerprints-<ts>.txt` - gates/allowlist/schema v2 SHA256指纹
- **Schema v2 源码**：包含 `types_route.rs`（如可用）
- **版本信息**：Cargo/Rustc版本、项目版本、Git提交信息
- **特性标志**：所有 SB_* 环境变量快照
- **完整性验证**：自动验证关键文件是否包含在RC包中

### Prometheus HTTP 查询（可选）
- `SB_PROM_HTTP=http://prom:9090`：启用真实 Prometheus HTTP 查询，优先于离线快照解析。
- 支持原生 PromQL：`sum()`、`rate()`、`increase()`、`absent()`、`sum by(...)`。
- 失败自动回退到离线模式，保持兼容性。

### Schema v2 强类型校验
- `--schema-v2-validate`：使用 schemars 生成的强类型 Schema 进行验证。
- 启用 `deny_unknown_fields` 进行严格字段检查。
- 默认保持向后兼容，不影响现有 `--schema` 行为。

### 否定维度与矛盾检测
- 支持 `not_domain`、`not_cidr`、`not_proto` 规则检测。
- `ConflictingRule` 错误码：当规则因否定约束导致空集时触发。
- 仅检测不生成，保持配置语义不变。