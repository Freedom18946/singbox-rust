
# L15-L17 详细工作包规划

状态: ✅ L15/L16 已完成；🔄 L17 规划中（更新：2026-02-12）

## Context

singbox-rust 已完成 L1-L16 里程碑：架构整固、功能对齐（acceptance baseline 100% parity, 209/209 closed）、联测仿真（83 case）、CI 治理、迁移治理、服务安全、TLS 高级能力、质量验证与性能基线。1617+ 测试通过，边界检查 exit 0。PX-015（Linux resolved 实机验证）已标记为 Accepted Limitation（非阻塞）。

L15-L17 将项目从"功能可用"推向"可发布"：
- **L15 CLI 完善与功能补全（12 WP）**：补齐 CLI 最后缺口（uuid/rand/ECH/AdGuard）、Chrome 证书模式、Go specs 验收签署
- **L16 质量验证与性能基线（10 WP）**：Criterion 基准正式化、Go vs Rust 吞吐对比、热重载/信号/资源泄漏稳定性、feature-gate 矩阵穷举
- **L17 发布就绪与生产验证（10 WP）**：CI/CD pipeline、多平台构建、Docker、CHANGELOG、安全审查、用户文档、GUI 集成冒烟、7 天稳定性

总量: 32 工作包，6 个批次

---

## L15: CLI 完善与功能补全（12 WP）

### L15.1.1 — generate uuid 子命令

- **复杂度**: S | **优先级**: P0 | **依赖**: 无
- **内容**: Go cmd_generate.go L73-92 有 generate uuid，生成 V4 UUID 输出到 stdout。Rust GenerateCommands 枚举（app/src/cli/generate.rs:17-36）无此变体。新增 Uuid 变体，调用已存在的 uuid crate（app/Cargo.toml L357 已有 uuid = {version="1", features=["v4"]}）。
- **文件**: `app/src/cli/generate.rs`（GenerateCommands 枚举 + run() match arm + generate_uuid()）
- **验收**: `cargo run -p app -- generate uuid` 输出合法 UUID v4；1+ 单元测试；cargo check -p app 通过

### L15.1.2 — generate rand 子命令

- **复杂度**: S | **优先级**: P0 | **依赖**: 无
- **内容**: Go cmd_generate.go L33-71 有 generate rand <length>，支持 --base64/--hex 标志。新增 Rand 变体，含 length: usize、base64: bool、hex: bool 参数。使用已有 rand crate 生成随机字节，base64 crate 编码。默认 base64 输出（与 Go 一致）。
- **文件**: `app/src/cli/generate.rs`（GenerateCommands::Rand + generate_random()）
- **验收**: `generate rand 16 --base64` 输出 24 字符 base64；`generate rand 16 --hex` 输出 32 字符 hex；2+ 单元测试

### L15.1.3 — generate ech-keypair ECHConfig PEM 编码

- **复杂度**: L | **优先级**: P1 | **依赖**: 无
- **内容**: 当前仅生成原始 X25519 密钥对（generate.rs L77-108），不产生 Go 兼容的 ECH CONFIGS/ECH KEYS PEM 格式。Go 实现（common/tls/ech_shared.go L17-48）用 cryptobyte 构建 ECHConfig（含 HPKE KEM/KDF/AEAD、public_name、public_key），PEM 编码输出。Rust 需要：(a) 新增 server_name 必选参数；(b) 实现 marshal_ech_config() 按 draft-ietf-tls-esni 编码；(c) 构建 ECH CONFIGS PEM（含 config list 长度前缀）和 ECH KEYS PEM。
- **文件**: `crates/sb-tls/src/ech_keygen.rs`（新建，ECHConfig 序列化），`app/src/cli/generate.rs`（改写 EchKeypair 添加 server_name 参数）
- **验收**: 输出含 `-----BEGIN ECH CONFIGS-----` 和 `-----BEGIN ECH KEYS-----` PEM 块；3+ 单元测试（PEM 格式、config 解析往返、默认参数）

### L15.1.4 — rule-set convert --type adguard

- **复杂度**: L | **优先级**: P1 | **依赖**: 无
- **内容**: Go cmd_rule_set_convert.go + common/convertor/adguard/convertor.go（459 行）将 AdGuard DNS 过滤规则解析为 HeadlessRule 编译为 .srs。Rust RulesetCmd::Convert（ruleset.rs:105-116）仅 JSON↔SRS 互转。实现：(a) 扩展 Convert 添加 --type 参数（adguard）；(b) 新建 adguard.rs 解析器，支持 `||`(suffix)、`|`(start)、`^`(end)、`@@`(exclude)、`/regex/`、`$important`、hosts 行格式、注释跳过；(c) 输出 HeadlessRule JSON 或直接编译为 .srs。
- **文件**: `crates/sb-core/src/router/ruleset/adguard.rs`（新建），`crates/sb-core/src/router/ruleset/mod.rs`（pub mod），`app/src/cli/ruleset.rs`（Convert 添加 --type）
- **验收**: `rule-set convert --type adguard hosts.txt -o output.srs` 生成有效 .srs；解析 `||example.com^` 为 domain_suffix；5+ 单元测试

### L15.1.5 — rule-set format --write 原地写回

- **复杂度**: S | **优先级**: P2 | **依赖**: 无
- **内容**: Go rule-set format 有 -w/--write 标志原地写回。Rust RulesetCmd::Format（ruleset.rs:47-56）仅 --output。新增 --write/-w bool 标志，设置时写回输入文件路径。
- **文件**: `app/src/cli/ruleset.rs`（Format 变体添加 write 字段）
- **验收**: `rule-set format test.json -w` 原地更新；无 --output 且无 --write 输出 stdout；1+ 测试

### L15.1.6 — Certificate Store chrome 模式

- **复杂度**: M | **优先级**: P1 | **依赖**: 无
- **内容**: Go 支持 system/mozilla/chrome/none 四种证书存储模式，L14 实现了三种缺 Chrome。CertificateStoreMode（sb-tls/src/global.rs:25-32）新增 Chrome 变体；from_str_opt() 匹配 "chrome"；base_root_store() Chrome 模式使用 webpki-roots（Chrome/Mozilla 根证书高度重叠，无独立 Chrome root crate，日志注明近似）。
- **文件**: `crates/sb-tls/src/global.rs`（CertificateStoreMode +Chrome + from_str_opt + base_root_store）
- **验收**: `CertificateStoreMode::from_str_opt("chrome")` 返回 Chrome；Chrome root store 非空；配置 "certificate_store": "chrome" 无验证错误；3+ 单元测试

### L15.2.1 — Go Specs 验收清单系统签署

- **复杂度**: M | **优先级**: P0 | **依赖**: L15.1.1, L15.1.2, L15.1.4, L15.1.6
- **内容**: 99-验收清单总表.md 含 A~I 九大类 30+ MUST/SHOULD 检查项，当前零 checkmark。逐项对照 Rust 实现验证，记录证据（cargo 命令、测试名、代码引用），未通过项标注 Accepted Limitation + 原因。签署后作为 parity 最终证据。PX-015 已记录为 Accepted Limitation（无 Linux 实机补证要求）。
- **文件**: `agents-only/dump/go-version-analysis/2026-02-11-intake/sing-box-core-specs/99-验收清单总表.md`（逐项打勾），`agents-only/active_context.md`
- **验收**: 所有 MUST 项 checked 或标注 Accepted Limitation；签署日期和证据完整

### L15.2.2 — Interop-lab CLI 对齐测试用例

- **复杂度**: M | **优先级**: P1 | **依赖**: L15.1.1, L15.1.2, L15.1.4
- **内容**: 新增 3 个 interop-lab case：(a) p1_cli_generate_uuid_format.yaml—UUID 格式断言；(b) p1_cli_generate_rand_base64.yaml—rand base64 长度断言；(c) p1_cli_ruleset_convert_adguard.yaml—AdGuard→.srs 转换断言。
- **文件**: `labs/interop-lab/cases/` 3 个新 YAML，`labs/interop-lab/configs/test_adguard_filter.txt`（测试用 filter file）
- **验收**: 3 case 通过；case 总数 80+

### L15.2.3 — PX-015 状态决议与 CI 占位（已归档）

- **复杂度**: S | **优先级**: P1 | **依赖**: 无
- **内容**: PX-015 已转 Accepted Limitation。保留 `.github/workflows/linux-resolved-validation.yml` 作为历史可选验证入口，不再作为 parity 阻塞项。
- **文件**: `.github/workflows/linux-resolved-validation.yml`（新建），`agents-only/02-reference/GO_PARITY_MATRIX.md`（PX-015 状态更新）
- **验收**: workflow 文件可被 gh workflow view 识别；parity matrix PX-015 行注明 accepted limitation + optional CI path

### L15.3.1 — ECH Keypair 兼容性 interop-lab Case

- **复杂度**: S | **优先级**: P2 | **依赖**: L15.1.3
- **内容**: 新增 p1_cli_ech_keypair_pem_format.yaml，断言 ECH keypair 输出含 PEM header，base64 内容长度合理。
- **文件**: `labs/interop-lab/cases/p1_cli_ech_keypair_pem_format.yaml`（新建）
- **验收**: case 通过；PEM header 正确

### L15.3.2 — L15 验收与文档更新

- **复杂度**: S | **优先级**: P0 | **依赖**: L15.2.1, L15.2.2, L15.2.3
- **内容**: 完整 L15 验收：所有新 CLI 命令工作、AdGuard 转换正确、验收清单已签署。更新 CLAUDE.md、active_context.md、case_backlog.md。
- **文件**: `CLAUDE.md`, `agents-only/active_context.md`
- **验收**: cargo test --workspace 通过；新 interop-lab case 全通过；验收清单签署完整

---

## L16: 质量验证与性能基线（10 WP）

### L16.1.1 — Criterion 基准套件正式化

- **复杂度**: M | **优先级**: P0 | **依赖**: 无
- **内容**: benches/ 有 7+ Criterion 文件。需要：(a) 统一 bench 输出到 reports/benchmarks/；(b) 确保所有 bench suite cargo bench -p sb-benches 可运行（修复编译问题）；(c) 建立基准基线 JSON 用于回归对比。
- **文件**: `benches/benches/*.rs`（编译修复），`reports/benchmarks/`（新建目录），`reports/benchmarks/baseline.json`
- **验收**: `cargo bench -p sb-benches` 运行无 panic；基准 JSON 写入 baseline.json

### L16.1.2 — Go vs Rust 吞吐量对比框架

- **复杂度**: L | **优先级**: P1 | **依赖**: L16.1.1
- **内容**: 对比脚本，分别启动 Go/Rust sing-box（相同配置），测试 4 协议吞吐（SOCKS5 direct / Shadowsocks aes-256-gcm / VMess aes-128-gcm / Trojan TLS）。输出 CSV 到 reports/benchmarks/go_vs_rust_throughput.csv。
- **文件**: `scripts/bench_go_vs_rust.sh`（新建），`reports/benchmarks/go_vs_rust_throughput.csv`，`labs/interop-lab/configs/bench_*.json`（2 配置文件）
- **验收**: 脚本可执行（Go binary 可用时）；CSV 含 protocol/direction/throughput_mbps/latency_p50/p95

### L16.1.3 — 延迟百分位基线（P50/P95/P99）

- **复杂度**: M | **优先级**: P1 | **依赖**: L16.1.1
- **内容**: 在 protocol_comprehensive benchmark 基础上，扩展延迟百分位统计。4 协议各 1000 次连接+首包往返，记录 P50/P95/P99。输出到 reports/benchmarks/latency_percentiles.json。
- **文件**: `benches/benches/protocol_comprehensive.rs`（扩展），`reports/benchmarks/latency_percentiles.json`
- **验收**: JSON 含 4 协议各 P50/P95/P99；P50 < 10ms（localhost）

### L16.1.4 — Feature-gate 矩阵穷举验证

- **复杂度**: M | **优先级**: P0 | **依赖**: 无
- **内容**: xtask feature-matrix 已有 30 组合。扩展到 40+ 组合（加入 minimal 空 feature、每个 adapter 独立、tools-only 等边缘组合），输出 reports/feature_matrix_report.txt。
- **文件**: `xtask/src/main.rs`（feature_matrix 扩展），`reports/feature_matrix_report.txt`（新建）
- **验收**: 40+ 组合全部 cargo check pass；报告含组合名+结果

### L16.2.1 — 内存使用对比基准

- **复杂度**: M | **优先级**: P1 | **依赖**: 无
- **内容**: 内存基准：(a) 启动空闲 RSS；(b) 100 并发连接稳态；(c) 1000 并发连接峰值。macOS 用 mach_task_info，对比 Go runtime.MemStats。输出 JSON。
- **文件**: `scripts/bench_memory.sh`（新建），`reports/benchmarks/memory_comparison.json`
- **验收**: JSON 含 idle/100conn/1000conn 三级 RSS 数据

### L16.2.2 — 热重载稳定性测试

- **复杂度**: M | **优先级**: P1 | **依赖**: 无
- **内容**: 启动 Rust 内核→100 次 SIGHUP→每次后检查 /healthz 200→记录内存/FD 变化。任何一次失败即不通过。
- **文件**: `app/tests/hot_reload_stability.rs`（新建，feature gated long_tests），`reports/stability/hot_reload_100x.json`
- **验收**: 100 次 SIGHUP 后 healthz 200；FD 不单调增长；内存增长 < 10%

### L16.2.3 — 信号处理与资源泄漏检测

- **复杂度**: M | **优先级**: P1 | **依赖**: 无
- **内容**: (a) SIGTERM 在 50 活跃连接下→优雅关闭→退出码 0；(b) 连续启停 10 轮→FD 和端口回收；(c) tokio metrics active_tasks_count 无持续增长。
- **文件**: `app/tests/signal_reliability.rs`（新建，feature gated long_tests）
- **验收**: SIGTERM 退出码 0；10 轮启停无端口泄漏；active_tasks 无持续增长

### L16.2.4 — Interop-lab 性能对比 Case

- **复杂度**: S | **优先级**: P2 | **依赖**: L16.1.2
- **内容**: 新增 2 个 env_limited interop-lab case：p2_bench_socks5_throughput.yaml、p2_bench_shadowsocks_throughput.yaml。
- **文件**: `labs/interop-lab/cases/` 2 个新 YAML
- **验收**: 2 case 可执行（env_limited，依赖 Go binary）

### L16.3.1 — 回归阈值治理（CI bench gate）

- **复杂度**: M | **优先级**: P1 | **依赖**: L16.1.1
- **内容**: CI workflow bench-regression.yml：PR 上运行 Criterion，与 baseline 对比，吞吐降 >5% 或延迟增 >10% → warning（不 block merge）。
- **文件**: `.github/workflows/bench-regression.yml`（新建），`scripts/bench_compare.sh`（新建）
- **验收**: PR workflow 可触发；基线对比输出 pass/warn/fail

### L16.3.2 — L16 验收与基线固化

- **复杂度**: S | **优先级**: P0 | **依赖**: L16.1.1, L16.1.4, L16.2.2, L16.2.3, L16.3.1
- **内容**: 完整 L16 验收：bench suite 可运行、feature matrix 全通过、稳定性测试通过、基线 JSON 已生成。更新 CLAUDE.md/active_context.md。
- **文件**: `CLAUDE.md`, `agents-only/active_context.md`
- **验收**: bench 基线存在；feature matrix 40+ pass；热重载 100x pass

---

## L17: 发布就绪与生产验证（10 WP）

### L17.1.1 — CI/CD Pipeline 完整化

- **复杂度**: L | **优先级**: P0 | **依赖**: 无
- **内容**: 当前仅 interop-lab CI。新增：(a) ci.yml—PR 触发，lint(clippy)+test(workspace)+check(parity)+boundaries 四步；(b) release.yml—tag 触发，多平台构建+artifact 上传+checksum。
- **文件**: `.github/workflows/ci.yml`（新建），`.github/workflows/release.yml`（新建）
- **验收**: PR 推送触发 CI 四步全 pass；v* tag 触发 release workflow

### L17.1.2 — 多平台构建验证

- **复杂度**: L | **优先级**: P0 | **依赖**: L17.1.1
- **内容**: release.yml matrix build：Linux x86_64(musl/gnu)、Linux aarch64(musl)、macOS x86_64、macOS aarch64、Windows x86_64。--features parity 全平台编译。
- **文件**: `.github/workflows/release.yml`（matrix 扩展），`Cross.toml`（新建，如用 cross）
- **验收**: 6 target 编译成功；产出 6 二进制 artifact

### L17.1.3 — Dockerfile 正式化

- **复杂度**: M | **优先级**: P1 | **依赖**: 无
- **内容**: 更新 deployments/docker/Dockerfile：multi-stage（builder + runtime）、BUILD_FEATURES 构建参数（默认 parity）、minimal alpine 运行时、healthcheck（/services/health）、非 root 用户、.dockerignore。
- **文件**: `deployments/docker/Dockerfile`（更新），`deployments/docker/.dockerignore`（新建），`deployments/docker/docker-compose.yml`（新建）
- **验收**: docker build 成功；镜像 < 50MB；非 root 运行

### L17.1.4 — CHANGELOG 与发布说明

- **复杂度**: M | **优先级**: P1 | **依赖**: 无
- **内容**: 新建 CHANGELOG.md（Keep a Changelog 格式）：Unreleased 节（L15-L17）+ v0.1.0 节（L1-L14 交付摘要）。含贡献者指南链接。
- **文件**: `CHANGELOG.md`（新建）
- **验收**: 含 v0.1.0 和 Unreleased 节；格式符合规范

### L17.2.1 — Release Artifact 打包

- **复杂度**: M | **优先级**: P0 | **依赖**: L17.1.1, L17.1.2
- **内容**: 命名：singbox-rust-{version}-{os}-{arch}.tar.gz/.zip。release.yml 中打包 binary + 配置模板 + README，生成 SHA256 checksum，softprops/action-gh-release 上传。
- **文件**: `.github/workflows/release.yml`（打包逻辑），`scripts/package_release.sh`（新建），`deployments/config-template.json`（新建）
- **验收**: Release 页含 6 artifact + checksums.txt；解压含 binary + config-template

### L17.2.2 — 用户文档：配置参考与迁移指南

- **复杂度**: L | **优先级**: P1 | **依赖**: L15.2.1
- **内容**: (a) docs/configuration.md—配置参考（基于 IR 结构，全部顶层字段+类型+默认值）；(b) docs/migration-from-go.md—从 Go 迁移指南（行为差异、不支持特性、配置映射）；(c) docs/troubleshooting.md—常见问题（从 agents-only 提取面向用户的内容）。
- **文件**: `docs/configuration.md`（新建），`docs/migration-from-go.md`（新建），`docs/troubleshooting.md`（新建）
- **验收**: 三篇完整；配置参考覆盖九大类；迁移指南列出所有 Accepted Limitation

### L17.2.3 — 安全检查清单

- **复杂度**: M | **优先级**: P0 | **依赖**: 无
- **内容**: (a) cargo audit 无 HIGH/CRITICAL；(b) 密码/token 不记录到 info/warn 日志（grep 检查）；(c) TLS 默认版本 >= 1.2 无不安全 cipher；(d) auth middleware timing-safe 比较验证；(e) cargo deny check licenses 许可合规。
- **文件**: `reports/security_audit.md`（新建），`deny.toml`（新建）
- **验收**: cargo audit 无 HIGH；密码不出现在日志；TLS >= 1.2；审查报告完整

### L17.3.1 — GUI.for SingBox 集成冒烟测试

- **复杂度**: L | **优先级**: P1 | **依赖**: L15.3.2, L17.1.3
- **内容**: 用 GUI_fork_source/ 的 GUI.for，替换 Go 内核为 Rust binary。验证：(a) GUI 启动+配置加载；(b) Proxy 切换；(c) 订阅导入；(d) connections 实时显示；(e) 日志面板。记录兼容性问题。
- **文件**: `reports/gui_integration_test.md`（新建），`scripts/gui_smoke_test.sh`（新建）
- **验收**: GUI 启动无崩溃；proxy 切换 UI 更新；connections 显示活跃连接

### L17.3.2 — 7 天稳定性 Canary 框架

- **复杂度**: M | **优先级**: P1 | **依赖**: L16.2.2, L16.2.3
- **内容**: 新建 7 天 canary 运行框架：(a) scripts/canary_7day.sh—启动 Rust 内核+混合流量生成+每小时采样 RSS/FD/connections/healthz；(b) 输出时序 JSON 日志到 reports/stability/canary_7day.jsonl；(c) 终止后生成摘要报告。
- **文件**: `scripts/canary_7day.sh`（新建），`reports/stability/canary_7day.jsonl`（运行时生成），`reports/stability/canary_summary.md`（模板）
- **验收**: 脚本可启动运行；每小时一条 JSON 记录；healthz 全 200；RSS 无单调增长

### L17.3.3 — L15-L17 完整 Capstone 验证

- **复杂度**: S | **优先级**: P0 | **依赖**: L15.3.2, L16.3.2, L17.2.1, L17.2.2, L17.2.3, L17.3.1, L17.3.2
- **内容**: 最终验证：cargo test --workspace 1650+ 通过、strict interop-lab case 全通过、bench 基线存在、feature matrix 40+ 通过、CI pipeline 可运行、Docker 可构建、安全审查无 HIGH、文档三篇完整、CHANGELOG 存在。标记项目 "Release Ready"。
- **文件**: `CLAUDE.md`, `agents-only/active_context.md`
- **验收**: 全部子项验证通过；CLAUDE.md 标记 Release Ready

---

## 批次调度

### Batch 1（无依赖，14 项，全并行）
| ID | 标题 | 复杂度 | 类型 |
|---|---|---|---|
| L15.1.1 | generate uuid 子命令 | S | Rust CLI |
| L15.1.2 | generate rand 子命令 | S | Rust CLI |
| L15.1.3 | ECH keypair PEM 编码 | L | Rust + TLS |
| L15.1.4 | AdGuard 过滤器转换 | L | Rust 新模块 |
| L15.1.5 | rule-set format --write | S | Rust CLI |
| L15.1.6 | Certificate Store chrome 模式 | M | Rust TLS |
| L15.2.3 | PX-015 CI 占位 | S | CI workflow |
| L16.1.1 | Criterion 基准正式化 | M | 基准测试 |
| L16.1.4 | Feature-gate 矩阵穷举 | M | 工具链 |
| L16.2.1 | 内存使用对比基准 | M | 脚本 |
| L16.2.2 | 热重载稳定性测试 | M | Rust 测试 |
| L16.2.3 | 信号处理与资源泄漏 | M | Rust 测试 |
| L17.1.1 | CI/CD Pipeline 完整化 | L | CI workflow |
| L17.1.3 | Dockerfile 正式化 | M | Docker |
| L17.1.4 | CHANGELOG | M | 文档 |
| L17.2.3 | 安全检查清单 | M | 审查 |

### Batch 2（依赖 Batch 1，7 项）
| ID | 标题 | 依赖 | 复杂度 |
|---|---|---|---|
| L15.2.1 | Go Specs 验收签署 | L15.1.1, L15.1.2, L15.1.4, L15.1.6 | M |
| L15.2.2 | Interop-lab CLI 对齐 case | L15.1.1, L15.1.2, L15.1.4 | M |
| L15.3.1 | ECH keypair 兼容性 case | L15.1.3 | S |
| L16.1.2 | Go vs Rust 吞吐量对比 | L16.1.1 | L |
| L16.1.3 | 延迟百分位基线 | L16.1.1 | M |
| L16.3.1 | 回归阈值治理 | L16.1.1 | M |
| L17.1.2 | 多平台构建验证 | L17.1.1 | L |

### Batch 3（依赖 Batch 2，4 项）
| ID | 标题 | 依赖 | 复杂度 |
|---|---|---|---|
| L15.3.2 | L15 验收与文档更新 | L15.2.1, L15.2.2, L15.2.3 | S |
| L16.2.4 | 性能对比 interop-lab case | L16.1.2 | S |
| L16.3.2 | L16 验收与基线固化 | L16.1.1, L16.1.4, L16.2.2, L16.2.3, L16.3.1 | S |
| L17.2.1 | Release Artifact 打包 | L17.1.1, L17.1.2 | M |

### Batch 4（依赖 Batch 3，3 项）
| ID | 标题 | 依赖 | 复杂度 |
|---|---|---|---|
| L17.2.2 | 用户文档 | L15.2.1 | L |
| L17.3.1 | GUI 集成冒烟测试 | L15.3.2, L17.1.3 | L |
| L17.3.2 | 7 天稳定性 Canary 框架 | L16.2.2, L16.2.3 | M |

### Batch 5（依赖 Batch 4，1 项）
| ID | 标题 | 依赖 | 复杂度 |
|---|---|---|---|
| L17.3.3 | Capstone 验证 | L15.3.2, L16.3.2, L17.2.1, L17.2.2, L17.2.3, L17.3.1, L17.3.2 | S |

---

## 依赖图

Batch 1 (14 items, fully parallel):
┌─ L15.1.1 ─┬──→ L15.2.1 ──→ L15.3.2 ──→ L17.3.3
├─ L15.1.2 ─┤        ↑            ↑
├─ L15.1.4 ─┤   L15.2.2 ─────────┤
├─ L15.1.6 ─┘                     │
├─ L15.1.3 ─────→ L15.3.1        │
├─ L15.1.5                        │
├─ L15.2.3 ───────────────────────┘
│
├─ L16.1.1 ──┬──→ L16.1.2 ──→ L16.2.4
│             ├──→ L16.1.3            │
│             └──→ L16.3.1 ──→ L16.3.2 ──→ L17.3.3
├─ L16.1.4 ──────────────────→ L16.3.2
├─ L16.2.1                         ↑
├─ L16.2.2 ──────────────────→ L16.3.2 ──→ L17.3.2 ──→ L17.3.3
├─ L16.2.3 ──────────────────→ L16.3.2 ──→ L17.3.2
│
├─ L17.1.1 ──→ L17.1.2 ──→ L17.2.1 ──→ L17.3.3
├─ L17.1.3 ──────────────→ L17.3.1 ──→ L17.3.3
├─ L17.1.4
├─ L17.2.3 ──────────────────────────→ L17.3.3
└─ (L17.2.2 依赖 L15.2.1) ──────────→ L17.3.3

---

## 验证策略

1. **单 WP 单元测试**: 每个 Rust 代码 WP 须含单元测试。目标 60+ 新测试（总计 1650+）
2. **Interop-lab 用例**: CLI 对齐和性能各产出 case。目标 8+ 新 YAML（总计 85+）
3. **回归门禁**: 每 Batch 完成后 `cargo test --workspace` + `make boundaries`
4. **Feature-gate 矩阵**: L16.1.4 产出 40+ 组合全 pass
5. **性能基线**: Criterion JSON baseline 固化，CI bench regression warning
6. **多平台构建**: 6 target CI 编译通过
7. **安全审查**: `cargo audit` 无 HIGH；`cargo deny` licenses 合规
8. **Go parity 验证**: 验收清单 30+ 项逐项签署
9. **文档**: 配置参考、迁移指南、排查手册三篇到位

---

## 风险登记

| 风险 | 可能性 | 影响 | 缓解 |
|---|---|---|---|
| ECH PEM 编码与 Go 不兼容 | 中 | 高 | 逐字节对比 Go 输出；用 Go 测试文件验证 Rust 输出可解析 |
| AdGuard 解析器边缘 case 不一致 | 中 | 中 | 运行 Go convertor_test.go 的相同输入验证 Rust 输出 |
| Cross-compilation 失败（musl/aarch64） | 中 | 高 | 先用 cross 验证；失败降级为仅 native targets |
| Criterion bench 不稳定（CI 噪声） | 高 | 低 | regression 设为 warning 不 block；>10% 才告警 |
| GUI.for 版本不兼容 | 中 | 中 | 使用 `GUI_fork_source/` 锁定版本；记录不兼容项 |
| Chrome Root Store 无独立 crate | 高 | 低 | 文档注明 Chrome≈Mozilla；后续 crate 可用时升级 |

---

## 统计摘要

- **总工作包**: 32
- **批次**: 6
- **L15 WP**: 12（CLI 完善+功能补全）
- **L16 WP**: 10（质量验证+性能基线）
- **L17 WP**: 10（发布就绪+生产验证）
- **预计新 Rust 源文件**: 6 (ech_keygen.rs, adguard.rs, hot_reload_stability.rs, signal_reliability.rs, bench_compare.sh, package_release.sh)
- **预计新 interop-lab case**: 8
- **预计新单元测试**: 60+
- **预计新 CI workflow**: 4 (ci.yml, release.yml, bench-regression.yml, linux-resolved-validation.yml)
- **预计新文档**: 6 (CHANGELOG, configuration, migration, troubleshooting, security_audit, canary_summary)
- **复杂度分布**: S:9, M:15, L:8
- **优先级分布**: P0:9, P1:18, P2:5

---

## 关键实现文件

| 文件 | 涉及 WP | 说明 |
|---|---|---|
| `app/src/cli/generate.rs` | L15.1.1, L15.1.2, L15.1.3 | CLI generate 扩展（uuid/rand/ech） |
| `app/src/cli/ruleset.rs` | L15.1.4, L15.1.5 | AdGuard convert + format --write |
| `crates/sb-core/src/router/ruleset/adguard.rs` | L15.1.4 | AdGuard 解析器（新建） |
| `crates/sb-tls/src/ech_keygen.rs` | L15.1.3 | ECHConfig PEM 编码（新建） |
| `crates/sb-tls/src/global.rs` | L15.1.6 | CertificateStoreMode +Chrome |
| `benches/benches/protocol_comprehensive.rs` | L16.1.1, L16.1.3 | Criterion 基准+延迟百分位 |
| `xtask/src/main.rs` | L16.1.4 | feature-matrix 扩展 |
| `.github/workflows/ci.yml` | L17.1.1 | 完整 CI pipeline（新建） |
| `.github/workflows/release.yml` | L17.1.1, L17.1.2, L17.2.1 | Release pipeline（新建） |
| `deployments/docker/Dockerfile` | L17.1.3 | Docker 正式化 |
| `go_fork_source/.../convertor/adguard/convertor.go` | L15.1.4 参考 | Go AdGuard 转换器 |
| `go_fork_source/.../tls/ech_shared.go` | L15.1.3 参考 | Go ECH keygen |
| `go_fork_source/.../cmd/sing-box/cmd_generate.go` | L15.1.1, L15.1.2 参考 | Go generate uuid/rand |
