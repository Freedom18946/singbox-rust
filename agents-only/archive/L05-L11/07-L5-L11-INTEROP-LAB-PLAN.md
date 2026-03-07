# L5-L11 单项目联测仿真计划（实施版）

> 更新日期：2026-02-12
> 状态：**L5-L14 ✅ 全部 Closed**

## 运行基线约束（强制）

1. Go 版本 sing-box + GUI + TUN 是当前网络基础，不可挑战、不可替换、不可中断。
2. Rust 内核联测仅作为并行对照样本，默认使用独立 API 端口与最小影响配置，不接管现网 TUN 路由。
3. 每次启用 Rust 内核后必须执行回收（停止进程并确认端口释放），避免干扰用户侧网络。

## L5 契约冻结与用例建模

### 目标
将 Go / GUI / Rust 三方契约差异结构化，形成可执行测试输入。

### 交付
- `labs/interop-lab/docs/compat_matrix.md`
- `labs/interop-lab/docs/case_backlog.md`
- `labs/interop-lab/docs/oracle_rules.md`
- `labs/interop-lab/cases/*.yaml`（P0 初始集）

## L6 单项目仿真底座

### 目标
在仓库内统一驱动内核、模拟上游、生成快照与报告。

### 已落地
- 新 crate：`labs/interop-lab`
- CLI：
  - `case list`
  - `case run <id>`
  - `case run --kernel both`
  - `case diff <id>`
  - `report open <id>`
- 核心模块：`case_spec` / `orchestrator` / `kernel` / `gui_replay` / `upstream` / `diff_report`

## L7 GUI 通信回放

### 范围
- Replay GUI 的 Clash API HTTP/WS 调用序列
- token 鉴权链路
- 断链重连与重放

### 当前实现
- 已支持 HTTP/WS 步骤回放
- 已支持 `/configs`、`/proxies`、`/connections`、`/memory`、`/traffic`、`/logs` 场景建模

## L8 数据面发送/解码专项

### 范围
- 模拟公网服务端与本地代理交互
- 验证 TCP/UDP/DNS/WS/TLS 回路

### 当前实现
- 已提供 upstream 模拟器：HTTP/TCP/UDP/WS/DNS/TLS
- 已提供 traffic plan 执行器：HTTP GET / TCP roundtrip / UDP roundtrip / DNS query

## L9 订阅解析专项

### 范围
- JSON/YAML/Base64 输入解析与归一化

### 当前实现
- `subscription` 模块支持三类输入
- 已落 3 个 P0 case：`p0_subscription_json/yaml/base64`
- 实网样本验证结论：
  - 标准 Clash 订阅样本可解析；
  - 部分订阅/中转 URL 返回 403/429 或挑战页（风控/人机检测/反代理策略），不属于解析器语义错误；
  - 该项按“基础可用”结项，后续在可直连/白名单环境做补充复验。

## L10 双核差分与稳定性回归

### 范围
- Go vs Rust 双核快照对比

### 当前实现
- `case diff <id>` 输出 `diff.json` + `diff.md`
- 比较维度：HTTP、WS、subscription、traffic

## L11 CI 准入与治理 ✅ Closed

### 规划
- PR smoke：P0 核心 case
- nightly full：全矩阵 + 故障注入

### 交付
- ✅ CI workflow：`interop-lab-smoke.yml`（PR）+ `interop-lab-nightly.yml`（定时全量）
- ✅ 趋势门禁脚本：`run_case_trend_gate.sh` + `aggregate_trend_report.sh`
- ✅ 历史趋势追踪：`trend_history.jsonl`（JSONL 格式，ISO 时间戳）
- ✅ 回归检测：strict case score 退化 >10% 自动 REGRESSION_WARNING
- ✅ Nightly workflow 集成聚合趋势报告 + 历史追踪
- ✅ L11 闭环完成

## L11 -> L12 交接（新增）

L5-L11 完成后，下一阶段进入“Go 规格驱动的能力收敛”：

- 交接规划文档：`agents-only/03-planning/08-L12-L14-GO-SPECS-WORKPACKAGES.md`
- 重点交接项：
  - 弃用与迁移治理（deprecated 提示、迁移路径可操作化）
  - Endpoint/Services/TLS 高级能力收敛
  - 长时回归趋势门禁 CI 化

## L12-L14 闭环总结（2026-02-12）

L12-L14 阶段为"Go 规格驱动的能力收敛"，在 L5-L11 联测仿真与 CI 治理基础上，完成了以下三个层级的工作：

### L12 迁移兼容治理

- 弃用字段 deprecated 提示体系（配置层 warning 日志）
- 迁移路径文档化与可操作化验证
- 配置 schema 兼容性回归

### L13 Services 安全与生命周期

- 服务生命周期增强（graceful shutdown、依赖顺序）
- 安全相关配置验证（凭据格式、端口冲突检测）
- 服务间通信契约收紧

### L14 TLS/Endpoint 高级能力与趋势门禁 CI 化

- **证书存储模式**: `CertStoreMode`（System/Mozilla/None），通过 `rustls-native-certs` 加载系统证书库
- **证书热重载**: `notify` crate 文件监听 + `CancellationToken` 优雅终止，自动重建 `rustls::ServerConfig`
- **TLS fragment 闭环验证**: sb-config `TlsFragmentIR` -> sb-tls `TlsFragmentConfig` -> sb-core 运行时路径已确认
- **TLS 能力矩阵诊断**: `TlsCapabilityMatrix` 工具输出 uTLS/ECH/REALITY 能力状态（accepted limitation 明确标注）
- **Nightly 趋势门禁模板**: `strict_default` / `env_limited_default` / `development` 三套阈值配置
- **interop-lab TLS case**: 3 个 TLS 互操作 case + 1 个 TLS fragment case

### 状态

- **L12**: ✅ Closed
- **L13**: ✅ Closed
- **L14**: ✅ Closed（含 L14.3.1 集成验证）

### 后续方向

L12-L14 完成后，所有已规划的能力收敛工作已结项。后续可能的方向：
- 实机联测（Linux runtime 验证、实网 TLS 对照）
- 性能基准建立（M3.2）
- 生产化准备（日志/监控/部署自动化）
