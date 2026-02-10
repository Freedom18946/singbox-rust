# L5-L11 单项目联测仿真计划（实施版）

> 更新日期：2026-02-10
> 状态：L5/L6 已开工，基础设施已入库（`labs/interop-lab`）

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

## L11 CI 准入与治理

### 规划
- PR smoke：P0 核心 case
- nightly full：全矩阵 + 故障注入

### 当前状态
- 待接入 `.github/workflows`（下一迭代）
