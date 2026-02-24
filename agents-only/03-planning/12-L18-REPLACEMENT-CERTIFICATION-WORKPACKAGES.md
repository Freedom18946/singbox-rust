# L18 详细工作包：替换认证 + 沙盒不扰民

状态：✅ 设计冻结，🔄 已进入实现与验证（更新：2026-02-24）

## 1. L18 目标与边界

- 主目标：Rust 替换认证（Go 为 Oracle）。
- 并行目标：性能零回归（相对 Go 阈值门禁）。
- 拓扑：双内核一 GUI（Go + Rust + GUI 驱动）。
- 环境：仅 macOS（self-hosted runner）。
- Docker 策略：本机替换验证默认非阻断；CI/certify 可开启阻断。

## 2. 沙盒不扰民设计（强约束）

### 2.1 通信与网络边界

- 所有认证通信仅允许 loopback：`127.0.0.1/localhost/::1`。
- 禁止外网监听地址（`0.0.0.0`）进入认证链路。
- 固定门禁端口：`9090/19090/11810/11811`；占用即 FAIL。

### 2.2 配置与系统接管防护

- 认证配置禁止 `tun/tproxy/redirect` 入站（避免接管系统流量）。
- GUI 认证运行在临时 sandbox HOME，不读写用户常规配置目录。
- 默认禁止“与真实代理并存”，检测到常见代理进程或常见代理端口即 FAIL。

### 2.3 系统代理保护

- 认证前记录 `scutil --proxy` 快照。
- 认证后再次快照并做字节级对比。
- 快照变化即 FAIL（说明可能污染了系统代理状态）。

### 2.4 进程与资源回收

- 仅回收本次 run 启动的 GUI/内核 PID，不做全局 `pkill`。
- run 结束后校验关键端口释放；未释放即 FAIL。

## 3. L18 工作包（执行顺序）

### Batch A（基线固化）

- L18.1 preflight：环境与端口前置，缺失即 FAIL。
- L18.2 Go Oracle：每轮现编译 + manifest 可追溯。

### Batch B（认证主干）

- L18.3 双核差分认证：`daily(P0/P1)` + `nightly(full both-kernel)`。
- L18.4 GUI 双轨认证：API 回放 + 真实 GUI 五步关键流。

### Batch C（硬门禁）

- L18.5 性能门禁：p95/RSS/启动三阈值硬判定。
- L18.6 capstone：`gui/canary/dual_kernel_diff/perf` 必过；`docker` 按运行模式决定是否阻断。

### Batch D（自动化与收敛）

- L18.7 self-hosted macOS CI：`daily/nightly/certify` 可调度。
- L18.8 状态总线：`agents-only` + `docs` + `reports` 单口径。

## 4. 落地资产（当前）

- `scripts/l18/preflight_macos.sh`
- `scripts/l18/build_go_oracle.sh`
- `scripts/l18/run_dual_kernel_cert.sh`
- `scripts/l18/gui_real_cert.sh`
- `scripts/l18/perf_gate.sh`
- `scripts/l18/l18_capstone.sh`
- `.github/workflows/l18-certification-macos.yml`
- `reports/L18_REPLACEMENT_CERTIFICATION.md`

## 5. 最新补强（沙盒不扰民）

已在 `gui_real_cert.sh` / `l18_capstone.sh` 接线：

- 临时 sandbox HOME（每次 run 独立目录）
- loopback URL 校验
- `tun/tproxy/redirect` 配置阻断
- 真实代理进程/端口互斥检测
- 系统代理快照前后比对
- 关键端口释放检查
- `--fail-fast` 失败即停模式（用于 daily 快速探测）

## 6. 执行建议

- 本地首跑：`scripts/l18/l18_capstone.sh --profile daily --fail-fast --gui-app <abs_path_to_gui_app>`
- 本机无 Docker 阻断：追加 `--require-docker 0`（默认值）。
- CI/certify 严格模式：追加 `--require-docker 1`。
- CI 调度：先 `daily`，稳定后启用 `nightly`，最终提交 `certify(7d)` 作为 L18 结项证据。
