# L12-L14 工作包规划（基于 Go 版本功能分析导入）

> 更新日期：2026-02-11  
> 输入来源：`agents-only/dump/go-version-analysis/2026-02-11-intake/sing-box-core-specs/*.md`  
> 目标：把导入的 Go 官方能力规格转成可执行工作包，并接入现有 L5-L11 联测体系。

---

## 0) 前提与边界

1. Go 版本 sing-box + GUI + TUN 是网络基线，不可中断、不可替换。  
2. Rust 内核仅做并行对照与能力补齐，不接管现网。  
3. 所有新增工作包必须绑定“可验证产物”（测试/用例/差分/报告），避免纯文档闭环。  

---

## 1) 关键增量信号（来自导入规格）

导入规格相比当前计划的新增重点：

1. **弃用与迁移治理**：对 deprecated 配置的强提示、替代建议、迁移路径可操作化。  
2. **Endpoint 体系闭环**：尤其是 WireGuard outbound 向 endpoint 迁移与 Tailscale/DERP 联动。  
3. **Services 安全默认值**：`ssm_api/ccm/ocm` 等服务的监听面、鉴权、日志与限流策略。  
4. **TLS 高级能力治理**：pinning/mTLS/ECH/Reality/fragment/kTLS 能力矩阵、风险提示与默认策略。  
5. **长期回归门禁**：高并发 + soak + 趋势门禁持续化（已在 L5-L11 打基础，需制度化到下一阶段）。  

---

## 2) L12：迁移与兼容治理（P0）

### L12.1 Deprecation 信号总线

- 目标：`check` 与运行时对 deprecated 字段统一输出“可操作迁移建议”。  
- 交付：
  - `sb-config`：deprecated 字段映射表（字段 -> 替代方案 -> 文档链接）
  - `app check`：输出路径 + 替代项 + 严重级别（warning/error）
  - 运行时日志：首次加载时聚合提示（避免刷屏）
- 验收：
  - 至少覆盖：legacy DNS、special outbounds 迁移、WireGuard outbound 迁移提示
  - 新增回归测试：deprecated 样本配置 -> 提示文本稳定

### L12.2 WireGuard outbound -> endpoint 迁移闭环

- 目标：旧配置不静默失效，新配置可稳定替换。  
- 交付：
  - 兼容层：旧 WireGuard outbound 能运行或明确拒绝并给迁移建议
  - 自动重写工具（可选）：输出 endpoint 形态建议片段
  - 迁移文档：最小变更示例（old -> new）
- 验收：
  - 导入旧配置时行为可预测（可运行或强提示失败）
  - interop case：旧/新两种配置均可验证可观测行为

### L12.3 DNS 迁移与平台差异策略对齐

- 目标：把 legacy/平台差异从“隐性风险”转成“显性策略”。  
- 交付：
  - macOS reverse mapping/FakeIP 风险提示与默认策略文档化
  - DNS legacy server 策略（保留兼容或硬迁移）在 `check` 中可见
  - 场景 case：平台差异导致的可解释失败（非 silent failure）
- 验收：
  - 同一配置在不同平台的差异可被日志/报告解释

---

## 3) L13：Services 安全默认值与控制面收敛（P1）

### L13.1 Services 最小暴露面

- 目标：`services[]` 默认不误暴露公网。  
- 交付：
  - `ssm_api/ccm/ocm` 默认监听 localhost
  - 鉴权必填或显式 opt-out（带警告）
  - 基础限流与审计日志开关
- 验收：
  - 无鉴权 + 非 localhost 配置时必须有强提示或阻断策略

### L13.2 Service 生命周期与故障隔离

- 目标：服务失败不拖垮主流程，且可诊断。  
- 交付：
  - 启停状态机统一（init/start/stop/error）
  - 失败分类（配置错误/依赖缺失/权限）
  - metrics & health endpoint 对应服务状态
- 验收：
  - 注入服务启动失败后，主内核仍可运行并输出可定位错误

### L13.3 API Bridge 契约回放

- 目标：`ssm_api/ccm/ocm` 进入 interop-lab 可编排回归。  
- 交付：
  - 新增 case：关键端点 smoke + auth negative + basic throughput
  - 产出：snapshot/diff/report 可复现
- 验收：
  - PR smoke 至少覆盖 1 套服务桥接路径

---

## 4) L14：TLS 高级能力矩阵与长期质量门禁（P1/P2）

### L14.1 TLS 能力矩阵与默认策略

- 目标：明确“支持/不支持/受限”的能力边界，避免用户误配。  
- 交付：
  - TLS capability matrix（pinning/mTLS/ECH/Reality/fragment/kTLS/uTLS 风险）
  - 配置校验：不支持项给明确提示与替代建议
- 验收：
  - 文档矩阵与实际校验行为一致（有测试）

### L14.2 Endpoint-Tailscale-DERP 场景闭环

- 目标：endpoint + dns(tailscale) + derp 联动可回归。  
- 交付：
  - interop case：联动最小闭环（连通/故障/恢复）
  - 风险场景：DERP 不可达、DNS fallback
- 验收：
  - 错误与恢复路径均可稳定复现

### L14.3 长时回归与趋势门禁 CI 化

- 目标：把当前手工趋势门禁固化到 CI/nightly。  
- 交付：
  - 接入 `run_case_trend_gate.sh` 到 nightly
  - 阈值配置模板（strict / env-limited）
- 验收：
  - nightly 自动产出 trend 报告并可追踪历史退化

---

## 5) 执行顺序（建议）

1. L12.1 -> L12.2 -> L12.3（先治理迁移与兼容风险）  
2. L13.1 -> L13.2 -> L13.3（再收敛服务安全与生命周期）  
3. L14.1 -> L14.2 -> L14.3（最后做高级能力边界与长期门禁）  

---

## 6) 与现有计划的对接点

- L5-L11 产出的 `interop-lab`、`p2_connections_ws_*`、`run_case_trend_gate.sh` 作为 L14.3 起点。  
- 现有 M2.4（DERP/Resolved/SSMAPI）作为 L13 的实现基础，不重复造轮子。  
- `99-验收清单总表.md` 可作为 L12-L14 的验收映射参考表。  
