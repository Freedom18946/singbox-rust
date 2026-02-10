# L5+ 实战联测计划（Go+GUI+TUN 基线）

> 更新时间：2026-02-10
> 适用范围：L5 之后的具体交互测试阶段

## 不可变基础（强制）

1. Go 版本 sing-box + GUI + TUN 是网络基础，不可挑战、不可替换、不可中断。
2. Rust 内核仅用于对照测试，默认不接管现网流量。
3. 每次 Rust 内核测试结束后必须回收，避免影响用户侧网络。

## 每轮测试固定流程

1. 确认 Go+GUI+TUN 正常在线（你的当前工作网络不受影响）。
2. 启动 Rust 测试实例（独立 API 端口，例如 `127.0.0.1:19090`）。
3. 执行指定 case 或 GUI 手工动作。
4. 保存 artifacts 与差分结果。
5. 回收 Rust 内核并确认端口释放。

推荐回收检查命令：

```bash
# 若有记录 PID，优先使用
kill <RUST_KERNEL_PID>

# 核对端口是否释放（示例 19090）
lsof -nP -iTCP:19090 -sTCP:LISTEN
```

---

## 场景 1：GUI 基础控制面回放（首轮必须）

- 目标：确认 Rust 与 Go 在 GUI P0 调用路径上的契约一致性。
- 你配合：提供 Go API 与 Rust API 的访问地址和 token。
- 我执行：
  - `cargo run -p interop-lab -- case run p0_clash_api_contract --kernel both`
  - `cargo run -p interop-lab -- case diff p0_clash_api_contract`
- 通过标准：`diff.md` 中 HTTP/WS mismatch 为 0 或仅有已登记例外。

## 场景 2：鉴权负路径（实际最容易出线上事故）

- 目标：验证错误 token/空 token 时，HTTP 与 WS 都按预期拒绝。
- 你配合：确认 GUI 当前 token 策略（是否允许空 token）。
- 我执行：新增并运行 `p1_auth_negative_*` case（wrong token / missing token）。
- 通过标准：HTTP 返回 401/403，WS 连接失败或立即关闭，且 Go/Rust 行为一致。

## 场景 3：连接面板真实交互（/connections）

- 目标：验证连接列表、实时流和关闭连接行为。
- 你配合：在 GUI 中发起 2-3 个真实请求（网页/测速均可）。
- 我执行：
  - 回放 `GET /connections` + `WS /connections`
  - 触发 `DELETE /connections/{id}`（对有效连接）
- 通过标准：连接出现、关闭后消失，Go/Rust 差分一致。

## 场景 4：流量与内存图表稳定性（/traffic + /memory）

- 目标：验证 dashboard 数据流不是 mock，且帧格式稳定。
- 你配合：保持 3-5 分钟常规网络活动。
- 我执行：持续收集 `WS /traffic`、`WS /memory` 并做帧摘要对比。
- 通过标准：帧持续输出、字段完整、无异常断流，Go/Rust 差分可解释。

## 场景 5：订阅导入真实流程（JSON/YAML/Base64）

- 目标：验证 GUI 常见订阅格式解析与节点统计一致。
- 你配合：提供可公开测试的订阅样本（或脱敏样本）。
- 我执行：运行 `p0_subscription_json/yaml/base64` + 实际 URL 补测。
- 通过标准：可解析样本节点数一致；受风控 URL 标注为环境限制，不判核心失败。

## 场景 6：网络波动与重连（L7/L8 关键）

- 目标：验证 WS 断连重连和上游抖动下的行为一致性。
- 你配合：允许在测试窗口短时断开某上游（或我用仿真注入）。
- 我执行：故障注入（delay/disconnect）并回放连接重建路径。
- 通过标准：Rust/Go 都能恢复或都按相同错误模式失败，且无僵尸连接残留。

## 场景 7：长时回归（夜间）

- 目标：提前发现累积泄漏、计数漂移、偶发崩溃。
- 你配合：给一个不影响白天工作的时间窗。
- 我执行：P0 case 循环运行 + 周期 diff 报告。
- 通过标准：无持续增长异常、无新 mismatch 趋势。

---

## 联测分工（建议）

1. 你负责：保持 Go+GUI+TUN 基线稳定、提供真实 GUI 操作输入与必要环境参数。
2. 我负责：编写/运行 case、收集 artifacts、输出差分结论、严格回收 Rust 测试进程。

