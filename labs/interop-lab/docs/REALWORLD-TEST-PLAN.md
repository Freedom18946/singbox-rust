# L5+ 实战联测计划（Go+GUI+TUN 基线）

> 更新时间：2026-02-11
> 适用范围：L5 之后的具体交互测试阶段

## 不可变基础（强制）

1. Go 版本 sing-box + GUI + TUN 是网络基础，不可挑战、不可替换、不可中断。
2. Rust 内核仅用于对照测试，默认不接管现网流量。
3. 每次 Rust 内核测试结束后必须回收，避免影响用户侧网络。

## 每轮测试固定流程

1. 确认 Go+GUI+TUN 正常在线。
2. 启动 Rust 测试实例（独立 API 端口，例如 `127.0.0.1:19090`）。
3. 执行指定 case 或 GUI 手工动作。
4. 保存 artifacts 与差分结果。
5. 回收 Rust 内核并确认端口释放。

推荐回收检查命令：

```bash
kill <RUST_KERNEL_PID>
lsof -nP -iTCP:19090 -sTCP:LISTEN
```

## 环境分级（L5.3.1）

- `strict`：默认 PR smoke 执行并阻断。
- `env_limited`：默认 nightly 执行，失败按环境归因，不阻断 PR。

快速命令：

```bash
# strict 回归
cargo run -p interop-lab -- case run --env-class strict

# env-limited 回归
cargo run -p interop-lab -- case run --env-class env-limited
```

## 场景 1：GUI 基础控制面回放

- Case：`p0_clash_api_contract`
- 目标：GUI P0 HTTP/WS 契约一致性。

## 场景 2：鉴权负路径（高事故风险）

- Case：`p1_auth_negative_wrong_token`、`p1_auth_negative_missing_token`
- 目标：wrong/missing token 下 HTTP/WS 拒绝语义一致。

## 场景 3：可选端点契约

- Case：`p1_optional_endpoints_contract`
- 目标：`/providers` `/rules` `/script` `/profile` 返回可解释（404/501/受限）。

## 场景 4：生命周期契约

- Case：`p1_lifecycle_restart_reload_replay`
- 目标：同端口 restart/reload 后控制面仍可用。

## 场景 5：核心链路与故障恢复

- Case：`p1_rust_core_*`、`p1_fault_*`、`p1_recovery_*`
- 新增：`p1_fault_jitter_http_via_socks`、`p1_recovery_jitter_http_via_socks`
- 目标：连通、故障、恢复语义可复现。

## 场景 6：订阅导入流程

- Case：`p0_subscription_*`、`p1_subscription_file_urls`
- 目标：JSON/YAML/Base64 与 URL 样本归因闭环。

## 场景 7：协议层与长稳回归

- Case：`p2_trojan_*`、`p2_shadowsocks_*`、`p2_connections_ws_*`
- 目标：协议套件、故障恢复与趋势门禁。

趋势门禁命令：

```bash
ITERATIONS=3 KERNEL=rust RUN_ENV_CLASS=strict \
  labs/interop-lab/scripts/run_case_trend_gate.sh p2_connections_ws_soak_suite
```

## 联测分工（建议）

1. 你负责：保持 Go+GUI+TUN 基线稳定、提供真实 GUI 操作输入与必要环境参数。
2. 我负责：编写/运行 case、收集 artifacts、输出差分结论、严格回收 Rust 测试进程。
