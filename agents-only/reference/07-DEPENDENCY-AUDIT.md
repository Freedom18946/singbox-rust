# 当前依赖边界状态（Dependency Boundary Status）

> 说明：本文件描述当前仓库采用的边界门禁口径，不再保留旧“违规清单”叙事。  
> 权威来源：`ARCHITECTURE-SPEC.md`、`agents-only/06-scripts/check-boundaries.sh`、`boundary-policy.json`。

---

## 当前口径

- `sb-core` 是内核合集层，不是“纯引擎层禁入一切协议/传输实现”。
- 现存协议/服务/传输模块允许保留在 `sb-core`，但必须 feature-gated，并通过边界门禁约束。
- `sb-adapters -> sb-core` 不是绝对禁止项；当前按预算与路径分类管理。
- 评估“是否越界”时，以 `check-boundaries.sh` 的实际 fail 条件为准，不以旧宪法摘要为准。

## 当前门禁分类

### V1: `sb-core` 非门控 Web 框架引用

- 检查范围：`crates/sb-core/src/`
- 目标：禁止未受 feature gate 保护的 `axum` / `tonic` / `tower` 等 Web 引用
- 结果语义：命中即 `FAIL`

### V2: `sb-core` 非门控 TLS/QUIC/WebSocket 引用

- 检查范围：`crates/sb-core/src/`
- 目标：禁止未受 feature gate 保护的 `rustls` / `quinn` / `reqwest` / `tokio-tungstenite` 等引用
- 结果语义：命中即 `FAIL`

### V3: `sb-core` 协议模块必须受 gate 保护

- 检查范围：`crates/sb-core/src/outbound/*`
- 目标：现存协议实现允许保留，但对应模块必须在 `outbound/mod.rs` 中受 feature gate 约束
- 结果语义：未门控协议模块即 `FAIL`

### V4: `sb-adapters -> sb-core` 重叠依赖按预算管理

- `V4a`：`outbound/`、`register.rs`、stub 路径中的 `use sb_core`，当前阈值由 `boundary-policy.json` 的 `v4.v4a_max` 控制
- `V4b`：`inbound/`、`service/`、`endpoint/` 中的 `use sb_core`，当前视为架构允许的 informational overlap
- 当前这不是“零容忍禁用”；重点是防止重叠继续无控制扩张

### Pattern Budgets

当前 `boundary-policy.json` 还定义了路径级模式预算，例如：

- `adapter_io_bridge_instances`
- `bridge_inbounds_runtime_refs`
- `legacy_global_context_installs`
- 产品路径中的 adapter 注册入口预算

这些预算与 `check-boundaries.sh` 联动，超出 `max` 且 `severity=fail` 时即失败。

### V5: `sb-subscribe -> sb-core`

- 目标：禁止 `sb-subscribe` 非可选依赖 `sb-core`
- 结果语义：若为非可选直接依赖，则 `FAIL`

### V6: strict feature tree / default closure / reverse deps

- 对 `sb-core` 的默认 feature 闭包、依赖 owner、可选依赖声明进行静态核对
- 目的：确保当前 ADR 口径下的保留依赖仍然可解释、可追踪、可 gate

## 当前接受的边界现实

- `sb-core` 中存在保留的服务/传输/协议实现，这是当前决议下的受控现实，不单独视为违规。
- `sb-adapters::register_all()` 在产品路径中存在集中注册入口；当前问题不是“是否存在”，而是“是否继续扩散到新的入口点”。
- 文档、审议、实施决策都应引用脚本与策略文件，而不是旧版“sb-core 只能依赖 sb-types / sb-common”的绝对化表述。

## 维护要求

- 任何修改边界预算、allowlist 或 fail/informational 语义的改动，必须同步更新：
  - `ARCHITECTURE-SPEC.md`
  - `boundary-policy.json`
  - 本文件
- 若新增例外，必须以“当前约束 + owner + gate 方式”描述，不得回退到旧宪法式总禁令。

## 验证命令

```bash
# 当前边界门禁（建议先看报告模式）
./agents-only/06-scripts/check-boundaries.sh --report

# 严格模式
./agents-only/06-scripts/check-boundaries.sh

# 查看当前路径级预算
sed -n '1,220p' agents-only/reference/boundary-policy.json
```

---

*最后更新：2026-03-21*
