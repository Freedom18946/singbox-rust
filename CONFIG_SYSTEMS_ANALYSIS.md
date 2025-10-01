# sb-config 配置系统重叠分析

## 执行摘要

sb-config 包含三个重叠的配置类型，造成架构混乱：

1. **`lib.rs::Config`** - 根模块配置（轻度使用）
2. **`model.rs::Config`** - 旧模型配置（几乎未使用）
3. **`ir::ConfigIR`** - 中间表示（主力配置）

**建议**：统一为单一配置系统，以 `ir::ConfigIR` 为核心。

---

## 详细分析

### 1. lib.rs::Config

**位置**: `crates/sb-config/src/lib.rs:27-40`

**结构**:
```rust
pub struct Config {
    pub schema_version: u32,
    pub inbounds: Vec<Inbound>,
    pub outbounds: Vec<Outbound>,
    pub rules: Vec<Rule>,
    pub default_outbound: Option<String>,
}
```

**使用量**: 2 个引用
- `crates/sb-core/tests/router_domain.rs`: 测试代码
- `crates/sb-core/src/routing/explain.rs`: `from_config()` 方法

**特点**:
- 包含 `schema_version` 字段
- 扁平的 rules 结构（V1 风格）
- 用于外部 API 和配置文件解析

**问题**:
- 与 V2 schema 不一致（V2 使用 `route.rules`）
- 与主力 ConfigIR 结构不同
- 使用量极少

---

### 2. model.rs::Config

**位置**: `crates/sb-config/src/model.rs:110-117`

**结构**:
```rust
pub struct Config {
    pub inbounds: Vec<Inbound>,
    pub outbounds: Vec<Outbound>,
    pub rules: Vec<Rule>,
}
```

**使用量**: 1 个引用
- `crates/sb-config/src/compat.rs:5`: `compat_1_12_4()` 占位符函数

**特点**:
- 最简单的结构
- Go sing-box 1.12.4 兼容层
- 自带 `normalize()` 方法

**问题**:
- 仅在占位符函数中使用
- 功能已被 `migrate_to_v2()` 替代（使用 `serde_json::Value`）
- 可以安全删除

---

### 3. ir::ConfigIR

**位置**: `crates/sb-config/src/ir/mod.rs:139-146`

**结构**:
```rust
pub struct ConfigIR {
    pub inbounds: Vec<InboundIR>,
    pub outbounds: Vec<OutboundIR>,
    pub route: RouteIR,  // 嵌套的路由结构（V2 风格）
}
```

**使用量**: 88+ 引用，14 个文件
- 核心文件：
  - `adapter/bridge.rs`, `adapter/mod.rs`
  - `routing/engine.rs`, `routing/router.rs`
  - `runtime/mod.rs`, `runtime/supervisor.rs`
  - `inbound/socks5.rs`, `inbound/http_connect.rs`

**特点**:
- 主力配置表示
- V2 schema 兼容（`route` 嵌套结构）
- 完整的字段支持（credentials, flow, network, packet_encoding 等）
- 被 sb-core 广泛使用

**优势**:
- 架构清晰，字段完整
- 与 V2 schema 一致
- 生产级使用

---

## 推荐方案

### 方案 A：保守统一（推荐）

1. **保留**: `ir::ConfigIR` 作为唯一内部表示
2. **删除**: `model.rs::Config`（未使用）
3. **保留但重构**: `lib.rs::Config` 作为外部 API facade
   - 添加 `From<Config> for ConfigIR` trait
   - 添加 `Config::into_ir()` 方法
   - 保持向后兼容

**工作量**: 2-3 天

**优点**:
- 最小化破坏性变更
- 保留外部 API 稳定性
- 清晰的内部/外部边界

**缺点**:
- 仍保留两个类型（但职责清晰）

---

### 方案 B：激进统一

1. **统一**: 所有地方使用 `ConfigIR`
2. **删除**: `lib.rs::Config` 和 `model.rs::Config`
3. **迁移**: `explain.rs` 和测试代码直接使用 `ConfigIR`

**工作量**: 4-5 天

**优点**:
- 单一配置表示
- 零歧义

**缺点**:
- 破坏外部 API
- 测试需要大量更新

---

## 实施步骤（方案 A）

### 第 1 步：删除 model.rs::Config

```bash
# 删除 model.rs 中的 Config 定义（保留其他类型如 Inbound, Outbound）
# 修改 compat.rs 删除 compat_1_12_4 占位符函数
```

**影响**: 无（未使用）

---

### 第 2 步：添加 Config → ConfigIR 转换

```rust
// 在 lib.rs 中添加
impl From<Config> for ir::ConfigIR {
    fn from(cfg: Config) -> Self {
        // 实现 V1 → V2 转换逻辑
        // - rules → route.rules
        // - default_outbound → route.default
    }
}
```

---

### 第 3 步：更新使用点

- `routing/explain.rs:from_config()`: 内部调用 `cfg.into()`
- `tests/router_domain.rs`: 可选更新为 ConfigIR

---

## 优先级

**P1（本次）**: 删除 `model.rs::Config`（工作量：30分钟）

**P1.5（可选）**: 添加 Config → ConfigIR 转换（工作量：2小时）

**P2（未来）**: 完全统一为 ConfigIR（工作量：4-5天）

---

## 结论

当前最紧迫的问题是 `model.rs::Config` 的存在造成了混乱，但实际未被使用。建议：

1. ✅ **立即执行**: 删除 `model.rs::Config`
2. 🔄 **本周执行**: 添加 Config → ConfigIR 转换
3. 📅 **Q1 规划**: 考虑完全统一为 ConfigIR
