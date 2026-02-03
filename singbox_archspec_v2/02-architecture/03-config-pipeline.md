# 配置编译流水线（Config -> IR）

## 目标

把“可随意变形的配置”变成“可直接执行的 IR”，并让 sb-core 不关心配置格式差异。

---

## 分层

1. **RawConfig**（解析层）
   - 负责 YAML/JSON/TOML 解析
   - 位置：`sb-config::raw`

2. **ValidatedConfig**（验证层）
   - schema 校验、字段范围、引用完整性
   - 位置：`sb-config::validate`

3. **CompiledConfig / IR**（编译层）
   - 预计算路由规则
   - 将协议/outbound 类型编译为 enum tags
   - 位置：`sb-config::compile`

---

## 输出接口（sb-core 使用）

- sb-core 只依赖 `sb-types::ConfigIr`
- app 负责：
  - 解析 RawConfig
  - 调用 sb-config 编译
  - 构建 adapters（工厂）
  - 将 `ConfigIr + Components` 注入 sb-core
