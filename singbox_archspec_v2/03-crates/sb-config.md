# sb-config（配置：解析/验证/编译）

## 1) 目标

- 支持多格式输入（JSON/YAML/TOML）
- 统一输出 `ConfigIr`（sb-types）
- 把校验与预计算放在启动/热更新阶段，而不是运行期热路径

## 2) 强制分层

- `raw`：仅 parse
- `validate`：语义校验
- `compile`：输出 IR

## 3) 禁止事项

- 不允许在 sb-config 内直接进行网络拉取订阅（属于 sb-subscribe 或 app）
- 不允许与 sb-core 互相依赖
