# app（组合根 + CLI）

## 1) 职责

- feature 聚合（用户只面向 app features）
- 启动 runtime（tokio）
- 读取配置 -> 编译 IR -> 构建 adapters/platform/transport/tls
- 组装 sb-core Engine
- （可选）启动 sb-api 与 metrics exporter

## 2) 组合根必须显式

- 不允许在 sb-core 内做“自动发现组件”
- 所有依赖注入在 app 完成：`Engine::new(deps...)`

## 3) 典型启动流程（伪代码）

```rust
fn main() {
  let raw = sb_config::load_from_file(...)?;
  let ir = sb_config::compile(raw)?;
  let deps = build_platform_and_infra(...)?;
  let adapters = sb_adapters::build_adapters(&ir, deps)?;
  let engine = sb_core::Engine::new(ir, adapters, deps.ports)?;
  run(engine, ...);
}
```
