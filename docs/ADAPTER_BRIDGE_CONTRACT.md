# Adapter Bridge Contract

目标：在**不改变对外契约**（CLI/JSON/Explain/指标）的前提下，优先使用 `sb-adapter` 的真实实现；
当 adapter 不可用或开发中时，回退到 `feature="scaffold"` 的最小实现。

## 运行时开关

- `ADAPTER_FORCE=adapter`  → 仅尝试 adapter，失败不回退（暴露问题）
- `ADAPTER_FORCE=scaffold` → 强制使用脚手架
- 未设置                  → 优先 adapter，失败自动回退脚手架

## 编译期特性

- `--features adapter`   启用 adapter 桥接（默认）
- `--features scaffold`  启用脚手架实现

> 若工程尚未引入 `sb-adapter`，建议 CI 使用：
> `cargo test --no-default-features --features scaffold`

## 装配顺序

1. 根据 IR 先构建 **出站**（命名映射），再构建 **入站**；
2. 入站在运行时可通过路由引擎 → 命名出站进行转发；
3. Explain/Trace 和 metrics 均不受装配路径影响，仍由 `sb-core` 输出。

## 回滚策略

若 adapter 行为升级导致回归，可临时：
```
ADAPTER_FORCE=scaffold app/run ...
```
并记录 `/metrics` 与 CLI JSON 以核对差异。