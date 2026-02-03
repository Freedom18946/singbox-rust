# 工具链与工程规范（Toolchain Policy）

## Rust 版本与 edition

- Rust：**1.92**（与现有规范一致）
- Edition：2021（保持现状；如未来升级需单独 ADR）

## 格式化与静态检查

- rustfmt：默认配置；禁止在仓库内维护“个性化 fmt 风格”
- clippy：`-D warnings`；允许的 lint 例外必须写在代码行级 `#[allow(...)]` 并解释原因

## 依赖治理

- `cargo deny`：
  - 许可证白名单（与仓库许可证政策一致）
  - 安全漏洞（advisories）
  - 重复依赖与 feature 泄漏

## 目录与命名

- crate 名：`sb-*` 前缀（保持现状）
- module 文件：snake_case
- trait 名：`*Port` / `*Connector` / `*Acceptor`

## 公共 API 稳定性

- `sb-types` 的 public API 变更必须：
  - 更新 `04-interfaces/*`
  - 通过 baseline（如仓库已有 `public-api-baseline.txt`，则更新并审查 diff）
