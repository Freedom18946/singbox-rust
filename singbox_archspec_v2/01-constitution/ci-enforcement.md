# CI 强制执行：依赖边界与质量门禁

## 1) 依赖边界检查（必须）

实现方式（建议）：
- 在 `tools/depcheck/` 写一个小工具：`cargo metadata --format-version=1`
- 解析 workspace 中每个 crate 的依赖，按白名单检查
- 白名单来源：本文件中的“允许依赖方向 + 每 crate 禁止库列表”

输出要求：
- 打印违反规则的 crate、依赖名、来源（direct/transitive）
- CI 以非零退出码失败

> coding agent 约束：**依赖边界检查必须先落地**，否则后续重构必然被回流污染。

---

## 2) clippy / rustfmt / deny / audit

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo deny check`（许可证/安全/重复依赖）
- `cargo test --workspace`

---

## 3) check-cfg 与 feature 管理

- 所有 feature 必须在 `app/Cargo.toml` 聚合并在 CI 提供两套构建：
  - `cargo build -p app`（默认最小）
  - `cargo build -p app --features acceptance`（验收全集）

---

## 4) 构建剖析（可选但推荐）

- `cargo build -Z timings`（本地）
- `cargo llvm-lines`（定位体积热点）
