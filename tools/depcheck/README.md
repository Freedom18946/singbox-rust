# depcheck

依赖边界检查工具（P2 产出）。

## 用途

- 检查 workspace crates 的 direct/transitive 依赖是否违反边界规则。
- 规则来源：`tools/depcheck/rules.toml`。

## 运行

```bash
python tools/depcheck/depcheck.py
```

跳过 transitive 检查：

```bash
python tools/depcheck/depcheck.py --no-transitive
```

JSON 输出：

```bash
python tools/depcheck/depcheck.py --format json
```

## 规则维护

- 修改 `tools/depcheck/rules.toml` 的 `[forbid]` 条目。
- 规则应与 `singbox_archspec_v2/01-constitution/dependency-constitution.md` 与
  `singbox_archspec_v2/05-reference/dependency-matrix.md` 保持一致。

## 离线说明

- transitive 检查基于 `Cargo.lock` 推导，不依赖网络。
- 若 `Cargo.lock` 缺失，将自动跳过 transitive 检查并输出警告。

## CI 策略（当前）

- 暂不接入 GitHub workflow。
- 仅作为本地门禁使用，后续若需接入 CI 再评估。
