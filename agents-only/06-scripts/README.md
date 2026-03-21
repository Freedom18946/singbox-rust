# 脚本索引（Scripts Index）

> 此目录只包含 AI / boundary governance 辅助脚本。
> 仓库业务脚本、E2E、CI、本地 release 入口位于顶层 `scripts/`，其最新导航见 `agents-only/reference/SCRIPTS-MAP.md`。

---

## 脚本清单

| 脚本 | 用途 | 运行方式 |
|------|------|---------|
| [analyze-deps.sh](./analyze-deps.sh) | 分析依赖关系 | `./analyze-deps.sh` |
| [find-violations.sh](./find-violations.sh) | 查找违规代码 | `./find-violations.sh` |
| [check-boundaries.sh](./check-boundaries.sh) | CI 边界检查 | `./check-boundaries.sh` |

---

## 使用说明

```bash
# 使脚本可执行
chmod +x agents-only/06-scripts/*.sh

# 从项目根目录运行
./agents-only/06-scripts/analyze-deps.sh
```
