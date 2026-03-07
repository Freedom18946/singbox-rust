# 源码分析索引（Analysis Index）

> 此目录包含源码分析相关的文档和结果

---

## 分析文档

| 文档 | 用途 |
|------|------|
| [CRATE-STRUCTURE.md](./CRATE-STRUCTURE.md) | 各 crate 结构分析 |
| [VIOLATION-LOCATIONS.md](./VIOLATION-LOCATIONS.md) | 违规代码精确位置 |
| [DEPENDENCY-GRAPH.md](./DEPENDENCY-GRAPH.md) | 依赖关系图 |
| [FEATURE-FLAGS.md](./FEATURE-FLAGS.md) | Feature flag 分析 |
| [PUBLIC-API.md](./PUBLIC-API.md) | 公共 API 清单 |

---

## 分析工作流

1. 运行 `../06-scripts/analyze-deps.sh` 生成依赖图
2. 运行 `../06-scripts/find-violations.sh` 定位违规
3. 手动更新 VIOLATION-LOCATIONS.md
4. 更新 CRATE-STRUCTURE.md
