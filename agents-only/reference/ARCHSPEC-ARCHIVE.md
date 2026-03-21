# singbox_archspec_v2 归档说明

> 来源：已删除的 `singbox_archspec_v2/` 目录  
> 归档用途：解释旧架构资料来自哪里，以及为什么不能再把旧摘要当成现行规范。

---

## 使用说明

- 本文件是归档说明，不是当前架构规范。
- 现行口径只看 `ARCHITECTURE-SPEC.md`。
- 若旧资料与现行 ADR / 边界门禁冲突，以现行文档和脚本为准。

## 旧资料去了哪里

旧目录中的核心内容已分散吸收到当前文档体系：

| 旧主题 | 当前位置 |
|------|------|
| 依赖宪法 / crate 边界 | `ARCHITECTURE-SPEC.md` |
| 验收标准 | `ACCEPTANCE-CRITERIA.md` |
| 结构导航 | `PROJECT-STRUCTURE.md` |
| 依赖边界状态 | `07-DEPENDENCY-AUDIT.md` |
| Parity / capability / closure 口径 | `GO_PARITY_MATRIX.md`, `docs/capabilities.md`, `reports/capabilities.json` |

## 旧宪法摘要已废弃

> WARNING: `singbox_archspec_v2` 时期的“sb-core 纯引擎层、禁入协议实现 / TLS / QUIC / Web”摘要已经被 L19.3.1 ADR 修订。  
> 当前项目采用“内核合集层 + feature gate + 边界门禁”的治理方式。

因此：

- 旧资料可以作为演化背景阅读
- 旧资料不能继续作为当前违规判定依据
- 任何仍引用旧宪法摘要的文档，都应被视为待同步对象

## 如何查看历史

- 通过 Git 历史检索 `singbox_archspec_v2/`
- 不在本文档中固定某个 commit hash，因为这会继续制造新的漂移点

---

*最后更新：2026-03-21*
