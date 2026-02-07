# 迁移记录模板

> 复制此模板到 `dump/` 目录，替换 `{{placeholder}}` 内容

---

## 迁移信息

| 项目 | 值 |
|------|-----|
| 日期 | {{YYYY-MM-DD}} |
| 迁移 ID | {{M-001}} |
| 状态 | ✅ 完成 / ⏸️ 进行中 |

---

## 迁移详情

| 维度 | 值 |
|------|-----|
| **源位置** | `{{crates/xxx/src/...}}` |
| **目标位置** | `{{crates/yyy/src/...}}` |
| **原因** | {{违反依赖边界/职责归属错误/...}} |

---

## 涉及文件

| 文件 | 操作 | 新路径 |
|------|------|--------|
| `{{file1.rs}}` | 移动 | `{{new/path/file1.rs}}` |
| `{{file2.rs}}` | 移动+修改 | `{{new/path/file2.rs}}` |

---

## Import 变更

```diff
- use old_crate::module::Type;
+ use new_crate::module::Type;
```

---

## 测试影响

| 测试文件 | 变更 |
|---------|------|
| `{{test_file.rs}}` | 更新 imports |

---

## 验证命令

```bash
cargo check -p {{affected_crate}}
cargo test -p {{affected_crate}}
```

**验证结果**：{{通过/失败}}

---

## 回滚步骤

如需回滚：
```bash
git revert {{commit_hash}}
```
