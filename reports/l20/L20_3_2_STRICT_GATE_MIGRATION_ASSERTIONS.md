# L20.3.2 strict gate 迁移追踪断言

日期：2026-03-05  
范围：`L20.3.2`

## 变更摘要

1. `agents-only/06-scripts/l20-migration-allowlist.txt`
   - 新增 wave#1 版本化断言清单：`VERSION|l20.3.2-wave1-v1`
   - 覆盖 8 条断言（5 forbid + 3 require）
2. `agents-only/06-scripts/check-boundaries.sh`
   - 新增 `V7: L20 migration assertions`
   - 按 allowlist 逐条执行 `forbid/require` 正则检查并计数失败

## 最小验证

1. `bash agents-only/06-scripts/check-boundaries.sh --strict`

结果：

- ✅ `V7` 识别版本：`l20.3.2-wave1-v1`
- ✅ `V7` 断言通过：`PASS (8 assertions)`
- ✅ 全量边界门禁通过：`全部检查通过 (0 违规)`

## 证据路径

1. `agents-only/06-scripts/l20-migration-allowlist.txt`
2. `agents-only/06-scripts/check-boundaries.sh`
3. `reports/l20/L20_3_1_WAVE1.md`
