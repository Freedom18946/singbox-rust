# L20.1.2 uTLS profile 能力矩阵细化

日期：2026-03-05  
范围：`L20.1.2`

## 变更摘要

1. `scripts/capabilities/schema.json`
   - 能力对象新增可选字段：`parent_capability_id`
2. `scripts/capabilities/generate.py`
   - 新增 capability id：`tls.utls.chrome` / `tls.utls.firefox` / `tls.utls.randomized`
   - `map_claim_to_capabilities()` 增加 profile 关键词映射
   - profile capability 证据锚点接入 `reports/security/tls_fingerprint_baseline.json`
3. `docs/capabilities.md`
   - 能力索引和详情新增 profile 级条目
4. `scripts/check_claims.sh`
   - 高风险 uTLS/fingerprint claim 若出现 profile 关键词，要求链接到对应 profile capability id

## 最小验证

1. `python3 scripts/capabilities/generate.py --out reports/capabilities.json`
2. `jq '.capabilities[] | select(.id|test("^tls\\.utls")) | {id,parent_capability_id,overall_state,accepted_limitation}' reports/capabilities.json`
3. `bash scripts/check_claims.sh`

结果：

- ✅ capabilities 生成成功：`reports/capabilities.json`
- ✅ profile 能力已写入：`tls.utls.chrome` / `tls.utls.firefox` / `tls.utls.randomized`
- ✅ `bash scripts/check_claims.sh` 输出：`[claim-guard] PASS (6 claims checked)`

## 证据路径

1. `reports/capabilities.json`
2. `docs/capabilities.md`
3. `scripts/capabilities/generate.py`
4. `scripts/check_claims.sh`
