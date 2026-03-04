# L20.2.2 QUIC-ECH 显式模式机（reject / experimental）

日期：2026-03-05  
范围：`L20.2.2`

## 变更摘要

1. `crates/sb-config/src/ir/experimental.rs`
   - `ExperimentalIR` 新增 `quic_ech_mode: Option<String>`。
2. `crates/sb-config/src/validator/v2.rs`
   - QUIC+ECH 校验新增模式机：
     - 默认（未配置或 `reject`）：硬拒绝（`error`）
     - `experimental`：放行为 `warning`（明确风险提示）
   - 非法模式值新增显式报错：
     - 路径：`/experimental/quic_ech_mode`
     - 类型错误：`TypeMismatch`
     - 枚举错误：`InvalidEnum`
3. `docs/capabilities.md`
   - 更新 `tls.ech.quic` 护栏说明为“默认 reject、显式 experimental”。
4. `scripts/capabilities/generate.py`
   - `tls.ech.quic` 证据说明改为模式机语义（不再描述为无条件 hard-block）。

## 最小验证

1. `cargo test -p sb-config tls_quic_ech -- --nocapture`
2. `cargo test -p sb-config test_parse_experimental_block -- --nocapture`
3. `python3 scripts/capabilities/generate.py --out reports/capabilities.json --probe-report reports/runtime/capability_probe.json`
4. `bash scripts/check_claims.sh`
5. `bash agents-only/06-scripts/check-boundaries.sh --strict`

结果：

- ✅ `tls_quic_ech` 相关测试通过（5/5）：
  - 默认 reject 仍硬拒绝
  - `experimental` 降级为 warning（不再 hard error）
  - 非法模式值报错路径正确
- ✅ `experimental` 字段解析测试通过
- ✅ capability 产物与 claim/boundary 门禁全绿

## 证据路径

1. `crates/sb-config/src/validator/v2.rs`
2. `crates/sb-config/src/ir/experimental.rs`
3. `docs/capabilities.md`
4. `reports/capabilities.json`
