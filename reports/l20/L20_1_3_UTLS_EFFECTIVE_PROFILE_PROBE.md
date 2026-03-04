# L20.1.3 启动探针输出 uTLS 实际生效模式

日期：2026-03-05  
范围：`L20.1.3`

## 变更摘要

1. `app/src/capability_probe.rs`
   - `tls.utls` 探针从“仅计数”扩展为 profile 级映射：
     - `requested_profile`
     - `effective_profile`
     - `fallback_reason`
     - `utls_request_count`
   - 新增 profile 规范化/映射逻辑，覆盖 `chrome/firefox/randomized` 等 alias。
   - 新增单测：profile 生效映射与探针 details 校验。
2. `app/src/run_engine.rs`
   - 启动探针写入 ECH probe 的 provider 决策细节（含 fallback reason），并保留 probe-only 模式产物输出。
3. `docs/capabilities.md`
   - 补充 `tls.utls` runtime probe details 字段说明。

## 最小验证

1. `cargo check -p app --features parity --bin run`
2. `cargo test -p app capability_probe --features parity --lib`
3. `SB_CAPABILITY_PROBE_ONLY=1 SB_CAPABILITY_PROBE_OUT=reports/runtime/capability_probe.json SB_TLS_PROVIDER=aws-lc cargo run -q -p app --features parity --bin run -- -c /tmp/l20_probe_utls_config.json`
4. `python3 scripts/capabilities/generate.py --out reports/capabilities.json --probe-report reports/runtime/capability_probe.json`

结果：

- ✅ 编译通过（`app` parity/bin run）
- ✅ `capability_probe` 相关单测通过（5/5）
- ✅ `reports/runtime/capability_probe.json` 中 `tls.utls.details` 已包含 `requested_profile/effective_profile/fallback_reason`
- ✅ `reports/capabilities.json` 中 `tls.utls.runtime_probe.details` 与 probe 产物一致

## 证据路径

1. `reports/runtime/capability_probe.json`
2. `reports/capabilities.json`
3. `app/src/capability_probe.rs`
4. `app/src/run_engine.rs`
