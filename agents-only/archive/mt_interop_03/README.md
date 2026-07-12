<!-- tier: B -->
# MT-INTEROP-03 — 双核验收基线净化

Status: CLOSED (2026-07-12)

目标：103 个 interop case 每例只产生 `PASS`、`DIV-COVERED`、`ENV-LIMITED` 或需处理的
`FAIL`；终验要求零 `FAIL`。易变计数仅写最终验收记录，项目实时状态仍以
`agents-only/active_context.md` 为准。

## 工作组

1. 自管理四个旧外部 Clash API case。
2. 修正 DNS TTL reference oracle 与配置 TTL 传播。
3. 排除 `/memory` 首帧合成零值造成的 soak 泄漏误报。
4. 统一 protocol-local Rust profile 与 Go binary bootstrap。
5. 重验 graceful drain、FakeIP、reload、group-delay；合理差异登记 S4。
6. 全量复验、复审、文档同步、归档。

详细基线见 `failure_census_and_oracle_adr.md`；终验见 `acceptance.md`。
