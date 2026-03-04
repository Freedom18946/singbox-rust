# 代码迁移日志（Code Migration Log）

> **用途**：记录每次代码迁移的详细信息

---

## 迁移记录格式

```markdown
### [日期] 迁移标题
- **源位置**: `crates/xxx/src/...`
- **目标位置**: `crates/yyy/src/...`
- **涉及文件**: file1.rs, file2.rs
- **原因**: 违反依赖边界 / 职责归属错误
- **影响**: 需要更新的 imports / tests
- **验证**: 运行的验证命令
```

---

## 迁移历史

<!-- 按时间倒序记录 -->

### [2026-02-07] 初始化
- 创建迁移日志文档
- 等待 L1.1 审计完成后开始记录

---

## 待迁移队列

| 优先级 | 源 | 目标 | 内容 | 状态 |
|--------|-----|------|------|------|
| P1 | sb-core/outbound | sb-adapters/outbound | MIG-01: Direct/Block 去重（core 保留 thin wrapper） | 🟨 L19.3.3 已建档 |
| P1 | sb-core/outbound | sb-adapters/outbound | MIG-02: SOCKS5 单实现（统一握手/UDP 路径） | 🟨 L19.3.3 已建档 |
| P1 | sb-core/outbound | sb-adapters + sb-transport | MIG-03: Hysteria2 单实现 + QUIC util 下沉 | 🟨 L19.3.3 已建档 |
| P1 | sb-core/inbound | sb-adapters/inbound | MIG-04: HTTP/Mixed 入站收敛 | 🟨 L19.3.3 已建档 |
| P1 | sb-core/transport | sb-transport | MIG-05: Dialer/TLS 单真源 | 🟨 L19.3.3 已建档 |
| P2 | sb-adapters/outbound | sb-core/outbound | MIG-06: Selector 职责收敛（语义留 core，adapter 仅适配） | 🟨 L19.3.3 已建档 |
