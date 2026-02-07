# 验收标准（Acceptance Criteria）

> **本文档定义所有可验证的验收条款**：通过这些标准即可确认实现符合需求。

---

## 1. 功能对齐验收（Parity Acceptance）

### 1.1 总体指标

| 指标 | 目标 | 当前 | 验收方式 |
|------|------|------|---------|
| 总体对齐率 | ≥ 95% | 88% | `GO_PARITY_MATRIX.md` |
| Inbound 协议 | 100% | 100% (18/18) | 功能测试 |
| Outbound 协议 | 100% | 100% (19/19) | 功能测试 |
| DNS 传输 | 100% | 100% (11/11) | 功能测试 |
| 路由规则 | 100% | 100% (38/38) | 规则匹配测试 |

### 1.2 协议验收检查表

```bash
# 每个协议需要通过以下验证：
□ 配置解析正确（JSON/YAML）
□ 握手成功（Client <-> Server）
□ 数据传输正确
□ 错误处理合理
□ 超时/重连逻辑正确
```

---

## 2. 架构验收（Architecture Acceptance）

### 2.1 依赖树验收

**✅ PASS 条件**：

```bash
# sb-core 禁止依赖检查
cargo tree -p sb-core | grep -E "axum|tonic|tower|hyper|reqwest|rustls|quinn|tokio-tungstenite"
# 预期输出：无匹配

# sb-types 禁止依赖检查
cargo tree -p sb-types | grep -E "tokio|hyper|axum|rustls|quinn"
# 预期输出：无匹配

# sb-api 不依赖 sb-adapters
cargo tree -p sb-api | grep "sb-adapters"
# 预期输出：无匹配
```

### 2.2 代码归属验收

| 条目 | 验收标准 |
|------|---------|
| 协议实现 | 全部在 `sb-adapters/` 下 |
| 平台服务 | 全部在 `sb-platform/` 下 |
| sb-core | 只包含路由/策略/调度/生命周期 |

---

## 3. 可测试性验收（Testability Acceptance）

### 3.1 单元测试

| Crate | 要求 | 验证命令 |
|-------|------|---------|
| sb-core | 不依赖真实网络 | `cargo test -p sb-core --lib` |
| sb-types | 100% 纯逻辑 | `cargo test -p sb-types` |
| sb-config | Schema 验证 | `cargo test -p sb-config` |

### 3.2 集成测试覆盖

```bash
# 协议集成测试
cargo test --test shadowsocks_integration  # 14 tests
cargo test --test trojan_integration       # 16 tests
cargo test --test vless_integration        # 17 tests
cargo test --test dns_outbound_integration # 15 tests
```

---

## 4. 性能验收（Performance Acceptance）

### 4.1 基准测试

| 场景 | 指标 | 验收标准 |
|------|------|---------|
| 进程匹配 (macOS) | 延迟 | < 1ms（Go 为 ~149ms） |
| 路由决策 | 吞吐 | > 100K rules/sec |
| DNS 缓存 | 命中率 | > 90% (typical) |

### 4.2 资源使用

| 指标 | 验收标准 |
|------|---------|
| 内存占用 | 启动 < 50MB |
| 连接开销 | < 1KB/conn |
| GC 暂停 | N/A (Rust) |

---

## 5. 安全验收（Security Acceptance）

### 5.1 依赖安全

```bash
# 无 HIGH/CRITICAL 漏洞
cargo deny check advisories
# 预期：全部 PASS

# 许可证合规
cargo deny check licenses
# 预期：全部 PASS
```

### 5.2 密钥管理

| 检查项 | 验收标准 |
|--------|---------|
| 文件权限 | 密钥文件 0600 |
| 日志脱敏 | tokens/keys 自动 redact |
| TLS 版本 | 强制 TLS 1.2+ |

---

## 6. CI/CD 验收

### 6.1 CI 流水线检查

```yaml
# 必须通过的 CI 步骤：
- cargo fmt --check
- cargo clippy --workspace --all-features
- cargo test --workspace
- cargo deny check
- cargo build -p app --features parity --release
```

### 6.2 Parity 构建

```bash
# Parity 特性集验证
cargo build -p app --features "parity" --release

# 功能验证
./target/release/app version
./target/release/app check -c test_config.json
```

---

## 7. 验收流程

### 7.1 自动化验收

```bash
#!/bin/bash
# acceptance_check.sh

set -e

echo "=== 1. 依赖边界检查 ==="
! cargo tree -p sb-core | grep -qE "axum|tonic|tower|hyper|rustls|quinn"
! cargo tree -p sb-types | grep -qE "tokio|hyper|axum"

echo "=== 2. 代码质量 ==="
cargo fmt --check
cargo clippy --workspace --all-features -- -D warnings

echo "=== 3. 测试通过 ==="
cargo test --workspace

echo "=== 4. 安全检查 ==="
cargo deny check

echo "=== 5. Parity 构建 ==="
cargo build -p app --features parity --release

echo "=== ✅ ALL PASSED ==="
```

### 7.2 手动验收清单

- [ ] 配置文件兼容性（与 Go sing-box 配置）
- [ ] 热重载功能（SIGHUP）
- [ ] 管理 API 响应
- [ ] 日志输出格式
- [ ] Prometheus metrics 导出

---

## 8. 验收记录模板

```markdown
## 验收记录

**日期**: YYYY-MM-DD
**验收人**: [Name]
**版本**: [Git SHA]

### 自动化检查
- [ ] 依赖边界: PASS/FAIL
- [ ] 代码质量: PASS/FAIL
- [ ] 测试覆盖: PASS/FAIL (覆盖率 %)
- [ ] 安全检查: PASS/FAIL
- [ ] Parity 构建: PASS/FAIL

### 手动检查
- [ ] 配置兼容: PASS/FAIL
- [ ] 热重载: PASS/FAIL
- [ ] API: PASS/FAIL
- [ ] 日志: PASS/FAIL
- [ ] Metrics: PASS/FAIL

### 备注
[任何特殊情况或已知问题]

### 结论
□ 通过验收
□ 需要返工
```

---

*下一步：阅读 [03-ARCHITECTURE-SPEC.md](./03-ARCHITECTURE-SPEC.md) 了解架构规范*
