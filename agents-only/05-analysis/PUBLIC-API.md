# 公共 API 清单（Public API）

> **更新方式**：对比 `public-api-baseline.txt` 更新

---

## 当前状态

**基线文件**：`/public-api-baseline.txt`

**最后验证**：待验证

---

## 关键公共接口

### sb-core

| 模块 | 公共类型 | 稳定性 |
|------|---------|-------|
| router | `Router`, `Rule` | 稳定 |
| dns | `DnsResolver`, `DnsConfig` | 稳定 |
| inbound | `InboundManager` | 可能变动 |
| outbound | `OutboundManager` | 可能变动 |

### sb-types

| 模块 | 公共类型 | 稳定性 |
|------|---------|-------|
| 待分析 | | |

### sb-config

| 模块 | 公共类型 | 稳定性 |
|------|---------|-------|
| 待分析 | | |

---

## 重构影响

重构后需要更新 `public-api-baseline.txt`：
- [ ] 确认当前基线是否最新
- [ ] 识别重构会影响的公共 API
- [ ] 规划 API 变更策略

---

## 验证命令

```bash
# 比较当前 API 与基线
cargo public-api diff public-api-baseline.txt
```
