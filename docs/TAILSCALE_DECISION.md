# Tailscale 集成策略决策文档

> **状态**: 📋 待决策 | **优先级**: 高 | **影响**: 架构级

---

## 执行摘要

Go sing-box 使用嵌入式 `tsnet.Server` + gVisor netstack 实现完整的 Tailscale 用户态网络栈。Rust 实现当前使用 daemon/stub 模式,依赖外部 `tailscaled` 进程。本文档评估三种可行方案并提供建议。

---

## 现状分析

### Go 实现 (参考)
```
protocol/tailscale/
├── endpoint.go      # tsnet.Server 嵌入
├── inbound.go       # Tailscale 入站监听
├── outbound.go      # Tailscale 出站拨号
└── wireguard.go     # WireGuard 集成
```

**关键能力**:
- 完整用户态网络栈 (gVisor netstack)
- 内置控制平面 (不依赖 tailscaled)
- MagicDNS 通过 netstack 路由
- TCP/UDP 监听和拨号
- 无需系统权限 (不创建 TUN 设备)

### Rust 现状
```
crates/sb-core/src/endpoint/tailscale.rs (1108 行)
├── TailscaleControlPlane trait   # 控制平面抽象
├── DaemonControlPlane            # Unix socket 与 tailscaled 通信
├── StubControlPlane              # 测试用 stub
└── TailscaleEndpoint             # 端点实现
```

**当前能力**:
- ✅ 配置解析和验证
- ✅ 生命周期管理
- ✅ 通过 tailscaled daemon 拨号/监听
- ❌ 无用户态 netstack
- ❌ 需要外部 tailscaled 进程
- ❌ MagicDNS 走系统网络 (非 tailnet)

---

## 方案评估

### 方案 A: tsnet FFI 集成

**方法**: CGO 绑定 Go 的 tsnet.Server

| 维度 | 评估 |
|------|------|
| **保真度** | ⭐⭐⭐⭐⭐ 100% Go 对等 |
| **复杂度** | ⭐⭐⭐⭐⭐ 极高 (CGO + Go + gVisor) |
| **可维护性** | ⭐⭐ 低 (跨语言调试困难) |
| **构建兼容性** | ❌ macOS ARM64 失败 |
| **工作量** | 4-8 周 |

**已尝试**:
- `tsnet` crate (v0.1.0): gVisor 构建约束失败
- `libtailscale` crate (v0.2.0): Go 构建失败

**阻塞原因**: gVisor 不支持 darwin/arm64 + Go 1.25.4 组合

### 方案 B: Pure Rust 实现

**方法**: 纯 Rust 实现 Tailscale 协议栈

| 维度 | 评估 |
|------|------|
| **保真度** | ⭐⭐⭐ 中等 (核心功能可达) |
| **复杂度** | ⭐⭐⭐⭐⭐ 极高 |
| **可维护性** | ⭐⭐⭐⭐ 高 (纯 Rust) |
| **构建兼容性** | ✅ 全平台 |
| **工作量** | 8-16 周 |

**需要实现**:
- [ ] Tailscale 控制协议 (Noise + DERP)
- [ ] WireGuard 用户态 (已有 boringtun)
- [ ] 轻量级 TCP/IP 栈 (smoltcp?)
- [ ] MagicDNS 处理

**参考项目**:
- `boringtun`: WireGuard 用户态
- `smoltcp`: 嵌入式 TCP/IP 栈

### 方案 C: Daemon-Only 模式 (当前)

**方法**: 保持依赖外部 tailscaled

| 维度 | 评估 |
|------|------|
| **保真度** | ⭐⭐ 低 (功能受限) |
| **复杂度** | ⭐ 最低 |
| **可维护性** | ⭐⭐⭐⭐⭐ 最高 |
| **构建兼容性** | ✅ 全平台 |
| **工作量** | 已完成 |

**限制**:
- 需要用户安装 Tailscale 客户端
- 无法在容器/沙盒环境使用
- macOS App Store 分发困难

---

## 功能对比矩阵

| 功能 | Go (tsnet) | Rust A (FFI) | Rust B (Pure) | Rust C (Daemon) |
|------|------------|--------------|---------------|-----------------|
| 用户态网络栈 | ✅ | ✅ | ✅ | ❌ |
| 无需 tailscaled | ✅ | ✅ | ✅ | ❌ |
| MagicDNS | ✅ | ✅ | ✅ | ⚠️ 系统路由 |
| TCP/UDP 隧道 | ✅ | ✅ | ✅ | ✅ |
| 沙盒环境 | ✅ | ✅ | ✅ | ❌ |
| App Store 分发 | ✅ | ⚠️ | ✅ | ❌ |
| 构建复杂度 | - | 高 | 中 | 低 |
| macOS ARM64 | - | ❌ | ✅ | ✅ |

---

## 建议

### 短期 (接受限制)

**推荐**: 方案 C - 保持 Daemon-Only 模式

- 文档化限制,告知用户需要安装 Tailscale 客户端
- DaemonControlPlane 已可用,通过 Unix socket 与 tailscaled 通信
- 适用于服务器/桌面场景

### 中期 (评估 Pure Rust)

**下一步**:
1. 评估 `smoltcp` 作为用户态 TCP/IP 栈的可行性
2. 研究 Tailscale 控制协议开放程度
3. 考虑基于 `boringtun` 构建 WireGuard 层

### 长期 (监控 FFI 选项)

- 跟踪 `tsnet`/`libtailscale` crate 更新
- 等待 gVisor darwin/arm64 支持改善
- 考虑贡献上游修复

---

## 决策记录

| 日期 | 决策 | 理由 |
|------|------|------|
| 2025-12-16 | 评估完成 | FFI 阻塞,Pure Rust 工作量大,保持 Daemon 模式 |

---

## 相关文档

- [TAILSCALE_RESEARCH.md](./TAILSCALE_RESEARCH.md) - 前期研究记录
- [GO_PARITY_MATRIX.md](../GO_PARITY_MATRIX.md) - 功能对齐矩阵
- [VERIFICATION_RECORD.md](../VERIFICATION_RECORD.md) - 验证记录
