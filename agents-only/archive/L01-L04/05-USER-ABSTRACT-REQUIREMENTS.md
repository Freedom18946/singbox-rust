# 用户抽象需求（User Abstract Requirements）

> **项目核心目标**：将 Go 版本 sing-box 重构为 Rust 实现，作为 GUI.for" SingBox 的内核替换。

---

## 1. 项目背景

### 1.1 目标产品
将标准/知名的 **Go 版本 sing-box** 项目重构为 **Rust 实现**。

### 1.2 预期使用环境
- **操作系统**: macOS
- **GUI 前端**: GUI.for" SingBox
- **协议优先级**: Trojan 优先 + Shadowsocks 全套支持

---

## 2. 参考资源

### 2.1 sing-box（核心代理）

| 类型 | 地址 |
|------|------|
| GitHub | https://github.com/SagerNet/sing-box |
| 官方文档 | https://sing-box.sagernet.org/ |
| **本地源码** | `go_fork_source/sing-box-1.12.14` |

> ⚠️ **注意**：具体版本已由用户指定，位于本地 `go_fork_source/sing-box-1.12.14`，不需要重复下载。以本地文件夹实现为准。

### 2.2 GUI.for" SingBox（GUI 前端）

| 类型 | 地址 |
|------|------|
| GitHub | https://github.com/GUI-for-Cores/GUI.for.SingBox |
| 官方文档 | https://gui-for-cores.github.io/ |
| **本地源码** | `GUI_fork_source/` |

> ⚠️ **注意**：GUI 源码位于 `GUI_fork_source/`，版本以本地文件夹为准。

### 2.3 AI 联网搜索用途
- 文档内的配置写法
- API 调用参数
- 协议规范细节
- **不用于**下载源码或版本确认

---

## 3. 使用场景

### 3.1 替换流程

```
[GUI.for" SingBox] 
      │
      │ 更新内核时
      ▼
┌─────────────────────────────────┐
│  覆盖 singbox 程序文件          │
│  (原为 Go 编译产物)             │
│  (目标为 Rust 编译产物)         │
└─────────────────────────────────┘
      │
      │ 替换后
      ▼
[Rust singbox-rust 程序]
```

### 3.2 兼容性要求

**Rust 实现必须与 Go 版本完全一致**：

| 维度 | 要求 |
|------|------|
| 参数调用 | CLI 参数完全兼容 |
| 配置文件 | JSON/YAML 格式兼容 |
| 行为 | 运行时行为一致 |
| 生命周期 | 启动/重载/关闭流程一致 |
| API | Clash API / V2Ray API 兼容 |
| 退出码 | 错误码含义一致 |

### 3.3 实际替换验证

```bash
# Go 版本行为
./sing-box run -c config.json
./sing-box check -c config.json
./sing-box version

# Rust 版本必须产生相同结果
./singbox-rust run -c config.json
./singbox-rust check -c config.json
./singbox-rust version
```

---

## 4. 协议优先级

### 4.1 核心协议（必须完整支持）

| 优先级 | 协议 | 状态 |
|--------|------|------|
| 🔴 P0 | **Trojan** | ✅ 已实现 |
| 🔴 P0 | **Shadowsocks** 全套 | ✅ 已实现 |
| 🟡 P1 | VMess / VLESS | ✅ 已实现 |
| 🟡 P1 | SOCKS5 / HTTP | ✅ 已实现 |
| 🟢 P2 | Hysteria2 / TUIC | ✅ 已实现 |

### 4.2 传输层（必须支持）

| 传输 | 状态 |
|------|------|
| TCP / UDP | ✅ |
| WebSocket | ✅ |
| gRPC | ✅ |
| HTTP/2 | ✅ |
| QUIC | ✅ |

### 4.3 TLS（必须支持）

| 功能 | 状态 |
|------|------|
| Standard TLS | ✅ |
| REALITY | ✅ |
| uTLS 指纹 | ◐ 部分 |
| ECH | ◐ 部分 |

---

## 5. 验收标准（用户视角）

### 5.1 功能验收
- [ ] GUI.for" SingBox 可以正常识别 Rust 版本
- [ ] 所有现有配置文件无需修改即可使用
- [ ] Trojan 节点连接正常
- [ ] Shadowsocks 节点连接正常
- [ ] 规则路由正常工作
- [ ] 热重载（SIGHUP）正常

### 5.2 性能验收
- [ ] 启动时间 ≤ Go 版本
- [ ] 内存占用 ≤ Go 版本
- [ ] 代理延迟无明显增加

### 5.3 稳定性验收
- [ ] 长时间运行（24h+）无崩溃
- [ ] 网络切换后自动恢复
- [ ] 错误日志清晰可读

---

*本文档定义用户的核心期望。所有技术决策应服务于这些需求。*
