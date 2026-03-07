# 需求澄清（Requirements Clarification）

> **来源**：2026-02-07 用户问答澄清
> **用途**：补充需求分析中的模糊点

---

## 1. 平台范围

| 平台 | 状态 | 说明 |
|------|------|------|
| **macOS** | ✅ 目标平台 | 完整支持 |
| Linux | ⏸️ 待定 | 编译时不编译 |
| Windows | ⏸️ 待定 | 编译时不编译 |

**实现方式**：使用条件编译 `#[cfg(target_os = "macos")]`，Linux/Windows 功能编译为 stub。

---

## 2. 行为一致性

**容忍度**：B - 低容忍

- 核心功能必须与 Go 版本一致
- 边缘情况可以「更好」但需记录差异
- 发现差异时需讨论解决方案

---

## 3. 版本输出格式

**决策**：需要根据 GUI 解析方式确定

**GUI 解析方式**：
```typescript
// GUI.for.SingBox/frontend/src/hooks/useCoreBranch.ts:150-152
const res = await Exec(CoreFilePath, ['version'])
versionDetail.value = res.trim()
return res.match(/version (\S+)/)?.[1] || ''  // 关键正则
```

**兼容性要求**：
- Rust 版本输出必须包含 `version X.X.X` 格式
- 示例：`singbox-rust version 0.1.0`（会被解析为 `0.1.0`）
- Go 输出：`sing-box version 1.12.14 ...`

---

## 4. 二进制命名

| 项目 | 值 |
|------|-----|
| 编译产物名 | `singbox-rust` |
| 替换方式 | 用户手动重命名为 `sing-box` |

**注意**：GUI 进程检测使用 `processName.startsWith('sing-box')`，重命名后可兼容。

---

## 5. uTLS/ECH 处理

**策略**：B - 尽量支持，不阻塞发布

- 遇到具体开发困难时再决定是否放弃
- 当前状态：◐ 部分支持，后续迭代

---

## 6. 稳定性测试

**范围**：D - 多场景混合

| 场景 | 内容 |
|------|------|
| 空闲运行 | 无流量待机 |
| 低流量 | 模拟日常使用 |
| 高流量 | 大量并发连接（目标场景） |
| 网络切换 | WiFi ↔ 有线 ↔ 断开 |

**本地测试时可缩短时间，但目标压力必须大。**

---

## 7. 性能基准

**标准**：D - 体感相当即可

无需具体数字对比，用户体验无明显差异即可。

---

## 8. GUI 兼容性关键点

### 8.1 启动检测

```typescript
// kernel.ts:17
export const CoreStopOutputKeyword = 'sing-box started'
```

**要求**：Rust 启动成功后必须输出包含 `sing-box started` 的日志。

**Go 输出示例**：
```
INFO[0000] sing-box started (0.05s)
```

**Rust 实现建议**：
```rust
info!("sing-box started ({}s)", elapsed.as_secs_f64());
```

### 8.2 进程检测

```typescript
// kernelApi.ts:235
running.value = processName.startsWith('sing-box')
```

**要求**：进程名以 `sing-box` 开头（用户重命名后满足）。

### 8.3 默认参数

```typescript
// kernel.ts:299-306 DefaultCoreConfig
args: [
  'run',
  '--disable-color',
  '-c', '$APP_BASE_PATH/$CORE_BASE_PATH/config.json',
  '-D', '$APP_BASE_PATH/$CORE_BASE_PATH',
]
```

**要求**：必须支持这些 CLI 参数。

---

## 9. 测试方案

### 9.1 背景问题

本机可能已运行真实 Go 版本 TUN 代理，直接测试会冲突。

### 9.2 解决方案（用户建议）

在子目录创建模拟服务端项目：

```
singbox-rust/
├── app/                    # 主程序（客户端）
└── test-server/            # 新：模拟服务端（Rust）
    ├── Cargo.toml
    └── src/
        └── main.rs         # 简单的 Trojan/SS 服务端
```

**测试流程**：
1. 启动 test-server 监听指定端口（如 10080）
2. 配置 singbox-rust 连接 localhost:10080
3. 使用 curl 等工具通过 singbox-rust 代理访问公网
4. 绕过本机 TUN 环境，使用保留端口

### 9.3 替代方案

- 使用 Docker 隔离网络
- 临时停止 Go 版本 TUN（不推荐）
- 直接使用公网测试服务器（如有）

---

## 10. 缺失功能处理

### 10.1 问题

> 欠缺部分功能的 Rust 程序，会被 GUI 识别为什么？

### 10.2 分析

GUI **不会**主动检测功能完整性，只会：

1. **版本检测**：`sing-box version` → 正则解析
2. **启动检测**：检查输出是否包含 `sing-box started`
3. **进程检测**：检查进程名是否以 `sing-box` 开头
4. **运行时错误**：配置中使用不支持的功能时，内核会报错

### 10.3 结论

| 场景 | 行为 |
|------|------|
| 缺少某协议 | 配置使用该协议时报错并退出 |
| 缺少某功能 | 同上 |
| GUI 会卡死吗？ | **不会**，只要能正常启动和输出日志 |
| feature flag 自动跳过？ | **不会**，GUI 不知道功能是否存在 |

**建议**：对于未实现的功能，返回清晰的错误信息，如：
```
ERROR: Protocol 'xxx' is not supported in this build
```

---

*本文档记录需求澄清结果，与需求分析文档配合使用。*
