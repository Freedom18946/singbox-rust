# 移动平台支持评估文档

> **状态**: 📋 评估完成 | **优先级**: 低-中 | **影响**: 生态扩展

---

## 执行摘要

Go sing-box 通过 `experimental/libbox/` (48 文件) 提供 iOS/Android 移动绑定,使用 gomobile 生成跨平台库。Rust 尚无对应实现,但可通过 UniFFI 或 cbindgen 实现类似功能。

---

## Go libbox 分析

**目录**: `experimental/libbox/` (48 files)

**主要组件**:
```
command_*.go     # 命令协议 (status, log, group, urltest 等)
config*.go       # 配置管理
service*.go      # 后台服务
platform_*.go    # 平台特定 (iOS/Android)
tun*.go          # TUN 设备管理
memory*.go       # 内存管理
```

**功能**:
- 后台代理服务生命周期管理
- TUN 设备创建和管理
- 配置加载/验证
- 连接状态查询
- 日志流式传输
- Clash 模式切换
- 分组/选择器控制

**绑定方式**: gomobile (生成 .aar/.framework)

---

## Rust 实现选项

### 选项 A: UniFFI (推荐)

**库**: mozilla/uniffi-rs

**优势**:
- Mozilla 维护,生产验证 (Firefox)
- 自动生成 Kotlin/Swift 绑定
- 异步支持
- 类型安全

**工作量**: 2-3 周

**示例**:
```rust
// lib.rs
#[uniffi::export]
pub fn start_service(config_path: String) -> Result<ServiceHandle, Error> {
    // ...
}

#[uniffi::export]
pub fn stop_service(handle: ServiceHandle) -> Result<(), Error> {
    // ...
}
```

### 选项 B: cbindgen + 手动绑定

**方法**: 生成 C 头文件,手动编写 Swift/Kotlin 封装

**优势**:
- 更细粒度控制
- 更小的 FFI 开销

**劣势**:
- 手动维护成本高
- 容易出错

**工作量**: 4-6 周

### 选项 C: 延迟实现

**方法**: 保持当前状态,优先核心功能

**理由**:
- 桌面/服务器使用 CLI
- 移动市场需求需验证

---

## 功能映射

| Go libbox | Rust 对应 | 状态 |
|-----------|-----------|------|
| BoxService | sb_core::Box | ✅ 存在 |
| StartService | Box::start() | ✅ 存在 |
| StopService | Box::close() | ✅ 存在 |
| SetSystemProxy | 未实现 | ⏳ |
| QueryConnections | 未实现 | ⏳ |
| StreamLog | 未实现 | ⏳ |
| TUN 管理 | sb-platform TUN | ⏳ 部分 |
| 配置解析 | sb-config | ✅ 存在 |

---

## 建议

### 短期 (不实现)

1. **保持 CLI 优先** - 核心功能完善
2. **文档化需求** - 收集移动使用反馈

### 中期 (评估 UniFFI)

如有明确需求:
1. 创建 `singbox-mobile` crate
2. 使用 UniFFI 定义绑定接口
3. 实现最小可行 API (start/stop/status)

### 必要 API 清单 (如决定实现)

```rust
// 最小 API
#[uniffi::export]
pub struct MobileService { ... }

#[uniffi::export]
impl MobileService {
    pub fn new(config_json: String) -> Result<Self, Error>;
    pub fn start(&self) -> Result<(), Error>;
    pub fn stop(&self) -> Result<(), Error>;
    pub fn status(&self) -> ServiceStatus;
}

// 扩展 API
pub fn stream_logs(&self, callback: Box<dyn LogCallback>);
pub fn query_connections(&self) -> Vec<ConnectionInfo>;
pub fn set_system_proxy(&self, enabled: bool);
```

---

## 决策记录

| 日期 | 决策 | 理由 |
|------|------|------|
| 2025-12-16 | 选项 C (延迟) | 核心功能优先,移动需求待验证 |

---

## 相关资源

- [UniFFI 文档](https://mozilla.github.io/uniffi-rs/)
- [Go libbox](../go_fork_source/sing-box-1.13.13/experimental/libbox/) (历史基线)
- [cbindgen](https://github.com/eqrion/cbindgen)
