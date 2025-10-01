# singbox-rust 下一步工作计划

> **规划时间**: 2025-10-02
> **规划周期**: 近期（本周）→ 短期（本月）→ 中期（Q1 2026）→ 长期（Q1-Q2）

---

## 🎯 工作优先级框架

### 优先级定义

- **🔥 P0-Critical**: 阻塞生产使用的问题
- **⭐ P1-High**: 高 ROI 优化，显著改善性能/可维护性
- **🔧 P2-Medium**: 重要但不紧急的改进
- **💡 P3-Low**: Nice-to-have 功能

---

## 📅 近期目标（本周）

### 1. ⭐ 验证和稳定化（P1-High）

**目标**: 确保所有修复在生产环境稳定运行

**任务清单**:
```bash
# 1. 运行完整测试套件
cargo test --workspace --all-features

# 2. 运行集成测试
cargo test --workspace --test '*' -- --include-ignored

# 3. 性能回归测试
cargo bench --workspace

# 4. 跨平台编译验证
cargo check --target x86_64-unknown-linux-gnu
cargo check --target x86_64-apple-darwin
cargo check --target x86_64-pc-windows-msvc

# 5. Clippy 严格检查
cargo clippy --workspace --all-features -- -D warnings
```

**预期结果**:
- ✅ 所有测试通过
- ✅ 无性能回归
- ✅ 跨平台编译成功
- ✅ 零 clippy 警告

**工作量**: 2-3 小时

---

### 2. 📝 更新项目文档（P2-Medium）

**任务**:
- [ ] 更新 `README.md` - 反映最新架构和稳定性
- [ ] 更新 `CHANGELOG.md` - 记录 P0+P1 修复
- [ ] 创建 `CONTRIBUTING.md` - 贡献指南
- [ ] 创建 `ROADMAP.md` - 未来规划（基于本文档）

**工作量**: 2-3 小时

---

### 3. 🏷️ 发布新版本（P2-Medium）

**建议版本号**: `v0.2.0` (minor version bump，因为有 API deprecation)

**发布清单**:
- [ ] 更新所有 `Cargo.toml` 版本号
- [ ] 创建 git tag: `v0.2.0`
- [ ] 生成 release notes
- [ ] 发布到 GitHub Releases
- [ ] (可选) 发布到 crates.io

**工作量**: 1-2 小时

---

## 📅 短期目标（本月）

### 1. 🚀 实施原生进程匹配 API（⭐ P1-High，最高 ROI）

**动机**:
- 当前命令行工具有 20-50x 性能开销
- 高并发场景下会成为瓶颈
- 原生 API 延迟：15-70μs vs 150-500ms

**实施计划**:

#### 阶段 1: macOS 原型（2-3 天）

```rust
// 创建 crates/sb-platform/src/process/native_macos.rs

use darwin_libproc::{pid_listpids, proc_pidinfo, ProcType};

pub struct NativeMacOsProcessMatcher {
    // 可选：缓存 PID→进程信息映射
    cache: LruCache<u32, ProcessInfo>,
}

impl NativeMacOsProcessMatcher {
    pub fn find_process_by_port(&self, port: u16) -> Result<u32> {
        // 1. 使用 pid_listpids 获取所有 PID
        let pids = pid_listpids(ProcType::ProcAllPIDS, 0)?;

        // 2. 遍历 PID，使用 proc_pidinfo 检查 socket 信息
        for pid in pids {
            let fds = proc_pidinfo::<proc_fdinfo>(pid, 0)?;
            for fd in fds {
                if fd.proc_fdtype == PROX_FDTYPE_SOCKET {
                    let socket_info = proc_pidfdinfo::<socket_fdinfo>(pid, fd.proc_fd)?;
                    if socket_info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport == port {
                        return Ok(pid);
                    }
                }
            }
        }
        Err(ProcessMatchError::ProcessNotFound)
    }
}
```

**依赖**:
```toml
[target.'cfg(target_os = "macos")'.dependencies]
darwin-libproc = "0.3"
```

**测试**:
```rust
#[cfg(target_os = "macos")]
#[test]
fn bench_native_vs_lsof() {
    // 对比性能
    let native = NativeMacOsProcessMatcher::new().unwrap();
    let fallback = MacOsProcessMatcher::new().unwrap();

    let conn = create_test_connection();

    let t1 = Instant::now();
    native.find_process_id(&conn).unwrap();
    let native_time = t1.elapsed();

    let t2 = Instant::now();
    fallback.find_process_id(&conn).unwrap();
    let fallback_time = t2.elapsed();

    println!("Native: {:?}, Fallback: {:?}, Speedup: {:.1}x",
             native_time, fallback_time,
             fallback_time.as_micros() as f64 / native_time.as_micros() as f64);
}
```

**工作量**: 2-3 天

---

#### 阶段 2: Windows 原生实现（2-3 天）

```rust
// 创建 crates/sb-platform/src/process/native_windows.rs

use winapi::um::iphlpapi::{GetExtendedTcpTable, GetExtendedUdpTable};
use winapi::shared::tcpmib::MIB_TCPTABLE_OWNER_PID;

pub struct NativeWindowsProcessMatcher;

impl NativeWindowsProcessMatcher {
    pub fn find_process_by_port(&self, protocol: Protocol, port: u16) -> Result<u32> {
        match protocol {
            Protocol::Tcp => self.find_tcp_process(port),
            Protocol::Udp => self.find_udp_process(port),
        }
    }

    fn find_tcp_process(&self, port: u16) -> Result<u32> {
        let mut size = 0;
        unsafe {
            // 1. 获取表大小
            GetExtendedTcpTable(
                null_mut(), &mut size, FALSE,
                AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0
            );

            // 2. 分配缓冲区
            let mut buffer = vec![0u8; size as usize];
            GetExtendedTcpTable(
                buffer.as_mut_ptr() as *mut _, &mut size, FALSE,
                AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0
            );

            // 3. 解析表
            let table = &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
            for i in 0..table.dwNumEntries {
                let row = &table.table[i as usize];
                if u16::from_be(row.dwLocalPort as u16) == port {
                    return Ok(row.dwOwningPid);
                }
            }
        }
        Err(ProcessMatchError::ProcessNotFound)
    }
}
```

**依赖**:
```toml
[target.'cfg(target_os = "windows")'.dependencies]
winapi = { version = "0.3", features = ["iphlpapi", "tcpmib", "winsock2"] }
```

**工作量**: 2-3 天

---

#### 阶段 3: 集成和 Feature Flag（1 天）

```toml
# crates/sb-platform/Cargo.toml
[features]
default = ["native-process-match"]
native-process-match = []
fallback-process-match = []
```

```rust
// crates/sb-platform/src/process/mod.rs

#[cfg(all(target_os = "macos", feature = "native-process-match"))]
pub use native_macos::NativeMacOsProcessMatcher as ProcessMatcher;

#[cfg(all(target_os = "macos", not(feature = "native-process-match")))]
pub use macos::MacOsProcessMatcher as ProcessMatcher;

// Windows 类似
```

**工作量**: 1 天

---

**总工作量**: **5-7 天**
**预期收益**: **20-50x 性能提升**

---

### 2. 🔧 Config → ConfigIR 转换（P2-Medium）

**目标**: 保持外部 API 稳定性，简化内部使用

```rust
// crates/sb-config/src/lib.rs

impl From<Config> for ir::ConfigIR {
    fn from(cfg: Config) -> Self {
        let mut ir = ir::ConfigIR::default();

        // 转换 inbounds
        for inbound in cfg.inbounds {
            ir.inbounds.push(convert_inbound(inbound));
        }

        // 转换 outbounds
        for outbound in cfg.outbounds {
            ir.outbounds.push(convert_outbound(outbound));
        }

        // 转换 rules -> route
        ir.route.rules = cfg.rules.into_iter()
            .map(convert_rule)
            .collect();
        ir.route.default = cfg.default_outbound;

        ir
    }
}

impl Config {
    pub fn into_ir(self) -> ir::ConfigIR {
        self.into()
    }
}
```

**工作量**: 2-3 小时

---

### 3. 📊 添加标签基数监控（P2-Medium）

**目标**: 防止 Prometheus 标签爆炸

```rust
// crates/sb-metrics/src/cardinality.rs

use std::sync::atomic::{AtomicUsize, Ordering};
use std::collections::HashSet;
use parking_lot::Mutex;

pub struct CardinalityMonitor {
    metrics: Mutex<HashMap<String, HashSet<Vec<String>>>>,
    total_series: AtomicUsize,
    warning_threshold: usize,
}

impl CardinalityMonitor {
    pub fn new(warning_threshold: usize) -> Self {
        Self {
            metrics: Mutex::new(HashMap::new()),
            total_series: AtomicUsize::new(0),
            warning_threshold,
        }
    }

    pub fn record_label_usage(&self, metric_name: &str, labels: Vec<String>) {
        let mut metrics = self.metrics.lock();
        let label_set = metrics.entry(metric_name.to_string()).or_insert_with(HashSet::new);

        if label_set.insert(labels) {
            let total = self.total_series.fetch_add(1, Ordering::Relaxed) + 1;

            if total > self.warning_threshold {
                log::warn!(
                    "High cardinality detected: {} unique time series (threshold: {})",
                    total, self.warning_threshold
                );
            }
        }
    }

    pub fn get_cardinality(&self, metric_name: &str) -> usize {
        self.metrics.lock()
            .get(metric_name)
            .map(|set| set.len())
            .unwrap_or(0)
    }
}
```

**集成**:
```rust
// 在 IntCounterVec::with_label_values() 调用时监控
HTTP_METHOD_TOTAL.with_label_values(&[method]).inc();
CARDINALITY_MONITOR.record_label_usage("http_method_total", vec![method.to_string()]);
```

**工作量**: 2-3 小时

---

## 📅 中期目标（Q1 2026）

### 1. 🧪 测试覆盖率提升到 80%+（P2-Medium）

**当前状态**:
- sb-types: ~90%
- sb-config: ~75%
- sb-metrics: ~80%
- sb-platform: ~60%
- sb-core: ~65%
- 平均: ~70%

**行动**:
- [ ] 使用 `cargo-tarpaulin` 生成覆盖率报告
- [ ] 识别未覆盖的关键路径
- [ ] 添加缺失的单元测试
- [ ] 添加错误路径测试
- [ ] 添加边界条件测试

**工作量**: 16-20 小时

---

### 2. 📖 文档覆盖率提升到 80%+（P2-Medium）

**当前状态**:
- 公共 API 文档: ~60%
- 内部 API 文档: ~40%

**行动**:
```rust
// 为所有公共 API 添加文档
#![warn(missing_docs)]

/// Brief description.
///
/// # Arguments
///
/// * `arg1` - Description
///
/// # Returns
///
/// Description of return value
///
/// # Errors
///
/// Description of error cases
///
/// # Examples
///
/// ```
/// use crate::example;
/// let result = example::function();
/// ```
pub fn function() -> Result<()> { ... }
```

**工具**:
```bash
# 生成文档并检查警告
cargo doc --workspace --all-features --no-deps

# 使用 cargo-deadlinks 检查死链接
cargo install cargo-deadlinks
cargo deadlinks
```

**工作量**: 16-20 小时

---

### 3. 🏗️ 架构文档更新（P2-Medium）

**创建文件**:
- `docs/ARCHITECTURE.md` - 整体架构
- `docs/DATA_FLOW.md` - 数据流图
- `docs/CONFIGURATION.md` - 配置系统详解
- `docs/TESTING.md` - 测试策略
- `docs/PERFORMANCE.md` - 性能优化指南

**工作量**: 8-12 小时

---

### 4. 🔒 subtle crate 集成（P2-Medium）

**目标**: 使用常量时间比较防止时序攻击

```rust
// crates/sb-security/src/credentials.rs

use subtle::ConstantTimeEq;

impl Credentials {
    /// Constant-time credential verification
    pub fn verify(&self, username: &str, password: &str) -> bool {
        let username_match = self.username
            .as_ref()
            .map(|u| u.as_bytes().ct_eq(username.as_bytes()).into())
            .unwrap_or(false);

        let password_match = self.password
            .as_ref()
            .map(|p| p.as_bytes().ct_eq(password.as_bytes()).into())
            .unwrap_or(false);

        username_match && password_match
    }
}
```

**工作量**: 2-3 小时

---

## 📅 长期目标（Q1-Q2 2026）

### 1. 🪟 完整 Windows 平台支持（P1-High）

#### WinTun 集成（6-9 天）

**推荐方案**: 使用 `wintun` crate

```toml
[target.'cfg(target_os = "windows")'.dependencies]
wintun = "0.4"
```

```rust
// crates/sb-platform/src/tun/native_windows.rs

use wintun::{Adapter, Session};

pub struct NativeWindowsTun {
    adapter: Adapter,
    session: Arc<Session>,
    name: String,
    mtu: u32,
}

impl NativeWindowsTun {
    pub fn create(config: &TunConfig) -> Result<Self> {
        // 1. 创建 WinTun 适配器
        let adapter = Adapter::create("singbox", "SingBox", None)?;

        // 2. 配置 IP 地址
        if let Some(ipv4) = config.ipv4 {
            adapter.set_address(ipv4, config.ipv4_prefix_len)?;
        }

        // 3. 启动会话
        let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY)?);

        Ok(Self {
            adapter,
            session,
            name: config.name.clone(),
            mtu: config.mtu,
        })
    }
}

impl TunDevice for NativeWindowsTun {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let packet = self.session.receive_blocking()?;
        let len = packet.bytes().len().min(buf.len());
        buf[..len].copy_from_slice(&packet.bytes()[..len]);
        Ok(len)
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let mut packet = self.session.allocate_send_packet(buf.len() as u16)?;
        packet.bytes_mut().copy_from_slice(buf);
        self.session.send_packet(packet);
        Ok(buf.len())
    }
}
```

**测试**:
- 需要管理员权限
- 需要 WinTun 驱动程序安装

**工作量**: 6-9 天

---

### 2. 🚀 CI/CD 增强（P2-Medium）

**GitHub Actions 流水线**:

```yaml
# .github/workflows/ci.yml
name: CI

on: [push, pull_request]

jobs:
  test:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        rust: [stable, nightly]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@master
        with:
          toolchain: ${{ matrix.rust }}
      - run: cargo test --workspace --all-features

  coverage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo install cargo-tarpaulin
      - run: cargo tarpaulin --workspace --out xml
      - uses: codecov/codecov-action@v3

  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo bench --workspace
      - uses: benchmark-action/github-action-benchmark@v1

  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo install cargo-audit
      - run: cargo audit
```

**工作量**: 4-6 小时

---

### 3. 🎯 性能优化（P1-High）

**基于 profiling 的优化**:

```bash
# 1. CPU profiling
cargo flamegraph --bin singbox-rust

# 2. Memory profiling
cargo instruments -t Allocations --bin singbox-rust

# 3. Benchmark
cargo bench --workspace
```

**已识别的优化点**:
- ✅ 进程匹配（20-50x 提升）- 已计划实施
- 🔄 配置解析缓存
- 🔄 路由规则编译优化
- 🔄 DNS 查询缓存
- 🔄 连接池预热

**工作量**: 16-24 小时（取决于 profiling 结果）

---

## 📊 工作量总结

| 时间范围 | 优先级 | 任务数 | 总工时 |
|----------|--------|--------|--------|
| **本周** | P1-P2 | 3 | 5-8 小时 |
| **本月** | P1-P2 | 3 | 44-52 小时 |
| **Q1 2026** | P2 | 4 | 44-58 小时 |
| **Q1-Q2** | P1-P2 | 3 | 100-130 小时 |
| **总计** | | 13 | **193-248 小时** |

---

## 🎯 推荐执行顺序

### Sprint 1（本周，5-8h）
1. ✅ 验证和稳定化
2. ✅ 更新项目文档
3. ✅ 发布 v0.2.0

### Sprint 2（第 2 周，22-26h）
1. ⭐ macOS 原生进程匹配原型
2. 📊 标签基数监控

### Sprint 3（第 3 周，22-26h）
1. ⭐ Windows 原生进程匹配
2. 🔧 Config → ConfigIR 转换

### Sprint 4（第 4 周，8-12h）
1. 🔒 subtle crate 集成
2. 📖 开始文档覆盖率提升

---

## 💡 关键决策点

### 决策 1: 是否立即实施原生进程匹配？

**建议**: ✅ **是** - 高 ROI，20-50x 性能提升

**理由**:
- 明确的性能瓶颈
- 成熟的解决方案（darwin-libproc, winapi）
- 中等实施复杂度
- 可以 feature flag 控制，风险可控

---

### 决策 2: WinTun 集成优先级？

**建议**: 🔄 **中期** - Q1 2026

**理由**:
- 当前占位符实现可用（测试和开发）
- 6-9 天工作量较大
- 依赖 Windows 测试环境
- 可以先完成高 ROI 项目（进程匹配）

---

### 决策 3: 是否完全统一为 ConfigIR？

**建议**: 🔄 **按需** - 不紧急

**理由**:
- 当前方案已足够（lib::Config 作为 facade）
- 破坏性变更风险
- 优先完成高 ROI 项目

---

## 📋 跟踪机制

**建议创建以下文件持续跟踪**:

1. `TODO.md` - 短期任务（本周/本月）
2. `ROADMAP.md` - 中长期规划
3. `PERFORMANCE.md` - 性能优化跟踪
4. `TECHNICAL_DEBT.md` - 技术债台账

**使用 GitHub Projects 或 Issues 管理任务**

---

## 🎉 总结

### 优先级 Top 3

1. ⭐⭐⭐ **原生进程匹配 API**（本月）- 20-50x 性能提升
2. ⭐⭐ **测试和文档覆盖率**（Q1）- 提升可维护性
3. ⭐ **Windows WinTun 集成**（Q1-Q2）- 完整平台支持

### 近期聚焦

**本周**: 稳定化 + 发布 v0.2.0
**本月**: 原生进程匹配 API 实施

### 长期愿景

将 singbox-rust 打造成**生产级、跨平台、高性能**的代理工具 🚀
