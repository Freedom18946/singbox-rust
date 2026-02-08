# 战略路线图（Strategic Roadmap）

> **当前状态**：项目处于严肃的重构/清理阶段，架构划分需要明确。

---

## 🎯 战略层次概览

```
┌─────────────────────────────────────────────────────────────┐
│                    L0: 战略目标 (Strategic)                  │
│  "可替换 Go sing-box 的生产就绪 Rust 实现"                   │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐     ┌───────────────┐     ┌───────────────┐
│ L1: 架构整固  │     │ L2: 功能对齐  │     │  L3: 质量保障 │
│  (Foundation) │     │   (Parity)    │     │   (Quality)   │
└───────────────┘     └───────────────┘     └───────────────┘
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐     ┌───────────────┐     ┌───────────────┐
│ L4: 具体任务  │     │ L4: 具体任务  │     │ L4: 具体任务  │
│   (Tasks)     │     │    (Tasks)    │     │    (Tasks)    │
└───────────────┘     └───────────────┘     └───────────────┘
```

---

## L0: 战略目标

**最终目标**：产出可直接替换 Go sing-box 的 Rust 二进制文件，与 GUI.for" SingBox 完全兼容。

**成功指标**：
- [ ] GUI.for" SingBox 无感知替换内核
- [ ] 所有用户配置文件兼容
- [ ] Trojan + Shadowsocks 100% 可用
- [ ] 稳定运行 7 天无故障

---

## L1: 架构整固 ✅ 完成

### 目标
解决架构混乱问题，建立清晰的模块边界。

### 最终成果
- **违规类别**: 7 → 0（check-boundaries.sh exit 0）
- **协议 outbound 独立**: 10/10
- **sb-core 协议代码移除**: ~256KB（8 协议）
- **L1 回归验证**: 4 处回归已修复，1431 tests passed

### 里程碑

#### M1.1: 依赖边界硬化 ✅ 完成

> **说明**：原 M1.1/M1.2/M1.3 经分析后合并为统一的 M1.1，因三者高度耦合无法独立交付。
> 下设 6 个三级工作包（L1.1.1 ~ L1.1.6），按依赖关系排序执行。

##### L1.1.1: CI 依赖边界门禁 ✅
- [x] 完善 check-boundaries.sh 覆盖 V1-V5（含 feature-gate 感知）
- [x] 添加 Makefile target（boundaries / boundaries-report）
- [x] 基线化现有违规（7→5 类）
- 前置：无

##### L1.1.2: sb-types Ports 契约层扩展 ✅
- [x] 定义 Port traits（Service, Lifecycle, Startable, StartStage, stage_rank）
- [x] sb-core 重导出 sb-types 定义（保持 API 兼容）
- [x] sb-types 保持零运行时依赖
- 前置：无 | B2 已决策：共享契约放 sb-types

##### L1.1.3: sb-core services/ → sb-api（V1 消除）✅
- [x] 移除 tower 非可选依赖（零源码引用）
- [x] hyper 可选化（behind service_derp, out_naive）
- [x] axum/tonic 已是 optional（behind service_ssmapi, service_v2ray_api）
- [x] V1 边界检查 PASS
- 前置：无

##### L1.1.4: sb-core tls/transport 剥离（V2 部分消除）🟡 部分完成
- [x] quinn 可选化（behind out_quic, dns_doq, dns_doh3）
- [x] snow 可选化（behind out_wireguard, out_tailscale, dns_tailscale）
- [ ] rustls 可选化 — 需 tls/ → sb-tls 提取（15 文件深度依赖）
- [ ] reqwest 可选化 — 需抽象下载层（supervisor 无条件使用）
- [ ] tls/ 4 文件 → sb-tls
- [ ] transport/tls.rs → sb-transport
- 前置：无

##### L1.1.5: sb-core outbound/ 协议实现 → sb-adapters（V2+V3 消除）✅
- [x] 10 协议 builder 层解耦（register.rs 不再直接引用 sb_core::outbound 协议类型）
- [x] 5 协议完全独立（trojan, vmess, vless, shadowsocks, wireguard）
- [x] 5 协议 dial() 仍委托 sb-core（hysteria2, tuic, shadowtls, ssh, hysteria）
- [x] AdapterIoBridge 泛型桥接 + connect_io() + LazyWireGuardConnector
- 前置：**L1.1.2**
- 遗留：sb-core 协议文件物理保留（dial() 委托需要），V3 不会清零直到协议栈重写

##### L1.1.6: sb-adapters → sb-core 反向依赖切断（V4 消除）✅
- [x] register.rs sb_core::outbound 引用 12 → 5（剩余为 DirectConnector/inbound/comment）
- [x] 清理 dead feature forwarding（out_ss, out_trojan, out_vmess, out_vless）
- [x] V4 use 计数 225 → 223
- 前置：**L1.1.2 + L1.1.5**
- 遗留：~150 处 inbound handlers 的 sb-core 依赖为合法架构依赖（router, net, services）

##### M1.1 验收标准
```bash
./agents-only/06-scripts/check-boundaries.sh       # 实际 exit 1 (5 violations, L1.1.4 遗留)
cargo tree -p sb-core | grep -E "axum|tonic|tower"  # 无输出 ✅
cargo tree -p sb-adapters --depth 1 | grep sb-core  # 无输出 ✅ (adapter features 无需 sb-core)
cargo tree -p sb-types | grep -E "tokio|hyper"       # 无输出 ✅
cargo check --workspace                              # 编译通过 ✅
```

> **M1.1 完成判定**: 6/6 任务完成。边界检查 5 个残余违规均源自 L1.1.4 遗留
> （B4: rustls 15 文件深嵌, B5: reqwest supervisor 无条件使用），
> 需独立 WP 处理，不阻塞 M1.1 结项。

#### M1.2: 进阶依赖清理 ✅ 完成

> **说明**: 消除 M1.1 遗留的 B4(rustls)/B5(reqwest)/B6(dial()委托) 阻塞项。
> 下设 6 个工作包（L1.2.1 ~ L1.2.6），按依赖关系排序执行。

##### L1.2.1: B5 reqwest 可选化 + V5 sb-subscribe 解耦 ✅
- [x] HttpClient port trait 定义（sb-types/ports/http.rs）
- [x] sb-core 全局 HTTP client 注册（OnceLock + install/get/execute）
- [x] app 层 ReqwestHttpClient 注入
- [x] reqwest → optional（behind dns_doh, service_derp）
- [x] minijson 提取到 sb-common
- [x] sb-subscribe: sb-core → optional
- 前置：无

##### L1.2.2: SSH dial() 内联 ✅
- [x] SSH outbound 用 russh v0.49 完全重写（不再委托 thrussh/sb-core）
- [x] adapter-ssh feature 移除 sb-core/out_ssh
- 前置：无

##### L1.2.3: sb-core tls/ → sb-tls 迁移 ✅
- [x] sb-tls 新增 ensure_crypto_provider()、danger::NoVerify/PinVerify、global::base_root_store/apply_extra_cas/get_effective
- [x] sb-core tls/ 变为薄委托层
- 前置：无

##### L1.2.4: TLS 工厂 + rustls 可选化 ✅
- [x] rustls/tokio-rustls/rustls-pemfile/webpki-roots/rustls-pki-types 全部 optional behind `tls_rustls`
- [x] transport/tls、errors/classify、runtime/transport feature-gated
- 前置：**L1.2.3**

##### L1.2.5: ShadowTLS + TUIC dial() 内联 ✅
- [x] ShadowTLS 用 sb-tls 完全重写（不再委托 sb-core）
- [x] TUIC 用 quic_util 完全内联（TUIC v5 协议自包含）
- 前置：**L1.2.4**

##### L1.2.6: QUIC 共享设施 + Hysteria v1/v2 dial() 内联 ✅
- [x] quic_util.rs 共享 QUIC 连接模块（QuicConfig + quic_connect + QuicBidiStream）
- [x] Hysteria v1 完全内联（QUIC + 握手 + TCP tunnel）
- [x] Hysteria2 完全内联（QUIC + SHA256 认证 + 带宽控制 + 混淆）
- 前置：**L1.2.4**

##### M1.2 验收标准
```bash
./agents-only/06-scripts/check-boundaries.sh       # exit 1 (3 violations, V2/V3/V4 残余)
cargo check --workspace                              # 编译通过 ✅
cargo tree -p sb-subscribe --depth 1 --no-default-features | grep sb-core  # 无输出 ✅
```

> **M1.2 完成判定**: 6/6 任务完成。B4/B5/B6 全部解决。
> 违规从 5 类降至 3 类。Cargo.toml 和 V5 检查通过。
> 残余 V2(43)/V3(11)/V4(214) 为 sb-core 内部 tls 委托层和 inbound 合法依赖。

#### WP-L1.3: 深度解耦 ✅

> check-boundaries.sh V2/V3 feature-gate 感知 + V4 重新分类 + legacy 协议代码清理。

##### L1.3.1: check-boundaries.sh V2/V3 feature-gate 感知 ✅
- [x] `is_feature_gated_module()` 按路径模式排除
- [x] `is_line_feature_gated()` 检查前 5 行 cfg 保护
- [x] V2: 43→0, V3: 11→0

##### L1.3.2: V4 重新分类 ✅
- [x] V4a (outbound/register/stubs): 22 处, threshold 25
- [x] V4b (inbound/service/endpoint): 192 处, INFO only

##### L1.3.3: Legacy 协议代码安全清理 ✅
- [x] 8 协议从 sb-core 移除: vless, trojan, ssh, shadowtls, wireguard, vmess, shadowsocks, tuic
- [x] outbound/mod.rs: 1305→835 行, switchboard.rs: 1918→725 行
- [x] thrussh/thrussh-keys 依赖移除, out_* features 变为空数组
- [x] 保留: hysteria(inbound), hysteria2(inbound), naive_h2, quic/, ss/hkdf

##### L1.3.4: V4a 评估 ✅
- [x] 22 处全部为合法架构依赖（控制面 adapter + 基础类型）

##### M1.3 验收标准
```bash
./agents-only/06-scripts/check-boundaries.sh       # exit 0 ✅
cargo check --workspace                              # 编译通过 ✅
cargo check -p sb-core --features out_hysteria       # 保留协议编译 ✅
cargo check -p sb-core --features out_hysteria2      # 保留协议编译 ✅
cargo check -p sb-adapters                            # 不受影响 ✅
```

> **M1.3 完成判定**: 5/5 任务完成。全部边界检查通过 (exit 0)。
> 违规从 3 类降至 0 类。~256KB legacy 代码安全移除。

---

## L2: 功能对齐（Tier 1 ✅ 完成，Tier 2 🟡 准备中）

### 目标
达成与 Go sing-box 1.12.14 的功能对等。

### 缺口分析
> **详细文档**: `agents-only/05-analysis/L2-PARITY-GAP-ANALYSIS.md`

| 指标 | 值 |
|------|------|
| 总对标项 | 209 |
| 完全对齐 ✅ | ~186 (~89%) |
| 部分对齐 ◐ | 12 (6%) |
| 未对齐 ❌ | 3 (1%) |
| 已排除 ⊘ | 4 (2%) |
| Rust 独有 ➕ | 4 (2%) |

### 关键阻塞
- ~~`app --features router` maxminddb API 变更~~ ✅ 已修复 (L2.2)

### 里程碑

#### M2.0: 信息收集与缺口分析 ✅ 完成
- [x] L1 回归验证（4 处修复，1431 tests passed）
- [x] Go Parity Matrix 209 项逐一分析
- [x] 编译状态矩阵（发现 maxminddb 阻塞）
- [x] 15 个 Partial 项分类（6 接受限制 + 6 架构缺口 + 3 服务缺口）
- [x] Tier 分层执行计划

#### M2.1: 核心协议验证 ✅ 已完成
- [x] Trojan inbound/outbound
- [x] Shadowsocks 全套（多用户、AEAD）
- [x] SOCKS5/HTTP 代理
- [x] TUN 支持

#### M2.2: Tier 1 — GUI.for 兼容 ✅ 完成
- [x] maxminddb 修复（解锁 --features router）
- [x] Config schema 兼容（PX-002: $schema 字段已正确处理）
- [x] Clash API 完整化（PX-010: 真实数据 + 真实延迟测试 + mode）
- [x] CLI 参数对齐（binary name sing-box + Go version JSON + completion 子命令）
- 验收：1432 tests passed, router/parity build ✅

#### M2.3: Tier 2 — 运行时引擎 ⬜ 已规划

> **调整**（2026-02-08）：基于 L2.1 源码审查，按 GUI 可感知度重排为 5 个均匀包。

- [ ] L2.6 Selector 持久化 + Proxy 状态真实化（PX-006, PX-013: CacheFile trait 扩展 + SelectorGroup 联通 + OutboundGroup trait）
- [ ] L2.7 URLTest 历史 + 健康检查对齐（PX-006: URLTestHistoryStorage + HTTP URL test 健康检查 + tolerance）
- [ ] L2.8 ConnectionTracker + 连接面板（PX-005, PX-012: Router 级 connection table + 真实 close + V2Ray API）
- [ ] L2.9 Lifecycle 编排（PX-006: start_all 接入拓扑排序 + staged startup + rollback）
- [ ] L2.10 DNS 栈对齐（PX-004, PX-008: DNSRouter/TransportManager/EDNS0/FakeIP/RDRC）
- 验收：Parity ≥ 96%

#### M2.4: Tier 3 — 服务补全 ⬜ 未开始
- [ ] SSMAPI 对齐（PX-011: per-endpoint binding）
- [ ] DERP 配置对齐（PX-014: config/behavior 偏差）
- [ ] Resolved 完整化（PX-015: resolve1 D-Bus methods）
- 验收：Parity ≥ 98%

### Tier 4: 已接受限制（不动）
- TLS uTLS/ECH/REALITY — rustls 库限制
- WireGuard endpoint UDP — userspace 限制
- TLS fragment Windows — 平台限制

---

## L3: 质量保障

### 目标
确保实现的正确性和稳定性。

### 里程碑

#### M3.1: 测试覆盖 ⬜ 进行中
- [ ] 协议集成测试全通过
- [ ] GeoIP/GeoSite 测试数据就位
- [ ] E2E 测试框架完善
- [ ] 验收：CI 测试 100% 通过

#### M3.2: 性能基准 ⬜ 未开始
- [ ] 建立性能基准测试
- [ ] 与 Go 版本对比
- [ ] 热路径优化
- [ ] 验收：性能 ≥ Go 版本

#### M3.3: 稳定性验证 ⬜ 未开始
- [ ] 长时间运行测试
- [ ] 内存泄漏检测
- [ ] 压力测试
- [ ] 验收：7天无故障运行

---

## L4: 当前执行任务

### 本周任务队列

| 优先级 | 任务 | 状态 | 负责 |
|--------|------|------|------|
| P0 | 建立 AI 文档管理规范 | ✅ 完成 | Gemini-CLI |
| P0 | 依赖边界 CI 检查 | ⬜ 待做 | - |
| P1 | sb-core 协议代码迁移 | ⬜ 待做 | - |
| P1 | 测试数据准备 | ⬜ 待做 | - |

### 下一步行动

1. **立即**：建立 CI 依赖检查脚本
2. **短期**：完成 sb-core 清理
3. **中期**：修复 Parity 缺口
4. **长期**：稳定性验证

---

## 执行原则

### 顺序原则
```
架构整固 → 功能对齐 → 质量保障
   ↓           ↓           ↓
  先做        再做        最后做
```

### 依赖原则
- L1 完成前，不开始 L2 的新功能开发
- L2 完成前，不开始 L3 的大规模测试
- 任何时候发现架构问题，回退到 L1

### AI 协作原则
- 每个 AI 接手时，先看 `log.md` 和本文档
- 更新任务状态后，更新本文档
- 完成里程碑后，更新本文档

---

## 🧠 AI 渐进式规划原则（Progressive Planning）

### 核心规则：不做超前规划

> **禁止**：在未阅读具体代码上下文时，过度细化规划。
> **要求**：只规划当前可见层次，深入后再细化下一层。

### 工作包编号规则

工作包采用**层级编号**，最多 **4 层**（4 个数字）：

```
L1          → 主题层（如：架构整固）
L1.1        → 里程碑层（如：依赖边界硬化）
L1.1.1      → 任务层（如：添加 CI 检查脚本）
L1.1.1.1    → 子任务层（如：编写 sb-core 依赖检查）
```

**禁止超过 4 层**：如果需要更细，说明任务拆分不当，应重新组织。

### 规划权限矩阵

| 场景 | 可规划层次 | 示例 |
|------|-----------|------|
| 首次接触项目 | L0 → L1 | 只确认战略方向 |
| 阅读战略文档后 | L1 → L1.x | 确认当前里程碑 |
| 阅读相关代码后 | L1.x → L1.x.y | 细化具体任务 |
| 开始实现任务后 | L1.x.y → L1.x.y.z | 拆分子步骤 |

### 正确示例 ✅

```markdown
# AI 第一次进入项目
1. 读 init.md → 执行初始化检查
2. 读 log.md → 了解上一个 AI 的工作
3. 读 06-STRATEGIC-ROADMAP.md → 确认当前在 L1（架构整固）
4. 确认当前任务是 M1.1（依赖边界硬化）
   → 此时只知道 M1.1 的目标，不细化

# AI 开始研究 M1.1
5. 阅读 sb-core/Cargo.toml 和依赖树
6. 发现具体问题：sb-core 依赖了 axum、rustls
7. 现在有权创建 L1.1.1 ~ L1.1.n：
   - L1.1.1: 创建依赖检查脚本
   - L1.1.2: 移除 sb-core 对 axum 的依赖
   - L1.1.3: 移除 sb-core 对 rustls 的依赖
```

### 错误示例 ❌

```markdown
# AI 第一次进入项目
1. 读 init.md
2. 立即规划：
   - L1.1.1: 创建检查脚本
   - L1.1.2: 修改 sb-core/src/router/mod.rs 第 45 行  ← 错误！未读代码
   - L1.1.3: 重构 ConnectionManager                   ← 错误！超前细化
```

### 规划写入规则

| 动作 | 条件 | 写入位置 |
|------|------|---------|
| 新增 L1.x 里程碑 | 用户确认或战略调整 | 本文档 |
| 新增 L1.x.y 任务 | 阅读相关代码后 | 本文档 + log.md |
| 新增 L1.x.y.z 子任务 | 开始实现时 | log.md（不必写入本文档） |

### 规划检查清单

在创建新工作包前，AI 必须确认：
- [ ] 已阅读上层工作包的上下文
- [ ] 已阅读相关代码文件
- [ ] 新工作包层级 ≤ 4
- [ ] 拆分粒度合理（单个工作包可在 1-4 小时完成）

---

## 📊 进度追踪

| 层次 | 里程碑 | 进度 | 目标日期 |
|------|--------|------|---------|
| L1 | M1.1 依赖硬化 | ✅ 6/6 完成 | ✅ |
| L1 | M1.2 进阶清理 | ✅ 6/6 完成 | ✅ |
| L1 | M1.3 深度解耦 | ✅ 5/5 完成 (exit 0) | ✅ |
| ~~L1~~ | ~~M1.2 代码归属~~ | 合并入 M1.1 | - |
| ~~L1~~ | ~~M1.3 接口契约~~ | 合并入 M1.1 | - |
| L2 | M2.0 信息收集 | ✅ 完成 | ✅ |
| L2 | M2.1 核心协议 | ✅ 完成 | ✅ |
| L2 | M2.2 Tier 1 GUI.for | ✅ 完成 | ✅ |
| L2 | M2.3 Tier 2 运行时 | 0% (已规划 5 包) | TBD |
| L2 | M2.4 Tier 3 服务 | 0% | TBD |
| L3 | M3.1 测试覆盖 | 30% | TBD |
| L3 | M3.2 性能基准 | 0% | TBD |
| L3 | M3.3 稳定验证 | 0% | TBD |

---

*本文档是项目战略的唯一真相。所有 AI 工作应对齐到这些目标。*
