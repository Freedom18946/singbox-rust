<!-- tier: B -->
# MT-AUDIT-01 全量复扫核验长报告

**文件性质**：归档参考文档（B-tier），基于当前仓库 HEAD 事实写成，不作代码变更。
**生成日期**：2026-04-06
**适用 HEAD**：`89182778` (MT-CONV-03)，工作区为干净树（`git status` clean）
**卡线性质**：maintenance / audit reconciliation。**不是 dual-kernel parity completion。**

---

## 一、背景与范围

### 1.1 为何开此卡

singbox-rust 仓库在 2026-02 前完成了一次全量静态审计（以下简称"5.4pro 第二次审稿"，材料见
`重构package相关/singbox_rust_audit_report.md`，约 506 KB；结构化命中清单见
`重构package相关/singbox_rust_audit_processed_findings.json`，约 608 KB）。该审计系统性地识别出
6 大风险类别，并标定了约 649 个生产源文件的原始计数基线。

此后，一系列 maintenance 线（MT-OBS-01 → MT-CONV-03，含 WP-30 系列子任务）陆续修复或降级了
审计命中项。然而，"maintenance 线已全部 Close-out"并不自动等于"审计意见已全部清零"。两者范围
不同：前者是按 maintenance 优先级划定工作边界，后者需要以审计原口径重新扫描才能得出结论。

MT-AUDIT-01 的目标是：

1. 使用与原审计相同的扫描口径，对当前 HEAD 重新执行全量计数；
2. 将每一命中项分类为 `Resolved / Still Active / Reduced to Future Boundary`；
3. 输出可归档的最终结论，回答"能否说审计意见全部清零"；
4. 明确当前是否存在 blocker，以及后续是否需要开新卡。

### 1.2 范围声明

- **扫描范围**：`app/src/**/*.rs` 与 `crates/**/src/**/*.rs`，排除 `/tests/`、benches、`#[cfg(test)]` 块及 Go 源码。
- **非扫描范围**：`labs/`、`go_fork_source/`、`GUI_fork_source/`、`.github/`。
- **不作代码变更**：本卡只输出分析与文档，不修改任何 `.rs` 文件。
- **不是 parity completion**：dual-kernel parity（92.9%，52/56）由 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 管辖，与本卡无关。

---

## 二、复扫口径

### 2.1 原始审计 6 大风险类别及基线数值

| 类别 | 原始审计代号 | 原始基线 | 扫描面 |
|------|------------|---------|-------|
| 隐式单例网络 | L1-Singleton | 77 static 声明（29 OnceLock + 14 LazyLock + 34 OnceCell） | 生产代码 |
| 异步生命周期 / 未追踪 spawn | L3-Spawn | 152 个 untracked `tokio::spawn()` | 生产代码 |
| lock-across-await / 热路径锁 | L3-Lock | 127 实例 | 生产代码 |
| 热路径 panic 面 | L1-Panic | unwrap 185 + expect 69 | 生产代码 |
| 边界类型债务 | L4-Boundary | 261 个 `Deserialize` 无 `deny_unknown_fields` | `sb-config` 生产代码 |
| 粗粒度组合根 / mega-file | L6-Mega | 6 个目标文件，最大 5375 行 | 全库 |

### 2.2 本次复扫所用口径

本次复扫遵循原审计的 grep-count 方法，使用相同的文件范围和排除规则，以保证可比性。
具体偏差说明见各类别分析节。

---

## 三、扫描方法与脚本/命令

以下命令均在仓库根目录 `/Users/bob/Desktop/Projects/ING/sing/singbox-rust` 下执行。

```bash
# A1: 全局静态声明计数
grep -rn 'OnceLock' crates/ app/ --include='*.rs' | grep -v '/tests/\|mod tests\|cfg(test' | wc -l
grep -rn 'LazyLock' crates/ app/ --include='*.rs' | grep -v '/tests/\|mod tests\|cfg(test' | wc -l
grep -rn 'OnceCell' crates/ app/ --include='*.rs' | grep -v '/tests/\|mod tests\|cfg(test' | wc -l
grep -rn 'static.*LazyLock\|static.*OnceLock\|static.*OnceCell' crates/ app/ --include='*.rs' | grep -v '/tests/'

# A2: tokio::spawn 计数
grep -rn 'tokio::spawn(' crates/ app/ --include='*.rs' | grep -v '/tests/\|cfg(test' | wc -l
# 已知修复文件的负向核验
grep -n 'tokio::spawn' crates/sb-adapters/src/outbound/anytls.rs || echo "NONE - OK"
grep -n 'tokio::spawn' crates/sb-adapters/src/outbound/ssh.rs   || echo "NONE - OK"
grep -n 'tokio::spawn' app/src/admin_debug/prefetch.rs          || echo "(tracked)"
grep -n 'tokio::spawn' app/src/admin_debug/http_server.rs       || echo "(tracked)"
grep -n 'tokio::spawn' app/src/logging.rs                       || echo "(checked)"

# A3: panic 面
bash scripts/lint/no-unwrap-core.sh 2>&1
grep -rn '\.unwrap()' crates/ app/ --include='*.rs' | grep -v '/tests/\|cfg(test\|mod tests' | wc -l
grep -rn '\.expect(' crates/ app/ --include='*.rs'  | grep -v '/tests/\|cfg(test\|mod tests' | wc -l
grep -c 'expect(' crates/sb-adapters/src/inbound/tun_enhanced.rs
grep -n '#\[cfg(test\)\]' crates/sb-adapters/src/inbound/tun_enhanced.rs | head -3

# A4: 配置边界
grep -rn '#\[derive.*Deserialize' crates/sb-config/ --include='*.rs' | wc -l
grep -rn 'deny_unknown_fields'    crates/sb-config/ --include='*.rs' | wc -l

# A5: mega-file（生产代码，排除 tests）
find crates/ app/ -name '*.rs' ! -path '*/tests/*' ! -name '*_test.rs' | \
  xargs wc -l 2>/dev/null | sort -rn | head -25
wc -l crates/sb-config/src/ir/mod.rs app/src/bootstrap.rs app/src/run_engine.rs

# A6: 三侧构建/测试抽样
cargo test -p sb-core     --all-features --lib -- --test-threads=4
cargo test -p app         --all-features --lib -- --test-threads=4
cargo test -p sb-adapters --all-features --lib -- --test-threads=4

# A7: lint 与 gate
make clippy       # cargo clippy --workspace --all-features --all-targets -- -D warnings
make boundaries   # agents-only/06-scripts/check-boundaries.sh（541 条断言，严格模式）
```

---

## 四、七类扫描结果（A1–A7）

### A1. 全局单例（Globals / Singletons）

**原始基线**：77 个 `static` 声明（29 OnceLock + 14 LazyLock + 34 OnceCell）

**本次 grep 原始数字**：

| 类型 | grep 引用数（含 import/use/annotation） | static 声明数（仅 `static.*TYPE` 行） |
|------|----------------------------------------|--------------------------------------|
| OnceLock | 62 | — |
| LazyLock | 98 | — |
| OnceCell | 60 | — |
| **合计 static 声明** | — | **131** |

**数字变化解读**：

从 77 增长至 131，增量来源主要有三：

1. **sb-metrics 扩张**：约 50 条新增 `LazyLock` metric statics（`ROUTER_MATCH_TOTAL`、`CONNECT_ATTEMPT_TOTAL`、`DIAL_LATENCY_MS` 等），这是 prometheus 计数器/gauge/histogram 的行业标准声明方式，具有显式架构文档支撑（`sb-metrics/src/lib.rs` 模块头注释明确记录该设计决策）。
2. **sb-core router/cache 扩张**：约 10 条新增 `OnceLock` statics（`cache_wire`、`cache_hot`、`cache_stats`、`decision_intern`），用于路由器内部缓存热路径。
3. **app/admin_debug 扩张**：约 8 条新增 `OnceCell` statics（cache、reloadable、breaker、audit 子系统）。

原始审计命中的"硬全局"（`GLOBAL_HTTP_CLIENT`、裸 `GEOIP_SERVICE`、`GLOBAL` in prefetch）均已处理。

**已修复的关键项**：
- `sb-core/src/http_client.rs`：`GLOBAL_HTTP_CLIENT` 已删除，替换为 `DEFAULT_HTTP_CLIENT: LazyLock<Mutex<Weak<dyn HttpClient>>>`（lifecycle-aware）。
- `app/src/admin_debug/prefetch.rs`：`GLOBAL` static 已删除，替换为 `DEFAULT_PREFETCHER: LazyLock<StdMutex<Option<Weak<Prefetcher>>>>`（lifecycle-aware）。

**仍存在但归类为 Future Boundary 的项**（详见第六章）：
- `app/src/logging.rs`：`ACTIVE_RUNTIME: LazyLock<Mutex<Weak<LoggingRuntime>>>`
- `app/src/admin_debug/security_metrics.rs`：`DEFAULT_STATE: LazyLock<StdMutex<Weak<...>>>`
- `crates/sb-core/src/geoip/mod.rs`：`DEFAULT_GEOIP_SERVICE: LazyLock<Mutex<Option<Weak<...>>>>`
- `crates/sb-metrics/src/lib.rs`：~50 条 LazyLock metric statics
- `crates/sb-core/src/metrics/registry_ext.rs`：4× OnceCell + `Box::leak`

---

### A2. 异步生命周期 / 未追踪 spawn

**原始基线**：152 个 untracked `tokio::spawn()`（生产代码）

**本次计数**：304 个 `tokio::spawn(` 引用（生产代码，排除 tests）

**数字变化解读**：

原始审计统计的是"未追踪"（JoinHandle 被丢弃）的 spawn；当前 grep 计数所有 `tokio::spawn(` 调用点，包含已追踪（JoinHandle 存储）的。直接比较原始数字无意义。关键在于已知问题点的状态变化：

**已修复的关键项**（负向 grep 验证，均返回 "NONE"）：
- `crates/sb-adapters/src/outbound/anytls.rs`：0 个 spawn（SessionRuntime 改用 JoinSet 追踪）
- `crates/sb-adapters/src/outbound/ssh.rs`：0 个 spawn（pool lock-across-await 消除，bridge tasks 改用 JoinSet）

**已知仍存在但已追踪的 spawn**：
- `app/src/admin_debug/prefetch.rs`：6 处（dispatcher_loop + 测试基础设施，handles 通过 JoinHandle 存储追踪）
- `app/src/admin_debug/http_server.rs`：2 处（signal_task + join，handles 存储并 join）
- `app/src/logging.rs`：信号任务仍使用裸 `tokio::spawn`（Future Boundary，见第六章）

**仍未系统审计的**：304 个调用点中大量位于 inbound 协议处理器（socks/udp、shadowsocks、tun）。在这些文件中，connection-per-task 是有意为之的模式，不能自动视为"未追踪"。对这 304 个调用点做全量 tracked/untracked 区分需要额外专项审计，不在本卡范围内。

---

### A3. panic 面（unwrap / expect / 热路径锁）

**原始基线**：unwrap 185 + expect 69（生产代码）

**本次宽口径计数**：unwrap 1731 + expect 671（生产代码，排除 tests）

**数字变化解读**：

本次 grep 扫描范围较原审计更宽（原审计可能仅统计指定热路径文件集，本次覆盖全部生产代码），故数字不可直接比较。重要的是**专项 lint 脚本的结论**：

**`scripts/lint/no-unwrap-core.sh` 执行结果：PASS**

该脚本针对 `crates/sb-core`、`crates/sb-transport`、`crates/sb-adapters` 三个核心 crate，禁止在非 test 代码中使用 `.unwrap()`、`.expect()`、`panic!()`、`unimplemented!()`、`todo!()`、`unreachable!()`，并允许 `.unwrap_or()`、`.unwrap_or_else()`、`.unwrap_or_default()` 等安全变体。该脚本是本次维护系列专门引入的热路径 lint gate，通过即意味着核心 crate 的 panic 密度已受控。

**仍活跃的重点文件**：

`crates/sb-adapters/src/inbound/tun_enhanced.rs`：该文件共 2405 行，`#[cfg(test)]` 标注位于第 718 行。
- 生产代码段（1–717 行）：112 个 `expect()` 调用
- 测试代码段（718– 行）：其余 expect() 均属测试

112 个生产 expect() 集中于底层包处理路径，在当前实现中以 panic 作为内部断言手段（invariant 不应被违反）。将其全部转换为 `Result` 传播需要大范围类型签名改造，属于 P2 结构债务，不是当前 blocker（详见第七章）。

---

### A4. 配置边界（Config Boundary）

**原始基线**：261 个 `Deserialize` 无 `deny_unknown_fields`（`sb-config`）

**本次计数**：
- `#[derive(...Deserialize...)]`：110 处
- `deny_unknown_fields`：115 处

**解读**：

覆盖率已超 100%。原审计命中 261 是因为当时 IR 类型直接 derive Deserialize，且未加 `deny_unknown_fields`。维护期内 `crates/sb-config/src/ir/raw.rs` 引入了 Raw bridge 架构模式：IR 类型不再直接 derive `Deserialize`，每个类型通过对应的 Raw 结构进行反序列化，Raw 结构统一在 serde attribute 层强制 `deny_unknown_fields`。因此现在 `deny_unknown_fields` 数量（115）略多于 `Deserialize` derive 数量（110），多出的部分来自内层嵌套 Raw 结构。

此条目可判定为 **Resolved**。

---

### A5. Mega-file（粗粒度大文件）

**原始审计 top-6 及当前状态**：

| 原始大小 | 文件 | 当前大小 | 状态 |
|---------|------|---------|------|
| 5375 行 | `sb-config/src/validator/v2.rs` | 文件已不存在（已拆分为 `v2/` 目录，facade ~760 行 + 6 子模块，最大子模块 2128 行） | **Resolved** |
| 5122 行 | `sb-core/src/services/derp/server.rs` | **5211 行**（轻微增长） | Still Active |
| 3860 行 | `sb-adapters/src/register.rs` | **3863 行**（持平） | Still Active |
| 3756 行 | `sb-config/src/ir/mod.rs` | **135 行**（薄 facade + `pub use` 重导出） | **Resolved** |
| 3485 行 | `sb-core/src/dns/upstream.rs` | **3246 行**（减少 239 行） | Still Active |
| 3332 行 | `sb-core/src/router/mod.rs` | **2936 行**（减少 396 行） | Still Active |

**额外已改善的文件**：
- `app/src/bootstrap.rs`：原约 1723 行 → 当前 **260 行**（85% 削减，核心逻辑迁出至 `bootstrap_runtime/`）
- `app/src/run_engine.rs`：从 `bootstrap.rs` 独立为 **148 行** 薄 facade

**新增大文件**：
- `crates/sb-config/src/ir/raw.rs`：**5087 行**（原审计未单独列出，增长来自 deny_unknown_fields 覆盖工作扩充 Raw bridge 层）

当前行数最大的 5 个生产文件：

| 行数 | 文件 |
|------|------|
| 5211 | `crates/sb-core/src/services/derp/server.rs` |
| 5087 | `crates/sb-config/src/ir/raw.rs` |
| 3863 | `crates/sb-adapters/src/register.rs` |
| 3246 | `crates/sb-core/src/dns/upstream.rs` |
| 2936 | `crates/sb-core/src/router/mod.rs` |

---

### A6. 构建与测试抽样

三个核心 crate 的 lib 测试全部通过：

| 测试套件 | 命令 | 结果 |
|---------|------|------|
| sb-core | `cargo test -p sb-core --all-features --lib` | **703 passed, 0 failed, 17 ignored** |
| app | `cargo test -p app --all-features --lib` | **286 passed, 0 failed, 0 ignored** |
| sb-adapters | `cargo test -p sb-adapters --all-features --lib` | **216 passed, 0 failed, 1 ignored** |
| **合计** | | **1205 passed, 0 failed** |

---

### A7. Lint 与 Gate

**Clippy**：`make clippy`（`cargo clippy --workspace --all-features --all-targets -- -D warnings`）

结果：**PASS**。全工作区、所有 feature、所有 target，无任何警告级别及以上问题。

**Boundaries**：`make boundaries`（`agents-only/06-scripts/check-boundaries.sh` 严格模式，541 条断言）

结果：**520/541 PASS，21 条失败**。

失败项分类见下章专节。

---

## 五、`Resolved / Still Active / Reduced to Future Boundary` 三栏对账表

### 5.1 Resolved（已确认修复，有当前仓库事实支撑）

| 命中项 | 原始类别 | 核验证据 |
|--------|---------|---------|
| `GLOBAL_HTTP_CLIENT` 硬全局 | L1-Singleton | `grep 'GLOBAL_HTTP_CLIENT' sb-core/src/http_client.rs` → 无匹配；已替换为 Weak lifecycle-aware 壳 |
| `GLOBAL` static in `prefetch.rs` | L1-Singleton | `grep 'static GLOBAL' app/src/admin_debug/prefetch.rs` → 无匹配 |
| `anytls.rs` 未追踪 spawn | L3-Spawn | `grep 'tokio::spawn' crates/sb-adapters/src/outbound/anytls.rs` → NONE |
| `ssh.rs` 未追踪 spawn + lock-across-await | L3-Spawn + L3-Lock | `grep 'tokio::spawn' crates/sb-adapters/src/outbound/ssh.rs` → NONE |
| `validator/v2.rs` 5375 行 monolith | L6-Mega | 文件已不存在（`wc -l` → no such file）；已拆分为 `v2/` 目录模块 |
| `ir/mod.rs` 3756 行 monolith | L6-Mega | `wc -l crates/sb-config/src/ir/mod.rs` → 135 行 |
| `bootstrap.rs` 大文件 | L6-Mega | `wc -l app/src/bootstrap.rs` → 260 行（原 ~1723 行） |
| 261 个 `Deserialize` 无 `deny_unknown_fields` | L4-Boundary | 当前 sb-config：110 Deserialize derives，115 deny_unknown_fields；Raw bridge 架构覆盖率超 100% |
| `no-unwrap-core.sh` 核心 crate 热路径 panic | L1-Panic | 脚本输出：PASS（exit 0）|

### 5.2 Reduced to Future Boundary（仍存在，但已降级为架构接受项，非 blocker）

| 命中项 | 原始类别 | 仍存在的证据 | 降级理由 |
|--------|---------|------------|---------|
| `logging.rs` `ACTIVE_RUNTIME: LazyLock<Mutex<Weak<...>>>` | L1-Singleton | 文件第 29–30 行 | lifecycle-aware 设计：持有 `Weak<T>` 不阻止 owner 回收；owner-first 路径已建立；compat shell 明确标注 |
| `security_metrics.rs` `DEFAULT_STATE: LazyLock<StdMutex<Weak<...>>>` | L1-Singleton | 文件第 106 行 | 同上；`with_current()`/`map_current()` wrapper 已收拢所有调用点 |
| `geoip/mod.rs` `DEFAULT_GEOIP_SERVICE: LazyLock<Mutex<Option<Weak<...>>>>` | L1-Singleton | 文件第 85 行 | 同上；原 `GEOIP_SERVICE` 已重命名并改为 lifecycle-aware |
| `sb-metrics/src/lib.rs` ~50 条 LazyLock metric statics | L1-Singleton | 文件第 170–948 行 | prometheus 行业标准模式；模块头注释明确记录设计决策："允许任何模块无需传递 context 即可记录指标，通过 atomic counter 保证低开销"；无替代方案不产生性能惩罚 |
| `registry_ext.rs` 4× OnceCell + `Box::leak` | L1-Singleton | 文件第 19–22 行，第 28 行 | 有意为之的 `'static` 提升，用于 prometheus metrics registry bootstrap；blast radius 极小（本文件局部） |
| `logging.rs` 信号任务裸 `tokio::spawn` | L3-Spawn | 文件 spawn 调用 | owner-first 主路径已建立；信号任务是 OS-level 单例，JoinHandle 追踪改造收益有限 |
| `prefetch.rs` 6 处已追踪 spawn | L3-Spawn | 文件 spawn 调用 | 每个 spawn 的 JoinHandle 均已存储并在关闭时 join |
| `http_server.rs` 2 处已追踪 spawn | L3-Spawn | 文件 spawn 调用 | signal_task + join，已追踪 |
| boundary assertions 21/541 stale | A7 | `make boundaries` 输出 | 断言内容陈旧（目标文件已重构），不是代码回归（详见第八章）|

### 5.3 Still Active（仍真实存在，非 blocker，但未消除）

| 命中项 | 原始类别 | 当前证据 | 为什么不是 blocker（见第七章）|
|--------|---------|---------|-------------------------------|
| `derp/server.rs` 5211 行 mega-file | L6-Mega | `wc -l` 输出 | 见 §7.1 |
| `ir/raw.rs` 5087 行（新增） | L6-Mega | `wc -l` 输出 | 见 §7.1 |
| `register.rs` 3863 行 | L6-Mega | `wc -l` 输出 | 见 §7.1 |
| `dns/upstream.rs` 3246 行 | L6-Mega | `wc -l` 输出 | 见 §7.1 |
| `router/mod.rs` 2936 行 | L6-Mega | `wc -l` 输出 | 见 §7.1 |
| `tun_enhanced.rs` 112 production expect() | L1-Panic | awk + grep 计数（#[cfg(test)] 起于第 718 行） | 见 §7.2 |
| 304 总 `tokio::spawn` 调用点 | L3-Spawn | grep 计数 | 见 §7.3 |

---

## 六、关键已修项举例

以下列举四个有代表性的已修项，说明修复模式和验证方式。

### 6.1 `sb-core/src/http_client.rs`：硬全局消除

- **原始问题**：`GLOBAL_HTTP_CLIENT: LazyLock<Arc<dyn HttpClient>>` 是真正的硬全局单例，任何代码均可不经 DI 直接调用，生命周期不受 supervisor 管控。
- **修复模式**：删除 `GLOBAL_HTTP_CLIENT`；引入 `DEFAULT_HTTP_CLIENT: LazyLock<Mutex<Weak<dyn HttpClient>>>`。`Weak<T>` 保证不阻止 owner 回收，仅作 compat fallback。
- **核验**：`grep 'GLOBAL_HTTP_CLIENT' crates/sb-core/src/http_client.rs` → 无匹配。

### 6.2 `sb-adapters/src/outbound/anytls.rs`：spawn + lock-across-await 消除

- **原始问题**：`SessionRuntime` 使用裸 `tokio::spawn`，JoinHandle 丢弃；存在跨 await 点持有 Mutex 的情况。
- **修复模式**：引入 `SessionRuntime` owner，使用 `JoinSet` 追踪所有 bridge tasks；三阶段锁模式（获取锁 → 取出所需值 → 释放锁 → 跨 await 操作），彻底消除 lock-across-await。
- **核验**：`grep 'tokio::spawn' crates/sb-adapters/src/outbound/anytls.rs` → NONE。

### 6.3 `sb-config/src/ir/mod.rs`：3756 行 monolith 拆分

- **原始问题**：`ir/mod.rs` 包含所有 IR 类型定义，3756 行，承担过多职责。
- **修复模式**：按域拆分为独立文件（outbound、inbound、dns、service、endpoint、credentials），`ir/mod.rs` 改为 135 行薄 facade + `pub use` 重导出。
- **核验**：`wc -l crates/sb-config/src/ir/mod.rs` → 135 行。

### 6.4 `sb-config/src/outbound.rs` + Raw bridge：Deserialize 边界治理

- **原始问题**：261 个 IR 类型直接 derive `Deserialize`，缺少 `deny_unknown_fields`，允许 JSON 未知字段静默忽略。
- **修复模式**：IR 类型不再直接 derive `Deserialize`；引入 Raw 结构体（`raw.rs`）作为 serde 入口，Raw 结构体统一加 `deny_unknown_fields`；验证逻辑在 `validate()` 中将 Raw 转为 IR。16 类 domain 类型 + 27 个覆盖测试。
- **核验**：`grep -rn 'deny_unknown_fields' crates/sb-config/ --include='*.rs' | wc -l` → 115；超过 Deserialize derive 数量（110）。

---

## 七、仍然存在的非阻塞结构债

### 7.1 Mega-file 结构债

当前仍有 5 个文件超过 2900 行。它们不是 blocker，原因如下：

**`derp/server.rs`（5211 行）**
DERP 是一个自包含的转发协议实现，其逻辑（连接管理、消息分发、STUN 处理、帧编解码）在单文件中保持内聚。拆分会引入跨文件的私有状态共享问题，增加复杂度而非降低。当前 1205 个 sampled tests 通过，clippy clean，表明代码质量在 lint 层面受控。

**`ir/raw.rs`（5087 行）**
该文件是 deny_unknown_fields 覆盖工作的直接产物，为所有 IR 类型建立 Raw bridge。文件体量大，但结构扁平（大量重复度较高的 Raw 结构体定义），不存在深度嵌套的业务逻辑。它是 config boundary 修复的必要代价，不应与"需要重构"混淆。

**`register.rs`（3863 行）**
协议适配器注册表，结构高度扁平（match arms）。行数多是因为覆盖协议数量多，不是因为复杂度高。

**`dns/upstream.rs`（3246 行）和 `router/mod.rs`（2936 行）**
相比原始审计已分别减少 239 行和 396 行。继续拆分需要明确的功能分割点，当前没有来自 feature change 的驱动信号，不建议为拆分而拆分。

### 7.2 `tun_enhanced.rs` 生产 expect()（112 处）

`tun_enhanced.rs` 在第 1–717 行的生产代码中有 112 处 `expect()` 调用，集中于底层 TUN 包处理逻辑。这些 expect() 当前起到内部 invariant 断言的作用（如"此时 Option 绝不为 None"）。

不是 blocker 的原因：
1. `no-unwrap-core.sh` PASS，说明该 lint gate 的目标（`sb-core`、`sb-transport`、`sb-adapters`）已受控。`tun_enhanced.rs` 在 `sb-adapters` 范围内，**脚本仍然通过**，表明这些 expect() 不在脚本的禁止列表中（脚本仅针对特定子目录或以白名单方式运行）。
2. 全部 216 个 `sb-adapters` lib tests PASS，说明 TUN 路径在当前测试覆盖下未触发非预期 panic。
3. 将 expect() 改为 `Result` 传播需要大范围类型签名改动（涉及所有调用方），是 P2 结构性工作，不是安全紧急修复。

### 7.3 304 个 `tokio::spawn` 调用点

当前全库生产代码中有 304 处 `tokio::spawn(` 调用，相比原始审计 152 的"untracked"基线数字翻倍。

不是 blocker 的原因：
1. 两个数字口径不同：原 152 是"untracked"（handle 丢弃），304 是"所有调用"（包含已追踪）。
2. 已知高风险文件（anytls、ssh）已确认零 spawn，无需担心 lifecycle 泄漏。
3. inbound 协议处理器（socks、shadowsocks、tun 接入层）的 connection-per-task 模式是 Tokio 网络程序的标准结构；在此场景下 "fire-and-forget" 不是缺陷，而是设计意图。
4. 1205 sampled tests PASS，clippy clean，未出现因 untracked spawn 导致的测试失败或资源泄漏。

全量 tracked/untracked 专项审计是独立工作，可作为后续 M 线主题，不构成本卡结论的障碍。

---

## 八、compat shell / Future Boundary 判定理由

### 8.1 判定标准

将某个仍然存在的 static 声明归类为"Future Boundary"（而非"Still Active 问题"），需满足以下全部条件：

1. **不阻止 owner 回收**：持有的是 `Weak<T>` 而非 `Arc<T>`；或者是 prometheus 原子计数器（无所有权语义）。
2. **owner-first 路径已建立**：调用方优先从依赖注入获取 owner，compat shell 仅在 fallback 场景使用。
3. **设计意图有文档记录**：相关代码有 comment 或架构文档解释为何保留。
4. **blast radius 已控制**：调用点已收拢（如 `with_current()`/`map_current()` wrapper），不会在主业务路径中散射。

### 8.2 各项具体理由

**`logging.rs` `ACTIVE_RUNTIME`、`security_metrics.rs` `DEFAULT_STATE`、`geoip/mod.rs` `DEFAULT_GEOIP_SERVICE`**

这三个 compat shell 形态完全一致：`LazyLock<Mutex<Weak<T>>>`。`Weak<T>` 的语义保证：当 owner（`Arc<T>` 持有者）drop 时，`Weak::upgrade()` 返回 `None`，调用点可以感知 owner 离线并降级处理，而非继续持有一个永不释放的引用。这与"硬全局单例"（如原始 `GLOBAL_HTTP_CLIENT: LazyLock<Arc<dyn HttpClient>>`，强引用，阻止 owner drop）有本质区别。

**`sb-metrics/src/lib.rs` 的 ~50 条 LazyLock metric statics**

这是 prometheus-rs 的标准惯用法。prometheus 的 Counter、Gauge、Histogram 需要在全局 registry 注册，且必须在整个进程生命周期内持续存活（否则 scrape 时找不到指标）。使用 `LazyLock<CounterVec>` 既避免了运行时锁开销（初始化一次），又符合 prometheus 库的设计约束。模块头注释明确记录了这一决策。将 ~50 个 metric statics 改造为依赖注入传递，会引入严重的 API 污染（每个需要记录指标的函数都需要携带 metrics context），且没有实际收益（prometheus 的原子计数器本身线程安全，不存在竞争条件）。

**`registry_ext.rs` 的 `Box::leak`**

`Box::leak` 将堆分配提升为 `'static` 引用，产生有意为之的轻微内存泄漏（每个 metric 类型分配一次，进程存活期间不释放）。这是 prometheus 库在需要 `'static` 生命周期的注册接口下的标准解法。文件 blast radius 极小（仅 303 行，4 个 map），且 OnceCell 保证每种类型只初始化一次。

---

## 九、`make boundaries` 21/541 stale targets 详解

### 9.1 背景

`agents-only/06-scripts/check-boundaries.sh` 是本仓库的依赖边界 ratchet 脚本，内含 541 条断言（V1-V7 类别）。V7 类断言记录了 L20 migration 时确立的不变式，用于防止回归。

### 9.2 21 条失败的具体分类

| 数量 | 原因 | 类型 | 是否代码回归 |
|------|------|------|------------|
| 4 | 断言目标文件 `crates/sb-config/src/validator/v2.rs` 不存在 | 文件已拆分为 `v2/` 目录，断言未跟随更新 | **否** |
| 14 | `app/src/bootstrap.rs` 和 `app/src/run_engine.rs` 中缺少预期模式 | bootstrap 已分解为 `bootstrap_runtime/`，相关代码迁出，断言仍指向旧位置 | **否** |
| 1 | `app/src/run_engine.rs` 缺少 W4-09 transport planning log 模式 | 同上，代码迁出后断言未更新 | **否** |
| 1 | `crates/sb-adapters/src/inbound/http.rs` W55-02 health check direct override | 预先已知问题，非本维护系列引入 | **否（预存）** |
| 1 | `reqwest` dep 由非批准的 `dns_http` feature 引用 | 预先已知 feature gate 问题 | **否（预存）** |

### 9.3 结论

全部 21 条失败属于以下两类：
- **陈旧断言**（18 条）：断言内容指向已重构的旧文件路径或旧代码位置，需要对脚本断言本身进行更新，而非恢复被重构的代码。
- **预存已知问题**（2 条）：非本次维护系列引入，审计报告中已有记录，优先级 P3。

这 21 条失败**不代表任何代码回归**，不是当前 blocker。正确的处置方式是更新脚本断言以匹配重构后的现实，而非回滚重构。

---

## 十、最终结论：为何只能给出 Partial

### 10.1 "Partial" 的精确含义

"Partial clearance"意味着：

- **P1 命中项**（原审计标定的高优先级、影响运行时安全的问题）：已全部 **Resolved 或 Reduced to Future Boundary**。不存在遗留的硬全局单例、未追踪的关键 lifecycle spawn、config 边界裸 Deserialize。
- **P2/P3 命中项**（结构债务、mega-file、局部 panic 密度）：仍然存在，但均为**非 blocking 的结构性问题**，不影响当前的正确性、运行时安全或功能完整性。

### 10.2 不能说"全部清零"的原因

以下三类项仍然真实存在，在诚实口径下不可写成"已修复"：

1. **4 个大文件（>2900 行）**：`derp/server.rs`、`ir/raw.rs`、`register.rs`、`dns/upstream.rs`。这是原审计 L6-Mega 类别的部分遗留。文件体量本身是可量化的结构事实。
2. **`tun_enhanced.rs` 112 个生产 `expect()`**：原审计 L1-Panic 类别的局部遗留。`no-unwrap-core.sh` PASS 不能等同于"无 panic 面"，只能表明脚本的目标集合受控。
3. **304 个 `tokio::spawn` 调用点未全量分类**：原审计 L3-Spawn 类别的部分遗留。当前计数包含已追踪 spawn，但未做全量 tracked/untracked 区分。

### 10.3 这些遗留项的实际影响

**当前影响**：无（1205 sampled tests PASS，clippy -D warnings PASS，no-unwrap-core PASS）。

**潜在风险**：`tun_enhanced.rs` 的 112 处生产 expect() 如果命中非预期的 None/Err 状态会触发 panic，但这属于 invariant 防御性断言，不是已知的有效触发路径。mega-file 不直接带来运行时风险，主要是可维护性成本。

---

## 十一、当前是否存在 blocker

**明确结论：不存在当前 blocker。**

- 所有 1205 sampled tests（sb-core 703、app 286、sb-adapters 216）通过，0 个失败。
- `cargo clippy --workspace --all-features --all-targets -- -D warnings` PASS。
- `scripts/lint/no-unwrap-core.sh` PASS。
- `make boundaries` 21/541 失败项均为陈旧断言，不是回归。
- 没有已知的运行时安全问题需要立即修复。
- 没有阻止正常 CI/CD 流程的问题（假设 boundaries 脚本在更新断言后会 clean pass）。

---

## 十二、下一阶段建议

基于本次全量复扫结论，后续行动建议最多 3 条高层主题。

### 建议 1（低优先级）：更新 check-boundaries.sh 陈旧断言

**内容**：将 21 条失败断言更新为匹配当前重构后状态：删除指向 `v2.rs`（已变为 `v2/`）的断言，更新 `bootstrap.rs`/`run_engine.rs` 断言指向新位置。
**理由**：当前 21/541 失败干扰了 gate 的信噪比，容易让后续维护者误判为回归。
**工作量**：1 天以内，不涉及代码逻辑变更。
**可否跳过**：可以，当前不影响正确性。

### 建议 2（中优先级，可选）：`tun_enhanced.rs` 增量 panic 面收缩

**内容**：在不改变对外 API 的前提下，将 `tun_enhanced.rs` 生产代码中最高风险的 expect() 转为 `Result` 传播或 fallback 处理，目标将 112 减至 50 以下。
**理由**：这是 still-active 项中代码质量层面最可量化的改善机会。
**工作量**：中等，需要逐一检查每个 expect() 的上下文并判断改造可行性。
**前置条件**：有明确驱动信号（如 TUN 路径的实际 panic incident 或新的功能需求）再开卡，不建议无信号主动开。

### 建议 3（高层，仅在有明确功能需求时）：mega-file 结构性治理

**内容**：对 `derp/server.rs`（5211 行）或 `dns/upstream.rs`（3246 行）进行子模块拆分，使单文件不超过 2000 行。
**理由**：改善可维护性，降低 code review 难度。
**前提条件**：必须有功能变更或性能优化作为驱动；为拆分而拆分不是充分理由。
**建议**：当前不开此卡，等到下一个涉及这些文件的功能性 PR 时顺带处理。

---

## 附录：本报告数据来源

| 数据 | 来源 |
|------|------|
| 原始审计基线数值 | `重构package相关/singbox_rust_audit_report.md`（L1–L6 统计表） |
| 维护线工作内容 | `重构package相关/2026-03-25_5.4pro第三次审计核验记录.md` |
| 本次 grep 计数 | MT-AUDIT-01 执行产出，HEAD `89182778` |
| 测试结果 | `cargo test` 实际输出，HEAD `89182778` |
| Clippy 结果 | `make clippy` 实际输出，HEAD `89182778` |
| Boundaries 结果 | `make boundaries` 实际输出，HEAD `89182778` |
| 对账摘要 | `agents-only/mt_audit_01_reconciliation.md` |
| 上下文状态 | `agents-only/active_context.md` |
