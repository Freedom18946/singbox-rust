<!-- tier: B -->
# Round D 审计报告:测试 / CI / 文档可信度 + 种子重评

> Agent:audit-RD(general-purpose, opus)| 2026-06-10 | tokens ≈122k | tool_uses 37
> 范围:测试三态分类、门禁声明实测抽验、flake 根因、文档漂移、5 个种子优先级重评。
> 以下为 agent 最终报告**原文**(无压缩)。

---

HEAD `02d8d16e`。所有命令只读,临时产物在 `/tmp`。

## 1. 测试可信度三态分类表(按行为域)

| 行为域 | 三态 | 证据 | 说明 |
|--------|------|------|------|
| **reload / rollback** | **A 类** | `crates/sb-core/src/runtime/supervisor.rs:2418-2533` + `:2245`(K/L 续接)。实跑:`cargo test -p sb-core --lib --features service_v2ray_api rollback` → **10 PASS**(默认 feature 仅 5,4 个在 `#[cfg(feature="service_v2ray_api")]` real_listener 子模块) | 真 `TcpListener::bind`、端口可重绑定断言(`f_`)、真 gRPC listener close-count 断言。强证据 |
| **inbound 生命周期** | **A 类(有 1 处缺口)** | `supervisor.rs:2348-2365` request_shutdown 计数双重;`:572` step0 在新引擎构建前 stop 旧 inbound → 续接缺口(见 RD-01) | 端口释放语义被真实断言;但旧 inbound 续接窗口未被任何测试覆盖 |
| **协议握手(trojan)** | **B/A 混合** | `crates/sb-adapters/tests/trojan_integration.rs`:`test_trojan_config_basic`(:19)仅断言 `connector.name()=="trojan"`(B);`skip_cert_verify_true/false_*`(:477/:512)绑真自签 TLS listener 并断言握手结果(A);**最深的 `test_trojan_connection_to_mock_server`/`_timeout` 是 `#[ignore]`**(:174/:202) | 构造级 B 类占多数;真握手 A 类存在但最关键两条被 ignore |
| **路由决策** | **A 类** | `app/tests/route_explain.rs:20` 通过 `assert_cmd` 调真 `app` 二进制,断言 explain/trace JSON 形状(用户可观察语义) | 端到端 CLI 语义 |
| **DNS** | **A/B 混合** | `crates/sb-core/tests/dns_steady.rs`:`bad_domain_returns_err`(真系统 resolver,环境依赖)、`udp_pool_timeout_is_handled`(真 UDP socket→discard 端口);`cache_hit_and_expire` 纯逻辑(B) | 见 flake 分析 |
| **clash_api** | **A 类** | `crates/sb-api/tests/clash_http_e2e.rs:90` 真 `axum::serve` + 随机端口 `TcpListener` + 真 `reqwest`,断言 HTTP status+JSON body。注:bind 失败时 `start()` 返 `None` 优雅跳过(轻微覆盖侵蚀,非伪测) | 强证据 |
| **配置解析** | **A 类(golden)** | `crates/sb-config/tests/`:`golden_go1124_roundtrip.rs`、`compatibility_matrix.rs`、`schema_version_check.rs` 等 18 个文件,golden 往返/parity 断言 | 无需 IO,合理 |

**量化抽样:**
- 全仓真实 listener:**142 文件** 使用 `TcpListener::bind`(crates+app+tests+xtests,排除 vendor)。
- 总测试函数:**~4307**(`#[test]`/`#[tokio::test]`)。
- `app/tests` 153 文件中,**63(~41%)** 无 listener/无 `assert_cmd`/无 spawn/无 http client = 纯构造或单元逻辑(B-class proxy 上限;多数为合法的 config/serde 测试)。
- `#[ignore]`:**157**,分布:stress/bench 占大头(`p0_protocols_stress`=20、perf bench≈30+)、network-dependent、env-sensitive global-OnceLock race、dual-kernel manual-only(`route_parity.rs` 3 条需 Go 二进制)。
- **xtests 确在门禁内**:`Cargo.toml:24` 为 workspace 成员,`cargo test --workspace`(Makefile `test`、STATUS 验证链)覆盖之。**未发现 feature-gated 永不开启的测试路径**——v2ray_api 等 gated 测试在开 feature 时确实运行(已实跑验证)。

## 2. 门禁与声明抽验

| 项 | 文档声明 | 实测 | 判定 |
|----|---------|------|------|
| check-boundaries.sh | exit 0 / 537 assertions / 0 违规 | `EXIT=0`,V7 537 assertions,"全部检查通过 (0 违规)" | **CONFIRMED** |
| clippy all-features all-targets | 0 warn | `cargo clippy --workspace --all-features --all-targets` 完成 1m27s;全 log `^warning`/`warning:`/`error` **= 0 行** | **CONFIRMED** |
| rollback_guard 9 测试 PASS | 9 个 | `--features service_v2ray_api` → **10 PASS**(9 rollback_guard + 1 reuse_handoff `j_`);默认 feature 仅 5 | **CONFIRMED**(需注明 4 条 feature-gated) |
| sb-core 1109 测试 | 1109 PASS | 未全跑(耗时);抽样模块全绿,filtered 计数自洽(rollback 跑时 559/568 filtered) | **HIGH-CONFIDENCE INFERENCE** |
| rustdoc 14 baseline | 14 | sb-core 单 crate `cargo doc --no-deps` = **13 warn**;workspace 14 合理 | **HIGH-CONFIDENCE INFERENCE** |
| flake 三件套 | 隔离重跑 PASS | `test_fakeip_persistence_sled` PASS;`dns_steady` 3/3 PASS(`--test-threads=1`) | **CONFIRMED**(intermittent,非常态坏) |

**注:** 单元 lint 现为 `warn` 非 `deny`(active_context 记录 2026-06-03 relaxed)。实跑 `cargo test -p sb-core` 时出现 2 个 `warn`(`supervisor.rs:2002` unused import、`v2ray_api.rs:987` dead fn `current_generation`)——**不破坏构建,但是新引入的轻微卫生债**,且 `cargo clippy` log 为 0 是因 clippy 走 all-features 路径覆盖了这些 cfg。**DISPROVED 风险点:** "0 warn" 仅对 clippy-all-features 成立;特定 feature 组合下 `cargo test` 仍有 2 warn。

**Flake 根因分类:**
- `bad_domain_returns_err`(`dns_steady.rs:43`):**环境/网络依赖**——真系统 resolver 解析 `nonexistent.invalid` 断言 `is_err()`;遇 NXDOMAIN-劫持/wildcard resolver(captive portal、某些 ISP)会假失败。真实风险低但属测试卫生缺陷。
- `udp_pool_timeout_is_handled`(`:53`):**时序依赖**——20ms timeout 对 `127.0.0.1:9` discard 端口,负载下紧;断言方向(期望 err)稳健。
- `test_fakeip_persistence_sled`(`cache_file.rs:904`):**fs/资源依赖**——sled DB 目录进程级锁 + flush/reopen 时序(同测试内重开同路径,首 handle drop 时机)。经典 sled 测试卫生。
- 三者**均已用 `serial_guard()`+`EnvVarGuard` 加固**跨测试 env race,但 serial guard 是 per-file `OnceLock`,`SB_DNS_POOL` 是进程全局——另一并行测试文件碰它仍可 race(仓内 `env-sensitive (global OnceLock); run in isolation` 的 ignore 印证此类存在)。
- `TIDY-APP-BREAKER-FLAKE`:app full-run circuit-breaker 计时,属时序类,登记未修复属合理(隔离即过)。

## 3. 发现清单

- **[RD-01] reload step0 在新配置验证前 stop 旧 inbound,续接缺口未测** | **HIGH** | TEST GAP / BEHAVIOR | CONFIRMED | `supervisor.rs:572-597`(step0 `request_shutdown` 全部旧 inbound + 1200ms grace)**先于** `:600 Engine::from_ir`(可失败)。01B rollback guard 只清新资源,无法 un-stop 旧 inbound;无测试覆盖"reload 失败时旧 inbound 已停"窗口 | drop-in 替换核心关切:坏配置 hot-reload 即便"fail-safe 回滚",仍造成短暂 accept 中断。Go sing-box 续接语义未对齐 | 构造一个 step0 后必失败的 new_ir,断言旧 inbound 端口在 grace 后是否仍 accept
- **[RD-02] capabilities.json 严重陈旧(335 commits / ~2.5 月)** | MEDIUM | DOC DRIFT | CONFIRMED | `generated_at 2026-03-21`、`source_commit c36d29d3`;`git rev-list --count c36d29d3..HEAD`=**335**;HEAD 2026-06-10 | 但自标 `docs-only`/`snapshot_unverified`,STATUS 也声明其为 ledger 非 runtime proof——**漂移有节制**。仍误导:README 多处 capability 链接指向它 | 重生成或在文件头加"相对 HEAD 落后 N commits"指针
- **[RD-03] README 头牌声明无证据锚点** | MEDIUM | DOC DRIFT | CONFIRMED | `README.md:93 "149x faster"`、`:103 "36 Total"`、`:123 "38 rule types"`;`149x` 唯一出处 `docs/RUST_ENHANCEMENTS.md:10` 仅复述无测量;`PERFORMANCE_REPORT.md` 自承"mixed real measurements, placeholder benchmarks, obsolete refs" | README 用未对冲营销数字,而其链接文档远更谨慎;与 "Maintenance mode" 表述并存,对外信号矛盾 | 给 149x 加 benchmark 锚点或降级措辞;36 与 parity 矩阵(in19+out21,含 de-scoped)对齐
- **[RD-04] TEST_EXECUTION_SUMMARY.md 严重误导** | MEDIUM | DOC DRIFT | CONFIRMED | `docs/TEST_EXECUTION_SUMMARY.md`(2026-01-01):trojan/ss 测试标 "PENDING / 0/8"、TLS 依赖 "Blocker"、"READY FOR EXECUTION";实际 trojan_integration **17 PASS/2 ign**,ss 验证测试存在 | 读者会误判协议测试未跑;与现实完全脱节 | 归档至 `docs/archive/` 或加 stale 横幅
- **[RD-05] CLEANUP_COMPLETION_REPORT.md 一次性历史报告滞留活动区** | LOW | DOC DRIFT | CONFIRMED | `docs/CLEANUP_COMPLETION_REPORT.md`(2025-10-18)称"docs 根仅 4 文件";实际 `docs/` 根 **45+ 文件/条目** | 自相矛盾的快照,易误导文档结构现状 | 移入 archive
- **[RD-06] proxy-pool/selector 测试腐烂(disabled ~7.5 月)** | LOW-MEDIUM | TEST GAP | CONFIRMED | `proxy_pool_select.rs`+`selector_p2.rs` 4 条 `ignore="PoolSelector API changed, needs rewrite"`,文件末次提交 **2025-10-26** | selector/pool 行为域覆盖被静默削弱,无 follow-up 卡片 | 评估 PoolSelector 当前 API,重写或正式 de-scope
- **[RD-07] 特定 feature 下 cargo test 有 2 个 warn(新卫生债)** | LOW | TEST/HYGIENE | CONFIRMED | `cargo test -p sb-core --lib`:`supervisor.rs:2002` unused import `build_context_from_ir`、`v2ray_api.rs:987` dead `current_generation` | "0 warn"声明仅对 clippy-all-features 成立;近期 reload 改动引入 | `cargo fix --lib -p sb-core --tests`
- **[RD-08] CI 工作流空 → 所有门禁纯本地手动** | INFO(后果) | CI | CONFIRMED(已知决策) | `.github/workflows/` 空;STATUS:"Workflow automation is disabled" | 已知决策非发现;后果:537 边界断言/clippy/1109 测试/flake 全靠人记得跑,无防回归自动网。对 drop-in 长期质量是结构性风险 | (评估项,非修复)
- **[RD-09] 协议握手最深测试 #[ignore]** | LOW | TEST GAP | CONFIRMED | `trojan_integration.rs:174/:202` 两条真连接/timeout 测试 ignore("requires actual TLS server"/"rustls CryptoProvider may not be available") | 握手行为域 A 类覆盖被削;真 TLS listener 测试(`skip_cert_verify_*`)部分弥补 | 在 self-signed listener harness 上重启用

## 4. 种子优先级重评表

| 种子 | 原状态 | 重评 | 仍成立? | 阻塞最高目标? | 理由 |
|------|--------|------|---------|----------------|------|
| **APP-RELOAD-INBOUND-CONTINUITY-01A** | DEFER/FOLLOW-UP AUDIT | **↑ 升级:应为最高优先级,P1** | 是(CONFIRMED `supervisor.rs:572`) | **是** | 唯一直接触及 drop-in 续接语义的种子。坏 reload 致旧 inbound accept 短暂中断,即便回滚。建议升级为活动卡片并补 RD-01 测试 |
| **SVC-V2RAY-API-01B** | DEFER/POLICY REVIEW | **维持 DEFER;偏卫生/policy** | 是(HTTP JSON endpoints de-scoped,gRPC StatsService 已实现 `v2ray_api.rs:780`) | 否 | GUI 走 clash_api 为主;v2ray HTTP JSON 非 drop-in 关键路径。policy review 而非实现债 |
| **APP-SIDECAR-POLICY-02A** | DEFER/FUTURE | **维持 DEFER** | 是 | 否 | log-only Continue 策略已 accepted(`app_sidecar_liveness_*`);纯未来 policy 项 |
| **TIDY-RUSTDOC-LINKS** | DEFER | **维持 DEFER;卫生** | 是(rustdoc ~14 baseline 复核一致) | 否 | 纯文档链接卫生,14 baseline 稳定 |
| **TIDY-APP-BREAKER-FLAKE** | 已记录未修复 | **维持;低风险时序 flake** | 是(隔离即过) | 否 | 时序类,隔离重跑稳定。可在测试内注入可控时钟去 flake,非紧急 |

**比已登记种子更重要但未登记的(基于 1-3 发现):**
- **新增建议 SEED-DNS-STEADY-HARDEN**(MEDIUM):`bad_domain_returns_err` 对 resolver 劫持环境假失败——比 breaker flake 更易在真实部署 CI 触发误报。
- **新增建议 SEED-DOC-STALE-SWEEP**(MEDIUM):RD-02/03/04/05 合并——README 头牌 + TEST_EXECUTION_SUMMARY + CLEANUP_REPORT 漂移,对外信任度损害大于多数卫生项。
- **新增建议 SEED-SELECTOR-TEST-ROT**(RD-06):比 TIDY-RUSTDOC-LINKS 严重(真行为域覆盖被静默削弱 7.5 月)。

## 5. 文档可信度总评

**可信(证据锚点扎实 / 自我对冲得当):**
- `active_context.md` — 与代码高度对应:rollback guard、step0 续接缺口登记、flake 三件套、commit 引用全部抽验吻合。**单一真相源名副其实**。
- `agents-only/reference/GO_PARITY_MATRIX.md` — A-tier,头部明确标注口径(209 closed ≠ 行为对齐;`v2.rs` 锚点已过期需按子模块查),calibration date 透明。诚实的陈旧标注。
- 根 `GO_PARITY_MATRIX.md` — 纯指针,无内容漂移。
- `docs/STATUS.md` — 权威链清晰,明确 capabilities.json 为 `snapshot_unverified` ledger、workflow 已停用。对冲得当。
- `reports/PERFORMANCE_REPORT.md` / `reports/TEST_COVERAGE.md` — 自标 historical/gap-tracker,主动否认作为真相源。健康。
- `docs/TODO_AUDIT.md` — 声明 "0 TODO/FIXME" 经 grep 抽验 **= 0,准确**。

**已漂移(应归档或加横幅):**
- `reports/capabilities.json` — 335 commits 陈旧(RD-02),自标缓解但 README 仍链接它。
- `docs/TEST_EXECUTION_SUMMARY.md` — 严重误导,与协议测试现实脱节(RD-04)。
- `docs/CLEANUP_COMPLETION_REPORT.md` — 一次性历史报告滞留活动区且数字自相矛盾(RD-05)。
- `README.md` — 头牌 `149x`/`36`/`38` 无锚点,与其谨慎的子文档语气冲突(RD-03)。

**总评:** agents-only 内部记忆体系(active_context + reference)**高度可信**,与代码紧耦合且对冲纪律到位;漂移集中在面向外部的 `docs/` 根与 `reports/` 历史层(均有"single source of truth"指针保护,危害可控但应清理)。最实质的非文档发现是 **RD-01 reload 续接缺口**——它是唯一直接威胁 drop-in 最高目标的活动技术债,建议将对应种子 `APP-RELOAD-INBOUND-CONTINUITY-01A` 从 DEFER 升级为 P1。
