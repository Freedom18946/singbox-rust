<!-- tier: B -->
# MT-INTEROP-03 failure census + oracle ADR

Date: 2026-07-12
Status: ACCEPTED / implemented
Baseline evidence: `agents-only/archive/mig03/mig03_wp14_final_acceptance_and_archive.md`

## Census

WP14 全量 103 例中 16 个原始 FAIL：

- 4 个外部启动依赖：`p0_clash_api_contract`、两个 auth negative、
  `p1_optional_endpoints_contract`。
- 2 个断言/专项：DNS TTL `ne_ref expected=2 actual=2`；deprecated WireGuard 无效
  runtime fixture。
- 5 个 harness/Go oracle：graceful drain 在进程退出后才读 socket、WS memory 首帧固定
  为 0、Go group-delay 实际路由为 `/group/*`、reload readiness 抢读旧进程、FakeIP
  flush 游标语义不同。
- 5 个 protocol-local：Rust 验收 binary profile 缺协议；`${INTEROP_GO_BINARY}` 未设置时
  没有 repo-local bootstrap。

## ADR: outcome 不能等同进程 exit

每例产出四态：

- `PASS`：全部适用断言通过，无登记差异。
- `DIV-COVERED`：全部适用断言通过，且 case 显式列出 S4 ID；内核专属断言必须锁定
  两侧语义。登记不能吞掉未知失败。
- `ENV-LIMITED`：仅限 `env_class: env_limited`，且每个失败均有非 Unknown 环境归因，
  或精确匹配 `expected_env_failures` 的 kernel/stage；新增或错核失败仍为 `FAIL`。
- `FAIL`：其余失败；全量终验不允许存在。

Decision：新增 `covered_divergences`、kernel-scoped assertion、summary outcome。任何 raw
failure 优先级高于静态 divergence 标签。Case loader 同时校验 divergence ID 必须存在于
S4、case 必须为双核、且至少包含一个 kernel-scoped assertion；伪造标签无法产生
`DIV-COVERED`。

## ADR: oracle 修正规则

- reference 数值单调性用 `gt_ref/gte_ref`，不用不表达方向的 `ne_ref`。
- DNS config 的 `ttl_min_s/ttl_max_s/ttl_neg_s` 必须传入 answer cache；否则 fixture 声明
  与运行时不一致。
- `/memory` 前导零是 Go 兼容 warm-up marker；线性回归只分析首个非零样本起的序列。
- 全量执行把 `benchmark` tag 稳定排序到 functional/soak 之后，避免 CPU 饱和污染紧随
  其后的 WS frame timeout；不放宽 WS 成功率或时限。
- reload 先给 down-edge 观察窗口；若内核原地 reload 不暴露 down，则窗口本身完成去抖，
  随后仍须重新验证稳定 ready，避免把旧响应当作 reload 完成。
- graceful drain 必须在 SIGTERM 前排队数据、SIGTERM 后读取，再等待退出。
- Go FakeIP flush 清 storage mapping，但当前进程 allocation cursor 不回退；Rust 同时重置
  mapping 和 cursor。登记 `DIV-M-012`，分别断言。

## 收口补充

- legacy debug-app 与 protocol-local case 统一使用独立 target 的全特性 app，自管理构建，
  避免前置或后续 benchmark/unit build 覆盖共享 `target/debug/app`；重复单例不再依赖全量
  case 顺序。
- repo-local Go 1.13.13 binary 是 `${INTEROP_GO_BINARY}` 缺省 bootstrap。
- VLESS 服务端修正标准 version=0 与 port-before-address 编码，双核 strict PASS。
- VMess 本地 Rust upstream 是非标准测试方言；case 只将已声明的 ok-traffic/errors.count
  两个 stage 记为 `ENV-LIMITED`，launch 或新增失败仍阻断。
