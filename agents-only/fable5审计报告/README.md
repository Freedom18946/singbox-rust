<!-- tier: B -->
# fable5 审计报告 — REPO-GLOBAL-CALIBRATION-01A

> 生成:2026-06-10,HEAD `02d8d16e`,audit-only 模式(零 tracked 修改、零 commit)。
> 方法:主线程文档地图 + 5 个并行 opus subagent 四轮扫描 + 主线程对全部 P0/P1 证据逐条 `文件:行号` 复核。
> 处置:2026-06-29 已审读并纳入版本控制,作为 B-tier 历史校准材料;当前状态以
> `agents-only/active_context.md`、`post_fable_packages/README.md`、`agents-only/post1313/` 为准。

## 文件索引

| 文件 | 内容 | Agent |
|------|------|-------|
| `01_RA_需求闭环扫描.md` | Round A:自顶向下需求闭环(协议/TUN/路由/DNS/服务/GUI 契约) | audit-RA |
| `02_RB1_生命周期并发扫描.md` | Round B-1:生命周期/资源所有权 + 并发时序 | audit-RB1 |
| `03_RB2_错误处理一致性边界.md` | Round B-2:错误处理 + 模式一致性 + 边界设计 | audit-RB2 |
| `04_RC_场景故障扫描.md` | Round C:17 故障场景 + 种子行为面复验 | audit-RC |
| `05_RD_测试CI文档可信度.md` | Round D:测试三态 + 门禁抽验 + 文档漂移 + 种子优先级重评 | audit-RD |
| `06_全局汇报_A-K.md` | **主报告**:按任务书 A–K 结构的全局校准汇报(最详尽版) | 主线程综合 |
| `Fable5审计报告 0610.md` | 0610 汇报压缩版 + 原始完成回报 | 主线程综合 |
| `stage_summary_extract_2026_06_29.md` | 2026-06-29 审读后可进入阶段总结的提炼稿与处置决定 | 当前线程 |

## 处置结论

这些报告保留在本目录并提交,不移动到 `agents-only/archive/`。原因:post-FABLE 包状态和能力报告仍以
本目录为锚点,移动整目录会制造无必要引用 churn;丢弃原文会丢失 post-FABLE/P1313 追踪的审计来源。
原文只能作为 2026-06-10 快照引用,不能直接代表当前阻塞项。

## 一句话结论

历史口径(2026-06-10):管理面(clash_api/选择持久化/主流协议 outbound)真实闭环且实测可用;但 **3 个 P0**(GUI TUN 配置被 schema 拒绝、启动确认字符串 `sing-box started` 缺失、WireGuard endpoint 孤岛接线)阻断 GUI drop-in 主流程,**reload 连续性簇**(提前关旧 inbound + bind 失败不可见 + 全局 registry 回滚缺口)是可靠性面最大结构缺口。后续 post-FABLE/P1313 已吸收大部分结论,当前状态必须查权威源。

## 复核状态

全部 P0 与核心 P1 发现已由主线程独立打开 `文件:行号` 验证(详见 06 报告 F 节每条的"主线程复核"标记);agent 幻觉率:本轮 0(所有抽验证据与代码一致)。
