<!-- tier: A -->
# L18 Phase 3 工作包：历史阶段说明

状态：✅ 历史阶段
更新：2026-03-09

> **说明**：
> Phase 3 原本用于 `nightly / certify` 长跑收口。
> 在 2026-03-09 进入全局静态审议后，主线已切换到 [L18-PHASE4.md](./L18-PHASE4.md)。
> 旧的 `nightly PASS / certify deferred` 叙事在当前 slim snapshot 下不构成本地可独立复核证据。

---

## 1. 原阶段目标（历史）

1. 取得一次本地 `nightly`（24h canary）full PASS。
2. 在 `nightly` 稳定后取得一次 `certify`（7d canary）PASS。
3. 产出 L18 关闭所需的长跑证据与最终状态文档更新。

## 2. 当前处理口径

1. `20260307T211512Z` / `20260307T230356Z` 仍可作为 provenance reference 保留。
2. 但由于本地大部分 batch 工件已为静态审计瘦身删除，当前快照不能把这些批次继续写成“已复核 PASS”。
3. 在补齐自包含 manifest 之前，所有缺失本地工件的长跑结论统一记为 `UNVERIFIED (slim snapshot)`。

## 3. 历史执行顺序（保留供参考）

### Step 1: nightly 24h

命令：

```bash
scripts/l18/run_capstone_fixed_profile.sh \
  --profile nightly \
  --gui-app /Users/bob/Desktop/Projects/ING/sing/singbox-rust/GUI_fork_source/GUI.for.SingBox-1.19.0/build/bin/GUI.for.SingBox.app \
  --require-docker 0 \
  --workspace-test-threads 1 \
  --allow-existing-system-proxy 1 \
  --allow-real-proxy-coexist 1
```

验收：

- `l18_capstone_status.json` 为 `PASS` 或仅 `docker=WARN`
- `canary_nightly.jsonl` 在 24h 内无 health 退化、无 RSS/FD 单调泄漏
- `dual_kernel_diff` / `perf_gate` 保持 PASS

### Step 2: certify 7d

前提：nightly 24h full PASS。

命令：

```bash
scripts/l18/run_capstone_fixed_profile.sh \
  --profile certify \
  --gui-app /Users/bob/Desktop/Projects/ING/sing/singbox-rust/GUI_fork_source/GUI.for.SingBox-1.19.0/build/bin/GUI.for.SingBox.app \
  --require-docker 0 \
  --workspace-test-threads 1 \
  --allow-existing-system-proxy 1 \
  --allow-real-proxy-coexist 1
```

验收：

- `certify` 总状态 PASS
- 7d canary 全程健康
- mandatory gate 证据完整可追溯

## 4. 当前替代入口

当前执行入口已切到：

- `agents-only/planning/L18-PHASE4.md`
- `agents-only/workpackage_latest.md`
- `agents-only/active_context.md`
