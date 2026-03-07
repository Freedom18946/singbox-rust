<!-- tier: A -->
# L18 Phase 3 工作包：nightly / certify 级运行

状态：🚀 就绪（待发车）
更新：2026-03-08

> **入口条件**：
> Phase 2 已于 `20260307T211512Z-l18-daily-preflight` 取得 clean full PASS，`reports/l18/phase2_baseline.lock.json` 已锁定。
> Phase 3 只跟进 nightly/certify 长跑中新暴露的真实失败，不回头处理已收敛的 env/workspace/router 默认值问题。

---

## 1. 目标

1. 取得一次本地 `nightly`（24h canary）full PASS。
2. 在 `nightly` 稳定后取得一次 `certify`（7d canary）PASS。
3. 产出 L18 关闭所需的长跑证据与最终状态文档更新。

## 2. 当前已满足前置

- `daily` capstone clean full PASS：`reports/l18/batches/20260307T211512Z-l18-daily-preflight`
- baseline 已锁定：`reports/l18/phase2_baseline.lock.json`
- fixed-profile 执行入口已稳定：
  - `scripts/l18/run_capstone_fixed_profile.sh`
  - `scripts/l18/l18_capstone.sh`
- 本地非阻断项仅剩 `docker=WARN (no daemon)`；在 `--require-docker 0` 下不阻塞 nightly

## 3. 执行顺序

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

## 4. 文档回填

完成 nightly/certify 后同步更新：

- `reports/L18_REPLACEMENT_CERTIFICATION.md`
- `agents-only/active_context.md`
- `agents-only/workpackage_latest.md`
- `agents-only/log.md`

## 5. 风险纪律

- 仅修复新暴露的真实失败；不要重开已收敛的 Phase 2 问题
- 不调整 perf threshold，除非出现新的可复算证据并单独审批
- 保持 fixed-profile 口径不漂移
