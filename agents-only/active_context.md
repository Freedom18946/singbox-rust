<!-- tier: S -->
# 当前上下文（Active Context）
> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。
---
## 战略状态
**当前阶段**: 部署收尾验收已完成基线，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)，以 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 为准
**当前阶段焦点**: MT-DEPLOY-01 已建立部署验收基线

## 最近闭环（2026-04-10）

### MT-DEPLOY-01: 部署验收基线 — 已完成
- 发现并修复 2 个阻塞 `parity` feature 构建的真实 blocker：
  - `app/src/tracing_init.rs`：`init_metrics_exporter_once` 缺少 `#[cfg(feature = "sb-metrics")]`
  - `app/Cargo.toml`：`router` feature 缺少 `tokio-util` 依赖（`watch.rs` 需要 `CancellationToken`）
- 验证通过的完整链路：
  - 构建：debug + release（parity features）PASS-STRICT
  - 版本：`app version` PASS-STRICT
  - 配置检查：`app check -c deployments/config-template.json` PASS-STRICT
  - 零副作用启动检查：`app run --check -c ...` PASS-STRICT
  - 近启动：standalone `run` binary 真实绑定 0.0.0.0:1080 + 优雅关闭 PASS-STRICT
  - 打包：`package_release.sh` 生成正确产物 PASS-STRICT
  - Clippy clean，286 app lib tests PASS
- 所有部署清单（Docker/k8s/systemd/Helm）入口一致：`app run -c <config>`
- 配置模板（`deployments/config-template.json`）跨清单一致
- 详细报告：`agents-only/mt_deploy_01_acceptance.md`

### 已完成维护线（归档视角）
- MT-AUDIT-01 → MT-CONV-01/02/03 → 文档闭环 → MT-DEPLOY-01：全部 close-out

## 当前验证事实
- `parity` feature 构建已修复，debug + release 均通过
- 286 app lib tests 通过，clippy clean
- Boundary 21/541 failures 均为 stale targets（非回归）
- 部署验收链 9 项全部 PASS-STRICT

## 环境限制项（PASS-ENV-LIMITED）
- E2E proxy 链路（需真实上游）：未测试
- Docker 镜像构建（需 Docker daemon）：未测试
- systemd/k8s/helm 部署（需目标基础设施）：未测试

## 当前默认准则
- 部署验收基线已建立，后续可进入实际部署或环境集成
- 不恢复细碎 maintenance 排程
- 不把 deployment acceptance 写成 parity completion
- 不推进 public `RuntimePlan`、public `PlannedConfigIR`、generic query API

## 暂停事项
- 不恢复 `.github/workflows/*`
- 不恢复 `WP-30k` 风格微卡
