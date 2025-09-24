## sb-route compare 抽样策略

### 1. 背景
对大型 DSL 差异对比，`samples` 阵列可能非常庞大。为便于人工审阅与 CI 快照，本工具提供两种抽样策略：
- `head`：取前 `N` 条（流式/稳定）；
- `random`：基于种子的水塘抽样（Reservoir Sampling），`--seed` 控制可复现结果。

### 2. 用法
```bash
# 取前 32 条
sb-route compare ... --diff-sample 32 --diff-sample-mode head
# 随机 64 条（可复现）
sb-route compare ... --diff-sample 64 --diff-sample-mode random --seed 42
# 按簇均匀采样（reason_kind）
sb-route compare ... --diff-sample 48 --diff-sample-mode random --seed 42 \
  --cluster-by reason_kind --max-per-cluster 8
```

### 3. 聚类采样
* `random`：基于种子水塘抽样（Reservoir Sampling）；配合 `--cluster-by` 可针对簇均匀采样，`--max-per-cluster` 控制上限。
* 输出增加 `sample_meta.clusters`，汇总每簇整体规模与采样条数（仅在 `emit=full` 时内嵌到输出JSON；`samples_only`模式下不包含该元信息）。
* 如需同时获取样本和聚类元信息，使用 `--emit full` 或新增的 `--out-sample-meta` 参数写入单独文件。

### 4. 输出不变性
抽样仅影响 `samples` 阵列；`matrix` 与统计字段不受影响。`--emit matrix_only` 与 `--out-matrix` 始终稳定。

**重要**：`--emit samples_only` 输出**纯数组格式** `[...]`，不含 `sample_meta`。这确保了userspace兼容性——scripts期望数组可直接处理，无需解包对象包装器。

### 5. 实现说明
随机模式采用 xorshift64* 伪随机数生成器 + 水塘抽样，无需外部依赖；同一 `seed` 与输入顺序，结果完全可复现。