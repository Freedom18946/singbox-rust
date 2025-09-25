## 订阅文件本地体检（AutoProbe）
当你启用 `--autoprobe` 或 `--autoprobe-default` 时，`sb-subs` 会在执行任何子命令之前尝试读取并体检本地订阅文件。
- **不会触网**，只读本地；
- 默认关闭（避免干扰脚本输出）；
- 支持环境变量 `SB_SUBS_AUTOPROBE`；
- 内置候选：`./sub.json`、`./examples/subs.nodes.sample.json`、以及你的绝对路径 `/Users/bob/Desktop/Projects/ING/sing/singbox-rust/sub.json`（存在才读取）。

## 路由分析三件套（结构无关维度）
- `stats_only`：规模/理由/决策分布（稳定）
- `shadow_only`：影子/遮蔽数组（若存在则输出）
- `keys_only`：键名频次 + 深度分布（探查陌生结构）
三者输出均可 `--fmt pretty` 直读，也可 `--out-*` 落地供回归。

## Compare 样本采样（head/random）
- `--diff-sample-mode head`：取前 N 条；
- `--diff-sample-mode random --seed <u64>`：可复现的随机抽样；只影响 `samples`，矩阵稳定。

## 规范化导出（sing_box / clash）
使用 `sb-subs probe --export ... --normalize {sing_box|clash}` 将过滤/去重后的数组落地为目标生态最小可用形。

## 更多文档
- Cookbook（可运行示例与排错）：`docs/COOKBOOK.md`
- 开发与质量闸门：`docs/DEVELOPMENT.md`
- 运维与部署（systemd/Docker）：`docs/OPS.md`
