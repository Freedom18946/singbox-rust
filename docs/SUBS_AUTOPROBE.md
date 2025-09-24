# sb-subs AutoProbe（全局可选启动体检）

AutoProbe 用于在执行任意子命令前，**可选**地对本地订阅文件做一次快速体检（不触网）。

## 1. 启用方式（缺省关闭）
1) 显式一次性：
```bash
sb-subs --autoprobe ./examples/subs.nodes.sample.json preview-plan
```
2) 默认模式 + 环境变量：
```bash
SB_SUBS_AUTOPROBE=./examples/subs.nodes.sample.json \
sb-subs --autoprobe-default preview-plan
```
3) 默认模式 + 内置候选：
```bash
sb-subs --autoprobe-default preview-plan
# 候选：./sub.json、./examples/subs.nodes.sample.json、
#      /Users/bob/Desktop/Projects/ING/sing/singbox-rust/sub.json
```

## 2. 输出示例
```
AUTOPROBE_OK: path='./examples/subs.nodes.sample.json' items=2
```
或
```
AUTOPROBE_SKIP: not_found='/Users/bob/Desktop/Projects/ING/sing/singbox-rust/sub.json'
```

## 3. 参数
- `--autoprobe-fmt (json|pretty|table)`：输出格式（默认 json）
- `--autoprobe-top <N>`：统计 Top-N（默认 10）

## 4. 兼容性
- AutoProbe 默认关闭，不改变任何既有行为；启用时只打印一段摘要，**不改变退出码**。
- 永不触网；仅读取本地文件；遇到错误不 panic。