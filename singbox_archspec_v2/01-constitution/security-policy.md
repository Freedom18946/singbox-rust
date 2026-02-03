# 安全策略（Security Policy）

## 原则

- 密钥材料只在 `sb-security/sb-tls` 管理
- adapters 不直接读取磁盘证书文件：由 app/platform 传入已解析的材料
- 控制面 API 默认最小暴露，鉴权必须可插拔

## 证书/密钥处理

- 证书加载：
  - app 读取（路径/权限/热更新）
  - sb-tls 接收结构化证书对象
- 私钥在内存中尽量减少拷贝，必要时使用 zeroize（如已在仓库中）

## 依赖与漏洞

- CI 强制 `cargo deny check advisories`
- 针对网络协议实现，建议配合 fuzz（见 `06-implementation-guides/fuzzing.md`）
