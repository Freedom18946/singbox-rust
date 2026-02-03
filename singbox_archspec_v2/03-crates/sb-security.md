# sb-security（安全材料与策略）

## 1) 职责

- 密钥/证书/PSK/用户凭据等“安全材料”的加载与管理
- zeroize 与内存安全策略
- credential provider（从文件/环境/系统 keychain 等）

## 2) 与 sb-tls 的关系

- sb-security 管“材料与来源”
- sb-tls 管“握手与加密协议栈封装”
- adapters 只接收已经结构化的 `SecurityMaterial`
