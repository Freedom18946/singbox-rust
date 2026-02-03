# 安全落地细节

## 1) Secret 生命周期

- 读取：app/sb-security
- 传递：结构化对象（避免字符串）
- 使用：sb-tls / adapters
- 销毁：zeroize（如适用）

## 2) 控制面鉴权

- 必须可配置：
  - token
  - basic auth
  - mTLS（可选）
- 默认关闭高风险接口（例如执行任意命令/读取任意文件）
