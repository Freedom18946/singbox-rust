# sb-runtime（运行时与资源治理）

> 如果仓库已有 sb-runtime，本规范给出“它应该存在的理由”。

## 1) 职责

- tokio runtime 的抽象与启动（可选）
- 统一 task 管理：
  - spawn 与命名
  - 取消/超时
  - join/崩溃回传
- 资源池：
  - buffer pool
  - connection pool（若需要）

## 2) 禁止事项

- 不实现协议
- 不包含路由策略
- 不包含控制面 server
