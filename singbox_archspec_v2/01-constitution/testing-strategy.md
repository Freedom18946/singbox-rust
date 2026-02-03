# 测试策略（Testing Strategy）

## 分层测试金字塔

### 1) sb-types：编译期契约测试

- `#[cfg(test)]` 仅做 trait 边界与类型行为测试
- 尽量不用 async runtime

### 2) sb-core：纯逻辑单元测试（mock ports）

- 重点：路由匹配、策略、超时/熔断、DNS 策略
- 使用 mock 实现 `DnsPort/OutboundConnector`：
  - 不需要真实网络

### 3) sb-adapters：协议 integration tests

- 使用 `sb-test-utils` 提供：
  - loopback listener
  - 虚拟 TUN（如可）
  - 录制握手/回放向量（golden tests）

### 4) app：端到端 smoke tests

- 最小配置启动
- 发送几条典型请求（HTTP/SOCKS）
- 验证 metrics/API 可用（在 acceptance feature 下）

## 失败注入（可选）

- 建议在 `sb-core` 提供 `chaos` feature（failpoints）
- 但必须保证默认禁用，且不污染热路径
