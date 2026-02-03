# sb-common（通用工具）

## 目标

sb-common 只放“真正跨层复用”的小工具，避免成为新的大杂烩。

允许：
- tracing re-export
- 小型 util（time、bytes helpers）
- 轻量数据结构（LRU、ring buffer）如果被多层共享

禁止：
- 协议实现
- 平台服务
- Web 框架
