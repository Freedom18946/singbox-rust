# 性能准则（Performance Guidelines）

## 热路径红线

- 禁止在热路径：
  - 频繁分配（Vec/String）
  - 频繁 clone 大对象
  - 大量 `dyn async-trait`（优先 enum）
  - 同步锁竞争（Mutex/RwLock 在高频路径会放大）

## 推荐做法

- Session：使用 Arc + 小对象，必要时 `SmallVec`
- 缓存：LRU/TTL 结构应在 sb-core，避免每个 adapter 自建一套
- copy：TCP 采用 `tokio::io::copy_bidirectional` 或自定义 buffer 池
- UDP：使用 bounded channel + batch send（如平台支持）

## 指标

- 关键 histogram：
  - route decision latency
  - outbound connect latency
  - dns resolve latency
  - relay throughput
