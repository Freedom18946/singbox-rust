# 数据面（Data Plane）执行路径

## 1) TCP/Stream 典型路径

1. Inbound accept（协议适配器）
2. 解析为统一 `Session`（sb-types）
3. 调用 sb-core `Engine::handle_stream(session, inbound_stream)`
4. sb-core 执行：
   - 策略与路由决策（rule engine）
   - DNS（如需：由 DnsPort）
   - 选择 outbound（OutPort）
5. outbound adapter 建立连接（可能复用 transport/tls）
6. 进入转发循环（copy/bidirectional relay），记录统计与事件

---

## 2) UDP/Packet 典型路径

- inbound adapter 将 packet 标准化为 `(Session, Datagram)`
- sb-core 负责 NAT 映射与路由选择
- outbound adapter 发包并返回响应（如有）
- 需要明确：
  - session key（四元组 + inbound tag + user）
  - 超时与清理策略（timer wheel / tokio interval）

---

## 3) 热路径优化红线

- `Session` 必须是轻量对象（避免大字段 clone）
- 路由匹配必须预编译（config -> IR）
- 动态分发必须收敛到 enum（Outbound/Inbound/Resolver）
