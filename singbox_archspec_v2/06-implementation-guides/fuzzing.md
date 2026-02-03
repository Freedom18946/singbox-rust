# 模糊测试（Fuzzing）建议

## 目标

优先覆盖协议解析与握手：

- VMess/VLESS/Trojan/SS 的 header 解析
- HTTP/SOCKS inbound 的边界输入
- QUIC/TLS 参数解析（若有自定义）

## 实施方式（建议）

- 使用 `cargo fuzz`（libFuzzer）
- 把 parser 抽成纯函数（无 I/O），方便 fuzz

## 输出

- 发现崩溃必须回填 regression test（golden）
