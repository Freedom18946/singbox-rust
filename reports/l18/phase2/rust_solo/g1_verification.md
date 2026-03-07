# WP-G1: Rust 内核启动 + Clash API 可达性验证

**日期**: 2026-03-07
**Git SHA**: b908446 (F3 fix included)
**Binary**: target/release/run (35MB arm64, rebuilt with F3)

## 验证结果

| 检查项 | 结果 | 详情 |
|--------|------|------|
| Kernel startup | PASS | PID 67144, clean start |
| Clash API `/proxies` | PASS | HTTP 200, 6 proxies |
| SOCKS5 inbound `:11810` | PASS | Listening, loopback proxy test HTTP 200 |
| SIGTERM shutdown | PASS | Clean exit, no SIGKILL needed |
| Port 19090 release | PASS | Free after shutdown |
| Port 11810 release | PASS | Free after shutdown |

## Clash API 详情

```
Proxy tags: DIRECT, GLOBAL, REJECT, alt-direct, direct, my-group
Proxy count: 6
```

## SOCKS5 Loopback Test

```
curl -x socks5h://127.0.0.1:11810 http://127.0.0.1:19090/version
→ {"meta":true,"premium":true,"version":"sing-box 0.1.0"} HTTP 200
```

## 外网 SOCKS5 Test

Not attempted (ENV_LIMITED — no external network dependency required for G1).

## Config

`labs/interop-lab/configs/l18_gui_rust.json`
- Clash API: 127.0.0.1:19090 (secret: test-secret)
- SOCKS inbound: 127.0.0.1:11810
- Route final: my-group (selector → direct, alt-direct)

## 验收

**WP-G1: PASS**
