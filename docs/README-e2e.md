# 快速验证（本地）

```bash
# 一键：端到端兼容性与汇总（可选 GO_SINGBOX_BIN）
scripts/e2e-run.sh
cat .e2e/summary.json

# 回溯三件套（失败时）
tail -n 200 .e2e/sing.log
python3 scripts/probe_http.py "127.0.0.1:<HTTP_PORT>" "$(( $(date +%s) + 5 ))"
lsof -nP -iTCP:<HTTP_PORT> -sTCP:LISTEN -P || true; netstat -an | grep <HTTP_PORT> || true
```

## 开关（默认关闭）
- `SB_HTTP_SMOKE_405=1`：accept 即回 405（烟囱）
- `SB_HTTP_DISABLE_STOP=1`：禁用 stop 打断（稳定采样）
- `SB_HTTP_LEGACY_WRITE=1`：HTTP 写法回退为 `write_all + shutdown`（速诊）

> NOTE: 主线默认关闭上述开关；只在验收/排障临时启用。

## 验收要点
1) 代理连通：`curl -x http://127.0.0.1:<http_port> https://example.com -I` 能 200 隧道；  
2) SOCKS 互通：`curl --socks5-hostname 127.0.0.1:<socks_port> https://example.com -I`；  
3) 指标暴露：访问 `http://127.0.0.1:<metrics_port>/metrics` 可见文本指标。

## SOCKS5 UDP 快速验证（实验项，默认关闭）
> 开关：`SB_SOCKS_UDP_ENABLE=1`  
> 目标：验证 UDP Associate → NAT → Direct UDP 的最小闭环

1. 启动 singbox-rust，并设置：
   ```sh
   export SB_SOCKS_UDP_ENABLE=1
   export SB_UDP_NAT_TTL=120
   export SB_UDP_NAT_SCAN=5
   export SB_UDP_NAT_MAX=4096
   ```
2. 本地起一个 UDP Echo：
   ```sh
   cargo run --example udp_echo -- 127.0.0.1:19090
   ```
3. 通过 SOCKS5 UDP 发一帧（可用 `socat` 或自备客户端）：
   ```sh
   scripts/e2e_udp_echo.zsh
   ```
4. 观察 `/metrics`：`socks_udp_packets_in_total`、`socks_udp_packets_out_total`、`socks_udp_nat_size`、`socks_udp_nat_evicted_total`。

## 产物与存档（.e2e/）
- `compat_subset.json`（或 `compat_subset_{go|rust}.json`）：`route --explain` 稳定子集对比
- `bench.json`：`bench io --json` 探测（可能缺特性而跳过）
- `summary.json`：聚合报告（时间戳 / 兼容状态 / bench 探测）
