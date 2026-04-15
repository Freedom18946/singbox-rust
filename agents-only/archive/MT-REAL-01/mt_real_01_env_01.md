# MT-REAL-01-ENV-01: DNS 隔离 + REALITY 握手验证

日期：2026-04-14

## 目标

- 绕过 Go TUN fake-IP DNS 污染，确认 Rust Phase 3 REALITY live dataplane 失败到底是 DNS 环境问题还是协议残差。

## 输入与方法

- 基线配置：`agents-only/mt_real_01_evidence/phase3_real_upstream.json`
- 隔离方法：
  - 从配置中提取全部订阅域名
  - 使用固定 DoH IP 旁路系统 DNS，生成 `domain -> real IP` 映射
  - 仅替换 outbound `server` 为真实 IP，保持 `tls.server_name` / REALITY SNI 伪装字段不变
- 生成证据：
  - `agents-only/mt_real_01_evidence/phase3_domain_ip_map.md`
  - `agents-only/mt_real_01_evidence/phase3_domain_ip_map.json`
  - `agents-only/mt_real_01_evidence/phase3_ip_direct.json`

## 运行结果

- Rust 内核以 `phase3_ip_direct.json` 启动成功：
  - `/version` 200
  - `/proxies` 可见全部 `21` 个真实 `vless+reality` 节点
  - 启动日志未出现新的 DNS 解析错误，也未再出现 `198.18.x.x` fake-IP 迹象
- 逐节点 `selector` + `socks5h://127.0.0.1:11080` 冒烟结果：
  - `0/21` 成功
  - `19/21` → `tls handshake eof`
  - `1/21` → `timeout`（`HK-A-BGP-2.5倍率`）
  - `1/21` → `REALITY requires DNS server name`（`UK-A-BGP-0.5倍率`）
  - 控制节点 `__phase3_invalid_vless` → `connection refused`

## 关键判定

- 对 `19` 个 `tls handshake eof` 节点，进程级 TCP 观测均命中了各自预期的真实公网 `server_ip:server_port`。
- 因此本轮已排除“其实还连到了 fake-IP”的环境歧义。
- 结论是：**FIX-03 没有拿到 live 成功验收；剩余阻断已收敛为 REALITY 协议实现残差，而不是 DNS 污染。**

## 下一步建议

- 进入 `FIX-04`，优先对比 Go REALITY 客户端与当前 Rust 实现在以下方面的差异：
  - `19` 个统一的 `tls handshake eof`
  - `UK-A-BGP-0.5倍率` 上额外暴露的 `REALITY requires DNS server name`
  - `HK-A-BGP-2.5倍率` 的超时样本是否只是节点环境问题
- 继续复用本卡生成的 `phase3_ip_direct.json`，避免下一轮再次被 fake-IP 争议干扰。
