# 12 时间同步与 NTP（NTP）

时间是所有加密协议的隐形地基：证书有效期、重放保护、握手校验……一旦系统时间漂移，再完美的配置也会像失准的罗盘。

sing-box 把这件事单独抽象为 `ntp` 模块。

## 1) 目标

- MUST：支持 `ntp` 配置段（见整体配置结构），用于在需要时提供时间同步/校验能力。
- SHOULD：在 TLS/Reality/QUIC 等依赖时间正确性的模块中，能够利用 NTP 结果做：
  - 启动前自检（时间偏移过大则告警）
  - 运行时监测（偏移异常时提示可能导致握手失败）

## 2) 功能需求（抽象）

- MUST：支持指定上游 NTP 服务器（或系统默认），并可配置同步间隔。
- SHOULD：支持通过 detour（走特定 outbound）访问 NTP 上游（适用于被限制网络）。
- SHOULD：在权限允许时支持“写入系统时间”；否则至少提供“只读校验 + 告警”模式。
- MUST：所有失败应可诊断（DNS 失败/超时/权限不足/不可达等）。

## 3) 验收清单

- 启用 ntp 后，时间偏移可被检测并记录。
- 在时间明显错误时，TLS 握手失败能给出“可能由系统时间导致”的提示（或推荐启用 NTP）。

## 来源链接（官方文文档）

- NTP  
  https://sing-box.sagernet.org/configuration/ntp/
- TLS（时间相关：Reality max_time_difference 等）  
  https://sing-box.sagernet.org/configuration/shared/tls/
