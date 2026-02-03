# sb-platform（平台服务）

## 1) 职责

- tun/tproxy/redirect 等透明代理能力
- systemd-resolved、NTP、netlink 等系统服务交互
- socket options 与平台差异封装（Linux/macOS/Windows）

## 2) 对外暴露形式（Ports 实现）

- `DnsPort` 的系统 resolver 实现（如 systemd-resolved）
- `TimePort`（NTP 或系统时钟校准）
- `TunDevicePort`（创建与管理 TUN）

## 3) 目录结构（建议）

```
sb-platform/
  src/
    lib.rs
    dns/
      resolved.rs
    time/
      ntp.rs
    tun/
      linux.rs
      ...
    net/
      socket_opts.rs
```
