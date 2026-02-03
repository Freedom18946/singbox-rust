# Feature 策略（Workspace Feature Policy）

## 原则

- **feature 聚合在 app**：用户只面对一个入口（`app --features ...`）
- **infra crate 可以有细粒度 feature**：`sb-transport`, `sb-tls`, `sb-security`, `sb-platform`
- **业务 crate 禁止用 feature 互相偷渡依赖**：`sb-core/sb-adapters/sb-api` 内部 feature 只能做“编译裁剪”，不能改变依赖方向

---

## 命名规范

- `proto_*`：协议支持（例：`proto_vmess`）
- `transport_*`：传输形态（例：`transport_quic`, `transport_ws`）
- `security_*`：安全能力（例：`security_reality`, `security_ech`）
- `platform_*`：系统能力（例：`platform_tun`, `platform_tproxy`）
- `observe_*`：观测能力（例：`observe_prometheus`）
- `admin_*`：控制面能力（例：`admin_clash`, `admin_v2ray`）

---

## app 作为组合根的职责

- 决定要启用哪些 adapters/transport/tls/platform
- 负责把 feature 映射到实际可用组件集合（并在编译期校验）
