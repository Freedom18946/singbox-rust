# 01 - 术语表（Glossary）

- **数据面（Data Plane）**：处理真实流量转发的部分（入站/路由/出站/传输/DNS）。
- **控制面（Control Plane）**：管理/配置/诊断/API/观测导出等（不直接参与流量转发）。
- **Ports（端口/契约）**：sb-core 依赖的抽象接口（Rust trait），由适配器/基础设施层实现。
- **Adapters（适配器）**：把外部协议/系统能力接入 Ports 的实现层（Inbound/Outbound 协议、平台服务）。
- **IR（Intermediate Representation）**：配置编译后的中间表示（验证/归一/预计算后可直接执行）。
- **Hot Path（热路径）**：每个连接/每个包都会走的路径，任何额外开销都会被放大。
- **Object-safe trait**：可以用 `dyn Trait` 的 trait；通常要求方法不返回 `impl Trait`、不含泛型等。
- **RPITIT/Async fn in traits**：Rust 支持在 trait 中声明 `async fn` 的能力；但并不自动支持 `dyn Trait`（object safety 仍是约束）。
