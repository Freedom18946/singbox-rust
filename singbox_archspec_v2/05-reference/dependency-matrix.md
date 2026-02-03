# 依赖矩阵（摘要）

| crate | 允许依赖 | 禁止依赖（示例） |
|------|----------|------------------|
| sb-types | std, thiserror, serde(可选) | tokio, axum, tonic, rustls, quinn |
| sb-core | sb-types, sb-common, tokio(sync/time) | 协议实现、平台服务、Web/TLS/QUIC 大库 |
| sb-adapters | sb-types, sb-config(IR), sb-transport/tls/platform | sb-core（禁止反向） |
| sb-transport | tokio(net/io), rustls/quinn(可选) | sb-core, sb-api |
| sb-platform | OS 相关 crate | sb-core 路由策略、协议实现 |
| sb-api | axum/tonic, sb-core(AdminPort) | sb-adapters |
| app | 全部（组合根） | 无（但需遵守 feature 策略） |
