# Crate 结构分析（Crate Structure Analysis）

> **更新方式**：运行分析脚本后更新

---

## sb-core 结构

**文件数**：441（需详细分析）

```
crates/sb-core/
├── src/
│   ├── router/        # 路由引擎 - 保留
│   ├── dns/           # DNS 系统 - 保留
│   ├── inbound/       # 入站管理 - 需评估
│   ├── outbound/      # 出站管理 - 需评估
│   ├── endpoint/      # 端点 - 需评估
│   ├── services/      # 服务 - 需移出
│   └── ...
└── Cargo.toml
```

**待分析**：
- [ ] 各子目录代码行数
- [ ] 各子目录依赖情况
- [ ] 识别需要移出的代码

---

## sb-adapters 结构

**文件数**：109

```
crates/sb-adapters/
├── src/
│   ├── inbound/       # 入站协议
│   ├── outbound/      # 出站协议
│   └── service/       # 服务实现
└── Cargo.toml
```

**待分析**：
- [ ] 对 sb-core 的依赖点
- [ ] 共享契约识别

---

## 其他 Crates

| Crate | 文件数 | 状态 |
|-------|-------|------|
| sb-config | 56 | ⬜ 待分析 |
| sb-transport | 57 | ⬜ 待分析 |
| sb-api | 29 | ⬜ 待分析 |
| sb-tls | 21 | ⬜ 待分析 |
| sb-platform | 22 | ⬜ 待分析 |
| sb-runtime | 17 | ⬜ 待分析 |
| sb-metrics | 9 | ⬜ 待分析 |
| sb-types | 10 | ⬜ 待分析 |
| sb-common | 10 | ⬜ 待分析 |
| sb-security | 5 | ⬜ 待分析 |
| sb-proto | 9 | ⬜ 待分析 |
| sb-subscribe | 24 | ⬜ 待分析 |
| sb-test-utils | 4 | ⬜ 待分析 |
| sb-admin-contract | 2 | ⬜ 待分析 |
