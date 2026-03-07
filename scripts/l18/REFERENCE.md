# L18 外部依赖参考（Go Kernel / GUI.for.SingBox）

> 单页速查。Go 1.12.14 + GUI 1.19.0 锁定版本，不主动升级。

---

## 1. Go↔Rust Config 字段对照

| 用途 | Go 字段 | Rust 字段 | 示例值 |
|------|---------|-----------|--------|
| 组件标识 | `tag` | `name` | `"socks-in"` |
| 监听端口 | `listen_port` | `port` | `11810` / `11811` |
| Clash API 地址 | `external_controller` | `external_controller` | Go:`127.0.0.1:9090` Rust:`127.0.0.1:19090` |
| Clash API 密钥 | `secret` | `secret` | `"test-secret"` |
| 默认路由 | `route.final` | `route.final` | `"my-group"` / `"direct"` |
| 出站选择器 | `outbounds[].default` | `outbounds[].default` | `"direct"` |
| 日志级别 | `log.level` | `log.level` | `"warn"` |

### L18 固定端口分配

| 角色 | Go | Rust | 用途 |
|------|-----|------|------|
| Clash API | `9090` | `19090` | GUI 管控 + API 回放 |
| SOCKS inbound | `11811` | `11810` | 代理功能验证 |
| Canary API | — | `29090` | capstone canary 运行时 |

---

## 2. GUI 依赖的 Clash API 最小集合

来源：`GUI_fork_source/GUI.for.SingBox-1.19.0/frontend/src/api/kernel.ts`

### HTTP 端点

| Method | Path | 用途 | L18 认证覆盖 |
|--------|------|------|-------------|
| `GET` | `/proxies` | 列出代理组和成员 | gui_smoke 五步流 |
| `PUT` | `/proxies/{group}` | 切换活跃代理 | switch_proxy 步骤 |
| `GET` | `/proxies/{name}/delay` | 延迟测试 | 非阻断 |
| `GET` | `/configs` | 获取运行时配置 | startup 步骤 |
| `PATCH` | `/configs` | 更新模式（body: `{"mode":"rule"}`) | 非阻断 |
| `GET` | `/connections` | 列出活跃连接 | connections_panel 步骤 |
| `DELETE` | `/connections/{id}` | 关闭单个连接 | 非阻断 |

### WebSocket 端点

| Path | 查询参数 | 用途 | L18 认证覆盖 |
|------|----------|------|-------------|
| `/traffic` | `?token={secret}` | 实时流量（`{up, down}`） | gui_smoke |
| `/memory` | `?token={secret}` | 实时内存（`{inuse, oslimit}`） | gui_smoke |
| `/connections` | `?token={secret}` | 实时连接列表 | connections_panel |
| `/logs` | `?token={secret}&level=debug` | 实时日志流 | logs_panel |

### 认证方式

- **HTTP**: `Authorization: Bearer {secret}` 请求头
- **WebSocket**: `?token={secret}` 查询参数（非请求头）

### GUI 不使用的端点

`/providers`、`/rules`、`/dns`、`/version`、`/cache`、`/upgrade` — 均不调用。

---

## 3. Go Oracle 构建参数基线

```bash
# 标准构建（L18 使用）
cd go_fork_source/sing-box-1.12.14
go build -tags with_clash_api -ldflags "-s -w" -o sing-box ./cmd/sing-box

# 验证
./sing-box version
# 预期输出包含: Tags: with_clash_api
```

| 参数 | 值 | 说明 |
|------|-----|------|
| build tags | `with_clash_api` | 启用 Clash API，GUI 必需 |
| ldflags | `-s -w` | 去符号表+调试信息，减小体积 |
| CGO | enabled（默认） | macOS 需要 |
| 入口 | `./cmd/sing-box` | sing-box CLI 入口 |
| 产物 | `sing-box`（~18MB arm64） | |

### 脚本引用

```bash
# 自动化构建（带 manifest + run-id）
scripts/l18/build_go_oracle.sh \
  --go-source-dir go_fork_source/sing-box-1.12.14 \
  --build-tags with_clash_api
```

---

## 4. GUI 构建参数基线

```bash
# 安装 wails（首次）
go install github.com/wailsapp/wails/v2/cmd/wails@latest

# 构建
cd GUI_fork_source/GUI.for.SingBox-1.19.0
wails build -clean
```

| 参数 | 值 | 说明 |
|------|-----|------|
| wails 版本 | v2.11.0 | |
| 前端包管理 | pnpm | wails.json 配置 |
| 构建模式 | production | |
| 产物路径 | `build/bin/GUI.for.SingBox.app` | macOS .app 包 |
| 产物大小 | ~13MB arm64 | |
| 进程名 | `GUI.for.SingBox` | L18 脚本用于进程检测 |
