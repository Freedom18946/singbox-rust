# CLASH-API-AUDIT.md — WP-L2.1 Clash API 对接审计报告

> 生成时间: 2026-02-08
> 修复完成: 2026-02-08
> 基于: Go sing-box 1.12.14 · GUI.for.SingBox 1.19.0 · singbox-rust (main HEAD)
> 方法: 逐端点读取 Go/GUI/Rust 源码，提取 JSON schema 并交叉对比
> **状态: ✅ 全部 18 项已修复 (P0×8 + P1×7 + P2×3)**

---

## 分级定义

| 级别 | 含义 | GUI 影响 |
|------|------|----------|
| **BREAK** | 字段缺失或语义不兼容，GUI 功能直接崩溃或显示错误 | 必须修复 |
| **DEGRADE** | 响应格式偏差，GUI 可运行但行为退化 | 应修复 |
| **COSMETIC** | 多余字段或微小格式差异，GUI 不受影响 | 可忽略 |
| **EXTRA** | Rust 返回了 Go 不存在的额外字段/端点 | 评估是否保留 |

---

## 统计汇总

| 级别 | 数量 | 已修复 | 保留/忽略 |
|------|------|--------|-----------|
| BREAK | 12 | ✅ 12 | 0 |
| DEGRADE | 5 | ✅ 5 | 0 |
| COSMETIC | 6 | ✅ 1 (C06) | 5 (不影响 GUI) |
| EXTRA | 4 | — | 4 (保留，无害) |

---

## BREAK 级偏差 (12) — ✅ 全部已修复

### B01 — GET /configs 缺少顶层 `mode` 字段 — ✅ P0 已修复

Config struct 重写为与 Go configSchema 1:1 对齐。新增 `mode`(顶层)、`mode-list`、`allow-lan`、`bind-address`、`log-level`、`ipv6`、`tun`、`redir-port`、`tproxy-port`。移除 `controller-port`、`external-controller`、`extra` HashMap。`allow-lan` 从 ConfigIR inbound listen 地址推断，`tun` 从 ConfigIR inbound 类型提取。

---

### B02 — GET /configs 缺少 `mode-list` 字段 — ✅ P0 已修复 (随 B01)

Config struct 含 `mode_list: Vec<String>`，默认 `["rule", "global", "direct"]`。

---

### B03 — GET /proxies 缺少 `udp` 字段 — ✅ P0 已修复

Proxy struct 新增 `pub udp: bool`，所有 outbound 默认 `true`（REJECT 为 `false`）。

---

### B04 — GET /proxies 缺少 `history` 数组 — ✅ P0 已修复

Proxy struct 新增 `pub history: Vec<DelayHistory>`。新增 `DelayHistory { time: String, delay: u16 }` struct。当前返回空数组 `[]`，后续可接入 URLTestHistoryStorage 填充。

---

### B05 — GET /proxies 缺少 GLOBAL 虚拟组 — ✅ P0 已修复

`get_proxies` handler 注入 GLOBAL Fallback 虚拟组，`all` 包含所有非 Direct/Reject/DNS 的 outbound tags，`now` 为首个可用 tag。

---

### B06 — GET /proxies/:name 无独立 GET 路由 — ✅ P1 已修复

新增 `get_proxy` handler，返回单个 proxy 的 proxyInfo（含 udp/history/all/now）。路由从 `put(select_proxy)` 改为 `get(get_proxy).put(select_proxy)`。

---

### B07 — GET /proxies/:name/delay 使用 TCP connect 而非 HTTP URL test — ✅ P1 已修复

`measure_outbound_delay` (TCP connect) → `http_url_test` (完整 HTTP/1.1 GET + 读取响应)。新增 `parse_url_components` 解析 URL 的 host/port/path。超时返回 504 Gateway Timeout，连接失败返回 503 Service Unavailable，成功返回 `{"delay": N}`。

---

### B08 — GET /connections 缺少 `downloadTotal` / `uploadTotal` / `memory` — ✅ P0 已修复

`get_connections` 返回完整 Snapshot 格式 `{downloadTotal, uploadTotal, connections, memory}`。totals 从当前连接累加，memory 使用真实进程内存。

---

### B09 — GET / (根路径) 响应格式不匹配 — ✅ P0 已修复

根端点返回 `{"hello": "clash"}`。

---

### B10 — GET /meta/group 响应格式错误 — ✅ P1 已修复

从 `{"groups": {map}}` 改为 `{"proxies": [array]}`，只包含 OutboundGroup 类型（Selector），使用 proxyInfo 格式。

---

### B11 — GET /meta/group/:name/delay 只测单节点 — ✅ P1 已修复

遍历 group 所有成员，并发 HTTP URL test，返回 `{tag1: delay1, tag2: delay2}` map 格式。

---

### B12 — GET /memory (WS) 硬编码假数据且非 WebSocket — ✅ P2 已修复

实现双模式端点：WS 请求升级为 WebSocket 每秒推送 `{"inuse": N, "oslimit": 0}`（首次 inuse=0），HTTP 请求返回当前快照。真实内存使用 Linux `/proc/self/statm`。移除硬编码假数据。

---

## DEGRADE 级偏差 (5) — ✅ 全部已修复

### D01 — PATCH /configs 返回 200+JSON 而非 204 NoContent — ✅ P0 已修复

成功时返回 `StatusCode::NO_CONTENT`。只处理 `mode` 字段（与 Go 一致）。

---

### D02 — PUT /configs 过严验证 — ✅ P1 已修复

与 Go 对齐，直接返回 204 NoContent（no-op）。移除所有验证逻辑。

---

### D03 — DELETE /connections 返回 JSON 而非 204 — ✅ P1 已修复

返回 `StatusCode::NO_CONTENT`。

---

### D04 — GET /version `premium` 字段为 `false` — ✅ P0 已修复

`premium` 改为 `true`，`version` 格式改为 `"sing-box X.Y.Z"`。

---

### D05 — GET /proxies/:name/delay 返回额外 `meanDelay` 字段 — ✅ P1 已修复

移除 `meanDelay`，仅返回 `{"delay": N}`。

---

## COSMETIC 级偏差 (6) — 1 已修复，5 保留

### C01 — DELETE /connections/:id 找不到时返回 404 — 保留

Go 无论是否找到都返回 204，Rust 未找到返回 404。GUI 不检查 DELETE 响应码，无影响。

---

### C02 — GET /traffic WS 多余字段 — 保留

Rust 额外返回 `upSpeed`, `downSpeed`, `timestamp`。GUI 只读 `up` 和 `down`，多余字段无影响。

---

### C03 — GET /logs WS 多余字段 — 保留

Rust 额外返回 `timestamp`, `source`, `connection_id`。GUI 只读 `type` 和 `payload`，无影响。

---

### C04 — GET /rules 多余 `order` 字段 — 保留

Rust 额外返回 `order`。无影响。

---

### C05 — Proxy `alive` 字段类型 — 保留

Go 无 `alive`，Rust 有 `alive: Option<bool>`。GUI 声明但未使用，无影响。

---

### C06 — 错误响应格式 — ✅ P2 已修复

全部 14 处 `{"error": "...", "message": "..."}` 统一为 `{"message": "..."}`（与 Go HTTPError struct 一致）。

---

## EXTRA 级偏差 (4) — 全部保留

### E01 — Rust `Proxy` struct 有 `delay` 顶层字段 — 保留

便捷字段，`skip_serializing_if = "Option::is_none"`，不影响兼容。

---

### E02 — Rust ConnectionMetadata 多余字段 — 保留

GUI 不读取这些字段。保留无害。

---

### E03 — Rust GET /meta/memory 多余字段 `sys`, `gc` — 已随 B12 移除

B12 修复后 HTTP 响应仅返回 `{inuse, oslimit}`，不再有 `sys`/`gc`。

---

### E04 — Rust GET /ui 返回 JSON 而非文件服务/重定向 — 保留

低优先级，singbox-rust 暂不实现内嵌 UI 文件服务。

---

## 修复执行记录

### P0 — GUI 硬依赖 ✅ 全部完成

| # | 偏差 | 修改文件 | 状态 |
|---|------|----------|------|
| 1 | B01 GET /configs schema 重写 | `types.rs`, `handlers.rs` | ✅ |
| 2 | B03 proxies 缺 `udp` | `types.rs`, `handlers.rs` | ✅ |
| 3 | B04 proxies 缺 `history` | `types.rs`, `handlers.rs` | ✅ |
| 4 | B05 proxies 缺 GLOBAL | `handlers.rs` | ✅ |
| 5 | B08 connections 缺 totals | `handlers.rs` | ✅ |
| 6 | B09 根路径 hello | `handlers.rs` | ✅ |
| 7 | D01 PATCH /configs 返回 204 | `handlers.rs` | ✅ |
| 8 | D04 version premium:true | `handlers.rs` | ✅ |

### P1 — 功能正确性 ✅ 全部完成

| # | 偏差 | 修改文件 | 状态 |
|---|------|----------|------|
| 9 | B07 delay HTTP URL test | `handlers.rs` | ✅ |
| 10 | B06 GET /proxies/:name 路由 | `server.rs`, `handlers.rs` | ✅ |
| 11 | B10 meta/group 格式 | `handlers.rs` | ✅ |
| 12 | B11 group delay 并发测试 | `handlers.rs` | ✅ |
| 13 | D02 PUT /configs 去验证 | `handlers.rs` | ✅ |
| 14 | D03 DELETE /connections 204 | `handlers.rs` | ✅ |
| 15 | D05 去 meanDelay | `handlers.rs` | ✅ |

### P2 — 完整性 ✅ 全部完成

| # | 偏差 | 修改文件 | 状态 |
|---|------|----------|------|
| 16 | B02 mode-list | `types.rs`, `handlers.rs` | ✅ (随 B01) |
| 17 | B12 memory WS 端点 | `websocket.rs`, `handlers.rs` | ✅ |
| 18 | C06 错误格式对齐 | `handlers.rs` | ✅ |

---

## 附录 A: Go configSchema 完整字段参考

```go
// configs.go:20-34
type configSchema struct {
    Port        int            `json:"port"`
    SocksPort   int            `json:"socks-port"`
    RedirPort   int            `json:"redir-port"`
    TProxyPort  int            `json:"tproxy-port"`
    MixedPort   int            `json:"mixed-port"`
    AllowLan    bool           `json:"allow-lan"`
    BindAddress string         `json:"bind-address"`
    Mode        string         `json:"mode"`
    ModeList    []string       `json:"mode-list"`
    LogLevel    string         `json:"log-level"`
    IPv6        bool           `json:"ipv6"`
    Tun         map[string]any `json:"tun"`
}
```

## 附录 B: Go proxyInfo() 完整字段参考

```go
// proxies.go:61-84
func proxyInfo(server *Server, detour adapter.Outbound) *badjson.JSONObject {
    var info badjson.JSONObject
    clashType := C.ProxyDisplayName(detour.Type())  // Block → "Reject"
    info.Put("type", clashType)
    info.Put("name", detour.Tag())
    info.Put("udp", common.Contains(detour.Network(), N.NetworkUDP))
    delayHistory := server.urlTestHistory.LoadURLTestHistory(...)
    info.Put("history", []*adapter.URLTestHistory{...})  // 始终为数组
    if group, isGroup := detour.(adapter.OutboundGroup); isGroup {
        info.Put("now", group.Now())
        info.Put("all", group.All())
    }
    return &info
}
```

## 附录 C: Go Snapshot (connections) 完整字段参考

```go
// manager.go:123-130
func (s *Snapshot) MarshalJSON() ([]byte, error) {
    return json.Marshal(map[string]any{
        "downloadTotal": s.Download,
        "uploadTotal":   s.Upload,
        "connections":   common.Map(s.Connections, ...),
        "memory":        s.Memory,
    })
}
```

## 附录 D: Go TrackerMetadata (单连接) 完整字段参考

```go
// tracker.go:67-87
json.Marshal(map[string]any{
    "id":       t.ID,
    "metadata": map[string]any{
        "network":         t.Metadata.Network,
        "type":            inbound,           // "inboundType/inboundTag"
        "sourceIP":        t.Metadata.Source.Addr,
        "destinationIP":   t.Metadata.Destination.Addr,
        "sourcePort":      F.ToString(t.Metadata.Source.Port),
        "destinationPort": F.ToString(t.Metadata.Destination.Port),
        "host":            domain,
        "dnsMode":         "normal",
        "processPath":     processPath,
    },
    "upload":      t.Upload.Load(),
    "download":    t.Download.Load(),
    "start":       t.CreatedAt,              // time.Time → ISO 8601
    "chains":      t.Chain,
    "rule":        rule,                     // "ruleString => action" 或 "final"
    "rulePayload": "",
})
```

## 附录 E: GUI kernel.d.ts 完整类型参考

```typescript
interface CoreApiConfig {
  port: number
  'socks-port': number
  'mixed-port': number
  'interface-name': string
  'allow-lan': boolean
  mode: string
  tun: { enable: boolean; stack: string; device: string }
}

interface CoreApiProxy {
  alive: boolean
  all: string[]
  name: string
  now: string
  type: string
  udp: boolean
  history: { delay: number }[]
}

interface CoreApiConnectionsData {
  memory: number
  uploadTotal: number
  downloadTotal: number
  connections: {
    chains: string[]
    download: number
    id: string
    metadata: {
      destinationIP: string
      destinationPort: string
      dnsMode: string
      host: string
      network: string
      processPath: string
      sourceIP: string
      sourcePort: string
      type: string
    }
    rule: string
    rulePayload: string
    start: string
    upload: number
  }[]
}

interface CoreApiTrafficData { down: number; up: number }
interface CoreApiMemoryData  { inuse: number; oslimit: number }
interface CoreApiLogsData    { type: string; payload: string }
```

---

*End of audit report — all actionable deviations resolved*
