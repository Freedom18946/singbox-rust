# L5 Case Backlog

联测执行基线与实战流程见：`labs/interop-lab/docs/REALWORLD-TEST-PLAN.md`。

## P0 (gating)

| Case ID | Goal | Status |
| --- | --- | --- |
| `l6_local_harness_smoke` | self-contained harness smoke (no external kernel) | implemented |
| `p0_clash_api_contract` | replay GUI P0 HTTP/WS contract against Go+Rust APIs | implemented (needs env endpoints) |
| `p0_subscription_json` | JSON `outbounds` parser | implemented |
| `p0_subscription_yaml` | YAML `proxies` parser | implemented |
| `p0_subscription_base64` | Base64 mixed-link parser | implemented |

备注（2026-02-10）：实网订阅 URL 采样显示，标准 Clash 订阅可解析；部分 URL 因站点风控/人机检测返回挑战页，标记为环境限制，不作为当前阻塞项。

## P1 (next)

- `p1_rust_core_http_via_socks`: 本地仿公网 HTTP echo，经 Rust SOCKS 入站转发验证核心链路（implemented）。
- `p1_subscription_file_urls`: 使用维护中的订阅文件批量解析（implemented）。
- restart/reload lifecycle replay.
- auth negative paths (wrong token / expired token).
- provider/rules/script/profile optional endpoints.
- fault injection matrix for upstream disconnect and jitter.

## P2 (later)

- full GUI desktop smoke through Wails bridge.
- high concurrency stress for `/connections` websocket.
- long-running soak with diff trend gates.
