# L5 Case Backlog

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

- restart/reload lifecycle replay.
- auth negative paths (wrong token / expired token).
- provider/rules/script/profile optional endpoints.
- fault injection matrix for upstream disconnect and jitter.

## P2 (later)

- full GUI desktop smoke through Wails bridge.
- high concurrency stress for `/connections` websocket.
- long-running soak with diff trend gates.
