<!-- tier: B -->
# post_fable_package13_http_inbound_plain_forward_parity_evidence

## Scope

Package13 closes package07/F-3 only. It adds basic plain HTTP proxy forwarding
for absolute-form GET requests while preserving CONNECT behavior and the
existing router/outbound registry path. It does not claim interactive GUI E2E
readiness.

## Implementation Evidence

| Area | Evidence |
|---|---|
| CONNECT preservation | CONNECT still uses the same response and bidirectional tunnel path after shared helper extraction. |
| Plain GET support | `GET http://host[:port]/path?query HTTP/1.1` is parsed with the existing `url` dependency and defaults `http://` to port 80. |
| Origin rewrite | Forwarded request head is rewritten to `GET /path?query HTTP/1.1`. |
| Header hygiene | `Proxy-Authorization` and `Proxy-Connection` are stripped before the origin write. |
| Routing discipline | Plain GET and CONNECT both use shared route/dial helpers with router decision, outbound registry, health fallback policy, conntrack, and stats wiring. |
| Failure behavior | Relative-form GET and unsupported schemes return 400; unsupported non-CONNECT methods return 405. |
| Mixed inbound | Mixed inbound continues to delegate HTTP-like traffic to `http::serve_conn`; the new e2e test covers plain GET through mixed. |

## Verification Results

| Command | Result |
|---|---|
| `cargo test -p sb-adapters --lib http --features "http,socks"` | PASS: 7 passed. |
| `cargo test -p sb-adapters --test e2e_proxy_flow --features "http,socks"` | PASS: 5 passed, including mixed plain HTTP forward. |
| `cargo test -p app --test inbound_http --features adapters,clash_api` | PASS: 6 passed, including plain GET/header/auth/rejection coverage. |
| `cargo test -p app --lib --features adapters,clash_api,v2ray_api` | PASS: 184 passed. |
| `cargo check --workspace --all-features` | PASS. |
| `cargo clippy --workspace --all-features --all-targets` | PASS, no warnings in final run. |
| `git diff --check` | PASS. |

## Residual Limits

- Plain forward support is intentionally scoped to HTTP/1.x GET without request
  bodies.
- HTTPS remains CONNECT-only; `https://` absolute-form GET is rejected with 400.
- Package07 is still PARTIAL because the Wails desktop-window interactive E2E
  remains blocked.
