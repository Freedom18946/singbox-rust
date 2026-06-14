<!-- tier: B -->
# post_fable_package13_http_inbound_plain_forward_parity

## Status

DONE.

## Source Findings

- F-3: package07 found that the HTTP inbound accepted CONNECT but returned
  405 for plain HTTP proxy forwarding. Go's HTTP/mixed inbound supports the
  basic absolute-form `http://` forward path.

## Objective

Close F-3 with a minimal parity patch: keep CONNECT behavior intact while
adding deterministic local plain HTTP GET forwarding through the existing
router and outbound registry path.

## Implementation Contract

- Support HTTP/1.x absolute-form GET requests such as
  `GET http://host[:port]/path?query HTTP/1.1`.
- Derive destination host and port from the absolute URI; default `http://`
  to port 80.
- Rewrite the upstream request line to origin-form before forwarding.
- Strip proxy-only headers before origin forwarding:
  `Proxy-Authorization` and `Proxy-Connection`.
- Reuse the same auth, router, outbound registry, health policy, conntrack,
  stats, and stop/lifecycle behavior as CONNECT.
- Reject unsupported methods with 405 and malformed or unsupported URI shapes
  with 400.

## Out Of Scope

- Request bodies and non-GET plain HTTP forwarding.
- HTTPS absolute-form forwarding; HTTPS remains CONNECT-only.
- Interactive Wails GUI E2E closure; package07 remains PARTIAL until a real
  desktop-window flow can be driven.

## Acceptance Criteria

- Plain HTTP GET via HTTP inbound reaches a local origin and returns 200.
- Origin observes origin-form path/query, not the absolute proxy URI.
- Proxy-only headers do not leak to origin.
- Basic proxy auth gates plain GET the same way it gates CONNECT.
- CONNECT regression remains green.
- Mixed inbound inherits the same plain forward support through its existing
  HTTP handler delegation.
- Required local gates pass.

## Tests / Verification

See `post_fable_package13_http_inbound_plain_forward_parity_evidence.md`.

## Completion Notes

DONE in package13.

- `crates/sb-adapters/src/inbound/http.rs` now routes CONNECT and plain
  absolute-form GET through shared proxy-auth, route/dial, and conntrack relay
  helpers.
- Plain GET rewrites to origin-form and strips `Proxy-Authorization` /
  `Proxy-Connection` before forwarding.
- `app/tests/inbound_http.rs` covers plain forward success, header stripping,
  Basic auth, CONNECT regression, and 400/405 rejection paths.
- `crates/sb-adapters/tests/e2e_proxy_flow.rs` covers mixed inbound plain GET
  delegation to the HTTP handler.
- package07 remains PARTIAL because interactive Wails desktop-window E2E is
  still blocked; only F-3 is closed here.
