<!-- tier: B -->
# Clash API Strict-Parity Audit

Scope: `DIV-M-001..012`, Go `sing-box-1.13.13` versus Rust current main.

Status: **CLOSED** (2026-07-23). Final live evidence:
`agents-only/archive/clash_api_strict_parity/acceptance.md`.

| DIV | Decision | Evidence and rationale |
|---|---|---|
| DIV-M-001 | FIX | Go `experimental/clashapi/cache.go:16` registers `POST /fakeip/flush` and returns 204. Rust registered `DELETE` and returned a JSON 200. |
| DIV-M-002 | KEEP | Go log frames contain only `type` and `payload` (`experimental/clashapi/server.go:358-365,410-418`). Rust adds timestamp/source and a local welcome/heartbeat stream. Additive metadata is retained for existing GUI behavior; no HTTP strict case depends on log body. |
| DIV-M-003 | KEEP | Grace duration is process shutdown behavior, not Clash API wire state. Go's 30s constant is not observable through the control-plane contract. |
| DIV-M-004 | FIX | Go `connections.go:42-76` parses `?interval=` and uses it for ticker cadence. Rust hard-coded one-second ticker in `clash/websocket.rs:113`. |
| DIV-M-005 | FIX | Go `dns.go:38-86` returns DNS-message fields (`Status`, `Question`, `Answer`, `Server`, flags). Rust returned `{name,type,addresses,ttl}` from `handlers.rs:1645-1730`. |
| DIV-M-006 | FIX | Go `configs.go:19-51` emits the configured/stored mode verbatim with zero port fields, no `interface-name`, and nullable `tun`. Rust now calculates the mode-list from nested route/DNS rules in Go ordering; strict Rust/Go fixtures use lowercase `default_mode`, matching GUI's lowercase enum. |
| DIV-M-007 | FIX | Go `proxies.go:51-137` emits only `type/name/udp/history` plus group `all/now`; Rust added `alive/delay` fields. Rust must serialize the Go wire projection while preserving internal convenience fields. |
| DIV-M-008 | KEEP | Go reports runtime heap while Rust reports process RSS on macOS. Platform-dependent metrics cannot be strict wire identity. Connection strict comparison uses the connection dimension; the peak ratio stays strict on Linux and is explicitly recorded as ignored off Linux. |
| DIV-M-009 | KEEP | Go and Rust perform real network delay probes. Exact milliseconds are timing-sensitive; status/shape remains covered by existing assertions. |
| DIV-M-010 | KEEP | Registry explicitly classifies Rust 500 versus Go synthetic fake-IP 200 for unresolvable names as intentional design divergence. Do not adopt Go fake-answer behavior. |
| DIV-M-011 | FIX | Go `trafficontrol/manager.go:39-103` accumulates upload/download totals across `Leave`. Rust `ConnTracker` already has equivalent unregister accumulation (`conntrack.rs:228-281`); strict case will prove totals survive connection close. |
| DIV-M-012 | FIX | Go `fakeip.Store.Reset` (`dns/transport/fakeip/store.go:159-161`) resets storage mappings only; current allocation pointers remain. Rust reset rewound both pointers in `dns/fakeip.rs:285-301` and cleared persisted metadata. Preserve pointers while clearing mappings. |

## Strict promotion mapping

Initial unlock hypothesis was rejected during S3/S6 audit: all mapped behaviors already had strict
both-kernel cases and were already credited. The closeout resolves S4 entries
`M-001/M-004/M-005/M-006/M-007/M-011/M-012` without changing the coverage numerator.
`M-002/M-003/M-008/M-009/M-010` remain explicit accepted divergences.
