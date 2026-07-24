<!-- tier: C -->
# VMESS-TLS-01 Acceptance

Status: IN PROGRESS

## Scope

Production VMess standard TLS parity with local Go sing-box 1.13.13 for raw TCP,
WebSocket, HTTPUpgrade, project yamux-outer composition, configuration failures,
and bidirectional live dataplane. REALITY, ECH, legacy alterId/CFB, canonical
`v1.mux.cool`, and full VMess packet/XUDP remain outside this line.

## Go Source Authority

- `go_fork_source/sing-box-1.13.13/protocol/vmess/{inbound,outbound}.go`
- `go_fork_source/sing-box-1.13.13/option/{vmess,tls}.go`
- `go_fork_source/sing-box-1.13.13/common/tls/{client,server,std_client,std_server}.go`
- `go_fork_source/sing-box-1.13.13/transport/v2ray/`

## Pre-fix Defect

Exact pre-fix command:

```text
cargo test -p app --features net_e2e --test vmess_tls_variants_e2e test_vmess_standard_tls -- --ignored --exact --nocapture
```

Result: 0 passed, 1 failed, 0 ignored, 4 filtered. rustls client received
`Connection reset by peer` because `start_vmess_tls_server(_tls_config)` ignored
TLS and started a plain VMess listener.

Source audit also confirmed production outbound set `VmessConfig.tls = None`,
transport TLS builders ignored their TLS argument, and production VMess inbound
had no TLS runtime dependency or termination.

## Go/Rust Contract

| Path or option | Go 1.13.13 authority | Rust VMESS-TLS-01 contract |
|---|---|---|
| inbound raw TCP | listener → TLS handshake → VMess | VMess adapter owns one prebuilt TLS acceptor; no sniff/fallback |
| outbound raw TCP | TCP dial → TLS handshake → VMess | VMess physical dialer owns one TLS client layer |
| inbound WS/HTTPUpgrade | V2Ray server transport owns TLS | transport owns TLS; raw accept loop must not wrap again |
| outbound WS/HTTPUpgrade | V2Ray client transport owns TLS | TCP → TLS → HTTP upgrade transport → VMess |
| TLS absent or `enabled=false` | TLS constructor returns nil | plain VMess; other TLS fields do not implicitly enable TLS |
| server name | explicit name, else server address | one central fallback; WS/HTTP Host never overwrites TLS name |
| `disable_sni` | suppress extension, retain verification name | rustls `enable_sni=false`; verification name unchanged |
| ALPN | ordered configured list | preserved into reusable client/server rustls config |
| TLS version | configured min/max | only supported 1.2/1.3 accepted; invalid/reversed range fails |
| server cert/key | inline list wins over path; both required | joined PEM inline wins; missing/read/parse/pair error before bind |
| custom CA | inline/path custom root pool | inline/path replaces built-in roots for Go-shaped VMess TLS |
| client cert/key | optional pair | pair required together; read/parse error during adapter build |
| `insecure` | client skips certificate verification | client-only; inbound use is rejected, never auto-generates a cert |
| multiplex | mux is above physical VMess dial path | project yamux remains outer to TLS physical connection; not Go mux |
| security `auto` with TLS | Go selects `zero` | pending VMess wire implementation/live proof |
| startup/reload/close | TLS config starts/closes with adapter | material read and rustls config built once; lifecycle proof pending |

## Config and TLS Lowering

Go-shaped typed inbound/outbound standard TLS IR is present behind strict Raw
bridges. VMess schema validation rejects unknown fields, missing server
certificate/key, invalid version ranges, inbound `insecure`, and incomplete
client identity. A single adapter lowering module converts IR to
`StandardTlsConfig`; shared transport builders load roots/identity/material,
apply ALPN/SNI/version policy, and return reusable rustls client/server configs.
No PEM or private-key content appears in errors.

## Evidence So Far

- ledger correction: `ce99c0a1ab4cd82c42a021d00f364b76a9b6d0ac`
- config focused tests: 7 passed, 0 failed, 0 ignored
- shared TLS focused tests: 12 passed, 0 failed, 0 ignored
- adapter TLS-lowering focused tests: 4 passed, 0 failed, 0 ignored

Remaining sections—live matrices, strict interop IDs, Linux verdict, full gates,
inventory accounting, and complete commit list—will be filled only from final
mechanical evidence.
