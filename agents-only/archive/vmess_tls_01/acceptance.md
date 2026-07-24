<!-- tier: C -->
# VMESS-TLS-01 Acceptance

Status: CLOSED (2026-07-24)

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
| security `auto` with TLS | Go selects `zero` | SECURITY_NONE request byte, option=0, raw TCP body after protected AEAD headers |
| startup/reload/close | TLS config starts/closes with adapter | material is parsed before bind; acceptor is reused; readiness and graceful close are live-tested |

## Config and TLS Lowering

Go-shaped typed inbound/outbound standard TLS IR is present behind strict Raw
bridges. VMess schema validation rejects unknown fields, missing server
certificate/key, invalid version ranges, inbound `insecure`, and incomplete
client identity. A single adapter lowering module converts IR to
`StandardTlsConfig`; shared transport builders load roots/identity/material,
apply ALPN/SNI/version policy, and return reusable rustls client/server configs.
No PEM or private-key content appears in errors.

## Outbound TLS Closure

Production registry construction now lowers VMess outbound TLS instead of
hard-coding `None`; unknown security names produce an invalid-config connector.
The shared transport chain is TCP → standard TLS → WebSocket/HTTPUpgrade when
present → project yamux. Requested features/configuration failures return errors
and never fall back to plain TCP. TLS client config carries server name,
verification roots/insecure mode, ALPN, and protocol-version bounds; the
connector timeout bounds TCP plus TLS plus transport establishment.

Go `sing-vmess` v0.2.8 source and live Go 1.13.13 interop confirmed that both
`none` and `zero` encode SECURITY_NONE (5), TCP option 0, and an unframed body
inside TLS while keeping AEAD request/response headers. Rust implements that
mode without changing AES-128-GCM or ChaCha20-Poly1305. Plain `auto` remains AES
on this architecture; TLS `auto` selects zero.

## Inbound Raw-TCP TLS Closure

The primary production path is `app run` → supervisor → bridge → canonical
adapter registry. `InboundTlsOptionsIR` now survives that bridge as a typed
dependency. The VMess registry builder lowers it and constructs a reusable
`TlsAcceptor` before the listener can report ready. The compatibility starter
was audited and wired too; malformed certificate/key input refuses startup in
both paths instead of producing a plain listener.

The VMess accept loop owns TLS when no V2Ray application transport is configured.
Each accepted socket receives one bounded server handshake before project yamux
or canonical VMess parsing.
Handshake failure records a VMess inbound error and closes that connection;
there is no plaintext retry or parser probe. Successful handshakes log only
negotiated ALPN/version metadata. Private-key and PEM contents are not logged.
When WebSocket or HTTPUpgrade is configured, one layered listener performs
TCP → TLS → application-transport handshakes before VMess parsing. It rejects
unsupported or multiple application transports rather than falling back to raw
TCP. gRPC plus TLS remains explicit unsupported configuration.

Production live testing exposed and fixed a separate startup defect:
`VmessInboundAdapter::serve` called `tokio::runtime::Handle::current()` from the
supervisor's dedicated inbound thread, which has no Tokio reactor. The adapter
now owns a current-thread runtime, reports readiness only after bind, accepts
shutdown through the existing driver channel, and exits cleanly on app SIGTERM.

## V2Ray Transport and Multiplex Closure

Go 1.13.13 source and live testing fixed transport ownership at the physical
connection. Outbound construction lowers TLS once, builds one client config,
then wraps TCP with TLS before WebSocket/HTTPUpgrade. Inbound construction
lowers TLS once, builds one reusable acceptor before bind, then performs TLS
before the application handshake. Neither direction performs a second TLS
handshake or retries plaintext.

WebSocket `Host` and HTTPUpgrade `host` are HTTP routing values, distinct from
TLS `server_name`. Explicit HTTP host wins; HTTPUpgrade alone uses Go's TLS
server-name fallback before socket authority. Both HTTP transports install
Go's `http/1.1` ALPN default only when user ALPN is empty. HTTPUpgrade follows Go's
HTTP/1.1 upgrade wire, rejects real WebSocket keys, validates method/path/host,
and preserves early bytes already buffered after the header delimiter.
WebSocket's stream adapter now flushes pending frames from `poll_write`, fixing
a live data stall hidden by handshake-only tests.

Project multiplex remains yamux-outer rather than canonical Go
`v1.mux.cool`. Its physical order is TCP → verified TLS → yamux, with canonical
VMess run independently on each substream. A counting proxy proves four logical
streams reuse exactly one TLS connection; a non-mux attempt neither echoes nor
falls back to plaintext.

## Composition Matrix

| Composition | Go supports? | Rust config parses? | Rust production builds? | Rust→Go live? | Go→Rust live? | Strict test? | Explicit non-goal? |
|---|---:|---:|---:|---:|---:|---:|---:|
| raw TCP | yes | yes | yes | yes | yes | `p2_vmess_dual_dataplane_local` | no |
| raw TCP + TLS | yes | yes | yes | yes | yes | `p2_vmess_tls_dual_dataplane_local` | no |
| WebSocket | yes | yes | yes | yes | yes | bidirectional live E2E | no |
| WebSocket + TLS | yes | yes | yes | yes | yes | bidirectional live E2E | no |
| HTTPUpgrade | yes | yes | yes | yes | yes | bidirectional live E2E | no |
| HTTPUpgrade + TLS | yes | yes | yes | yes | yes | bidirectional live E2E | no |
| TLS + project yamux | no | yes | yes | Rust↔Rust | Rust↔Rust | local live E2E | canonical `v1.mux.cool` |

## Strict Local TLS Regression Closure

`app/tests/vmess_tls_variants_e2e.rs` no longer contains five ignored
standard-TLS cases, bind-error skips, fixed readiness sleeps, fake REALITY/ECH
E2E labels, or error-is-acceptable passes. Nine unignored tests build a local
ephemeral CA/leaf in memory and exercise production VMess accept/connect paths
with bounded readiness, I/O, handshakes, and teardown.

Positive coverage proves verified standard TLS, negotiated ALPN, negotiated
TLS 1.2/1.3, project yamux, and byte-exact 1-byte through 32-KiB-plus payloads.
Negative coverage proves untrusted CA, wrong name, expired/not-yet-valid leaf,
missing key, malformed PEM, no common TLS version, Go-equivalent ALPN
no-overlap rejection, plain-to-TLS, TLS-to-plain, wrong UUID after TLS,
handshake timeout, and peer close during handshake. Direct rustls pairs expose
negotiated ALPN/version and certificate errors; identical configurations
separately traverse real VMess dataplanes.

Stress exposed a production cancellation bug: VMess `accept()` contains the
TLS/HTTP transport handshake but was recreated inside `select!`. The
immediately-ready heartbeat, and later task reaping, could drop that future
after TCP accept and reset a valid TLS client. The heartbeat is removed; one
pinned accept future now survives task-reap branches. Connection and mux-stream
tasks are tracked and aborted/drained on shutdown. Final 16-thread full-binary
stress: 20 rounds, 180 passed, 0 failed, 0 ignored.

## Strict Dual-Kernel Production Closure

`p2_vmess_tls_dual_dataplane_local` is `kernel_mode: both`, `env_class: strict`.
Its Rust snapshot starts the production Rust VMess+TLS server and a production
Go client; its Go snapshot starts the production Go server and a production
Rust client. Both clients expose a local SOCKS5 inbound, so the same harness
traffic crosses opposite implementations rather than talking to an in-process
protocol stub.

Server and client configs require TLS 1.3, SNI `anytls.local`, ALPN `h2`, and
the committed local self-signed CA fixture. Positive traffic sends a
deterministic 32 KiB payload through SOCKS5 and requires byte count and SHA-256
equality. Separate route targets select wrong-UUID and wrong-SNI outbounds;
both must fail. Generic kernel-specific background-command selection and
bounded TCP readiness polling contain no VMess special case. Harness cleanup
terminates and waits for crossed clients; kernel teardown remains bounded.

An initial harness draft using Go `tools connect` was rejected: that CLI closes
the connection when finite stdin reaches EOF and can exit zero before the
download goroutine returns, so it cannot prove request/echo round trips.
Acceptance uses long-lived production clients and harness-owned SOCKS5 traffic
instead.

Twenty consecutive post-fix runs passed both snapshots. Every per-run
normalized diff was `clean=true`, `traffic_mismatches=0`, and `gate_score=0`:

| Round | Run ID |
|---:|---|
| 1 | `20260724T074141Z-5910b96d-9a83-4c90-858f-6794f8efe179` |
| 2 | `20260724T074145Z-a671b5ee-f5c0-4352-b31e-5d767bf7f032` |
| 3 | `20260724T074149Z-d9ce4e00-630e-4bc2-bb45-639c7edfd7bb` |
| 4 | `20260724T074153Z-d5c80657-e815-4db0-bf93-817acdfdbb18` |
| 5 | `20260724T074157Z-3b73ea52-6406-4286-a249-51477311228f` |
| 6 | `20260724T074201Z-1aebc11a-ba16-45c3-8434-d05f713c7ad9` |
| 7 | `20260724T074206Z-6bfbf088-0f57-4bfc-9301-0e5ec63edef2` |
| 8 | `20260724T074211Z-c766fc18-2c6e-456e-91b7-76cfcbb036cc` |
| 9 | `20260724T074215Z-5d471960-de54-40ce-bd85-2bb2f2bfd10d` |
| 10 | `20260724T074219Z-f64120f3-547e-415b-a0ed-4966f415c9d4` |
| 11 | `20260724T074223Z-859fcc3f-67a2-4e60-b1ff-3ccadc9d42c7` |
| 12 | `20260724T074227Z-accb2b4f-9abc-4de8-9062-32f1793ece94` |
| 13 | `20260724T074231Z-c85a12ba-239d-4c3a-8001-fb09a8631b0e` |
| 14 | `20260724T074235Z-9d78e08e-4f70-4541-90c4-1036f0071df3` |
| 15 | `20260724T074239Z-48083cc2-347e-4963-ab89-490a487b25f6` |
| 16 | `20260724T074243Z-d836ef8c-b849-4274-b716-64c832d15239` |
| 17 | `20260724T074247Z-4df4b709-3901-40df-beee-ec31e8024998` |
| 18 | `20260724T074251Z-369694e7-e417-46a5-a2a1-18aca92a4287` |
| 19 | `20260724T074255Z-5a9904a2-3754-4614-9b5f-f24ca6e6bb3e` |
| 20 | `20260724T074259Z-91ef2901-1640-4df3-bf21-2f58fec13cc1` |

Ledger effect is coverage-neutral: inventory moves to 127 cases and 66 strict
both cases; distinct covered behavior remains 75/79.

## Group H Full-Gate Evidence

### macOS

- `cargo test -p sb-config vmess_ -- --nocapture`: 17 passed, 0 failed,
  0 ignored across library and integration targets.
- `cargo test -p sb-transport --features
  'transport_tls transport_ws transport_httpupgrade transport_mux'`: 152 passed,
  0 failed, 1 unrelated ignored.
- `cargo test -p sb-adapters --features adapter-vmess vmess`: 18 passed,
  0 failed, 0 ignored.
- production app live suites: TLS variants 9/9, Rust outbound→Go 6/6,
  Go→production Rust inbound 7/7, TLS-yamux 1/1, plain yamux 6/6,
  protocol chain 8/8, WebSocket outbound 4/4, and WebSocket inbound 5/5.
  No scoped test failed or was ignored.
- strict local TLS stress: 20 rounds × 9 tests = 180 passed, 0 failed,
  0 ignored under 16 test threads.
- strict both-kernel case: 20/20 repeated runs passed; 40/40 kernel snapshots
  passed; 20/20 normalized diffs were clean with zero traffic mismatch and
  gate score zero.
- `cargo test -p interop-lab`: 61 passed, 0 failed, 0 ignored. The fixed-source
  port regression also passed five isolated repeats and the normal parallel
  suite.
- acceptance app build, default app check, repository `make clippy`,
  focused all-feature/all-target adapter Clippy, `cargo fmt --all --check`,
  `git diff --check`, boundary validation (430 assertions), consistency
  validation, and typed dual-kernel ledger validation all passed.

### Linux

Docker Desktop 4.82.0 supplied Engine 29.6.1 on Linux arm64 with overlayfs.
The reusable test image was `singbox-rust-dev:1.92-alpine`; Rust and Cargo were
pinned to 1.92.0. The Go oracle was built from the pinned 1.13.13 fork with
Go 1.25.10, `CGO_ENABLED=0`, and `with_clash_api`; its reported revision was
`31e97570d07cabe92282c332b70109256216ebcb`.

- production TLS variants: 9 passed, 0 failed, 0 ignored.
- Rust outbound→Go server: 6 passed, 0 failed, 0 ignored.
- Go client→production Rust inbound: 7 passed, 0 failed, 0 ignored.
- project TLS-yamux: 1 passed, 0 failed, 0 ignored.
- `cargo check -p app --features acceptance,clash_api,adapters`: passed.
- `cargo clippy -p sb-adapters --features adapter-vmess --lib --tests`:
  passed with only pre-existing warnings.
- final strict both-kernel run:
  `20260724T103124Z-3b7affcf-3691-4846-9f79-a6a6565dfb5d`, outcome PASS.

Docker's sparse disk cap was expanded from 61,035 MiB to 81,920 MiB after a
no-space linker failure. No image, container, volume, or Cargo cache was
deleted. A prior no-space event had left the stargz snapshot metadata
inconsistent; switching the snapshotter to overlayfs preserved the named
target/registry/git volumes and restored repeatable execution.

## Red-Team Fixes During Full Gates

- Background-command resolution expanded `${INTEROP_GO_BINARY}` too early,
  turning an unset variable into an empty command before fallback resolution.
  Both command paths now preserve the placeholder; the resolver also finds the
  repository Go binary from the interop package working directory. A unit
  regression and an override-free macOS strict run prove fallback behavior.
- `TlsConfig::Standard` was destructured as the only enum variant. All-feature
  builds add REALITY/ECH variants, so the code did not compile. Conditional
  lowering now preserves standard-TLS ALPN defaults and rejects no other
  variant by destructuring.
- Linux app logs carried ANSI field styling into a file, making a successful
  WebSocket+TLS dataplane fail its text assertion. The spawned production app
  now receives `NO_COLOR=1`; the 7-test inbound suite passes on both systems.
- The interop source-port reuse test selected a listener-free port, dropped the
  probe, then raced parallel tests before its first connection. It now selects
  the port through a successful first connection and asserts immediate reuse
  on the second; five focused repeats and the 61-test parallel suite pass.
- Cold Linux acceptance builds could exceed the strict case's 600-second Rust
  startup budget. The budget is now 900 seconds; warm and cold-path evidence
  no longer confuses build latency with kernel readiness.

## Security and Inventory Review

- TLS verification remains enabled by default; `insecure` stays client-only.
- Wrong SNI, untrusted CA, expired/not-yet-valid certificates, wrong UUID,
  malformed material, TLS/plain mismatch, version mismatch, ALPN mismatch,
  timeout, and peer-close negatives fail closed.
- No private key, PEM body, raw credential, external endpoint, generated Go
  binary, Docker artifact, or interop run artifact is tracked.
- Coverage accounting is neutral: 127 total cases, 66 strict both-kernel cases,
  79 active BHVs, and 75/79 distinct BHVs covered.

## Recorded Commits

- ledger correction: `ce99c0a1ab4cd82c42a021d00f364b76a9b6d0ac`
- config/TLS lowering: `74fd5f68ef276fd53d4df7b4db92a191487c8c0d`
- outbound TLS closure: `248c84a4349a0d2b0bf08c7c04a159bed35c3163`
- inbound TLS closure: `426ef5e405c5e35193e9385fba60ca208aaf7120`
- transport/multiplex closure: `786ea4e08544b0ee4179c37e5f0ddce61d7fd562`
- strict local TLS matrix: `98de7cae36f3a07452c15c3109de36fe587dcd55`
- strict dual-kernel case: `31e97570d07cabe92282c332b70109256216ebcb`
- Linux/full-gate hardening: `d9cdc74b8b58a2a498b2a30f5a159edb7cb94e3b`

The final archive/status commit is the commit containing this CLOSED line; its
hash is recorded in the task handoff because a commit cannot contain its own
stable hash.

## Closure Verdict

VMESS-TLS-01 is production-ready within its declared scope. macOS and Linux
prove production standard TLS, crossed Go/Rust dataplanes, strict both-kernel
parity, transport composition, project-yamux ordering, negative behavior,
fail-loud configuration, and clean shutdown. No scoped test is ignored, no
plaintext fallback exists, and no further VMESS-TLS-01 implementation action
remains.
