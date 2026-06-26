<!-- tier: B -->
# post_fable_package04 WireGuard dataplane evidence

Date: 2026-06-13
Code commit: `f70bf5ef` (`fix(sb-core): expose WireGuard endpoints as outbounds`)
Status: DONE for package04 scope
Latest extension: 2026-06-27 post004 P6 incoming TCP listener DONE

## Conclusion

CAL-03 is closed: WireGuard endpoints are no longer outbound-namespace
islands. Endpoint tags are registered as outbound connectors while preserving
`Bridge.endpoints` lifecycle ownership. A production `app run` smoke with
`route.final: "wg-ep"` resolved the default outbound to `wg-ep`, reached
`sing-box started`, and did not emit `default outbound not found`.

CAL-09 is closed for feature wiring: legacy `outbounds:[{type:"wireguard"}]`
is enabled through the app `adapters` aggregate, so `parity` covers it
indirectly. The builder returns a real lazy WireGuard connector under
`adapter-wireguard-outbound`; it is no longer an unreachable app-build ghost.

The later post004 userspace dataplane line is also closed through the
user-directed P6 extension: Rust can now both dial TCP/UDP through the userspace
WG netstack and accept configured incoming in-tunnel TCP on endpoint
`listen_ports`.

This package does not certify public WireGuard peer interoperability or
performance. It proves endpoint/outbound resolution, startup, and the
stream-capable outbound adapter path.

## Endpoint form

| Item | Result |
|---|---|
| `endpoints[{type:"wireguard", tag:"wg-ep"}]` enters endpoint lifecycle | PASS |
| endpoint tag enters outbound namespace as `endpoint/wireguard` | PASS |
| `route.final: "wg-ep"` default resolution | PASS |
| `EndpointAsOutbound.connect()` | explicit Unsupported; points to `connect_io()` |
| `EndpointAsOutbound.connect_io()` | delegates to endpoint `dial_context(Network::Tcp, Socksaddr)` |
| duplicate endpoint / outbound tag conflict | loud startup error via `Bridge.startup_errors` |

## Legacy outbound form

| Item | Result |
|---|---|
| app feature `adapter-wireguard-outbound` | added |
| app `adapters` aggregate | includes `adapter-wireguard-outbound` |
| app `parity` aggregate | covered via `adapters` |
| sb-adapters builder under feature | returns real lazy connector |
| full public WG peer traffic | not certified in package04 |

## Runtime smoke

Command shape:

```bash
./target/debug/app run --disable-color -c /tmp/pf04-wg-smoke/config.json -D /tmp/pf04-wg-smoke
```

Fixture shape:

- no explicit outbounds;
- one WireGuard endpoint tagged `wg-ep`;
- endpoint has local `address`, private key, one IP peer, peer public key, and
  `allowed_ips: ["0.0.0.0/0"]`;
- route final is `wg-ep`.

Observed result:

```text
status=started
default_not_found_count=0
started_seen=1
resolved_seen=1
panic_seen=0
INFO sb_core::outbound: default outbound resolved default=wg-ep source="config"
INFO sb_core::endpoint::wireguard: WireGuard endpoint started tag=wg-ep
INFO app::run_engine_runtime::output: sing-box started; press Ctrl+C to quit
```

Before the runtime fix, the same smoke passed default resolution but panicked in
WireGuard endpoint startup with nested Tokio `block_on`. The final code starts
WireGuard endpoint transport initialization without nesting `block_on` inside
the active runtime thread.

## Verification snapshot

| Command | Result |
|---|---|
| `cargo test -p sb-core --lib endpoint` | PASS: 21 passed |
| `cargo test -p sb-core --lib adapter` | PASS: 13 passed |
| `cargo test -p sb-adapters --lib wireguard --features "adapter-wireguard-endpoint adapter-wireguard-outbound router"` | PASS: 5 passed |
| `cargo check -p app --features "adapters,clash_api"` | PASS |
| `cargo check -p app --features "parity"` | PASS |
| `cargo check --workspace --all-features` | PASS |
| `git diff --check` | PASS |

## Remaining limits

- No public WireGuard peer traffic or throughput certification was attempted.
- Domain peer endpoints still require a configured DNS resolver; failures remain
  WireGuard-specific and explicit.
- package04 does not cover TUN privileged dataplane proof, reload atomicity,
  subscription import behavior, or WireGuard protocol-stack rewrites.

---

## post004 extension: WireGuard userspace TCP/IP netstack — Phase 1

Date: 2026-06-21.

Scope decision (user-directed): package04 closed *resolution/registration* but the
data plane was never real — `WireGuardStream` fed raw application bytes straight
into `Tunn::encapsulate` (which expects a full IP packet) and `connect` ignored the
target, so traffic was silently dropped (a "looks-successful, semantically-broken"
stream). post004 deepens this to a real data plane, mirroring Go sing-box's
wireguard-go + gVisor `netstack` with a pure-Rust equivalent. Like post003 for TUN,
the bar is end-to-end correctness + live proof, not a re-label.

### Engine decision (smoltcp), with evidence

- **Chosen: smoltcp over boringtun** (user-confirmed). Functionally proven by
  `onetun` (github.com/aramperes/onetun), which is exactly boringtun+smoltcp for
  userspace WireGuard TCP/UDP forwarding, no root — same architecture as ours.
- **netstack choice does not affect Go interop**: interop is at the WG/Noise layer
  (boringtun ↔ wireguard-go + `reserved`); inner IP packets are terminated by the
  *remote peer's* kernel, which does not care which stack synthesized them. There is
  no production-grade Rust gVisor, and "aligning gVisor at the netstack layer" is
  neither possible nor necessary.
- **Honest caveat (logged for the future)**: Cloudflare used smoltcp for the same
  L4↔L3 WireGuard job in their SASE client and hit a performance ceiling on
  high-BDP / many-connection browsing (smoltcp lacks mature window scaling / SACK),
  then moved to lwIP. For functional drop-in this is acceptable; if performance
  parity becomes a hard requirement, the migration path is `netstack-lwip` (C FFI).
  The netstack lives behind `WireGuardTransport`, so it is swappable.

### Phase 1 delivered (real logic, no stubs)

- `crates/sb-transport/src/wireguard.rs` → split into `wireguard/mod.rs` +
  `wireguard/netstack.rs`; `transport_wireguard` now also pulls `smoltcp`.
- `netstack.rs`: a smoltcp `Device` (`WgPhy`) bridged to the tunnel (egress →
  `encapsulate` → UDP; UDP → `decapsulate` → ingress); a single driver task owns
  `Tunn`/UDP/`Interface`/`SocketSet` (no locking); established-gated TCP `connect`
  to arbitrary in-tunnel targets via a default route (gateway unused on `Medium::Ip`,
  no `set_any_ip`); self-allocated ephemeral source ports (smoltcp rejects port 0);
  `WgTcpStream` (mpsc + `Notify`) as the proxyable `AsyncRead`/`AsyncWrite`.
- `reserved` handled per Go `transport/wireguard/client_bind.go`: written into
  `packet[1..4]` on send, cleared on receive — at the UDP boundary, outside boringtun.
- `mod.rs`: `WireGuardTransport` is netstack-backed; the broken `WireGuardStream` /
  `get_stream` / `send` / `recv` / `timer_loop` are removed. `WireGuardConfig` gains
  `local_addrs: Vec<IpAddr>` + `reserved: [u8;3]`.
- Outbound (`sb-adapters/src/outbound/wireguard.rs`): `dial` now does a real
  `connect(target)` through the netstack (was target-ignoring `get_stream`); pulls
  `local_addrs` from `wireguard_local_address` + `wireguard_source_v4/v6`.
- Endpoint (`sb-core/src/endpoint/wireguard.rs`): per-peer config feeds `local_addrs`
  (from interface `address`) + `reserved`; `reserved` is parsed to 3 bytes instead of
  being rejected.

### Verification snapshot

| Command | Result |
|---|---|
| `cargo test -p sb-transport --features transport_wireguard --lib wireguard` | PASS: 10 passed (reserved set/clear, WgPhy queue, connect wrong-family loud-fail, non-IP loud-fail, no-peer timeout) |
| `cargo test -p sb-adapters --features adapter-wireguard-outbound,adapter-wireguard-endpoint --lib wireguard` | PASS: 5 passed |
| `cargo test -p app --features adapters --test wireguard_endpoint_test --test wireguard_endpoint_e2e` | PASS: 10 passed |
| `cargo check -p sb-transport` (default; netstack absent) | PASS (Phase 0 intact) |
| `cargo check -p sb-transport --features transport_wireguard` | PASS |
| `cargo check -p sb-adapters --features adapter-wireguard-outbound,adapter-wireguard-endpoint` | PASS |
| `cargo clippy -p sb-transport --features transport_wireguard --all-targets` | PASS: 0 warnings |
| `cargo fmt --all -- --check` | clean |

### Phase 2 delivered (UDP-over-WG)

- Transport: `WireGuardTransport::connect_udp()` opens a caller-facing `WgUdpSocket`
  backed by smoltcp `udp::Socket` entries in the same boringtun-owned driver. It
  supports `send_to(buf, dst)` and `recv_from(buf)` for in-tunnel datagrams, loud-fails
  when no WG interface source address exists or the target address family has no matching
  local source, and keeps the no-peer receive path bounded by caller timeout rather than
  hanging.
- Outbound registry: `OutboundRegistryHandle` now carries named UDP outbound factories.
  A named connector detour can therefore route UDP through its real adapter factory
  instead of falling back to the old unsupported connector path.
- Legacy WireGuard outbound: the lazy WireGuard connector exposes `connect_udp()` and
  `register` returns a `UdpOutboundFactory` alongside the TCP connector when the
  WireGuard outbound feature is enabled.
- Endpoint-as-outbound: endpoints gained an optional UDP outbound hook and factory.
  WireGuard endpoints expose `WireGuardEndpointUdpSession`, select peers by `allowed_ips`
  (first peer fallback), resolve FQDNs through the internal resolver when available, and
  use `WgUdpSocket` for datagrams. `listen_packet` remains explicitly unsupported for
  userspace WireGuard because returning an OS `UdpSocket` would bypass/leak around WG.
- All-features compatibility: the Tailscale direct-WireGuard initializer now supplies
  the extended WireGuard config fields (`local_addrs` empty, zero `reserved`) instead of
  failing to compile under combined adapter features.
- Lifecycle hardening found during Phase 2: WireGuard endpoint transport init now uses a
  persistent endpoint runtime, so the netstack driver spawned by synchronous lifecycle
  start is not dropped immediately after initialization.

### Phase 2 verification snapshot

| Command | Result |
|---|---|
| `cargo test -p sb-transport --features transport_wireguard --lib wireguard` | PASS: 14 passed (13 + dual-stack accept stress added 2026-06-26) |
| `cargo test -p sb-adapters --features adapter-wireguard-outbound,adapter-wireguard-endpoint,router --lib wireguard` | PASS: 5 passed |
| `cargo test -p sb-core endpoint` | PASS: 23 matched tests passed |
| `cargo test -p sb-core registry_` | PASS: 8 matched tests passed |
| `cargo check --workspace --all-features` | PASS |

### Phase 3 delivered (multi-socket concurrency hardening)

- **P3-1 multi-peer UDP routing**: `WireGuardEndpointUdpSession` socket cache changed from a single
  `Mutex<Option<Arc<WgUdpSocket>>>` to a per-peer `HashMap<peer_key, PeerSocketEntry>`. `socket_for`
  selects the peer by `allowed_ips` (target IP) and uses that peer's bucket; datagrams never ride the
  wrong tunnel. `peer_key` = `Arc<WireGuardTransport>` address (one tunnel per peer → unique).
- **P3-2 recv_from race fix**: replaced `Mutex<Option> + Notify` (check-then-await window where
  `notify_waiters` could fire between check and `notified()` registration) with `tokio::sync::watch`:
  `borrow_and_update()` is non-async and reflects the latest state atomically; `changed().await`
  registers the waiter before observing.
- **P3-3 ephemeral port dedup**: `alloc_ephemeral_port` now skips in-use ports (`HashSet<u16>`) and
  wraps the full 49152..=65535 range before returning 0 (loud-fail at smoltcp bind). Ports are
  reclaimed when sockets are reaped in `pump_sockets`/`pump_udp_writes`/`pump_udp_recv`. `pump_udp_recv`
  `rxbuf` hoisted from a 64KB-per-poll alloc to a Driver-owned `udp_rxbuf` scratch buffer.
- **P3-4 ensure_started TOCTOU**: re-check `transports.is_empty()` under the lock after building, so
  two concurrent callers don't both populate (which would orphan netstack drivers).
- **P3-5 udp_timeout**: `wireguard_udp_timeout` parsed via `humantime` (invalid → 5m fallback with
  warning); per-peer socket idle reap on `send_to`/`recv_from` paths. Tailscale endpoint
  `tailscale_udp_timeout` aligned (was hardcoded 300s, now parses IR).
- **P3-6 TCP stress**: `tcp_many_concurrent_dials_all_timeout_distinctly` — 16 concurrent dials on one
  tunnel, each gets a distinct ephemeral port and surfaces a timeout (not a hang/collision).

### Phase 3 verification snapshot

| Command | Result |
|---|---|
| `cargo test -p sb-transport --features transport_wireguard --lib wireguard` | PASS: 16 passed (14 + port-collision + TCP concurrent-dial) |
| `cargo test -p sb-adapters --features adapter-wireguard-outbound,adapter-wireguard-endpoint,router --lib wireguard` | PASS: 5 passed |
| `cargo test -p sb-core --lib endpoint` | PASS: 29 passed (23 + 6 new) |
| `cargo test -p sb-core --lib registry_` | PASS: 8 passed |
| `cargo clippy -p sb-transport --features transport_wireguard --all-targets` | 0 warnings |
| `cargo clippy -p sb-core --features router --all-targets` | 0 warnings |
| `cargo fmt --all -- --check` | clean |
| `cargo check --workspace --all-features` | PASS |

### Remaining (post004 roadmap after Phase 3)

- **Phase 4**: MIG-02 — make the disabled-feature outbound builder loud
  (`invalid_config_outbound`) instead of silent `None`; consume islanded `mtu` /
  `allowed_ips`.
- **Phase 5**: live round-trip proof vs a real Go sing-box WG peer (ordinary user,
  no root), double-sided assertion + `result.json`, as the `04b` harness.
- Not yet exercised live: a real TCP/UDP round-trip through the tunnel (that is the
  Phase 5 gate). Phase 1/2/3 prove stack mechanics + TCP/UDP wiring + loud failure modes
  + multi-socket concurrency + idle reap.

### Phase 4 delivered (MIG-02 WireGuard loud-disabled + islanded mtu/reserved/allowed_ips)

- **P4-1 loud disabled builder**: `build_wireguard_outbound` `#[cfg(not(feature =
  "adapter-wireguard-outbound"))]` branch changed from `stub_outbound("wireguard"); None`
  (silent — bridge turns None into a misleading "outbound not found") to
  `invalid_config_outbound("wireguard", unsupported_outbound_feature_reason(...))`, so a
  dial through a feature-disabled WireGuard outbound fails loudly carrying the outbound
  type, the missing cargo feature, and a `--features` rebuild hint. Mirrors the Tor
  long-tail pattern (`register.rs:2770-2773`).
- **P4-2 mtu consumed**: `OutboundIR` + `RawOutboundIR` gained `wireguard_mtu:
  Option<u32>`; raw→IR lowering passes it through; v2 validator extracts `mtu` from raw
  JSON in the Wireguard branch; `WireGuardOutboundConfig::try_from` now uses
  `ir.wireguard_mtu.unwrap_or(1420)` instead of hardcoded `1420`. Mirrors Go
  `WireGuardEndpointOptions.MTU`.
- **P4-3 reserved consumed**: `OutboundIR` + `RawOutboundIR` gained
  `wireguard_reserved: Option<Vec<u8>>`; lowering + v2 validator extract `reserved`;
  `try_from` parses to `[u8;3]` with a loud `InvalidConfig` when not exactly 3 bytes
  (mirrors endpoint-side parsing at `crates/sb-core/src/endpoint/wireguard.rs:370-377`).
  Replaces hardcoded `[0,0,0]`. Mirrors Go `WireGuardPeer.Reserved`.
- **P4-4 allowed_ips CIDR validation**: `try_from` now validates every `allowed_ips`
  entry via `IpNet::parse`, failing loudly on malformed CIDRs. For single-peer outbound
  the list is informational (the netstack uses a default route; allowed_ips do not
  participate in peer selection), but malformed CIDRs must no longer pass through
  silently as opaque strings.

### Phase 4 verification snapshot

| Command | Result |
|---|---|
| `cargo test -p sb-config --lib outbound` | PASS: 104 passed (103 + v2 mtu/reserved extraction) |
| `cargo test -p sb-config --lib wireguard` | PASS: 16 passed (roundtrip extended with mtu/reserved) |
| `cargo test -p sb-config --test compatibility_matrix` | PASS: 6 passed |
| `cargo test -p sb-adapters --features adapter-wireguard-outbound,adapter-wireguard-endpoint,router --lib wireguard` | PASS: 12 passed (5 original + 7 new: mtu consumed/default, reserved consumed/default/reject, allowed_ips invalid, disabled loud) |
| `cargo test -p sb-adapters --lib register` | PASS: 15 passed (includes wireguard_disabled_outbound_connect_fails_loudly) |
| `cargo test -p sb-transport --features transport_wireguard --lib wireguard` | PASS: 16 passed |
| `cargo test -p sb-core endpoint` | PASS: 29 passed |
| `cargo clippy -p sb-adapters --all-targets` | 0 warnings |
| `cargo clippy -p sb-config --all-targets` | 0 warnings |
| `cargo fmt --all -- --check` | clean |
| `cargo check --workspace --all-features` | PASS |

### Remaining (post004 roadmap after Phase 4)

- **Phase 5**: live round-trip proof vs a real Go sing-box WG peer (ordinary user, no
  root), double-sided assertion + `result.json`, as the `04b` harness.
- Not yet exercised live: a real TCP/UDP round-trip through the tunnel (that is the
  Phase 5 gate). Phase 1/2/3/4 prove stack mechanics + TCP/UDP wiring + loud failure
  modes + multi-socket concurrency + idle reap + loud disabled builder + islanded
  mtu/reserved/allowed_ips consumption.

### Phase 5 delivered (live round-trip proof vs Go sing-box)

- **04b harness**: `post_fable_package04b_wg_live_proof_harness.sh` — builds Go
  sing-box (1.13.13, `with_wireguard,with_gvisor`) and Rust app, generates WireGuard
  keypairs, starts a Python HTTP CONNECT stub, launches both kernels, and proves a live
  HTTP round-trip through the WG tunnel.
- **Topology** (single-host loopback, no root):
  - Rust app: WG endpoint (10.0.0.2/32), mixed inbound, http-out → stub.
  - Go sing-box: WG endpoint (10.0.0.1/32), mixed inbound, http-out → stub.
  - curl: `curl -x socks5://127.0.0.1:RM http://172.20.0.100:STUB/wg04b`
  - Path: curl → Rust mixed → route 172.20.0.100/32 → wg-rust (endpoint-as-outbound) →
    WG tunnel → Go gvisor netstack → route 172.20.0.100/32 → http-out → stub → response
    back through Go → WG tunnel → Rust → curl.
- **Round-trip proof**: the request traverses Rust→Go through the WG tunnel, and the
  response traverses Go→Rust through the WG tunnel. This proves bidirectional tunnel
  data flow with a single curl.
- **Four assertions** (all green):
  1. `curl_round_trip_success`: HTTP 200 + body `WG04B-OK`.
  2. `stub_hit`: stub log has `CONNECT_LINE CONNECT 172.20.0.100:STUB_PORT`.
  3. `go_inbound_from_wg_hit`: Go log has `inbound connection to 172.20.0.100:STUB_PORT`.
  4. `rust_outbound_to_wg_hit`: Rust log has `outbound TCP connection to
     172.20.0.100:STUB_PORT tag=wg-rust`.
- **SOCKS5 not HTTP proxy**: the Rust HTTP inbound hardcodes `ip: None` in `RouteCtx`,
  preventing `ip_cidr` rule matching. SOCKS5 with an IP-typed address populates
  `ctx.ip`, enabling the route rule to match. This is a known Rust-side gap (the
  convenience deciders like `decide_http` do parse host literals, but the production
  HTTP inbound path calls `decide_with_meta` which does not).
- **Honest limitation**: a Go-initiated curl through WG to Rust is not possible because
  the Rust smoltcp netstack only supports outbound dial (no incoming TCP forwarder,
  unlike Go's gvisor `SetTransportProtocolHandler`). The round-trip response path
  already proves Go→Rust tunnel traversal. Adding incoming TCP support to the Rust
  smoltcp netstack is a future enhancement, not a Phase 5 blocker.

### Phase 5 verification snapshot

| Command | Result |
|---|---|
| `SKIP_GO_BUILD=1 SKIP_BUILD=1 GO_BIN=/tmp/gp04b_build/sing-box WORK=/tmp/pf04b-wg-live bash .../post_fable_package04b_wg_live_proof_harness.sh` | PASS: historical Phase 5 proof, `result.json` status=PASS, exit 0 |
| `cat /tmp/pf04b-wg-live/result.json` | curl 200, stub_hit=true, go_inbound=true, rust_outbound=true, cleanup=complete |
| Go sing-box build (`go build -tags with_wireguard,with_gvisor`) | PASS (32MB binary, tags confirmed) |
| Rust app build (`cargo build -p app --features adapters,clash_api`) | PASS |

### Phase 1-5 audit (2026-06-27)

The sealed phase history was re-read against its commits and implementation
surface. Result: the documented claims are real, not just prose.

| Phase | Sealed commit(s) | Re-audit result |
|---|---|---|
| P1 userspace TCP netstack | `8f976824` | REAL: `wireguard.rs` was replaced by `wireguard/mod.rs` + `netstack.rs`; smoltcp owns IP/TCP over boringtun; raw-byte `WireGuardStream` path was removed; outbound dial now targets the requested in-tunnel host/port. |
| P2 UDP-over-WG | `069c1e96`, `7964e5a6` | REAL: `WgUdpSocket`, UDP outbound factories, endpoint UDP sessions, persistent endpoint runtime, and dual-stack UDP happy-path stress are present. |
| P3 concurrency hardening | `9dadcd10` | REAL: per-peer UDP socket buckets, watch-based recv readiness, ephemeral port dedup/reclaim, UDP scratch-buffer reuse, `ensure_started` TOCTOU guard, parsed `udp_timeout`, and TCP concurrent-dial stress are present. |
| P4 MIG-02 | `c0e11036` | REAL: disabled WireGuard outbound is loud, and outbound `mtu`/`reserved`/`allowed_ips` are consumed or validated instead of islanded. |
| P5 live Go proof | `9f0bf903` | REAL: 04b harness exists and proves Rust→Go request plus Go→Rust response through WG against Go sing-box. Its documented limitation was also real at that time: Rust had no incoming TCP forwarder before P6. |

### Phase 6 delivered (incoming TCP listener + independent Go→Rust proof)

P6 closes the Phase 5 limitation from the screenshot.

- Config/IR: endpoint `listen_ports` is accepted by the strict v2 endpoint
  schema, lowered into `EndpointIR.wireguard_listen_ports`, round-tripped through
  raw IR, and type/range checked as TCP port numbers.
- Transport: `WireGuardConfig.listen_ports` opens smoltcp TCP listeners inside
  the WG netstack. Established listener sockets are converted into `TcpAccept`
  values carrying `WgTcpStream`, local address, and remote address.
- Endpoint: `WireGuardEndpoint` consumes accept receivers, spawns WG-runtime
  accept tasks after both transport startup and connection-handler registration
  are ready, builds `InboundContext`, and calls `route_connection`.
- Local destination parity: accepted traffic to the endpoint's WG-local address
  is translated to loopback before routing, while `origin_destination` preserves
  the original WG destination. This matches the existing outbound/local-address
  handling and lets live single-host proof reach the local stub without proxy
  recursion.
- 04b harness: now proves both the original Rust→Go→stub→Go→Rust curl and an
  independent Go→Rust curl:
  `curl -x socks5://127.0.0.1:$GM http://10.0.0.2:$STUB/wg04b-rust`.
  Go routes `10.0.0.2/32` to `wg-go`; Rust accepts the in-tunnel TCP connection
  on `listen_ports`, routes it through the endpoint handler, translates
  `10.0.0.2:$STUB` to `127.0.0.1:$STUB`, and reaches the direct stub.

### Phase 6 verification snapshot

| Command | Result |
|---|---|
| `cargo test -p sb-config wireguard` | PASS: 18 passed; endpoint `listen_ports` lowering/raw/type coverage included |
| `cargo test -p sb-transport wireguard::netstack --features transport_wireguard` | PASS: 15 passed; incoming TCP listener + paired-netstack ping/pong included |
| `cargo test -p sb-core wireguard --features router` | PASS: 8 passed; endpoint listener routes accepted TCP to `ConnectionHandler` |
| `cargo test -p sb-adapters --features adapter-wireguard-outbound,adapter-wireguard-endpoint,router --lib wireguard` | PASS: 12 passed |
| `cargo test -p app --features adapters --test wireguard_endpoint_test --test wireguard_endpoint_e2e` | PASS: 10 passed |
| `SKIP_GO_BUILD=1 GO_BIN=/tmp/gp04b_build/sing-box WORK=/tmp/pf04b-wg-live-p6 bash .../post_fable_package04b_wg_live_proof_harness.sh` | PASS: Rust→Go round-trip and independent Go→Rust curl both green |
| `/tmp/pf04b-wg-live-p6/result.json` | status=PASS; both curl statuses 200; `stub_hit`, `stub_go_to_rust_hit`, `go_inbound_from_wg_hit`, `rust_outbound_to_wg_hit`, `go_outbound_to_rust_wg_hit`, `rust_inbound_from_go_wg_hit` all true; cleanup=complete |
| `cargo check -p app --features adapters,clash_api` | PASS |
| `cargo check -p app --features parity` | PASS |
| `cargo check --workspace --all-features` | PASS |
| `cargo fmt --all -- --check` + `git diff --check` | PASS |
| `bash agents-only/06-scripts/verify-consistency.sh` | PASS; `active_context.md` 96 lines and pointers resolve |

### P7/P8 follow-up posture

- **P7 `system:true` kernel WireGuard — PLANNED, not implemented**. Proposed
  phases: audit OS/kernel-WG surfaces and privilege requirements; define exact
  config semantics for `system_interface`/`interface_name`; implement interface
  lifecycle and route ownership per platform; add manual privileged gates; only
  then decide whether it can become a default user path.
- **P8 smoltcp→lwIP — DEFERRED**. No migration is justified by current
  correctness evidence. Triggers would be sustained performance/BDP failure,
  TCP option correctness gaps, fragmentation/PMTU defects, or live workload
  failures that cannot be reasonably fixed behind the current `WireGuardTransport`
  seam. If triggered, plan as benchmark → adapter seam → dual-stack parity tests
  → rollback-safe migration.

### post004 closure (updated 2026-06-27)

Phase 1-6 complete. The WireGuard userspace dataplane is proven:
- **Phase 1**: smoltcp netstack + boringtun tunnel (real IP packets, not raw bytes).
- **Phase 2**: UDP-over-WG via smoltcp `udp::Socket`.
- **Phase 3**: multi-socket concurrency (per-peer bucketing, port dedup, TOCTOU fix,
  idle reap, TCP stress).
- **Phase 4**: MIG-02 loud disabled builder + islanded mtu/reserved/allowed_ips.
- **Phase 5**: live round-trip proof vs Go sing-box (Rust→Go→stub→Go→Rust through WG).
- **Phase 6**: endpoint incoming TCP listener and independent Go→Rust curl proof.

Future WireGuard work is no longer a hidden Phase 6 item. The remaining major
lines are P7 `system:true` kernel-WG planning and P8 smoltcp→lwIP only if evidence
requires it.
