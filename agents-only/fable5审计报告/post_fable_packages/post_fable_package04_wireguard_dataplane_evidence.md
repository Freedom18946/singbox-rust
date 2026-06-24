<!-- tier: B -->
# post_fable_package04 WireGuard dataplane evidence

Date: 2026-06-13
Code commit: `f70bf5ef` (`fix(sb-core): expose WireGuard endpoints as outbounds`)
Status: DONE for package04 scope

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

### Remaining (post004 roadmap)

- **Phase 2**: UDP-over-WG (smoltcp `udp::Socket`; endpoint `listen_packet` factory).
- **Phase 3**: multi-socket concurrency hardening on one tunnel.
- **Phase 4**: MIG-02 — make the disabled-feature outbound builder loud
  (`invalid_config_outbound`) instead of silent `None`; consume islanded `mtu` /
  `allowed_ips`.
- **Phase 5**: live round-trip proof vs a real Go sing-box WG peer (ordinary user,
  no root), double-sided assertion + `result.json`, as the `04b` harness.
- Not yet exercised live: a real TCP/UDP round-trip through the tunnel (that is the
  Phase 5 gate). Phase 1 proves the stack mechanics + wiring + loud failure modes.

