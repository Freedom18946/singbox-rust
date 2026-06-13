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
