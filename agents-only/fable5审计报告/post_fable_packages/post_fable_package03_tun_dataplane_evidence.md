<!-- tier: B -->
# post_fable_package03 TUN dataplane evidence

Date: 2026-06-13
Code commit: `edf42095` (`fix(sb-adapters): wire GUI TUN stack to runtime backend`)
Status: PARTIAL

## Conclusion

Package03 fixed the runtime wiring and startup honesty gap for GUI TUN configs:
GUI-default-ish `stack: "mixed"` now resolves to the Enhanced/smoltcp backend,
TUN runtime preparation happens before the supervisor can report started, and
TUN open/configure failure blocks startup instead of being hidden behind
`sing-box started`.

Local dataplane traffic is not proven on this macOS normal-user environment.
The live smoke reached the real TUN runtime attempt and failed before startup
with `Operation not permitted (os error 1)`, which is an acceptable platform
permission blocker for this package but keeps the package short of DONE.

## Stack policy

| GUI/runtime stack | Runtime policy | Operator signal |
|---|---|---|
| missing / empty / `default` | Enhanced/smoltcp | normal runtime |
| `mixed` | Enhanced/smoltcp | normal runtime; GUI default path |
| `smoltcp` | Enhanced/smoltcp | normal runtime |
| `gvisor` | Enhanced/smoltcp compat path | loud warning: no gVisor netstack is wired |
| `system` | Unsupported | loud error: no real system-stack backend is wired |
| `manual` + `dry_run: true` | diagnostic no-op | loud warning: no dataplane |
| `manual` without explicit dry run | Unsupported | loud error |
| unknown | InvalidInput | loud error listing supported values and restrictions |

## Runtime field mapping

| GUI / Go field | Runtime target | Notes |
|---|---|---|
| `address` | Enhanced TUN IPv4/IPv6 device addresses | split by IP family; each entry may include CIDR; host IP is used for current platform config |
| `inet4_address` / `inet6_address` | fallback device addresses | used only when `address` lacks that IP family |
| `route_address` | effective include routes | takes precedence over legacy `include_routes` |
| `route_exclude_address` | effective exclude routes | takes precedence over legacy `exclude_routes` |
| `auto_route` | platform hook route config | hook configure failure is fatal during TUN startup preparation |
| `auto_redirect` | platform hook redirect config | fatal if requested but unsupported |
| `strict_route` | platform hook strict-route config | fatal if requested but unsupported |
| `dry_run` | diagnostic gate | default is now `false`; only explicit `true` permits manual/no-op |

## Startup honesty

- `TunInbound::try_new` prepares the selected backend at build time.
- Enhanced/smoltcp calls platform device creation plus route/redirect hooks before
  the supervisor can publish runtime readiness.
- `Bridge.startup_errors` records fatal TUN build failures.
- `Supervisor::start_with_registry` rejects non-empty startup errors before
  `sing-box started`.
- Reload paths also call the same bridge startup check, but package03 does not
  claim package05 reload continuity or bind readiness closure.

## Live smoke

Command:

```bash
./target/debug/app run --disable-color -c /tmp/pf03-tun-smoke-utun9/config.json -D /tmp/pf03-tun-smoke-utun9
```

Config shape:

- inbound `type: "tun"`, `stack: "mixed"`, `interface_name: "utun9"`
- `address`: `172.19.0.1/30`, `fdfe:dcba:9876::1/126`
- `auto_route: true`, `strict_route: true`
- `route_address: ["10.0.0.0/8"]`
- `route_exclude_address: ["192.168.0.0/16"]`
- outbound `direct`, route final `direct`

Observed result:

```text
status=exited:1
started_seen=0
ERROR sb_adapters::register: failed to prepare TUN runtime backend inbound=tun-in error=Operation not permitted (os error 1)
Error: Supervisor::start_with_registry failed

Caused by:
    runtime startup blocked by adapter errors: tun inbound 'tun-in' failed to prepare runtime backend
```

Interpretation: the GUI default `mixed` value entered the real Enhanced/smoltcp
startup path. macOS denied the TUN open/configure operation for this normal-user
run. The process exited before `sing-box started`, so the GUI cannot mistake this
for a ready dataplane.

## Verification snapshot

| Command | Result |
|---|---|
| `cargo test -p sb-adapters --lib tun --features "adapter-tun tun router"` | PASS: 71 passed, 1 ignored |
| `cargo test -p sb-adapters --lib enhanced --features "adapter-tun tun router"` | PASS: 30 passed |
| `cargo test -p sb-config --lib pf02` | PASS: 8 passed |
| `cargo build -p app --bin app --features adapters,clash_api` | PASS |
| `cargo check --workspace --all-features` | PASS |
| `git diff --check` | PASS |
| `WORK=/tmp/pf07-after-tun bash agents-only/fable5审计报告/post_fable_packages/post_fable_package07_probe_harness.sh` | PASS: 14 pass, 0 fail |

## Remaining limits

- DONE requires a privileged/local-platform smoke that proves real TUN traffic,
  not only a real TUN startup attempt plus loud permission failure.
- `system` remains intentionally unsupported until a true system-stack backend is
  implemented.
- `gvisor` is compatibility-mapped to Enhanced/smoltcp; no gVisor netstack exists
  in this repository.
- package03 does not close WireGuard dataplane, reload continuity, generic bind
  readiness, or F-3 HTTP plain forwarding.

---

## 03b privileged dataplane acceptance harness

Date: 2026-06-14
Status: STILL PARTIAL, but boxed behind a reproducible privileged harness.

### Environment

- Platform: Darwin arm64 (`Darwin 25.5.0`, local user `bob`, UID 501).
- HEAD at start: `83387086`.
- `sudo -n true`: failed with `sudo: a password is required`.
- Local route state note: this machine already had `198.18.0.0/15` routed via
  `utun4` before the normal-user run. The harness captures before/after route
  and interface state so a privileged run can distinguish pre-existing network
  state from routes it adds.

### Harness

Path:

```bash
agents-only/fable5审计报告/post_fable_packages/post_fable_package03b_tun_smoke_harness.sh
```

Modes:

- `PF03B_MODE=normal`: validates config and expects a loud TUN permission/backend
  failure before `sing-box started`.
- `PF03B_MODE=privileged`: requires root/admin privileges and proves real traffic
  by curling a routed target without proxy flags.
- `PF03B_MODE=auto`: chooses normal for non-root, privileged for root.

The harness writes `result.json`, `config.json`, app/check/proxy logs, curl
artifacts, and before/after route/interface snapshots under `WORK`.

### Config

The generated config keeps the GUI-default-ish TUN shape:

- inbound `type: "tun"`, `tag: "pf03b-tun-in"`, `stack: "mixed"`,
  `interface_name: "utun9"`;
- `address: ["172.19.0.1/30"]`;
- `route_address: ["198.18.0.0/16"]`;
- `route_exclude_address: ["127.0.0.0/8", "::1/128"]`;
- `auto_route: true`, `strict_route: true`;
- route rule `ip_cidr: "198.18.0.0/16" -> pf03b-http-out`;
- `final: "block"` so success cannot come from the fallback outbound;
- outbound `pf03b-http-out` is an HTTP CONNECT proxy pointing to a local Python
  proof stub on `127.0.0.1:<dynamic-port>`.

Privileged success requires plain:

```bash
curl --noproxy '*' http://198.18.0.2:18080/pf03b
```

to return HTTP 200 and the local stub to log
`CONNECT 198.18.0.2:18080`.

### Commands and results

| Command | Result |
|---|---|
| `cargo test -p sb-adapters --lib tun --features "adapter-tun tun router"` | PASS: 71 passed, 1 ignored |
| `cargo test -p sb-adapters --lib enhanced --features "adapter-tun tun router"` | PASS: 30 passed |
| `cargo test -p sb-config --lib pf02` | PASS: 8 passed |
| `cargo build -p app --bin app --features adapters,clash_api` | PASS |
| `PF03B_SKIP_BUILD=1 WORK=/tmp/pf03b-tun-smoke-normal PF03B_MODE=normal bash .../post_fable_package03b_tun_smoke_harness.sh` | PASS |
| `PF03B_SKIP_BUILD=1 WORK=/tmp/pf03b-tun-smoke-privileged PF03B_MODE=privileged bash .../post_fable_package03b_tun_smoke_harness.sh` | BLOCKED, exit 3: root/admin privileges required |
| `cargo check --workspace --all-features` | PASS |
| `cargo clippy --workspace --all-features --all-targets` | PASS |

Normal-user `result.json` summary:

```json
{
  "status": "PASS",
  "message": "normal-user TUN startup failed before 'sing-box started' with a loud permission/backend error",
  "stages": {
    "config_validation": "pass",
    "tun_startup": "permission_failed_before_started",
    "sing_box_started_seen": false,
    "cleanup": "complete"
  }
}
```

Privileged `result.json` summary:

```json
{
  "status": "BLOCKED",
  "exit_code": 3,
  "message": "privileged mode requires root/admin privileges; rerun with sudo -E after building the kernel",
  "stages": {
    "config_validation": "pass",
    "tun_startup": "not_run_missing_privilege",
    "configured_outbound_hit": false,
    "cleanup": "complete"
  }
}
```

### Log excerpts

Normal-user app log:

```text
ERROR sb_adapters::register: failed to prepare TUN runtime backend inbound=pf03b-tun-in error=Operation not permitted (os error 1)
runtime startup blocked by adapter errors: tun inbound 'pf03b-tun-in' failed to prepare runtime backend
```

Config validation log:

```text
Config validation passed
```

### Conclusion

03b does not close package03 as DONE on this machine because the privileged
dataplane proof did not run. The closure state is now better boxed:

- normal-user GUI-style TUN startup behavior is deterministic and loud;
- privileged real-traffic proof has a one-command harness and exact acceptance
  criteria;
- the local blocker is specific: no root/admin privilege is available through
  noninteractive sudo in this agent session.

---

## package15 closeout pointer

Package15 adds
`post_fable_package15_acceptance_closeout_manual_gates.sh` as the post-FABLE
manual-gate index. It reruns/captures the 03b normal-user and privileged gates
under a shared `WORK` directory, preserving package03 as PARTIAL unless the
privileged dataplane proof actually passes.

---

## package17 external acceptance execution

Date: 2026-06-16.

Artifact roots:

- `/tmp/pf17_external_acceptance/`
- `/tmp/pf17_tun_normal/`
- `/tmp/pf17_tun_privileged/`

Environment:

- macOS arm64 (`Darwin ... arm64`).
- UID 501 (`bob`).
- `sudo -n true` failed with `sudo: a password is required`.

Commands:

| Command | Result |
|---|---|
| `cargo build -p app --bin app --features gui_runtime` | PASS |
| `./target/debug/app version` | PASS: `sing-box version 0.1.0 (0d1cbe7b1426)` observed |
| `PF03B_SKIP_BUILD=1 WORK=/tmp/pf17_tun_normal PF03B_MODE=normal bash .../post_fable_package03b_tun_smoke_harness.sh` | PASS |
| `PF03B_SKIP_BUILD=1 WORK=/tmp/pf17_tun_privileged PF03B_MODE=privileged bash .../post_fable_package03b_tun_smoke_harness.sh` | BLOCKED, exit 3 |

Normal-user result excerpt:

```json
{
  "status": "PASS",
  "message": "normal-user TUN startup failed before 'sing-box started' with a loud permission/backend error",
  "stages": {
    "config_validation": "pass",
    "tun_startup": "permission_failed_before_started",
    "sing_box_started_seen": false,
    "cleanup": "complete",
    "configured_outbound_hit": false,
    "curl_success": false
  },
  "uid": 501
}
```

Normal-user app log excerpt:

```text
ERROR sb_adapters::register: failed to prepare TUN runtime backend inbound=pf03b-tun-in error=Operation not permitted (os error 1)
runtime startup blocked by adapter errors: tun inbound 'pf03b-tun-in' failed to prepare runtime backend
```

Privileged result excerpt:

```json
{
  "status": "BLOCKED",
  "exit_code": 3,
  "message": "privileged mode requires root/admin privileges; rerun with sudo -E after building the kernel",
  "stages": {
    "config_validation": "pass",
    "tun_startup": "not_run_missing_privilege",
    "sing_box_started_seen": false,
    "cleanup": "complete",
    "configured_outbound_hit": false,
    "curl_success": false
  },
  "uid": 501
}
```

Conclusion:

Package17 did not obtain the required privileged TUN dataplane PASS. package03
therefore remains PARTIAL. The residual gate is exactly the root/admin rerun of
the 03b harness; success still requires `configured_outbound_hit=true`, curl
HTTP 200, `sing-box started`, and cleanup complete.

---

## post003 extension: UDP NAT + IPv6 TUN dataplane

Date: 2026-06-20.

Scope decision (user-directed): close package03 by extending the Enhanced TUN
datapath beyond TCP/IPv4 to cover UDP forwarding and IPv6, not just by re-running
the existing privileged TCP proof.

### Findings that shaped the work

- The "Enhanced/smoltcp" backend is a hand-rolled TCP/IP state machine
  (`tun_enhanced.rs`); the real smoltcp `TunStack` is unused dead code. The name
  is a misnomer. No smoltcp was added or removed here.
- Before this change: `process_packet` only parsed TCP, so UDP (proto 17) was
  silently dropped; `build_tcp_response_packet` returned `Unsupported` for IPv6,
  so IPv6 TCP egress was broken.
- `OutboundRegistryHandle` had `connect_tcp` but no `connect_udp`.
- Real bug found and fixed: `DirectUdpTransport::send_to` used `send_to` on a
  *connected* UDP socket, which macOS/BSD rejects with EISCONN ("Socket is
  already connected", os error 56). This would also have failed a live UDP proof.

### Implementation

- `crates/sb-adapters/src/inbound/tun_packet.rs`: added `build_ipv6_tcp_packet`,
  `build_ipv6_udp_packet`, and IPv6 pseudo-header checksums
  (`calculate_tcp_checksum_ipv6`, `calculate_udp_checksum_ipv6`). All emit bare IP
  packets (no AF prefix); the macOS platform `write` adds the 4-byte AF header.
- `crates/sb-adapters/src/inbound/tun_session.rs`: `build_tcp_response_packet`
  now handles IPv6; new `build_udp_response_packet` dispatches v4/v6 and rejects
  mixed-family tuples.
- `crates/sb-core/src/outbound/mod.rs`: new `OutboundRegistryHandle::connect_udp`
  (Direct → `DirectConnector::connect_udp`; Block → PermissionDenied; HTTP / SOCKS5
  / Naive / Hysteria2 → loud `Unsupported`). SOCKS5/Hysteria2 UDP associate is a
  documented future item.
- `crates/sb-core/src/outbound/direct_connector.rs`: `DirectUdpTransport::send_to`
  uses `send` on a connected socket (EISCONN fix), falling back to `send_to` for
  unconnected sockets.
- `crates/sb-adapters/src/inbound/tun_udp.rs` (new): `EnhancedUdpNat` — per-flow
  NAT keyed by the client 4-tuple, reverse relay task that writes bare IP/UDP
  reply packets back to TUN, idle TTL eviction, 4096-entry cap, MTU-bounded
  replies. Header references P1313-09 as the owner of any future general UDP NAT.
- `crates/sb-adapters/src/inbound/tun_enhanced.rs`: `parse_raw_udp` (+ v4/v6
  helpers), `process_packet` UDP branch, `forward_udp`/`route_udp_tuple`
  (`Transport::Udp`), an `udp_nat` field wired through all four constructors, and
  a periodic eviction task started/stopped around the packet loop.

### UDP live-proof limitation (honest)

A single-host *live* UDP-through-utun proof with a `direct` outbound is not
feasible: `direct` dials the literal destination, which `auto_route` sends back
into utun (routing loop); a more-specific loopback alias short-circuits both the
client and the outbound to lo0, so neither traverses the TUN. Destination override
(route-options) would resolve this but belongs to P1313-04. Therefore UDP is
proven by composition:

- the full Rust UDP path (parse → route → outbound send → reverse relay → write
  back) is proven by the deterministic unit test
  `udp_forward_direct_echo_relays_back` (real `DirectConnector` UDP socket + real
  reverse relay, no root);
- the shared utun device read/write path is proven live by the TCP probes;
- `parse_raw_udp` is unit-tested.

IPv6 TCP, by contrast, is proven live through utun because the 03b harness routes
an IPv6 target into the tunnel while the outbound dials IPv4 loopback (no loop).

### Local verification (non-root)

| Command | Result |
|---|---|
| `cargo test -p sb-adapters --lib tun_packet --features "adapter-tun tun router"` | PASS (incl. IPv6 v4/v6 checksum verify-to-0) |
| `cargo test -p sb-adapters --lib tun_session --features "adapter-tun tun router"` | PASS (IPv6 TCP roundtrip + UDP v4/v6 + mixed-family reject) |
| `cargo test -p sb-adapters --lib tun_udp --features "adapter-tun tun router"` | PASS (ttl/eviction-period/mtu floor) |
| `cargo test -p sb-adapters --lib inbound::tun_enhanced --features "adapter-tun tun router"` | PASS (incl. `udp_forward_direct_echo_relays_back`, `bootstrap_tcp_session_ipv6_syn_sends_syn_ack`, `parse_raw_udp_*`) |
| `cargo test -p sb-adapters --lib tun --features "adapter-tun tun router"` | 85 passed, 1 ignored |
| `cargo test -p sb-core --lib outbound --features router` | 85 passed |
| `cargo check --workspace --all-features` | PASS |
| `cargo build -p app --bin app --features gui_runtime` | PASS |
| `cargo clippy --workspace --all-features --all-targets` | 0 warnings |
| `git diff --check` | clean |
| `PF03B_MODE=normal bash .../post_fable_package03b_tun_smoke_harness.sh` | PASS (config with IPv6 fields validates; TUN startup fails before `sing-box started` with permission error) |

`make boundaries`: 2 pre-existing assertion failures (`W75-01` in `bridge.rs`,
`W199-03` in `register.rs`) confirmed present on a clean stashed HEAD and unrelated
to this change; no new violations introduced.

### 03b harness extension

`post_fable_package03b_tun_smoke_harness.sh` now adds an IPv6 TCP probe
(`PF03B_PROBE_IPV6=1`, default on): the generated config gains an IPv6 TUN address
(`fd00:19::1/64`), an IPv6 `route_address` (`fd00:db8::/32`), and a second route
rule to the same HTTP proxy outbound; privileged mode curls
`http://[fd00:db8::2]:18080`. The privileged PASS now requires both the IPv4 and
IPv6 TCP proofs (plus cleanup complete). `result.json` gained `curl6_*` and
`configured_outbound6_hit` fields, and root-mode adds best-effort IPv6 route
cleanup.

### Privileged proof status

DONE (2026-06-20). Root rerun of the extended 03b harness passed end-to-end.

First privileged attempt (`WORK=/tmp/pf03b_post003_privileged`) FAILED with a precise,
newly-surfaced breakpoint: TUN traffic for both IPv4 and IPv6 entered utun, was parsed,
and routed to the HTTP outbound, but `connect_tcp` returned
`HTTP proxy uses CONNECT method ...; use switchboard registry instead` — i.e. the
Enhanced TUN datapath could not egress through proxy outbounds at all (direct-only).
This pre-existing gap was never exercised before because no privileged run had ever
completed. Fixed by `connect_tcp_stream` + boxed-stream session relay (see below).

Second privileged attempt (`WORK=/tmp/pf03b_post003_privileged2`) PASS:

```json
{
  "status": "PASS", "exit_code": 0,
  "stages": {
    "config_validation": "pass",
    "tun_startup": "started",
    "sing_box_started_seen": true,
    "curl_http_status": "200",  "curl_success": true,  "configured_outbound_hit": true,
    "curl6_http_status": "200", "curl6_success": true, "configured_outbound6_hit": true,
    "cleanup": "complete"
  }
}
```

`connect_proxy.log` confirmed both stacks tunnelled through the HTTP outbound:

```text
CONNECT_LINE CONNECT 198.18.0.2:18080 HTTP/1.1
TUNNELED_LINE GET /pf03b HTTP/1.1
CONNECT_LINE CONNECT fd00:db8::2:18080 HTTP/1.1
TUNNELED_LINE GET /pf03b HTTP/1.1
```

This live root run proves, end-to-end: real utun device read/write; IPv4 and IPv6 packet
parsing; IPv6 reply-packet construction (IPv6 traffic fully round-tripped); routing to the
outbound; TUN egress through an HTTP proxy outbound; and the hand-rolled TCP engine working
against a real macOS kernel TCP client (curl). UDP remains proven by the deterministic unit
test (live single-host UDP-through-utun-via-direct is infeasible per the loop note above).

### Follow-up fix surfaced by the live run: TUN egress through proxy outbounds

The first privileged run revealed that the Enhanced TUN datapath could only use `direct`:
proxy outbounds registered as adapter `Connector`s expose `connect()` (raw `TcpStream`),
which the HTTP/SOCKS wrappers intentionally refuse ("use switchboard registry instead").
The datapath relied on `connect_tcp` returning a `TcpStream`, so all proxy egress failed.

Fix:

- `crates/sb-core/src/outbound/mod.rs`: new `OutboundRegistryHandle::connect_tcp_stream`
  returning `sb_transport::IoStream`. `Connector` outbounds are dialed via `connect_io`
  (the CONNECT-aware path; gated on `v2ray_transport`, always on in adapter/app builds,
  with a raw-`connect` fallback otherwise); Direct/SOCKS5/HTTP/Naive/Hysteria2 are boxed.
- `crates/sb-adapters/src/inbound/tun_session.rs`: `create_session_with_state` and the two
  relay tasks are now generic over `S: AsyncRead + AsyncWrite + Unpin + Send` (split with
  `tokio::io::split`); the session's outbound address is taken from the routed tuple.
- `crates/sb-adapters/src/inbound/tun_enhanced.rs`: `bootstrap_tcp_session` now uses
  `connect_tcp_stream`, so TUN traffic egresses through HTTP/SOCKS/layered outbounds.

This makes TUN a real catch-all that works with proxy outbounds — a core drop-in capability,
not only `direct`.

### post003 conclusion

package03 is DONE: GUI-default `stack:"mixed"` TUN carries live TCP traffic (IPv4 + IPv6)
through a configured proxy outbound and returns it through the tunnel; UDP NAT and IPv6
reply packets are implemented and verified (UDP by unit test, IPv6 live). Remaining
documented limitations: SOCKS5/Hysteria2 UDP associate (loud `Unsupported`, future work);
IP fragmentation not handled (over-MTU datagrams dropped); single-host live UDP-through-utun
proof infeasible without destination override (P1313-04). UDP/IPv6 general NAT layer ownership
stays with P1313-09.


