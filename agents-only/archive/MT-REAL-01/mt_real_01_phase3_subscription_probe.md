# MT-REAL-01 Phase 3 Subscription Probe

## Scope

- Probe the user-provided real subscription.
- Verify whether `GUI.for.SingBox` has actually pulled and cached it.
- Attempt Rust real-upstream bring-up on isolated ports `127.0.0.1:19090` and `127.0.0.1:11080`.

## Subscription Findings

- Raw subscription payload contains 22 links total.
- Protocol mix:
  - `vless`: 21
  - `anytls`: 1
- This does **not** satisfy the original Phase 3 protocol coverage target of `shadowsocks + trojan + vmess`.

## GUI Subscription Pull

- `GUI.for.SingBox` local state already contains this subscription in:
  - `~/Library/Application Support/GUI.for.SingBox/subscribes.yaml`
  - `~/Library/Application Support/GUI.for.SingBox/subscribes/ID_ekfvjidr.json`
- GUI metadata shows:
  - subscription name: `CTC2`
  - update time: `2026-04-13 15:29:02 +08:00`
- GUI cache currently materializes:
  - 21 nodes
  - protocol set: `["vless"]`
- New finding:
  - the raw subscription also contains 1 `anytls` link, but that protocol does not appear in the GUI cache file for this subscription.

## Rust Bring-Up

- Local Phase 3 config was generated to `agents-only/mt_real_01_evidence/phase3_real_upstream.json` and kept out of git via `.gitignore`.
- Rust core starts successfully on the requested isolated ports:
  - Clash API: `127.0.0.1:19090`
  - mixed inbound: `127.0.0.1:11080`
- Control-plane verification passes:
  - `GET /version`
  - `GET /configs`
  - `GET /proxies`
  - selector/urltest groups are visible

## Real Dataplane Blocker

- SOCKS5 egress immediately fails when the selector points at any real VLESS node.
- Root cause is a Rust-side bug in [crates/sb-adapters/src/register.rs](/Users/bob/Desktop/Projects/ING/sing/singbox-rust/crates/sb-adapters/src/register.rs:222):
  - `parse_required_outbound_socket_addr()` builds `"{server}:{port}"` and parses it as `SocketAddr`
  - domain-form servers such as `hk08.ctcxianyu.com:10012` are therefore rejected during outbound registration
  - selector then fails with `vless outbound is disabled due to invalid config`

## Environment Finding

- Under the current baseline network environment, resolving the subscription hostnames returns `198.18.1.x` fake-IP addresses.
- Because of that, replacing domain names with locally resolved IPs is not a trustworthy workaround for Phase 3 real-upstream validation.

## Status

- GUI subscription pull: `PASS`
- Rust Clash API + selector/urltest control plane on real-subscription config: `PASS`
- Rust real VLESS upstream connectivity: `FAIL`
- Original Phase 3 protocol coverage (`ss/trojan/vmess`): `ENV-LIMITED`

## Next Input Needed

- To finish the original Phase 3 matrix, provide either:
  - a subscription that includes `shadowsocks`, `trojan`, and `vmess`, or
  - individual nodes for those three protocols.
