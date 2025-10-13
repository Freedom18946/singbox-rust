# sing-box Parity Matrix

Baseline: SagerNet/sing-box `dev-next` (GitHub, 2025-10-12)  
Last audited: 2025-10-12 22:10 UTC

Status legend
- ✅ Supported: behaviour matches upstream for the documented surface
- ◐ Partial: implementation exists but lacks upstream options, integration, or packaging
- ✗ Missing: no usable implementation yet

## CLI Surface (single binary expected)

| Feature | Upstream reference | Status | Notes |
| --- | --- | --- | --- |
| Unified `sing-box` dispatcher | `cmd/sing-box/cmd.go` | ✗ Missing | `app/src/main.rs` wires only `check` / `auth` / `prom` / `run` / `route` / `version`; the rest of the commands live as standalone binaries under `app/src/bin/*` and are not exposed as subcommands. |
| `check` | `cmd/sing-box/cmd_check.go` | ◐ Partial | `app/src/bin/check.rs` validates only basic HTTP/SOCKS/TUN shapes; no schema enforcement for DNS, services, or advanced adapters. |
| `format` | `cmd/sing-box/cmd_format.go` | ◐ Partial | Implemented as a separate binary in `app/src/bin/format.rs`; lacks integration with the main CLI and only handles JSON (no upstream directory recursion defaults). |
| `merge` | `cmd/sing-box/cmd_merge.go` | ◐ Partial | `app/src/bin/merge.rs` covers basic merge but omits upstream conflict diagnostics and recursive directory loading. |
| `generate` (reality/ech/tls/wireguard/vapid) | `cmd/sing-box/cmd_generate*.go` | ✅ Supported | Implemented inside the main CLI (`app/src/cli/generate.rs`) with parity subcommands. |
| `geoip` | `cmd/sing-box/cmd_geoip*.go` | ◐ Partial | Provided as standalone CLI (`app/src/bin/geoip.rs`); requires manual DB paths and does not bundle sing-geoip data. |
| `geosite` | `cmd/sing-box/cmd_geosite*.go` | ◐ Partial | `app/src/bin/geosite.rs` supports list/lookup/export against text DBs only; no binary DB or auto-update. |
| `rule-set` | `cmd/sing-box/cmd_rule_set*.go` | ◐ Partial | `app/src/bin/ruleset.rs` exposes inspect/format but omit compile/decompile/upgrade flow implemented upstream. |
| `tools` (`connect`, `fetch`, `synctime`, `fetch-http3`) | `cmd/sing-box/cmd_tools*.go` | ◐ Partial | `app/src/bin/tools.rs` implements TCP connect/fetch/synctime; HTTP/3 path is gated and QUIC tooling differs from upstream. |
| `run` | `cmd/sing-box/cmd_run.go` | ◐ Partial | Entry exists via `app/src/main.rs:24`, yet the loader (`app/src/config_loader.rs`) only understands HTTP/SOCKS/TUN inbounds and a subset of outbounds. |
| `version` | `cmd/sing-box/cmd_version.go` | ✅ Supported | `app/src/cli/version.rs` prints semantic version plus JSON format flag. |

## Configuration Coverage

### Top-level sections

| Section | Upstream doc | Status | Notes |
| --- | --- | --- | --- |
| `log` | `docs/configuration/log/index.md` | ✗ Missing | No serializer in `crates/sb-config`; settings are ignored during load. |
| `dns` | `docs/configuration/dns/index.md` | ✗ Missing | DNS block absent from `crates/sb-config`; runtime cannot configure resolvers. |
| `ntp` | `docs/configuration/ntp/index.md` | ✗ Missing | NTP service is not modelled or started. |
| `certificate` | `docs/configuration/certificate/index.md` | ✗ Missing | No certificate loader or reference counting. |
| `endpoints` | `docs/configuration/endpoint/index.md` | ✗ Missing | Endpoint arrays unsupported; `sb-config` lacks data structures. |
| `inbounds` | `docs/configuration/inbound/index.md` | ◐ Partial | Only HTTP/SOCKS/TUN (and simplified direct) are recognised by `crates/sb-config/src/model.rs`. |
| `outbounds` | `docs/configuration/outbound/index.md` | ◐ Partial | `crates/sb-config/src/model.rs` exposes only direct/block; richer definitions in `crates/sb-config/src/outbound.rs` are not invoked by the loader. |
| `route` | `docs/configuration/route/index.md` | ◐ Partial | IR supports geoip/geosite/port (`crates/sb-config/src/ir/mod.rs`), but CLI lacks rule-set tooling and schema validation. |
| `services` | `docs/configuration/service/index.md` | ✗ Missing | DERP/resolved/ssm-api definitions are not present. |
| `experimental` | `docs/configuration/experimental/index.md` | ✗ Missing | No bridge for experimental options. |

### Inbound protocols

| Protocol | Upstream doc | Status | Notes |
| --- | --- | --- | --- |
| `http` | `docs/configuration/inbound/http.md` | ◐ Partial | Adapter available (`crates/sb-adapters/src/inbound/http.rs`), yet config exposes only minimal listen/auth fields (`crates/sb-config/src/model.rs`). |
| `socks` | `docs/configuration/inbound/socks.md` | ◐ Partial | TCP logic present (`crates/sb-adapters/src/inbound/socks/tcp.rs`); UDP assist and advanced auth are not surfaced. |
| `tun` | `docs/configuration/inbound/tun.md` | ◐ Partial | Multiple platform variants exist, but config allows only optional name. |
| `direct` | `docs/configuration/inbound/direct.md` | ◐ Partial | Forwarder implemented (`crates/sb-core/src/inbound/direct.rs`) yet unreachable via current config/CLI. |
| `redirect` / `tproxy` | `docs/configuration/inbound/redirect.md` / `.../tproxy.md` | ✗ Missing | Linux adapters exist but no IR/CLI glue to instantiate them. |
| `shadowsocks`, `shadowtls`, `trojan`, `vless`, `vmess`, `naive`, `hysteria`, `hysteria2`, `tuic`, `anytls` | respective docs | ✗ Missing | Core adapters under `crates/sb-adapters/src/inbound/` are not exposed through configuration or runtime selection; V2Ray transport options remain inaccessible. |

### Outbound protocols

| Protocol | Upstream doc | Status | Notes |
| --- | --- | --- | --- |
| `direct` / `block` | `docs/configuration/outbound/direct.md` / `.../block.md` | ◐ Partial | Supported via `crates/sb-config/src/model.rs`, but advanced dialing controls are absent. |
| `http` / `socks` | `docs/configuration/outbound/http.md` / `.../socks.md` | ◐ Partial | Parsing exists (`crates/sb-config/src/outbound.rs`), yet TLS/transport settings are not forwarded to adapters. |
| `vmess` / `vless` | `docs/configuration/outbound/vmess.md` / `.../vless.md` | ◐ Partial | Structs defined in `crates/sb-config/src/outbound.rs`; runtime multiplex/transport wiring is incomplete. |
| `tuic` | `docs/configuration/outbound/tuic.md` | ◐ Partial | Config struct present, but runtime omits zero-RTT/UDP relay parity. |
| `shadowsocks`, `shadowtls`, `trojan`, `hysteria`, `hysteria2`, `ssh` | respective docs | ✗ Missing | Either no config types or adapters remain stubs; e.g., WireGuard uses `Unsupported` stub (`crates/sb-core/src/outbound/wireguard_stub.rs`). |
| `anytls`, `tor`, `urltest`, `wireguard` | respective docs | ✗ Missing | No usable implementation or only placeholder scaffolding. |
| `selector` / `urltest` | `docs/configuration/outbound/selector.md` / `.../urltest.md` | ◐ Partial | `crates/sb-core/src/outbound/selector_group.rs` exists, but requires manual wiring and lacks health-check integration. |

## Services

| Service | Upstream doc | Status | Notes |
| --- | --- | --- | --- |
| `derp` | `docs/configuration/service/derp.md` | ✗ Missing | Repository lacks DERP service implementation; `rg derp` only finds documentation. |
| `resolved` | `docs/configuration/service/resolved.md` | ✗ Missing | No resolver bridge or config. |
| `ssm-api` | `docs/configuration/service/ssm-api.md` | ✗ Missing | Admin API scaffolding absent. |

## Geo & Rule-Set Tooling

| Area | Upstream reference | Status | Notes |
| --- | --- | --- | --- |
| GeoIP database tooling | `cmd/sing-box/cmd_geoip*.go` | ◐ Partial | `app/src/bin/geoip.rs` handles text/MMDB input but the project does not ship databases or caching helpers. |
| Geosite database tooling | `cmd/sing-box/cmd_geosite*.go` | ◐ Partial | `app/src/bin/geosite.rs` works with text DB only; no binary format or updater. |
| Rule-set compile/convert | `cmd/sing-box/cmd_rule_set*.go` | ✗ Missing | `app/src/bin/ruleset.rs` inspects metadata but lacks compile/decompile/upgrade flows. |

## Runtime Observations

- WireGuard outbound remains a stub returning `Unsupported` (`crates/sb-core/src/outbound/wireguard_stub.rs:41`).
- The config loader discards advanced sections (`app/src/config_loader.rs`) so adapters beyond HTTP/SOCKS/TUN cannot be instantiated.
- No automation for packaging GeoIP/Geosite or rule-set assets; builds rely on external files.

## Summary of Priority Gaps

1. Deliver a unified CLI that mirrors upstream subcommand behaviour (`app/src/main.rs`, `app/src/bin/*`).
2. Expand `sb-config` to parse the full configuration schema and map to adapters (inbounds, outbounds, services, experimental).
3. Expose and complete high-traffic protocol adapters (shadowsocks/trojan/vless/vmess) currently blocked by configuration gaps.
4. Finish GeoIP/Geosite/Rule-set tooling, including data distribution and compile/decompile support.
5. Replace protocol stubs (WireGuard, AnyTLS, Tor) with working implementations or document intentional exclusions.
