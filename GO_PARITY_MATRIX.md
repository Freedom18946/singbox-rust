# sing-box Parity Matrix

Baseline: SagerNet/sing-box `dev-next` (GitHub, 2025-10-14)
Last audited: 2025-10-14 23:30 UTC

Status legend
- ✅ Supported: behaviour matches upstream for the documented surface
- ◐ Partial: implementation exists but lacks upstream options, integration, or packaging
- ✗ Missing: no usable implementation yet

## CLI Surface (single binary expected)

| Feature | Upstream reference | Status | Notes |
| --- | --- | --- | --- |
| Unified `sing-box` dispatcher | `cmd/sing-box/cmd.go` | ◐ Partial | Unified dispatcher exists at `app/src/main.rs`; subcommands (`check/merge/format/generate/geoip/geosite/ruleset/run/tools/version`) are wired behind features. Runtime `run` remains limited by config→runtime bridging. |
| `check` | `cmd/sing-box/cmd_check.go` | ◐ Partial | `app/src/bin/check.rs` validates only basic HTTP/SOCKS/TUN shapes; no schema enforcement for DNS, services, or advanced adapters. |
| `format` | `cmd/sing-box/cmd_format.go` | ◐ Partial | Implemented at `app/src/cli/format.rs`; JSON/YAML support present; directory recursion and some defaults differ from upstream. |
| `merge` | `cmd/sing-box/cmd_merge.go` | ◐ Partial | `app/src/cli/merge.rs` covers basic merge; missing upstream-grade conflict diagnostics and recursive directory loading. |
| `generate` (reality/ech/tls/wireguard/vapid) | `cmd/sing-box/cmd_generate*.go` | ✅ Supported | Implemented inside the main CLI (`app/src/cli/generate.rs`) with parity subcommands. |
| `geoip` | `cmd/sing-box/cmd_geoip*.go` | ◐ Partial | `app/src/cli/geoip.rs` supports list/lookup/export; manual DB paths; dataset not bundled; no auto-update. |
| `geosite` | `cmd/sing-box/cmd_geosite*.go` | ◐ Partial | `app/src/cli/geosite.rs` works with text DB; no binary DB or updater. |
| `rule-set` | `cmd/sing-box/cmd_rule_set*.go` | ◐ Partial | `app/src/cli/ruleset.rs` has validate/info/format; compile/decompile/upgrade parity incomplete. |
| `tools` (`connect`, `fetch`, `synctime`, `fetch-http3`) | `cmd/sing-box/cmd_tools*.go` | ◐ Partial | `app/src/cli/tools.rs` implements connect/fetch/synctime; HTTP/3 feature-gated; QUIC tooling differs. |
| `run` | `cmd/sing-box/cmd_run.go` | ◐ Partial | Entry exists; config→runtime bridge incomplete: inbounds/router/outbounds not fully instantiated; hot reload disabled. |
| `version` | `cmd/sing-box/cmd_version.go` | ✅ Supported | `app/src/cli/version.rs` prints semantic version plus JSON format flag. |

## Configuration Coverage

### Top-level sections

| Section | Upstream doc | Status | Notes |
| --- | --- | --- | --- |
| `log` | `docs/configuration/log/index.md` | ✗ Missing | Not consumed by runtime; no serializer hook. |
| `dns` | `docs/configuration/dns/index.md` | ◐ Partial | Schema present (tests/golden); not converted to IR or wired to runtime resolver; env still controls backends. |
| `ntp` | `docs/configuration/ntp/index.md` | ◐ Partial | Fields present in tests; runtime service feature-gated and not started from config. |
| `certificate` | `docs/configuration/certificate/index.md` | ✗ Missing | No certificate loader or reference counting in runtime. |
| `endpoints` | `docs/configuration/endpoint/index.md` | ✗ Missing | Endpoint arrays unsupported in runtime. |
| `inbounds` | `docs/configuration/inbound/index.md` | ◐ Partial | IR supports HTTP/SOCKS/TUN/Direct; runtime start-up path disabled; advanced inbounds not exposed. |
| `outbounds` | `docs/configuration/outbound/index.md` | ◐ Partial | IR parses major protocols; builders not invoked to create adapters; many transport options env-driven. |
| `route` | `docs/configuration/route/index.md` | ◐ Partial | IR rich; runtime does not install router index from IR by default; hot-reload disabled. |
| `services` | `docs/configuration/service/index.md` | ✗ Missing | DERP/resolved/ssm-api not implemented. |
| `experimental` | `docs/configuration/experimental/index.md` | ✗ Missing | No runtime bridge. |

### Inbound protocols

| Protocol | Upstream doc | Status | Notes |
| --- | --- | --- | --- |
| `http` | `docs/configuration/inbound/http.md` | ◐ Partial | Adapter exists; runtime start disabled; advanced fields not surfaced. |
| `socks` | `docs/configuration/inbound/socks.md` | ◐ Partial | TCP/UDP support present; runtime start disabled; auth variants limited in config. |
| `tun` | `docs/configuration/inbound/tun.md` | ◐ Partial | Started from config (phase-1 skeleton). No L3/L4 forwarding yet. |
| `direct` | `docs/configuration/inbound/direct.md` | ◐ Partial | Started from config (TCP+UDP forwarder); basic timeouts; no auth. |
| `redirect` / `tproxy` | `docs/configuration/inbound/redirect.md` / `.../tproxy.md` | ◐ Partial | Adapters implemented; missing IR/runtime glue. |
| `shadowsocks`, `shadowtls`, `trojan`, `vless`, `vmess`, `naive`, `hysteria`, `hysteria2`, `tuic`, `anytls` | respective docs | ◐ Partial | Implementations exist in `sb-adapters`; lacking config→runtime wiring and advanced options exposure. |

### Outbound protocols

| Protocol | Upstream doc | Status | Notes |
| --- | --- | --- | --- |
| `direct` / `block` | `docs/configuration/outbound/direct.md` / `.../block.md` | ◐ Partial | Implemented; IR present; runtime builder path incomplete; advanced dial controls limited. |
| `http` / `socks` | `docs/configuration/outbound/http.md` / `.../socks.md` | ◐ Partial | Parsing exists; TLS/transport settings not fully forwarded; env toggles used for transport. |
| `vmess` / `vless` | `docs/configuration/outbound/vmess.md` / `.../vless.md` | ◐ Partial | Outbound code exists; multiplex/transport configuration not driven from IR yet. |
| `tuic` | `docs/configuration/outbound/tuic.md` | ◐ Partial | Outbound present; some features (0-RTT/UDP relay options) need parity checks. |
| `shadowsocks`, `shadowtls`, `trojan`, `hysteria`, `hysteria2`, `ssh` | respective docs | ◐ Partial | Implementations exist; config-driven builders incomplete; SSH is limited; WireGuard remains stub. |
| `anytls`, `tor`, `wireguard` | respective docs | ✗ Missing | No usable implementation or only placeholder (WireGuard stub). |
| `selector` / `urltest` | `docs/configuration/outbound/selector.md` / `.../urltest.md` | ◐ Partial | Selector (manual) wired from config using core selector; URLTest pending. |

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

- `run` path now starts HTTP/SOCKS/TUN inbounds from IR, installs router index; hot reload updates router index and outbound registry (inbounds not hot-reloaded).
- DNS pool minimally consumed from `dns.servers` (env still overrides via `SB_DNS_*`).
- V2Ray transport chain (TLS/WS/H2/HTTPUpgrade/gRPC) for VMess/VLESS uses env toggles; not IR-driven.
- WireGuard outbound remains a stub (`crates/sb-core/src/outbound/wireguard_stub.rs`).
- No automation for packaging GeoIP/Geosite or rule-set assets; builds rely on external files.

## Summary of Priority Gaps

1. Bridge `ConfigIR` → runtime: start inbounds/router/outbounds; enable hot reload; wire selector/urltest and health checks.
2. Consume `dns` block: backend pool/strategy from config, env as override; unify resolver metrics/errors.
3. Drive P0 protocol outbounds from IR with transport/multiplex options (VMess/VLESS/Trojan/Shadowsocks/TUIC/Hysteria2).
4. Add sniff→route conditions; ensure performance and correctness at scale.
5. Finish rule-set compile/decompile/upgrade and package GeoIP/Geosite datasets with updater.
6. Address stubs or document exclusions (WireGuard, AnyTLS, Tor); add conformance tests.

## Planned Milestones
- M1: Minimal run path from config (HTTP/SOCKS/TUN + direct/block/http/socks) with router and hot reload.
- M2: P0 protocol activation with transport/multiplex and selector/urltest; DNS config integration.
- M3: Sniffing-based routing, tooling parity (rule-set/geo), `ntp` service from config; publish packaging scripts.
