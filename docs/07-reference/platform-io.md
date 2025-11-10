# Platform IO Support Matrix

This page summarizes platform-specific IO capabilities (TUN/wintun and transparent proxy inbounds like redirect/tproxy), their current status in the Rust implementation, and suggested alternatives when unavailable.

Status legend: ✅ Supported • ◐ Partial • ✗ Not available

## Summary

- Linux
  - TUN: ✅ via `sb-platform` Linux TUN (device creation/config). Integration into the TUN inbound is still conservative in scaffold mode.
  - redirect (iptables REDIRECT): ◐ Code exists under `sb-adapters` (`inbound/redirect.rs`), not yet wired to config in this build. Clear error is emitted if configured.
  - tproxy (IP_TRANSPARENT): ◐ Code exists under `sb-adapters` (`inbound/tproxy.rs`), not yet wired to config in this build. Clear error is emitted if configured.
- macOS
  - TUN (utun): ◐ Supported through `sb-platform::tun::MacOsTun` and optional `tun2socks` pipeline under `sb-adapters` (`tun_macos`). Scaffold TUN inbound remains a stub (parses/sniffs; no device IO by default).
  - redirect/tproxy: ✗ Not available on macOS.
- Windows
  - WinTun: ◐ Placeholder adapter in `sb-platform::tun::windows` (requires WinTun). Not fully integrated; scaffold TUN inbound is a stub by default.
  - redirect/tproxy: ✗ Not available on Windows.

## Configuration and Feature Flags

- Inbounds
  - `type: tun` — available on all platforms. In scaffold mode it runs without real device IO; advanced pipelines live in `sb-adapters`.
  - `type: redirect` (Linux-only) — accepted by IR; current build emits a clear error at startup: not wired yet. Suggested alternatives: `tun`, `socks`, `http` inbounds.
  - `type: tproxy` (Linux-only) — accepted by IR; current build emits a clear error at startup: not wired yet. Suggested alternatives: `tun`, `socks`, `http` inbounds.

- Adapter features (optional, for future wiring):
  - `sb-adapters/redirect`, `sb-adapters/tproxy` (Linux)
  - `sb-adapters/tun_macos` (macOS, utun + tun2socks)
  - `sb-adapters/tun_linux` (Linux, native TUN)
  - `sb-adapters/tun_windows` (Windows, WinTun)

## Error Messages and Alternatives

When `redirect` or `tproxy` are configured in the current build, the runtime logs an error like:

- inbound 'redirect' is not supported on this platform: requires Linux iptables REDIRECT and adapter integration. Hint: Use 'tun' inbound (platform TUN) or local SOCKS/HTTP instead.

This is intentional per WS9: document platform differences, provide safe defaults, and suggest alternatives.

## Notes

- For Linux transparent proxying today, prefer `type: tun` with appropriate route rules. When adapter wiring is enabled in a future milestone, `redirect`/`tproxy` will be turned on under Linux with clear capability checks.
- WinTun requires driver installation and Administrator privileges. The current Windows implementation is a placeholder; use SOCKS/HTTP inbounds as a fallback.

