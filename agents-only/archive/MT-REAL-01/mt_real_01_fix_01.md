# MT-REAL-01-FIX-01: Domain-Host VMess/VLESS Outbound Registration Fix

## Scope

- Fix Rust-side outbound registration so VMess/VLESS outbounds accept domain-form `server` values.
- Re-run the requested verification gates:
  - `cargo test -p sb-adapters`
  - `cargo clippy --workspace --all-features --all-targets -- -D warnings`
  - `cargo test -p interop-lab`
  - `cargo test -p sb-core`
- Resume MT-REAL-01 Phase 3 with the existing real-subscription config.

## Code Changes

- `crates/sb-adapters/src/register.rs`
  - `parse_required_outbound_socket_addr()` no longer parses `server:port` as `SocketAddr`.
  - It now validates `server` is non-empty and `port > 0`, then returns `(String, u16)`.
  - VMess/VLESS builders now pass `server` and `port` through directly.
- `crates/sb-adapters/src/outbound/vmess.rs`
  - `VmessConfig` now stores `server: String` and `port: u16`.
  - Dial paths use the configured host directly instead of `SocketAddr::ip()`.
- `crates/sb-adapters/src/outbound/vless.rs`
  - `VlessConfig` now stores `server: String` and `port: u16`.
  - Dial paths use the configured host directly instead of `SocketAddr::ip()`.
- Tests updated:
  - registration tests now assert `example.com:443` is accepted for VMess/VLESS
  - added invalid empty-server / zero-port coverage
  - app integration tests updated to construct VMess/VLESS configs with `server` + `port`

## Verification

### Rust package / lint gates

- `cargo test -p sb-adapters`: `PASS`
- `cargo clippy --workspace --all-features --all-targets -- -D warnings`: `PASS`
- `cargo test -p interop-lab`: `PASS` (`29 passed`)
- `cargo test -p sb-core`: `ENV-LIMITED`
  - main crate tests and most integration binaries passed
  - remaining failure was `crates/sb-core/tests/dns_steady.rs::bad_domain_returns_err`
  - this host resolves to `198.18.1.100` in the current environment instead of erroring, so the failure is caused by local DNS interception, not this VMess/VLESS change

### Phase 3 resume check

- `cargo build -p app --features acceptance,parity --bin app`: `PASS`
- Rust core startup with `agents-only/mt_real_01_evidence/phase3_real_upstream.json`: `PASS`
  - Clash API `127.0.0.1:19090`
  - mixed inbound `127.0.0.1:11080`
  - `/version` and `/proxies` reachable
  - selector and urltest groups visible
- Critical regression check vs prior blocker: `PASS`
  - the prior startup-time failure for domain-form VLESS hosts is gone
  - the config now registers and boots successfully

## New Phase 3 Blocker

- Real SOCKS5 egress still fails, but for a different reason:
  - `Failed to create REALITY connector: Invalid configuration: public_key must be 64 hex characters (X25519 public key)`
- The real subscription nodes carry REALITY public keys in the common 43-character base64url form.
- Current Rust validation path still expects a 64-hex-character key:
  - schema hint: `crates/sb-config/src/validator/v2_schema.json`
  - runtime error visible in `agents-only/mt_real_01_evidence/phase3_runtime/app.log`
- This means `MT-REAL-01-FIX-01` is complete, and MT-REAL-01 Phase 3 is now blocked by a separate REALITY key-format compatibility issue.

## Evidence

- runtime logs: `agents-only/mt_real_01_evidence/phase3_runtime/app.log`
- clash proxy snapshot: `agents-only/mt_real_01_evidence/phase3_runtime/proxies.json`
- version snapshot: `agents-only/mt_real_01_evidence/phase3_runtime/version.json`
- prior subscription probe: `agents-only/mt_real_01_phase3_subscription_probe.md`

## Conclusion

- `MT-REAL-01-FIX-01`: `PASS`
- Direct objective achieved:
  - domain-form VMess/VLESS outbounds no longer fail registration at startup
- MT-REAL-01 Phase 3 can continue only after addressing the newly surfaced REALITY public-key compatibility blocker.
