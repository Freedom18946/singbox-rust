# MT-REAL-01-FIX-02: REALITY `public_key` base64url Compatibility

## Scope

- Align Rust REALITY client `public_key` parsing with Go sing-box.
- Only change `crates/sb-tls/src/reality/config.rs` plus its tests.
- Resume MT-REAL-01 Phase 3 startup and dataplane probing after the fix.

## Root Cause

- Go sing-box accepts REALITY client public keys as base64url raw (no padding).
- Rust only accepted 64-character hex strings and rejected the common 43-character base64url form used by real-world subscriptions.
- This caused all REALITY-backed nodes to fail during config validation before any actual connection attempt.

## Code Change

- File: `crates/sb-tls/src/reality/config.rs`
- Added a shared private helper:
  - `decode_public_key(key: &str) -> Result<[u8; 32], String>`
- New behavior:
  - if length is 64 and all chars are hex: decode as hex
  - otherwise try base64url decode:
    - `URL_SAFE_NO_PAD`
    - then `URL_SAFE`
  - decoded value must be exactly 32 bytes
- `RealityClientConfig::validate()` and `public_key_bytes()` now both use the same decode path.
- `short_id` handling is unchanged.
- `RealityServerConfig` private-key handling is unchanged.

## Tests

- Existing hex-path tests remain in place.
- Added coverage for:
  - 43-char base64url public key: validate + bytes success
  - 44-char padded base64url public key: validate + bytes success
  - invalid base64url string: explicit error

## Verification

### Package and lint gates

- `cargo test -p sb-tls`: `PASS`
  - `96 passed`, `0 failed`
- `cargo clippy --workspace --all-features --all-targets -- -D warnings`: `PASS`
- `cargo test -p sb-adapters`: `PASS`
- `cargo test -p interop-lab`: `PASS` (`29 passed`)
- `cargo test -p sb-core`: `ENV-LIMITED`
  - same pre-existing `crates/sb-core/tests/dns_steady.rs` environment behavior as before
  - `bad_domain_returns_err` fails because this machine resolves `nonexistent.invalid`
  - `udp_pool_timeout_is_handled` then sees `PoisonError` from the shared test lock after the first failure

### Phase 3 resume check

- Rebuilt app binary:
  - `cargo build -p app --features acceptance,parity --bin app`
- Started Rust core with:
  - `agents-only/mt_real_01_evidence/phase3_real_upstream.json`
- Control plane:
  - Clash API on `127.0.0.1:19090`: `PASS`
  - mixed inbound on `127.0.0.1:11080`: `PASS`
  - `/version`: `PASS`
  - `/proxies`: `PASS`
- Selector dataplane probe:
  - `curl -x socks5h://127.0.0.1:11080 https://httpbin.org/ip`: still `FAIL`

## Key Outcome

- The old blocker is gone:
  - no `public_key must be 64 hex characters`
  - no `Failed to create REALITY connector`
- The new runtime error is now:
  - `REALITY handshake failed: Handshake failed: TLS handshake failed: tls handshake eof`

This confirms `MT-REAL-01-FIX-02` is complete: REALITY nodes are no longer rejected in validation, and Phase 3 now advances to the next real-connection issue.

## Evidence

- runtime log:
  - `agents-only/mt_real_01_evidence/phase3_runtime/fix02_app.log`
- clash snapshots:
  - `agents-only/mt_real_01_evidence/phase3_runtime/fix02_version.json`
  - `agents-only/mt_real_01_evidence/phase3_runtime/fix02_proxies.json`
- curl output:
  - `agents-only/mt_real_01_evidence/phase3_runtime/fix02_httpbin_ip.json`

## Conclusion

- `MT-REAL-01-FIX-02`: `PASS`
- Go-aligned REALITY client `public_key` parsing is now compatible with:
  - 64-char hex
  - 43-char base64url raw
  - 44-char base64url padded
- MT-REAL-01 Phase 3 is no longer blocked by config validation and can proceed to the next REALITY handshake/debug card.
