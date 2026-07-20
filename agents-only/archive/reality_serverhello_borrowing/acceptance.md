<!-- tier: C -->
# REALITY ServerHello Target-Profile Borrowing Acceptance

Date: 2026-07-20

## Decision

Authenticated Rust REALITY server now borrows the same network-visible target profile consumed by
Go `metacubex/utls v1.8.4`: TLS 1.3 cipher suite, key-share group, and first server-flight record
lengths. `DEV-REALITY-01` no longer remains an `ARCH-LIMIT` for local implementation. Real-network
camouflage sufficiency remains external research/measurement, not a local architecture gap.

This is canonical profile borrowing, not byte-for-byte replay of the decoy ServerHello. Both Go and
Rust generate fresh server random/key-exchange bytes while reproducing the target's selected
cipher/group and record shape.

## Implementation

- `RealityAcceptor` captures the already-primed decoy's TLS 1.3 ServerHello, CCS, and encrypted
  first flight with the same 8192-byte limit and combined-record (`>512`) rule as Go REALITY.
- Unsupported or malformed target profiles preserve active-probing behavior by relaying captured
  target bytes and continuing fallback instead of exposing an unborrowed local handshake.
- Target cipher and key-share group narrow the per-connection rustls crypto provider before TLS 1.3
  server construction.
- Opt-in vendored-rustls state splits EE/Certificate/CertificateVerify/Finished when the target uses
  separate records and applies RFC 8446 TLSInnerPlaintext zero padding to exact target lengths.
  Ring and aws-lc-rs TLS 1.3 encrypters implement the padding hook. Default `None` leaves ordinary
  rustls record framing unchanged; REALITY also suppresses unborrowed post-handshake tickets.

## Regression Evidence

`crates/sb-tls/tests/reality_active_probing.rs` adds two authenticated wire-capture regressions:

- combined target flight: exact record lengths `[127, 6, 777]`;
- separate target flight: exact lengths `[127, 6, 120, 1024, 180, 150]`;
- both assert borrowed `TLS_AES_256_GCM_SHA384` (`0x1302`) and X25519 (`0x001d`), then complete
  REALITY authentication and receive proxy payload.

Closure commands, all exit 0:

- `cargo fmt -p sb-tls`;
- `cargo clippy -p sb-tls --all-features --all-targets` — only three pre-existing
  `redundant_pub_crate` warnings in `reality/handshake.rs`;
- `cargo test -p sb-tls --all-features --all-targets` — 202 unit + 7 integration PASS, zero failure;
- `make verify-reality-local` — run `20260720T232557`: Go→Go 20/20, Rust→Go 20/20,
  Go Vision→Rust production server 20/20, four-phase probe 20/20, config validation and all four
  negative controls PASS. Runtime `round-summary.json` SHA-256:
  `895dbccb9bcc3f7da202b929f2180f32f474571ed22f07bc100ae52cec435bfc`.

## Scope Boundary

- No public Rust deployment or multi-vantage censor measurement occurred.
- R93 healthy-cohort bank and R94 upstream observable-minimum result remain unchanged.
- REALITY has no S3 BHV-ID; `52/56` coverage does not move.
- L4 byte identity and live second-tool fingerprinting remain non-goals.
