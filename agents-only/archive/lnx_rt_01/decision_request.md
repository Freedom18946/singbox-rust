<!-- tier: B -->
# LNX-RT-01 VMess scope decision

## Historical blocking finding

Linux workspace replay exposed six deterministic failures in
`app/tests/multiplex_vmess_e2e.rs`. The isolated single-stream case also fails with
`I/O error: early eof`.

Code inspection proves a pre-existing protocol mismatch:

- outbound auth: timestamp + UUID + alter ID + security + padding (31 bytes);
- inbound auth: timestamp + HMAC(UUID, timestamp) (24 bytes);
- outbound request: plaintext custom header and four-byte response auth;
- inbound request: nonce + AEAD ciphertext and sixteen-byte derived response tag;
- inbound warns that VMess multiplex is not implemented, while five cases enable yamux.

The mismatch predates LNX-RT-01. macOS did not provide positive evidence: its test helper treats
`early eof` as a constrained-environment skip. Linux correctly turns the same result into FAIL.

## Resolution (2026-07-17)

Decision closed by implementing canonical Go-compatible VMess TCP AEAD, as specified and accepted
in `vmess_canonical_plan.md`. Linux focused/workspace replay and strict dual-kernel evidence then
passed. LNX-RT-01 did not expand into legacy CFB, canonical CommandMux, UDP/packet VMess, or
redirect/tproxy app composition.

## Historical options

Original scoped option: record the failures as a pre-existing VMess implementation/test gap and
open a dedicated protocol card. This avoided a non-canonical local patch but left the replacement
goal incomplete.

Chosen option: implement and validate canonical VMess client/server framing with real Go/upstream
interoperability evidence, not only Rust-to-Rust agreement. Repository yamux-outer behavior was
preserved; canonical `v1.mux.cool` stayed outside scope.

Rejected: restore Linux `early eof` skipping, ignore the tests, or attach a static S4 label. Those
choices would suppress a real failure without evidence.
