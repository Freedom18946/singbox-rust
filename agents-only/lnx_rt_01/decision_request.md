<!-- tier: B -->
# LNX-RT-01 VMess scope decision

## Blocking finding

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

## Decision needed

Recommended: keep LNX-RT-01 scoped. Record these six T1 failures as a pre-existing VMess
implementation/test gap, finish remaining Linux gates, and open a dedicated VMess protocol + mux
card. This honors the explicit non-goal excluding VMess canonical-upstream work and avoids a
non-canonical local protocol patch.

Alternative: expand LNX-RT-01 to implement and validate canonical VMess client/server plus mux.
This is materially larger than Linux runtime replay and requires Go/upstream interoperability
evidence, not only making the Rust-to-Rust tests pass.

Rejected: restore Linux `early eof` skipping, ignore the tests, or attach a static S4 label. Those
choices would suppress a real failure without evidence.
