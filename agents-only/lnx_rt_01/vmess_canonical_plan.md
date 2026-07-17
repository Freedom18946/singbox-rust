<!-- tier: B -->
# VMess canonical protocol implementation plan (VMESS-CANON-01)

## Decision resolved

LNX-RT-01's `decision_request.md` asked whether to keep the six `multiplex_vmess_e2e`
failures scoped or to implement canonical VMess. Per the user's highest-goal mandate
(drop-in Go sing-box replacement) and the three-axis delegation (feasibility / long-term /
Go-equivalence, ignore short-term cost), the resolution is: **implement canonical
Go-compatible VMess AEAD**, not the self-consistent bespoke patch the WIP had started and
not a deferral.

## Why the current code is wrong

The uncommitted WIP made inbound and outbound agree with each other but neither matches Go
`sing-vmess`:
- auth uses `HMAC-SHA256(uuid, ts)[..16]`; canonical AEAD uses an encrypted `AuthID`
  (`AES-128-ECB` over `time||rand||crc32`, key `KDF(cmdKey,"AES Auth ID Encryption")`).
- `cmdKey` used `SHA256(uuid||magic)`; canonical is `MD5(uuid||"c48619fe-...")`.
- request header put port after the address; canonical is `PortThenAddress`.
- there is **no body chunk framing at all** — after the handshake it raw-relays, while
  canonical VMess frames every chunk with a masked 2-byte length + AEAD tag.

## Reference (authoritative)

`sing-vmess@v0.2.8` in the Go module cache. Key files: `protocol.go`, `kdf.go`,
`client.go`, `service.go`, `chunk_aead.go`, `chunk_length_stream.go`, `chunk_stream.go`.
sing-box wrappers: `protocol/vmess/{outbound,inbound}.go`, `option/vmess.go`.

## Canonical protocol (AEAD mode, alterId=0, the interop target)

- `cmdKey = MD5(uuid[16] || "c48619fe-8f02-49e0-b9e9-edf763e17e21")`.
- `KDF(key, salt, ...path)` = nested HMAC-SHA256, root key `"VMess AEAD KDF"`, block 64,
  out 32 at every level.
- Request wire: `AuthID(16) || encHeaderLen(2+16) || connNonce(8) || encHeader(headerLen+16)`.
  - AuthID = `AES128-ECB_encrypt(time_i64_be(8) || rand(4) || crc32_ieee(first12)(4))`,
    ECB key = `KDF(cmdKey,"AES Auth ID Encryption")[:16]`.
  - encHeaderLen = `AES128-GCM.seal(u16(headerLen))`, key/nonce =
    `KDF(cmdKey,"VMess Header AEAD Key_Length"/"...Nonce_Length", authId, connNonce)`, AAD authId.
  - encHeader = `AES128-GCM.seal(headerPlain)`, key/nonce =
    `KDF(cmdKey,"VMess Header AEAD Key"/"...Nonce", authId, connNonce)`, AAD authId.
  - headerPlain = `ver(1)=1 | reqNonce(16) | reqKey(16) | respHeader(1 rand) | option(1) |
    (padLen<<4|security)(1) | 0 | cmd(1)=1 | PortThenAddress | pad(padLen) | fnv1a32(all above)(4)`.
- Response wire: `encRespLen(2+16) || encRespHeader(4+16)`.
  - respKey = `SHA256(reqKey)[:16]`, respNonce = `SHA256(reqNonce)[:16]`.
  - encRespLen = seal(u16(4)) key/nonce `KDF(respKey,"AEAD Resp Header Len Key"/... IV)`.
  - encRespHeader = seal(`[respHeader, option, 0, 0]`) key/nonce `KDF(respKey,"AEAD Resp Header Key"/... IV)`.
- Body (security aes-128-gcm/chacha20, option `ChunkStream|ChunkMasking`, no pad/authlen):
  per chunk on wire `maskedLen(2) || AEAD.seal(piece)`, `maskedLen = (len(piece)+16) XOR shakeU16`.
  - AEAD nonce = `counter_u16_be || baseNonce[2..12]`, counter from 0, +1 per chunk.
  - `shake = SHAKE128(baseNonce16)`, read 2 bytes per chunk.
  - baseKey/baseNonce = reqKey/reqNonce (client→server), respKey/respNonce (server→client).
  - chacha body key = `MD5(k) || MD5(MD5(k))`.
  - plaintext piece <= 15000 bytes (WriteChunkSize).

## Deliverables

1. New module `crates/sb-adapters/src/vmess/` (crypto + header + async `VmessStream`).
2. Add deps `aes`, `sha3`, `crc32fast`, `fnv` (all already in workspace lock).
3. Rewrite `outbound/vmess.rs`: client handshake produces a canonical body stream.
4. Rewrite `inbound/vmess.rs`: server reads canonical request, writes canonical response,
   relays through canonical body stream. Keep the WIP router wiring (correct).
5. Go-generated crypto vectors baked into Rust unit tests (cmdKey, KDF, AuthID round-trip).
6. Codec round-trip unit tests (client<->server in-memory) for aes-128-gcm and chacha20.
7. Run `multiplex_vmess_e2e` (net_e2e) + adapters suite + fmt/clippy/boundaries.

## Acceptance (2026-07-17) — DONE

- Crypto locked to Go-generated vectors: cmdKey `b50d916a…`, KDF(AuthID/header len+payload),
  fixed AuthID — all byte-exact vs `sing-vmess`.
- Real Go interop, both directions, aes-128-gcm + chacha20, incl. 20 KB multi-chunk payloads:
  - Rust outbound (`VmessConnector`) → Go `vmess.Service` echo: PASS.
  - Go `vmess.Client` (`DialEarlyConn`) → Rust inbound (`serve`): PASS.
  - (Interop harnesses were throwaway under `/tmp`; deleted after the run.)
- `app` `multiplex_vmess_e2e`: 6/6 (was 6 fail). `vmess_tls_variants_e2e` / `vmess_websocket_*`
  pass. sb-adapters suite + `vmess::` module tests (8) pass.
- fmt, clippy (`-p sb-adapters --all-targets`), boundaries (W200-11 → injected-router + new
  W200-11b), consistency: all PASS.

## Non-goals this pass

- Legacy `aes-128-cfb` (alterId>0) body: not needed for Go default interop; keep a clear
  error. alterId>0 e2e cases will exercise it only if the server accepts — server default is
  AEAD, so alterId is inert on the wire when the auth path is AEAD.
- Canonical `v1.mux.cool` CommandMux: the repo keeps yamux-outer mux; each substream runs
  canonical VMess. Go mux interop is a separate card.
- UDP/packet VMess: out of scope; TCP dataplane only.
</content>
