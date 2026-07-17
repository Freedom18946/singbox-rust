//! Canonical VMess AEAD protocol codec.
//!
//! This module implements the VMess protocol exactly as the Go `sing-vmess`
//! library does, so that singbox-rust interoperates on the wire with a real
//! sing-box peer (either direction). It covers the AEAD request/response header
//! and the chunked AEAD body stream for `aes-128-gcm` and `chacha20-poly1305`.
//!
//! Reference: github.com/sagernet/sing-vmess (protocol.go, kdf.go, client.go,
//! service.go, chunk_aead.go, chunk_length_stream.go).
//!
//! 本模块严格按 Go `sing-vmess` 实现 VMess AEAD 协议，确保与真实 sing-box 对端在
//! 线上互通（双向）。覆盖 AEAD 请求/响应头与分块 AEAD 正文流。

mod stream;

pub use stream::{client_connect, server_finish, server_read_request, VmessStream};

use aes::cipher::{BlockDecrypt, BlockEncrypt};
use aes::Aes128;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use anyhow::{anyhow, Result};
use md5::{Digest as Md5Digest, Md5};
use sha2::Sha256;

/// VMess protocol version.
pub const VERSION: u8 = 1;

/// Command byte: TCP stream.
pub const COMMAND_TCP: u8 = 1;

/// Security type on the wire (matches sing-vmess constants).
pub const SECURITY_NONE: u8 = 5;
pub const SECURITY_AES128_GCM: u8 = 3;
pub const SECURITY_CHACHA20_POLY1305: u8 = 4;

/// Request option flags.
pub const OPTION_CHUNK_STREAM: u8 = 1;
pub const OPTION_CHUNK_MASKING: u8 = 4;

/// Maximum plaintext bytes per body chunk before sealing (WriteChunkSize).
pub const WRITE_CHUNK_SIZE: usize = 15000;
/// AEAD tag length.
pub const CIPHER_OVERHEAD: usize = 16;

// KDF salt constants (byte-identical to sing-vmess).
const KDF_SALT_AUTH_ID_ENCRYPTION_KEY: &[u8] = b"AES Auth ID Encryption";
const KDF_SALT_AEAD_RESP_HEADER_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
const KDF_SALT_AEAD_RESP_HEADER_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
const KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY: &[u8] = b"AEAD Resp Header Key";
const KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV: &[u8] = b"AEAD Resp Header IV";
const KDF_SALT_ROOT: &[u8] = b"VMess AEAD KDF";
const KDF_SALT_HEADER_PAYLOAD_KEY: &[u8] = b"VMess Header AEAD Key";
const KDF_SALT_HEADER_PAYLOAD_IV: &[u8] = b"VMess Header AEAD Nonce";
const KDF_SALT_HEADER_LEN_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const KDF_SALT_HEADER_LEN_IV: &[u8] = b"VMess Header AEAD Nonce_Length";

/// The magic string mixed into the command key derivation.
const CMD_KEY_MAGIC: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";

/// Derive the VMess command key: `MD5(uuid || magic)`.
pub fn command_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(uuid);
    h.update(CMD_KEY_MAGIC);
    let out = h.finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&out);
    key
}

/// FNV-1a 32-bit hash (matches Go `hash/fnv` New32a).
fn fnv1a32(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for &b in data {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

fn sha256(msg: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(msg);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// Nested HMAC-SHA256 over `msg`. `keys` are innermost-first; `keys.last()` is
/// the outermost HMAC key. Every level uses SHA-256 (block 64, output 32); all
/// VMess keys are <= 64 bytes so no key-hashing is required.
fn nested_hmac(keys: &[&[u8]], msg: &[u8]) -> [u8; 32] {
    let Some((last, rest)) = keys.split_last() else {
        return sha256(msg);
    };
    debug_assert!(last.len() <= 64);
    let mut kp = [0u8; 64];
    kp[..last.len()].copy_from_slice(last);
    let mut ipad = [0u8; 64];
    let mut opad = [0u8; 64];
    for i in 0..64 {
        ipad[i] = kp[i] ^ 0x36;
        opad[i] = kp[i] ^ 0x5c;
    }
    let mut inner_msg = Vec::with_capacity(64 + msg.len());
    inner_msg.extend_from_slice(&ipad);
    inner_msg.extend_from_slice(msg);
    let inner = nested_hmac(rest, &inner_msg);
    let mut outer_msg = Vec::with_capacity(64 + 32);
    outer_msg.extend_from_slice(&opad);
    outer_msg.extend_from_slice(&inner);
    nested_hmac(rest, &outer_msg)
}

/// VMess KDF: nested HMAC-SHA256 with root salt `"VMess AEAD KDF"`.
pub fn kdf(key: &[u8], salt: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut chain: Vec<&[u8]> = Vec::with_capacity(2 + path.len());
    chain.push(KDF_SALT_ROOT);
    chain.push(salt);
    chain.extend_from_slice(path);
    nested_hmac(&chain, key)
}

fn aes_gcm_seal(key16: &[u8], nonce12: &[u8], aad: &[u8], plain: &[u8]) -> Vec<u8> {
    let cipher = Aes128Gcm::new_from_slice(key16).expect("16-byte AES-128-GCM key");
    cipher
        .encrypt(Nonce::from_slice(nonce12), Payload { msg: plain, aad })
        .expect("AES-128-GCM seal is infallible")
}

fn aes_gcm_open(key16: &[u8], nonce12: &[u8], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key16).expect("16-byte AES-128-GCM key");
    cipher
        .decrypt(Nonce::from_slice(nonce12), Payload { msg: ct, aad })
        .map_err(|_| anyhow!("vmess: AEAD header authentication failed"))
}

/// The AuthID encryption key derived from the command key.
fn auth_id_cipher(cmd_key: &[u8; 16]) -> Aes128 {
    let k = kdf(cmd_key, KDF_SALT_AUTH_ID_ENCRYPTION_KEY, &[]);
    Aes128::new_from_slice(&k[..16]).expect("16-byte AES key")
}

/// Build the 16-byte encrypted AuthID for a request.
/// Layout before encryption: `time_i64_be(8) || rand(4) || crc32_ieee(first12)(4)`,
/// then a single AES-128-ECB block encryption.
pub fn build_auth_id(cmd_key: &[u8; 16], unix_secs: i64, rand4: [u8; 4]) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&unix_secs.to_be_bytes());
    b[8..12].copy_from_slice(&rand4);
    let crc = crc32fast::hash(&b[..12]);
    b[12..].copy_from_slice(&crc.to_be_bytes());
    let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(&b);
    auth_id_cipher(cmd_key).encrypt_block(&mut block);
    let mut out = [0u8; 16];
    out.copy_from_slice(&block);
    out
}

/// Decrypt and validate an AuthID (server side). Returns the embedded timestamp
/// on success.
pub fn open_auth_id(cmd_key: &[u8; 16], auth_id: &[u8; 16]) -> Result<i64> {
    let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(auth_id);
    auth_id_cipher(cmd_key).decrypt_block(&mut block);
    let decoded = block;
    let crc = u32::from_be_bytes([decoded[12], decoded[13], decoded[14], decoded[15]]);
    if crc32fast::hash(&decoded[..12]) != crc {
        return Err(anyhow!("vmess: bad AuthID checksum"));
    }
    let ts = i64::from_be_bytes(decoded[..8].try_into().expect("8 bytes"));
    Ok(ts)
}

/// A VMess request destination (address + port).
#[derive(Debug, Clone)]
pub enum Address {
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
    Domain(String),
}

impl Address {
    fn from_host(host: &str) -> Self {
        match host.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(v4)) => Address::Ipv4(v4.octets()),
            Ok(std::net::IpAddr::V6(v6)) => Address::Ipv6(v6.octets()),
            Err(_) => Address::Domain(host.to_string()),
        }
    }
}

/// Everything needed to drive both directions of a body stream once the
/// handshake is complete.
#[derive(Clone, Copy)]
pub struct SessionKeys {
    pub security: u8,
    pub req_key: [u8; 16],
    pub req_nonce: [u8; 16],
    pub resp_key: [u8; 16],
    pub resp_nonce: [u8; 16],
    pub response_header: u8,
    pub option: u8,
}

impl SessionKeys {
    fn derive(
        security: u8,
        option: u8,
        req_key: [u8; 16],
        req_nonce: [u8; 16],
        response_header: u8,
    ) -> Self {
        let resp_key = {
            let h = sha256(&req_key);
            let mut k = [0u8; 16];
            k.copy_from_slice(&h[..16]);
            k
        };
        let resp_nonce = {
            let h = sha256(&req_nonce);
            let mut n = [0u8; 16];
            n.copy_from_slice(&h[..16]);
            n
        };
        Self {
            security,
            req_key,
            req_nonce,
            resp_key,
            resp_nonce,
            response_header,
            option,
        }
    }
}

/// Serialize the plaintext request header (before AEAD sealing), including the
/// trailing FNV-1a checksum. `pad` random bytes of padding are appended before
/// the checksum. The argument list mirrors the flat VMess header wire fields.
#[allow(clippy::too_many_arguments)]
fn encode_header_plain(
    security: u8,
    option: u8,
    req_key: &[u8; 16],
    req_nonce: &[u8; 16],
    response_header: u8,
    command: u8,
    addr: &Address,
    port: u16,
    pad: &[u8],
) -> Vec<u8> {
    let mut h = Vec::with_capacity(64);
    h.push(VERSION);
    h.extend_from_slice(req_nonce);
    h.extend_from_slice(req_key);
    h.push(response_header);
    h.push(option);
    debug_assert!(pad.len() < 16);
    h.push(((pad.len() as u8) << 4) | (security & 0x0f));
    h.push(0); // reserved
    h.push(command);
    // PortThenAddress: port(2 be) then family byte then address.
    h.extend_from_slice(&port.to_be_bytes());
    match addr {
        Address::Ipv4(v4) => {
            h.push(0x01);
            h.extend_from_slice(v4);
        }
        Address::Ipv6(v6) => {
            h.push(0x03);
            h.extend_from_slice(v6);
        }
        Address::Domain(d) => {
            h.push(0x02);
            h.push(d.len() as u8);
            h.extend_from_slice(d.as_bytes());
        }
    }
    if !pad.is_empty() {
        h.extend_from_slice(pad);
    }
    let checksum = fnv1a32(&h);
    h.extend_from_slice(&checksum.to_be_bytes());
    h
}

/// Randomness needed to build a request. Split out so the encoder is a pure,
/// testable function.
pub struct RequestRandomness {
    pub req_key: [u8; 16],
    pub req_nonce: [u8; 16],
    pub response_header: u8,
    pub conn_nonce: [u8; 8],
    pub auth_rand4: [u8; 4],
    pub pad: Vec<u8>,
}

/// Encode the full on-wire client request:
/// `AuthID(16) || encLen(2+16) || connNonce(8) || encHeader(headerLen+16)`.
pub fn encode_client_request(
    cmd_key: &[u8; 16],
    security: u8,
    option: u8,
    host: &str,
    port: u16,
    unix_secs: i64,
    r: &RequestRandomness,
) -> (Vec<u8>, SessionKeys) {
    let addr = Address::from_host(host);
    let header = encode_header_plain(
        security,
        option,
        &r.req_key,
        &r.req_nonce,
        r.response_header,
        COMMAND_TCP,
        &addr,
        port,
        &r.pad,
    );
    let auth_id = build_auth_id(cmd_key, unix_secs, r.auth_rand4);

    let length_key = kdf(cmd_key, KDF_SALT_HEADER_LEN_KEY, &[&auth_id, &r.conn_nonce]);
    let length_iv = kdf(cmd_key, KDF_SALT_HEADER_LEN_IV, &[&auth_id, &r.conn_nonce]);
    let header_len = (header.len() as u16).to_be_bytes();
    let enc_len = aes_gcm_seal(&length_key[..16], &length_iv[..12], &auth_id, &header_len);

    let header_key = kdf(
        cmd_key,
        KDF_SALT_HEADER_PAYLOAD_KEY,
        &[&auth_id, &r.conn_nonce],
    );
    let header_iv = kdf(
        cmd_key,
        KDF_SALT_HEADER_PAYLOAD_IV,
        &[&auth_id, &r.conn_nonce],
    );
    let enc_header = aes_gcm_seal(&header_key[..16], &header_iv[..12], &auth_id, &header);

    let mut wire = Vec::with_capacity(16 + enc_len.len() + 8 + enc_header.len());
    wire.extend_from_slice(&auth_id);
    wire.extend_from_slice(&enc_len);
    wire.extend_from_slice(&r.conn_nonce);
    wire.extend_from_slice(&enc_header);

    let keys = SessionKeys::derive(security, option, r.req_key, r.req_nonce, r.response_header);
    (wire, keys)
}

/// Parsed server-side request.
pub struct ServerRequest {
    pub host: String,
    pub port: u16,
    pub keys: SessionKeys,
}

/// The fixed-size prefix a server must read before it can learn the header
/// length: `AuthID(16) || encLen(2+16) || connNonce(8)`.
pub const SERVER_PREFIX_LEN: usize = 16 + 2 + CIPHER_OVERHEAD + 8;

/// Given the fixed prefix, return the encrypted header length and the material
/// needed to open the header body.
pub fn server_parse_length(
    cmd_key: &[u8; 16],
    prefix: &[u8; SERVER_PREFIX_LEN],
) -> Result<(usize, [u8; 16], [u8; 8])> {
    let mut auth_id = [0u8; 16];
    auth_id.copy_from_slice(&prefix[..16]);
    let ts = open_auth_id(cmd_key, &auth_id)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if (ts - now).abs() > 120 {
        return Err(anyhow!("vmess: request timestamp out of range"));
    }
    let enc_len = &prefix[16..16 + 2 + CIPHER_OVERHEAD];
    let mut conn_nonce = [0u8; 8];
    conn_nonce.copy_from_slice(&prefix[16 + 2 + CIPHER_OVERHEAD..]);

    let length_key = kdf(cmd_key, KDF_SALT_HEADER_LEN_KEY, &[&auth_id, &conn_nonce]);
    let length_iv = kdf(cmd_key, KDF_SALT_HEADER_LEN_IV, &[&auth_id, &conn_nonce]);
    let plain = aes_gcm_open(&length_key[..16], &length_iv[..12], &auth_id, enc_len)?;
    let header_len = u16::from_be_bytes([plain[0], plain[1]]) as usize;
    Ok((header_len, auth_id, conn_nonce))
}

/// The decoded plaintext request header fields.
pub struct ParsedHeader {
    pub host: String,
    pub port: u16,
    pub security: u8,
    pub option: u8,
    pub req_key: [u8; 16],
    pub req_nonce: [u8; 16],
    pub response_header: u8,
}

/// Parse a decrypted VMess request header (plaintext, including the trailing
/// FNV-1a checksum). This is the pure parser reused by the server path and by
/// fuzzing.
pub fn parse_request_header(header: &[u8]) -> Result<ParsedHeader> {
    if header.len() < 38 + 4 {
        return Err(anyhow!("vmess: request header too short"));
    }
    if header[0] != VERSION {
        return Err(anyhow!("vmess: bad version {}", header[0]));
    }
    let mut req_nonce = [0u8; 16];
    req_nonce.copy_from_slice(&header[1..17]);
    let mut req_key = [0u8; 16];
    req_key.copy_from_slice(&header[17..33]);
    let response_header = header[33];
    let option = header[34];
    let pad_len = (header[35] >> 4) as usize;
    let security = header[35] & 0x0f;
    let command = header[37];
    if command != COMMAND_TCP {
        return Err(anyhow!("vmess: unsupported command {command}"));
    }
    // PortThenAddress
    let mut off = 38;
    if header.len() < off + 3 {
        return Err(anyhow!("vmess: truncated address"));
    }
    let port = u16::from_be_bytes([header[off], header[off + 1]]);
    off += 2;
    let family = header[off];
    off += 1;
    let host = match family {
        0x01 => {
            if header.len() < off + 4 {
                return Err(anyhow!("vmess: truncated ipv4"));
            }
            let ip = std::net::Ipv4Addr::new(
                header[off],
                header[off + 1],
                header[off + 2],
                header[off + 3],
            );
            off += 4;
            ip.to_string()
        }
        0x03 => {
            if header.len() < off + 16 {
                return Err(anyhow!("vmess: truncated ipv6"));
            }
            let mut b = [0u8; 16];
            b.copy_from_slice(&header[off..off + 16]);
            off += 16;
            std::net::Ipv6Addr::from(b).to_string()
        }
        0x02 => {
            if header.len() < off + 1 {
                return Err(anyhow!("vmess: missing domain length"));
            }
            let dlen = header[off] as usize;
            off += 1;
            if header.len() < off + dlen {
                return Err(anyhow!("vmess: truncated domain"));
            }
            let d = String::from_utf8_lossy(&header[off..off + dlen]).to_string();
            off += dlen;
            d
        }
        other => return Err(anyhow!("vmess: unknown address family {other}")),
    };
    // padding + fnv checksum trailer must fit.
    off += pad_len;
    if header.len() < off + 4 {
        return Err(anyhow!("vmess: truncated header checksum"));
    }
    let expect = fnv1a32(&header[..off]);
    let got = u32::from_be_bytes([
        header[off],
        header[off + 1],
        header[off + 2],
        header[off + 3],
    ]);
    if expect != got {
        return Err(anyhow!("vmess: header checksum mismatch"));
    }

    Ok(ParsedHeader {
        host,
        port,
        security,
        option,
        req_key,
        req_nonce,
        response_header,
    })
}

/// Open and parse the encrypted request header body (`header_len + 16` bytes).
pub fn server_parse_header(
    cmd_key: &[u8; 16],
    auth_id: &[u8; 16],
    conn_nonce: &[u8; 8],
    enc_header: &[u8],
) -> Result<ServerRequest> {
    let header_key = kdf(cmd_key, KDF_SALT_HEADER_PAYLOAD_KEY, &[auth_id, conn_nonce]);
    let header_iv = kdf(cmd_key, KDF_SALT_HEADER_PAYLOAD_IV, &[auth_id, conn_nonce]);
    let header = aes_gcm_open(&header_key[..16], &header_iv[..12], auth_id, enc_header)?;
    let p = parse_request_header(&header)?;
    let keys = SessionKeys::derive(
        p.security,
        p.option,
        p.req_key,
        p.req_nonce,
        p.response_header,
    );
    Ok(ServerRequest {
        host: p.host,
        port: p.port,
        keys,
    })
}

/// Encode the server response header:
/// `encRespLen(2+16) || encRespHeader(4+16)` where the plaintext response
/// header is `[response_header, option, 0, 0]`.
pub fn encode_server_response(keys: &SessionKeys) -> Vec<u8> {
    let resp_key = &keys.resp_key;
    let resp_nonce = &keys.resp_nonce;

    let len_key = kdf(resp_key, KDF_SALT_AEAD_RESP_HEADER_LEN_KEY, &[]);
    let len_iv = kdf(resp_nonce, KDF_SALT_AEAD_RESP_HEADER_LEN_IV, &[]);
    let payload_len = 4u16.to_be_bytes();
    let enc_len = aes_gcm_seal(&len_key[..16], &len_iv[..12], &[], &payload_len);

    let hdr_key = kdf(resp_key, KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY, &[]);
    let hdr_iv = kdf(resp_nonce, KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV, &[]);
    let payload = [keys.response_header, keys.option, 0, 0];
    let enc_hdr = aes_gcm_seal(&hdr_key[..16], &hdr_iv[..12], &[], &payload);

    let mut out = Vec::with_capacity(enc_len.len() + enc_hdr.len());
    out.extend_from_slice(&enc_len);
    out.extend_from_slice(&enc_hdr);
    out
}

/// Client-side: decode the encrypted response header length (2+16 bytes) into
/// the plaintext response-header length.
pub fn client_parse_response_len(keys: &SessionKeys, enc_len: &[u8]) -> Result<usize> {
    let len_key = kdf(&keys.resp_key, KDF_SALT_AEAD_RESP_HEADER_LEN_KEY, &[]);
    let len_iv = kdf(&keys.resp_nonce, KDF_SALT_AEAD_RESP_HEADER_LEN_IV, &[]);
    let plain = aes_gcm_open(&len_key[..16], &len_iv[..12], &[], enc_len)?;
    Ok(u16::from_be_bytes([plain[0], plain[1]]) as usize)
}

/// Client-side: decode and verify the encrypted response header body.
/// Returns the number of trailing command bytes to discard.
pub fn client_parse_response_header(keys: &SessionKeys, enc_header: &[u8]) -> Result<usize> {
    let hdr_key = kdf(&keys.resp_key, KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY, &[]);
    let hdr_iv = kdf(&keys.resp_nonce, KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV, &[]);
    let plain = aes_gcm_open(&hdr_key[..16], &hdr_iv[..12], &[], enc_header)?;
    if plain.is_empty() {
        return Err(anyhow!("vmess: empty response header"));
    }
    if plain[0] != keys.response_header {
        return Err(anyhow!("vmess: response header mismatch"));
    }
    // plain = [response_header, option, cmd, cmd_len]
    let cmd_len = if plain.len() >= 4 {
        plain[3] as usize
    } else {
        0
    };
    Ok(cmd_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uuid_bytes() -> [u8; 16] {
        // b831381d-6324-4d53-ad4f-8cda48b30811
        [
            0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3,
            0x08, 0x11,
        ]
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn command_key_matches_go() {
        assert_eq!(
            hex(&command_key(&uuid_bytes())),
            "b50d916ac0cec067981af8e5f38a758f"
        );
    }

    #[test]
    fn kdf_auth_id_matches_go() {
        let ck = command_key(&uuid_bytes());
        let k = kdf(&ck, KDF_SALT_AUTH_ID_ENCRYPTION_KEY, &[]);
        assert_eq!(hex(&k[..16]), "1415ba74ca8b3d041a8f583fb4116315");
    }

    #[test]
    fn kdf_header_paths_match_go() {
        let ck = command_key(&uuid_bytes());
        let auth_id = b"0123456789abcdef";
        let conn_nonce = b"nonce123";
        let lk = kdf(&ck, KDF_SALT_HEADER_LEN_KEY, &[auth_id, conn_nonce]);
        assert_eq!(hex(&lk[..16]), "573b4bac0d8a1c2a0e26a294228c563e");
        let li = kdf(&ck, KDF_SALT_HEADER_LEN_IV, &[auth_id, conn_nonce]);
        assert_eq!(hex(&li[..12]), "a18b001684fd9a1e66df5e27");
        let hk = kdf(&ck, KDF_SALT_HEADER_PAYLOAD_KEY, &[auth_id, conn_nonce]);
        assert_eq!(hex(&hk[..16]), "1110e46db2482d93ed3e913b0f385124");
        let hi = kdf(&ck, KDF_SALT_HEADER_PAYLOAD_IV, &[auth_id, conn_nonce]);
        assert_eq!(hex(&hi[..12]), "24062939775118219c791673");
    }

    #[test]
    fn auth_id_fixed_matches_go() {
        let ck = command_key(&uuid_bytes());
        let id = build_auth_id(&ck, 1_700_000_000, [0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(hex(&id), "694f7bc7fd6b6f1ee428722979100521");
        // round-trip open
        let ts = open_auth_id(&ck, &id).unwrap();
        assert_eq!(ts, 1_700_000_000);
    }

    #[test]
    fn header_round_trip_client_to_server() {
        let ck = command_key(&uuid_bytes());
        let r = RequestRandomness {
            req_key: [7u8; 16],
            req_nonce: [9u8; 16],
            response_header: 0x2a,
            conn_nonce: [1, 2, 3, 4, 5, 6, 7, 8],
            auth_rand4: [0, 0, 0, 0],
            pad: vec![0xEE; 5],
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let (wire, keys) = encode_client_request(
            &ck,
            SECURITY_AES128_GCM,
            OPTION_CHUNK_STREAM | OPTION_CHUNK_MASKING,
            "example.com",
            443,
            now,
            &r,
        );
        let mut prefix = [0u8; SERVER_PREFIX_LEN];
        prefix.copy_from_slice(&wire[..SERVER_PREFIX_LEN]);
        let (hlen, auth_id, conn_nonce) = server_parse_length(&ck, &prefix).unwrap();
        let enc_header = &wire[SERVER_PREFIX_LEN..SERVER_PREFIX_LEN + hlen + CIPHER_OVERHEAD];
        let req = server_parse_header(&ck, &auth_id, &conn_nonce, enc_header).unwrap();
        assert_eq!(req.host, "example.com");
        assert_eq!(req.port, 443);
        assert_eq!(req.keys.security, SECURITY_AES128_GCM);
        assert_eq!(req.keys.req_key, keys.req_key);
        assert_eq!(req.keys.req_nonce, keys.req_nonce);
        assert_eq!(req.keys.response_header, keys.response_header);
    }

    #[test]
    fn response_header_round_trip() {
        let ck = command_key(&uuid_bytes());
        let r = RequestRandomness {
            req_key: [3u8; 16],
            req_nonce: [4u8; 16],
            response_header: 0x77,
            conn_nonce: [8, 7, 6, 5, 4, 3, 2, 1],
            auth_rand4: [1, 1, 1, 1],
            pad: vec![],
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let (_wire, keys) = encode_client_request(
            &ck,
            SECURITY_AES128_GCM,
            OPTION_CHUNK_STREAM | OPTION_CHUNK_MASKING,
            "1.2.3.4",
            80,
            now,
            &r,
        );
        let resp = encode_server_response(&keys);
        let enc_len = &resp[..2 + CIPHER_OVERHEAD];
        let hlen = client_parse_response_len(&keys, enc_len).unwrap();
        assert_eq!(hlen, 4);
        let enc_hdr = &resp[2 + CIPHER_OVERHEAD..2 + CIPHER_OVERHEAD + hlen + CIPHER_OVERHEAD];
        let cmd_len = client_parse_response_header(&keys, enc_hdr).unwrap();
        assert_eq!(cmd_len, 0);
    }
}
