//! QUIC Initial packet decryption and SNI extraction.
//!
//! Decrypts QUIC Initial packets to extract SNI from the embedded TLS ClientHello,
//! enabling domain-based routing for QUIC/HTTP3 traffic.
//!
//! Supports QUIC v1 (RFC 9001), v2 (RFC 9369), and Draft-29.
//!
//! Go reference: `common/sniff/quic.go` + `common/sniff/internal/qtls/qtls.go`

use super::sniff::{sniff_tls_client_hello, SniffOutcome};
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use aes_gcm::{AeadInPlace, Aes128Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

// --- QUIC version constants ---
const VERSION_DRAFT_29: u32 = 0xff00001d;
const VERSION_1: u32 = 0x00000001;
const VERSION_2: u32 = 0x6b3343cf;

// --- Version-specific salts (RFC 9001 §5.2, RFC 9369 §3.2) ---
const SALT_OLD: [u8; 20] = [
    0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11,
    0xe0, 0x43, 0x90, 0xa8, 0x99,
];
const SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
    0xad, 0xcc, 0xbb, 0x7f, 0x0a,
];
const SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d,
    0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
];

/// Read a QUIC variable-length integer (RFC 9000 §16).
/// Returns (value, bytes_consumed) or None if buffer too short.
fn read_quic_varint(buf: &[u8], pos: usize) -> Option<(u64, usize)> {
    if pos >= buf.len() {
        return None;
    }
    let first = buf[pos];
    let len = 1usize << ((first & 0xc0) >> 6);
    if pos + len > buf.len() {
        return None;
    }
    let val = match len {
        1 => (first & 0x3f) as u64,
        2 => {
            let b1 = (first & 0x3f) as u64;
            (b1 << 8) | buf[pos + 1] as u64
        }
        4 => {
            let b1 = (first & 0x3f) as u64;
            (b1 << 24)
                | (buf[pos + 1] as u64) << 16
                | (buf[pos + 2] as u64) << 8
                | buf[pos + 3] as u64
        }
        8 => {
            let b1 = (first & 0x3f) as u64;
            (b1 << 56)
                | (buf[pos + 1] as u64) << 48
                | (buf[pos + 2] as u64) << 40
                | (buf[pos + 3] as u64) << 32
                | (buf[pos + 4] as u64) << 24
                | (buf[pos + 5] as u64) << 16
                | (buf[pos + 6] as u64) << 8
                | buf[pos + 7] as u64
        }
        _ => unreachable!(),
    };
    Some((val, len))
}

/// TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1).
fn hkdf_expand_label(secret: &[u8], label: &str, length: usize) -> Option<Vec<u8>> {
    let full_label = format!("tls13 {}", label);
    let mut info = Vec::with_capacity(3 + full_label.len() + 1);
    info.push((length >> 8) as u8);
    info.push(length as u8);
    info.push(full_label.len() as u8);
    info.extend_from_slice(full_label.as_bytes());
    info.push(0); // context length = 0

    let hkdf = Hkdf::<Sha256>::from_prk(secret).ok()?;
    let mut out = vec![0u8; length];
    hkdf.expand(&info, &mut out).ok()?;
    Some(out)
}

/// CRYPTO frame fragment for reassembly.
struct CryptoFragment {
    offset: u64,
    payload: Vec<u8>,
}

/// Extract SNI from a QUIC Initial packet by decrypting the payload
/// and parsing the embedded TLS ClientHello.
///
/// Returns `Some(SniffOutcome)` with protocol="quic" and extracted SNI,
/// or `None` if the packet cannot be parsed/decrypted.
pub fn sniff_quic_sni(buf: &[u8]) -> Option<SniffOutcome> {
    if buf.len() < 6 {
        return None;
    }

    let flags = buf[0];
    // Fixed bit must be set (RFC 9000 §17.2)
    if flags & 0x40 == 0 {
        return None;
    }

    let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    if version != VERSION_DRAFT_29 && version != VERSION_1 && version != VERSION_2 {
        return None;
    }

    // Validate packet type (Initial)
    // V1/Draft-29: Initial = type 0. V2: Initial = type 2 (swapped with Retry per RFC 9369)
    let packet_type = (flags & 0x30) >> 4;
    if (packet_type == 0 && version == VERSION_2)
        || (packet_type == 2 && version != VERSION_2)
        || packet_type > 2
    {
        return None;
    }

    let mut pos = 5;

    // DCID length (1-20 bytes per RFC 9000)
    if pos >= buf.len() {
        return None;
    }
    let dcid_len = buf[pos] as usize;
    pos += 1;
    if dcid_len == 0 || dcid_len > 20 || pos + dcid_len > buf.len() {
        return None;
    }
    let dcid = &buf[pos..pos + dcid_len];
    pos += dcid_len;

    // SCID length + skip
    if pos >= buf.len() {
        return None;
    }
    let scid_len = buf[pos] as usize;
    pos += 1;
    if pos + scid_len > buf.len() {
        return None;
    }
    pos += scid_len;

    // Token length (varint) + skip
    let (token_len, vlen) = read_quic_varint(buf, pos)?;
    pos += vlen;
    if pos + token_len as usize > buf.len() {
        return None;
    }
    pos += token_len as usize;

    // Packet length (varint)
    let (packet_len, vlen) = read_quic_varint(buf, pos)?;
    pos += vlen;

    let hdr_len = pos;
    if hdr_len + packet_len as usize > buf.len() {
        return None;
    }

    // Need at least 4 + 16 bytes after header for HP sample
    if hdr_len + 4 + 16 > buf.len() {
        return None;
    }

    // HP sample: 16 bytes starting at hdr_len + 4
    let sample = &buf[hdr_len + 4..hdr_len + 4 + 16];

    // --- Derive Initial keys ---
    let salt: &[u8] = match version {
        VERSION_1 => &SALT_V1,
        VERSION_2 => &SALT_V2,
        _ => &SALT_OLD,
    };

    let hp_label = match version {
        VERSION_2 => "quicv2 hp",
        _ => "quic hp",
    };

    // initial_secret = HKDF-Extract(salt, DCID)
    let (initial_secret, _) = Hkdf::<Sha256>::extract(Some(salt), dcid);
    // client_secret = HKDF-Expand-Label(initial_secret, "client in", 32)
    let client_secret = hkdf_expand_label(initial_secret.as_slice(), "client in", 32)?;
    // hp_key = HKDF-Expand-Label(client_secret, hp_label, 16)
    let hp_key = hkdf_expand_label(&client_secret, hp_label, 16)?;

    // --- Remove header protection ---
    // AES-ECB encrypt sample → mask
    let aes_cipher = Aes128::new_from_slice(&hp_key).ok()?;
    let mut block = aes::Block::clone_from_slice(sample);
    aes_cipher.encrypt_block(&mut block);
    let mask = block;

    // Apply mask to packet copy
    let mut packet = buf.to_vec();
    packet[0] ^= mask[0] & 0x0f;
    for i in 0..4 {
        packet[hdr_len + i] ^= mask[1 + i];
    }

    // Extract packet number
    let pn_len = (packet[0] & 0x03) as usize + 1;
    if hdr_len + pn_len > hdr_len + packet_len as usize {
        return None;
    }

    let packet_number: u32 = match pn_len {
        1 => packet[hdr_len] as u32,
        2 => u16::from_be_bytes([packet[hdr_len], packet[hdr_len + 1]]) as u32,
        3 => {
            ((packet[hdr_len] as u32) << 16)
                | ((packet[hdr_len + 1] as u32) << 8)
                | (packet[hdr_len + 2] as u32)
        }
        4 => u32::from_be_bytes([
            packet[hdr_len],
            packet[hdr_len + 1],
            packet[hdr_len + 2],
            packet[hdr_len + 3],
        ]),
        _ => return None,
    };

    let ext_hdr_len = hdr_len + pn_len;

    // Restore bytes after packet number that were corrupted by mask XOR
    // (Go: copy(newPacket[extHdrLen:hdrLen+4], packet[extHdrLen:]))
    let copy_end = hdr_len + 4;
    if ext_hdr_len < copy_end {
        packet[ext_hdr_len..copy_end].copy_from_slice(&buf[ext_hdr_len..copy_end]);
    }

    // --- Decrypt payload ---
    let (key_label, iv_label) = match version {
        VERSION_2 => ("quicv2 key", "quicv2 iv"),
        _ => ("quic key", "quic iv"),
    };

    let key = hkdf_expand_label(&client_secret, key_label, 16)?;
    let iv = hkdf_expand_label(&client_secret, iv_label, 12)?;

    // Construct 12-byte nonce: IV XOR packet_number
    // Go's xorNonceAEAD: nonceMask[4..12] ^= big_endian_u64(packet_number)
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&iv);
    let pn_be = (packet_number as u64).to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= pn_be[i];
    }

    // Ciphertext (includes GCM tag) = packet[ext_hdr_len .. hdr_len + packet_len]
    // AAD = packet[0..ext_hdr_len] (unprotected header)
    let payload_end = hdr_len + packet_len as usize;
    if ext_hdr_len >= payload_end {
        return None;
    }

    let aad = packet[..ext_hdr_len].to_vec();
    let mut buffer = packet[ext_hdr_len..payload_end].to_vec();

    let gcm_cipher = Aes128Gcm::new_from_slice(&key).ok()?;
    gcm_cipher
        .decrypt_in_place(Nonce::from_slice(&nonce), &aad, &mut buffer)
        .ok()?;

    let decrypted = buffer;

    // --- Parse QUIC frames ---
    let mut fragments: Vec<CryptoFragment> = Vec::new();
    let mut fpos = 0;

    while fpos < decrypted.len() {
        let frame_type = decrypted[fpos];
        fpos += 1;

        match frame_type {
            0x00 => continue, // PADDING
            0x01 => continue, // PING
            0x02 | 0x03 => {
                // ACK / ACK_ECN
                let (_, vl) = read_quic_varint(&decrypted, fpos)?; // Largest Acknowledged
                fpos += vl;
                let (_, vl) = read_quic_varint(&decrypted, fpos)?; // ACK Delay
                fpos += vl;
                let (range_count, vl) = read_quic_varint(&decrypted, fpos)?; // ACK Range Count
                fpos += vl;
                let (_, vl) = read_quic_varint(&decrypted, fpos)?; // First ACK Range
                fpos += vl;
                for _ in 0..range_count {
                    let (_, vl) = read_quic_varint(&decrypted, fpos)?; // Gap
                    fpos += vl;
                    let (_, vl) = read_quic_varint(&decrypted, fpos)?; // ACK Range Length
                    fpos += vl;
                }
                if frame_type == 0x03 {
                    // ECN counts: ECT0, ECT1, ECN-CE
                    for _ in 0..3 {
                        let (_, vl) = read_quic_varint(&decrypted, fpos)?;
                        fpos += vl;
                    }
                }
            }
            0x06 => {
                // CRYPTO
                let (offset, vl) = read_quic_varint(&decrypted, fpos)?;
                fpos += vl;
                let (length, vl) = read_quic_varint(&decrypted, fpos)?;
                fpos += vl;
                let length = length as usize;
                if fpos + length > decrypted.len() {
                    return None;
                }
                fragments.push(CryptoFragment {
                    offset,
                    payload: decrypted[fpos..fpos + length].to_vec(),
                });
                fpos += length;
            }
            0x1c => {
                // CONNECTION_CLOSE
                let (_, vl) = read_quic_varint(&decrypted, fpos)?; // Error Code
                fpos += vl;
                let (_, vl) = read_quic_varint(&decrypted, fpos)?; // Frame Type
                fpos += vl;
                let (reason_len, vl) = read_quic_varint(&decrypted, fpos)?; // Reason Phrase Length
                fpos += vl;
                fpos += reason_len as usize;
            }
            _ => return None, // Unknown frame type in Initial packet
        }
    }

    if fragments.is_empty() {
        return None;
    }

    // --- Reassemble CRYPTO fragments ---
    let total_len: u64 = fragments.iter().map(|f| f.payload.len() as u64).sum();

    // Build fake TLS record header: [ContentType=22, Version=0x0303, Length]
    let mut tls_record = Vec::with_capacity(5 + total_len as usize);
    tls_record.push(0x16);
    tls_record.push(0x03);
    tls_record.push(0x03);
    tls_record.push((total_len >> 8) as u8);
    tls_record.push(total_len as u8);

    // Reassemble in offset order (Go: find fragment at current index, append, loop)
    let mut index: u64 = 0;
    loop {
        let mut found = false;
        for frag in &fragments {
            if frag.offset == index {
                tls_record.extend_from_slice(&frag.payload);
                index = frag.offset + frag.payload.len() as u64;
                found = true;
                break;
            }
        }
        if !found {
            break;
        }
    }

    // Parse TLS ClientHello from reassembled data
    let tls_info = sniff_tls_client_hello(&tls_record)?;
    let sni = tls_info.sni?;

    Some(SniffOutcome {
        protocol: Some("quic"),
        host: Some(sni),
        alpn: Some("h3".to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Go parity: TestSniffQUICFirefox — single-packet QUIC Initial, SNI = "www.google.com"
    #[test]
    fn go_parity_sniff_quic_firefox() {
        let pkt = hex::decode(
            "c8000000010867f174d7ebfe1b0803cd9c20004286de068f7963cf1736349ee6ebe0ddcd3e4cd004\
             1a51ced3f7ce9eea1fb595458e74bdb4b792b16449bd8cae71419862c4fcbe766eaec7d1af65cd29\
             8e1dd46f8bd94a77ab4ca28c54b8e9773de3f02d7cb2463c9f7dcacfb311f024b0266ec6ab7bfb61\
             5b4148333fb4d4ece7c4cd90029ca30c2cbae2216b428499ec873fa125797e71c5a5da85087760ad\
             37ca610020f71b76e82651c47576e20bf33cf676cb2d400b8c09d3c8cb4e21c47d2b21f6b68732be\
             f30c8cefd5c723fc23eb29e6f7f65a5e52aad9055c1fb3d8b1811f0380b38d7e2eee8eb37dd5bd5d\
             4ca4b66540175d916289d88a9df7c161964d713999c5057d27edb298ef5164352568b0d4bac3c15d\
             90456e8fd460e41b81d0ec1b1e94b87d3333cc6908b018e0914ae1f214d73e75398da3d55a010616\
             1d3a75897b4eb66e98c59010fae75f0d367d38be48c3a5c58bc8a30773c3fff50690ac9d487822f8\
             5d4f5713d626baa92d36e858dd21259cf814bce0b90d18da88a1ade40113e5a088cdb304a2558879\
             152a8cf15c1839e056378aa41acba6fcb9974dee54bd50b5d4eb2c475654e06c0ec06b7f18f4462c\
             808684843a1071041b9bfb2688324e0120144944416e30e83eedbbbcbc275b1f53762d3db18f0998\
             ce54f0e1c512946b4098f07781d49264fa148f4c8220a3b02e73d7f15554aa370aafeff73cb75c52\
             c494edf90f0261abfdd32a4d670f729de50266162687aa8efe14b8506f313b058b02aaaab5825428\
             f5f4510b8e49451fdcb7b5a4af4b59c831afcb89fb4f64dba78e3b38387e87e9e8cdaa1f3b700a87\
             c7d442388863b8950296e5773b38f308d62f52548c0bbf308e40540747cca5bf99b1345bc0d70b8f\
             0e69a83b85a8d69f795b87f93e2bfccf52b529afea4ff6fd456957000000000000000000000000\
             000000000000000000000000000000000000000000000000000000000000000000000000000000\
             000000000000000000000000000000000000000000000000000000000000000000000000000000\
             000000000000000000000000000000000000000000000000000000000000000000000000000000\
             000000000000000000000000000000000000000000000000000000000000000000000000000000\
             000000000000000000000000000000000000000000000000000000000000000000000000000000\
             000000000000000000000000000000000000000000000000000000000000000000000000000000\
             000000000000000000000000000000000000000000000000000000000000000000000000000000\
             000000000000000000000000000000000000000000000000000000000000000000000000000000\
             000000000000000000000000000000000000000000000000000000000000000000000000000000\
             000000000000000000000000000000000000000000000000000000000000000000000000000000\
             000000000000000000000000000000000000000000000000000000000000000000000000000000\
             000000000000000000000000000000000000000000000000000000000000000000000000000000\
             000000000000000000000000000000000000000000000000000000000000000000000000000000\
             000000000000000000000000000000000000000000000000000000000000000000000000000000\
             000000000000000000000000000000000000000000000000000000000000000000000000000000\
             000000000000000000000000000000000000000000000000000000000000000000000000000000\
             000000000000000000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        let result = sniff_quic_sni(&pkt).expect("should extract SNI from Firefox QUIC");
        assert_eq!(result.protocol, Some("quic"));
        assert_eq!(result.host.as_deref(), Some("www.google.com"));
        assert_eq!(result.alpn.as_deref(), Some("h3"));
    }

    /// Go parity: TestSniffQUICSafari — single-packet QUIC Initial, SNI = "www.google.com"
    #[test]
    fn go_parity_sniff_quic_safari() {
        let pkt = hex::decode(
            "c70000000108e4e75af2e223198a0000449ef2d83cb4473a62765eba67424cd4a5817315cbf55a9e\
             8daaca360904b0bae60b1629cfeba11e2dfbbf5ea4c588cb134e31af36fd7a409fb0fcc0187e9b56\
             037ac37964ed20a8c1ca19fd6cfd53398324b3d0c71537294f769db208fa998b6811234a4a7eb3b5\
             eceb457ae92e3a2d98f7c110702db8064b5c29fa3298eb1d0529fd445a84a5fd6ff8709be90f8af4\
             f94998d8a8f2953bb05ad08c80668eca784c6aec959114e68e5b827e7c41c79f2277c716a967e7fc\
             c8d1b77442e6cb18329dbedb34b473516b468cba5fc20659e655fbe37f36408289b9a475fcee091b\
             d82828d3be00367e9e5cec9423bb97854abdada1d7562a3777756eb3bddef826ddc1ef46137cb01bb\
             504a54d410d9bcb74cd5f959050c84edf343fa6a49708c228a758ee7adbbadf260b2f1984911489712\
             e2cb364a3d6520badba4b7e539b9c163eeddfd96c0abb0de151e47496bb9750be76ee17ccdb61d35\
             d2c6795174037d6f9d282c3f36c4d9a90b64f3b6ddd0cf4d9ed8e6f7805e25928fa04b087e63ae02\
             761df30720cc01dfc32b64c575c8a66ef82e9a17400ff80cd8609b93ba16d668f4aa734e71c4a5d1\
             45f14ee1151bec970214e0ff83fc3e1e85d8694f2975f9155c57c18b7b69bb6a36832a9435f1f4b3\
             46a7be188f3a75f9ad2cc6ad0a3d26d6fa7d4c1179bd49bd5989d15ba43ff602890107db96484695\
             086627356750d7b2b3b714ba65d564654e8f60ac10f5b6d3bfb507e8eaa31bab1da2d676195046d1\
             65c7f8b32829c9f9b68d97b2af7ac04a1369357e4b65de2b2f24eaf27cc8d95e05db001adebe726f\
             927a94e43e62ce671e6e306e16f05aafcbe6c49080e80286d7939f375023d110a5ad9069364ae928\
             ca480454a9dcddd61bc48b7efeb716a5bd6c7cd39c486ceb20c738af6abf22ba1ddd8b4a3b781fc2\
             f251173409e1aadccbd7514e97106d0ebfc3af6e59445f74cd733a1ba99b10fce3fb4e9f7c88f5e2\
             5b567f5ba2b8dabacd375e7faf7634bfa178cbe51aee63032c5126b196ea47b02385fc3062a000fb\
             7e4b4d0d12e74579f8830ede20d10829496032b2cc56743287f9a9b4d5091877a82fea44deb2cffa\
             c8a379f78a151d99e28cbc74d732c083bf06d50584e3f18f254e71a48d6ababaf6fff6f425e9be001\
             510dfbe6a32a27792c00ada036b62ddb90c706d7b882c76a7072f5dd11c69a1f49d4ba183cb0b575\
             45419fa27b9b9706098848935ae9c9e8fbe9fac165d1339128b991a73d20e7795e8d6a8c6adfbf20\
             bf13ada43f2aef3ba78c14697910507132623f721387dce60c4707225b84d9782d469a5d9eaa099f\
             35d6a590ef142ddef766495cf3337815ceef5ff2b3ed352637e72b5c23a2a8ff7d7440236a19b981\
             d47f8e519a0431ebfbc0b78d8a36798b4c060c0c6793499f1e2e818862560a5b501c8d02ba1517be\
             1941da2af5b174e0189c62978d878eb0f9c9db3a9221c28fb94645cf6e85ff2eea8c65ba3083a738\
             2b131b83102dd67aa5453ad7375a4eb8c69fc479fbd29dab8924f801d253f2c997120b705c6e5217\
             fb74702e2f1038917dd5fb0eeb7ae1bf7a668fc7d50c034b4cd5a057a8482e6bc9c921297f44e769\
             67265623a167cd9883eb6e64bc77856dc333bd605d7df3bed0e5cecb5a99fe8b62873d58530f",
        )
        .unwrap();
        let result = sniff_quic_sni(&pkt).expect("should extract SNI from Safari QUIC");
        assert_eq!(result.protocol, Some("quic"));
        assert_eq!(result.host.as_deref(), Some("www.google.com"));
        assert_eq!(result.alpn.as_deref(), Some("h3"));
    }

    /// Go parity: TestSniffUQUICChrome115 — single-packet QUIC Initial, SNI = "www.google.com"
    #[test]
    fn go_parity_sniff_quic_uquic_chrome115() {
        let pkt = hex::decode(
            "cb0000000108181e17c387120abc000044d0705b6a3ef9ee37a8d3949a7d393ed078243c2ee2c362\
             7fad1c3f107c117f4f071131ad61848068fcbbe5c65803c147f7f8ec5e2cd77b77beea23ba779d93\
             6dccac540f8396400e3190ea35cc2942af4171a04cb14272491920f90124959f44e80143678c0b52\
             f5d31af319aaa589db2f940f004562724d0af40f737e1bb0002a071e6a1dbc9f52c64f070806a501\
             0abed0298053634d9c9126bd7949ae5087998ade762c0ad06691d99c0875a38c601fc1ee77bfc3b8\
             c11381829f2c9bdd022f4499c43ff1d6aee1a0d296861461dda217d22c568b276016ef3929e59d2f\
             7d7ddf7809920fb7dc805641608949f3f8466ab3d37149aac501f0b107d808f3add4acfc657e4a82\
             e2b88e97a6c74a00c419548760ab3414ba13915c78a1ca79dceee8d59fbe299f20b671ac44823218\
             368b2a026baa55170cf549519ac21dbb6d31d248bd339438a4e663bcdca1fe3ae3f045a5dc19b122\
             e9db9d7af9757076666dda4e9ace1c67def77fa14786f0cab3ebf7a270ea6e2b37838318c95779f8\
             0c3b8471948d0046c3614b3a13477c939a39a7855d85d13522a45ae0765739cd5eedef87237e824a\
             929983ace27640c6495dbf5a72fa0b96893dc5d28f3988249a57bdb458d460b4a57043de3da750a7\
             6b6e5d2259247ca27cd864ea18f0d09aa62ab6eb7c014fb43179b2a1963d170b756cce83eeaebff7\
             8a828d025c811848e16ff862a8080d093478cd2208c8ab0803178325bc0d9d6bb25e62fa50c4ad15\
             cf80916da6578796932036c72e43eb480d1e423ed812ac75a97722f8416529b82ba8ee2219c53501\
             2282bb17066bd53e78b87a71abdb7ebdb2a7c2766ff8397962e87d0f85485b64b4ee81cc84f99c47\
             f33f2b0872716441992773f59186e38d32dbf5609a6fda94cb928cd25f5a7a3ab736b5a4236b6d54\
             09ab18892c6a4d3480fc2350abfdf0bab1cedb55bdf0760fdb703e6688f4de596254eed4ed3e67eb\
             03d0717b8e15b31e735214e588c87ae36bc6c310e1894b4c15143e4ccf287b2dbc707a946bf9671a\
             e3c574f9486b2c82eec784bba4cbc76113cbe0f97ac8c13cfa38f2925ab9d06887a612ce48280a91\
             d7e074e6caf898d88e2bbf71360899abf48a03f9a70cf2891199f2d63b116f4871af0ebb4f490679\
             2f66cc21d1609f189138532875c129a68c73e7bcd3b5d8100beac1d8ac4b20d94a59ac8df5a5af58\
             a9acb20413eadf97189f5f19ff889155f0c4d37514ec184eb6903967ff38a41fc087abb0f2cad376\
             1d6e3f95f92a09a72f5c065b16e188088b87460241f27ecdb1bc6ece92c8d36b2d68b58d0fb4d4b3\
             c928c579ade8ae5a995833aadd297c30a37f7bc35440fc97070e1b198e0fac00157452177d16d280\
             3b4239997452b4ad3a951173bdec47a033fd7f8a7942accaa9aaa905b3c5a2175e7c3e07c48bf253\
             31727fd69cd1e64d74d8c9d4a6f8f4491adb7bc911505cb19877083d8f21a12475e313fccf57877f\
             f3556318e81ed9145dd9427f2b65275440893035f417481f721c69215af8ae103530cd0a1d35bf2c\
             b5a27628f8d44d7c6f5ec12ce79d0a8333e0eb48771115d0a191304e46b8db19bbe5c40f1c346dde\
             98e76ff5e21ff38d2c34e60cb07766ed529dd6d2cbacd7fbf1ed8a0e6e40decad0ca5021e91552be\
             87c156d3ae2fffef41c65b14ba6d488f2c3227a1ab11ffce0e2dc47723a69da27a67a7f26e1cb13a\
             7103af9b87a8db8e18ea",
        )
        .unwrap();
        let result = sniff_quic_sni(&pkt).expect("should extract SNI from uQUIC Chrome115");
        assert_eq!(result.protocol, Some("quic"));
        assert_eq!(result.host.as_deref(), Some("www.google.com"));
        assert_eq!(result.alpn.as_deref(), Some("h3"));
    }

    #[test]
    fn returns_none_for_short_packets() {
        assert!(sniff_quic_sni(&[]).is_none());
        assert!(sniff_quic_sni(&[0xc0]).is_none());
        assert!(sniff_quic_sni(&[0xc0, 0x00, 0x00, 0x00, 0x01]).is_none());
    }

    #[test]
    fn returns_none_for_non_quic() {
        // HTTP request
        assert!(sniff_quic_sni(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").is_none());
        // Short header (no fixed bit)
        assert!(sniff_quic_sni(&[0x80, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00]).is_none());
    }

    #[test]
    fn returns_none_for_unknown_version() {
        // Valid flags but unknown version
        let pkt = [0xc0, 0x00, 0x00, 0x00, 0x05, 0x08, 0x00];
        assert!(sniff_quic_sni(&pkt).is_none());
    }

    #[test]
    fn read_quic_varint_1byte() {
        assert_eq!(read_quic_varint(&[0x25], 0), Some((0x25, 1)));
        assert_eq!(read_quic_varint(&[0x00], 0), Some((0, 1)));
        assert_eq!(read_quic_varint(&[0x3f], 0), Some((63, 1)));
    }

    #[test]
    fn read_quic_varint_2byte() {
        // 0x7bbd = 0b01_111011_10111101 → first 2 bits = 01 → 2 bytes, value = 0x3bbd = 15293
        assert_eq!(read_quic_varint(&[0x7b, 0xbd], 0), Some((15293, 2)));
    }

    #[test]
    fn read_quic_varint_4byte() {
        // RFC 9000 example: 0x9d7f3e7d → 4 bytes, value = 0x1d7f3e7d = 494878333
        assert_eq!(
            read_quic_varint(&[0x9d, 0x7f, 0x3e, 0x7d], 0),
            Some((494878333, 4))
        );
    }

    #[test]
    fn read_quic_varint_8byte() {
        // RFC 9000 example: 0xc2197c5eff14e88c → 8 bytes, value = 151288809941952652
        assert_eq!(
            read_quic_varint(&[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c], 0),
            Some((151288809941952652, 8))
        );
    }

    #[test]
    fn read_quic_varint_buffer_too_short() {
        assert_eq!(read_quic_varint(&[], 0), None);
        // 2-byte varint but only 1 byte available
        assert_eq!(read_quic_varint(&[0x40], 0), None);
    }
}
