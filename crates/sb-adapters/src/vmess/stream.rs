//! VMess chunked-AEAD body stream plus the async handshake drivers.
//!
//! `VmessStream` wraps any byte stream and turns it into the VMess body wire
//! format: each chunk is `maskedLen(2) || AEAD.seal(piece)`, where `maskedLen`
//! is `(len(piece)+16) XOR SHAKE128(nonce)` and the AEAD nonce is
//! `counter_u16_be || baseNonce[2..12]`.
//!
//! `VmessStream` 将任意字节流转换为 VMess 正文线格式：每块为
//! `maskedLen(2) || AEAD.seal(piece)`，掩码长度与计数器 nonce 与 Go 完全一致。

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, KeyInit as GcmKeyInit};
use anyhow::{anyhow, Result};
use chacha20poly1305::ChaCha20Poly1305;
use md5::{Digest as Md5Digest, Md5};
use rand::Rng;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake128Reader};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::{
    client_parse_response_header, client_parse_response_len, encode_client_request,
    encode_server_response, RequestRandomness, ServerRequest, SessionKeys, CIPHER_OVERHEAD,
    OPTION_CHUNK_MASKING, OPTION_CHUNK_STREAM, SECURITY_AES128_GCM, SECURITY_CHACHA20_POLY1305,
    SECURITY_NONE, SERVER_PREFIX_LEN, WRITE_CHUNK_SIZE,
};

const MAX_CHUNK: usize = 16384 + CIPHER_OVERHEAD;

/// AEAD body cipher (per direction).
enum BodyCipher {
    Aes(Box<Aes128Gcm>),
    Cha(Box<ChaCha20Poly1305>),
}

impl BodyCipher {
    fn new(security: u8, key16: &[u8; 16]) -> Result<Self> {
        match security {
            SECURITY_AES128_GCM => Ok(BodyCipher::Aes(Box::new(
                Aes128Gcm::new_from_slice(key16).expect("16-byte key"),
            ))),
            SECURITY_CHACHA20_POLY1305 => {
                // key = MD5(k) || MD5(MD5(k))
                let mut key = [0u8; 32];
                let a = Md5::digest(key16);
                key[..16].copy_from_slice(&a);
                let b = Md5::digest(&key[..16]);
                key[16..].copy_from_slice(&b);
                Ok(BodyCipher::Cha(Box::new(
                    ChaCha20Poly1305::new_from_slice(&key).expect("32-byte key"),
                )))
            }
            other => Err(anyhow!("vmess: unsupported body security {other}")),
        }
    }

    fn seal(&self, nonce: &[u8; 12], plain: &[u8]) -> Vec<u8> {
        match self {
            BodyCipher::Aes(c) => c
                .encrypt(aes_gcm::Nonce::from_slice(nonce), plain)
                .expect("AES-128-GCM seal is infallible"),
            BodyCipher::Cha(c) => c
                .encrypt(chacha20poly1305::Nonce::from_slice(nonce), plain)
                .expect("ChaCha20-Poly1305 seal is infallible"),
        }
    }

    fn open(&self, nonce: &[u8; 12], ct: &[u8]) -> Result<Vec<u8>> {
        let r = match self {
            BodyCipher::Aes(c) => c.decrypt(aes_gcm::Nonce::from_slice(nonce), ct),
            BodyCipher::Cha(c) => c.decrypt(chacha20poly1305::Nonce::from_slice(nonce), ct),
        };
        r.map_err(|_| anyhow!("vmess: body chunk authentication failed"))
    }
}

fn shake_seed(nonce16: &[u8; 16]) -> Shake128Reader {
    let mut x = Shake128::default();
    x.update(nonce16);
    x.finalize_xof()
}

fn next_mask(shake: &mut Option<Shake128Reader>) -> u16 {
    match shake {
        Some(r) => {
            let mut b = [0u8; 2];
            r.read(&mut b);
            u16::from_be_bytes(b)
        }
        None => 0,
    }
}

fn chunk_nonce(base: &[u8; 12], counter: u16) -> [u8; 12] {
    let mut n = *base;
    n[..2].copy_from_slice(&counter.to_be_bytes());
    n
}

enum ReadWant {
    Len,
    Body(usize),
}

enum Step {
    Produced,
    NeedMore,
    Eof,
}

/// Client-only: the response header must be consumed lazily on the first read,
/// because a canonical server writes its response only on its first write.
#[derive(Clone, Copy)]
struct RespState {
    keys: SessionKeys,
    stage: RespStage,
}

#[derive(Clone, Copy)]
enum RespStage {
    Len,
    Header(usize),
    SkipCmd(usize),
}

struct ReadHalf {
    cipher: Option<BodyCipher>,
    base_nonce: [u8; 12],
    counter: u16,
    shake: Option<Shake128Reader>,
    raw: Vec<u8>,
    raw_pos: usize,
    want: ReadWant,
    plain: Vec<u8>,
    plain_pos: usize,
    eof: bool,
    resp: Option<RespState>,
}

impl ReadHalf {
    fn avail(&self) -> usize {
        self.raw.len() - self.raw_pos
    }

    fn compact(&mut self) {
        if self.raw_pos > 0 {
            self.raw.drain(..self.raw_pos);
            self.raw_pos = 0;
        }
    }

    /// Consume the lazily-read response header from `raw`. Returns `Produced`
    /// when the whole response header has been consumed.
    fn try_prelude(&mut self) -> Result<Step> {
        loop {
            let (keys, stage) = {
                let st = self.resp.as_ref().expect("prelude present");
                (st.keys, st.stage)
            };
            match stage {
                RespStage::Len => {
                    let need = 2 + CIPHER_OVERHEAD;
                    if self.avail() < need {
                        return Ok(Step::NeedMore);
                    }
                    let hlen = {
                        let e = &self.raw[self.raw_pos..self.raw_pos + need];
                        client_parse_response_len(&keys, e)?
                    };
                    self.raw_pos += need;
                    self.resp.as_mut().expect("prelude present").stage = RespStage::Header(hlen);
                }
                RespStage::Header(hlen) => {
                    let need = hlen + CIPHER_OVERHEAD;
                    if self.avail() < need {
                        return Ok(Step::NeedMore);
                    }
                    let cmd_len = {
                        let e = &self.raw[self.raw_pos..self.raw_pos + need];
                        client_parse_response_header(&keys, e)?
                    };
                    self.raw_pos += need;
                    if cmd_len > 0 {
                        self.resp.as_mut().expect("prelude present").stage =
                            RespStage::SkipCmd(cmd_len);
                    } else {
                        return Ok(Step::Produced);
                    }
                }
                RespStage::SkipCmd(n) => {
                    if self.avail() < n {
                        return Ok(Step::NeedMore);
                    }
                    self.raw_pos += n;
                    return Ok(Step::Produced);
                }
            }
        }
    }

    fn try_frame(&mut self) -> Result<Step> {
        loop {
            match self.want {
                ReadWant::Len => {
                    if self.avail() < 2 {
                        return Ok(Step::NeedMore);
                    }
                    let masked = {
                        let b = &self.raw[self.raw_pos..];
                        u16::from_be_bytes([b[0], b[1]])
                    };
                    let mask = next_mask(&mut self.shake);
                    let sealed = (masked ^ mask) as usize;
                    self.raw_pos += 2;
                    if sealed == 0 {
                        self.eof = true;
                        return Ok(Step::Eof);
                    }
                    if !(CIPHER_OVERHEAD..=MAX_CHUNK).contains(&sealed) {
                        return Err(anyhow!("vmess: invalid body chunk length {sealed}"));
                    }
                    self.want = ReadWant::Body(sealed);
                }
                ReadWant::Body(sealed) => {
                    if self.avail() < sealed {
                        return Ok(Step::NeedMore);
                    }
                    let nonce = chunk_nonce(&self.base_nonce, self.counter);
                    let plain = {
                        let ct = &self.raw[self.raw_pos..self.raw_pos + sealed];
                        self.cipher
                            .as_ref()
                            .expect("framed VMess body has cipher")
                            .open(&nonce, ct)?
                    };
                    self.counter = self.counter.wrapping_add(1);
                    self.raw_pos += sealed;
                    self.want = ReadWant::Len;
                    self.plain = plain;
                    self.plain_pos = 0;
                    return Ok(Step::Produced);
                }
            }
        }
    }
}

struct WriteHalf {
    cipher: Option<BodyCipher>,
    base_nonce: [u8; 12],
    counter: u16,
    shake: Option<Shake128Reader>,
    out: Vec<u8>,
    out_pos: usize,
}

impl WriteHalf {
    fn encode_frame(&mut self, piece: &[u8]) {
        let nonce = chunk_nonce(&self.base_nonce, self.counter);
        let sealed = self
            .cipher
            .as_ref()
            .expect("framed VMess body has cipher")
            .seal(&nonce, piece);
        self.counter = self.counter.wrapping_add(1);
        let mask = next_mask(&mut self.shake);
        let masked = (sealed.len() as u16) ^ mask;
        self.out.extend_from_slice(&masked.to_be_bytes());
        self.out.extend_from_slice(&sealed);
    }
}

/// A VMess body stream: reads decrypt the peer's chunks, writes encrypt ours.
pub struct VmessStream<S> {
    inner: S,
    r: ReadHalf,
    w: WriteHalf,
    raw_body: bool,
}

impl<S> VmessStream<S> {
    /// Build a stream once the handshake keys are known.
    /// `read_*` keys decrypt the peer-to-us direction; `write_*` keys encrypt
    /// the us-to-peer direction.
    fn new(
        inner: S,
        security: u8,
        read_key: [u8; 16],
        read_nonce: [u8; 16],
        write_key: [u8; 16],
        write_nonce: [u8; 16],
        option: u8,
        resp: Option<RespState>,
    ) -> Result<Self> {
        let mut read_base = [0u8; 12];
        read_base.copy_from_slice(&read_nonce[..12]);
        let mut write_base = [0u8; 12];
        write_base.copy_from_slice(&write_nonce[..12]);
        let raw_body = security == SECURITY_NONE && option & OPTION_CHUNK_STREAM == 0;
        let mask = option & OPTION_CHUNK_MASKING != 0;
        let read_cipher = if raw_body {
            None
        } else {
            Some(BodyCipher::new(security, &read_key)?)
        };
        let write_cipher = if raw_body {
            None
        } else {
            Some(BodyCipher::new(security, &write_key)?)
        };
        Ok(Self {
            inner,
            r: ReadHalf {
                cipher: read_cipher,
                base_nonce: read_base,
                counter: 0,
                shake: mask.then(|| shake_seed(&read_nonce)),
                raw: Vec::new(),
                raw_pos: 0,
                want: ReadWant::Len,
                plain: Vec::new(),
                plain_pos: 0,
                eof: false,
                resp,
            },
            w: WriteHalf {
                cipher: write_cipher,
                base_nonce: write_base,
                counter: 0,
                shake: mask.then(|| shake_seed(&write_nonce)),
                out: Vec::new(),
                out_pos: 0,
            },
            raw_body,
        })
    }
}

impl<S: AsyncWrite + Unpin> VmessStream<S> {
    fn flush_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.w.out_pos < self.w.out.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.w.out[self.w.out_pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "vmess: underlying write returned 0",
                    )))
                }
                Poll::Ready(Ok(k)) => self.w.out_pos += k,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.w.out.clear();
        self.w.out_pos = 0;
        Poll::Ready(Ok(()))
    }
}

fn io_err(e: anyhow::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for VmessStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.r.plain_pos < this.r.plain.len() {
                let n = buf.remaining().min(this.r.plain.len() - this.r.plain_pos);
                buf.put_slice(&this.r.plain[this.r.plain_pos..this.r.plain_pos + n]);
                this.r.plain_pos += n;
                return Poll::Ready(Ok(()));
            }
            if this.r.eof {
                return Poll::Ready(Ok(()));
            }
            // First consume the lazily-read response header (client only), then
            // decode framed AEAD or expose Go's TCP zero/none raw body.
            let need_fill = if this.r.resp.is_some() {
                match this.r.try_prelude().map_err(io_err)? {
                    Step::Produced => {
                        this.r.resp = None;
                        continue;
                    }
                    Step::NeedMore => true,
                    Step::Eof => true,
                }
            } else if this.raw_body {
                if this.r.avail() > 0 {
                    let n = buf.remaining().min(this.r.avail());
                    buf.put_slice(&this.r.raw[this.r.raw_pos..this.r.raw_pos + n]);
                    this.r.raw_pos += n;
                    return Poll::Ready(Ok(()));
                }
                this.r.compact();
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            } else {
                match this.r.try_frame().map_err(io_err)? {
                    Step::Produced => continue,
                    Step::Eof => return Poll::Ready(Ok(())),
                    Step::NeedMore => true,
                }
            };
            if !need_fill {
                continue;
            }
            this.r.compact();
            let mut tmp = [0u8; 8192];
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let filled = rb.filled();
                    if filled.is_empty() {
                        if this.r.resp.is_some() {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "vmess: eof during response header",
                            )));
                        }
                        this.r.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    this.r.raw.extend_from_slice(filled);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for VmessStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.raw_body {
            return Pin::new(&mut this.inner).poll_write(cx, data);
        }
        match this.flush_out(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = data.len().min(WRITE_CHUNK_SIZE);
        this.w.encode_frame(&data[..n]);
        match this.flush_out(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            // Frame is buffered; report it consumed and let poll_flush drain.
            Poll::Pending => {}
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.raw_body {
            return Pin::new(&mut this.inner).poll_flush(cx);
        }
        match this.flush_out(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.raw_body {
            return Pin::new(&mut this.inner).poll_shutdown(cx);
        }
        match this.flush_out(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// Client-side handshake: send the request, read the response header, and
/// return the ready body stream.
pub async fn client_connect<S>(
    mut inner: S,
    cmd_key: [u8; 16],
    security: u8,
    host: &str,
    port: u16,
) -> Result<VmessStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Go sing-vmess maps both "zero" and "none" to SECURITY_NONE. For TCP it
    // sends option=0 and exposes a raw body inside the protected outer
    // transport; the AEAD response header remains canonical.
    let option = if security == SECURITY_NONE {
        0
    } else {
        OPTION_CHUNK_STREAM | OPTION_CHUNK_MASKING
    };
    // Generate all randomness up front and drop the (non-Send) RNG before any
    // await, so the returned future stays `Send`.
    let r = {
        let mut rng = rand::thread_rng();
        let mut req_key = [0u8; 16];
        let mut req_nonce = [0u8; 16];
        let mut conn_nonce = [0u8; 8];
        let mut auth_rand4 = [0u8; 4];
        rng.fill(&mut req_key);
        rng.fill(&mut req_nonce);
        rng.fill(&mut conn_nonce);
        rng.fill(&mut auth_rand4);
        let response_header: u8 = rng.gen();
        let pad_len = (rng.gen::<u8>() % 16) as usize;
        let mut pad = vec![0u8; pad_len];
        rng.fill(&mut pad[..]);
        RequestRandomness {
            req_key,
            req_nonce,
            response_header,
            conn_nonce,
            auth_rand4,
            pad,
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (wire, keys) = encode_client_request(&cmd_key, security, option, host, port, now, &r);
    inner.write_all(&wire).await?;
    inner.flush().await?;

    // The response header is read lazily on the first body read: a canonical
    // server writes its response only on its first write, so eagerly reading it
    // here would deadlock when the application writes first.
    let resp = Some(RespState {
        keys,
        stage: RespStage::Len,
    });
    // client reads server->client (resp), writes client->server (req)
    VmessStream::new(
        inner,
        keys.security,
        keys.resp_key,
        keys.resp_nonce,
        keys.req_key,
        keys.req_nonce,
        keys.option,
        resp,
    )
}

/// Server-side: read and decrypt the request header from the stream.
pub async fn server_read_request<S>(inner: &mut S, cmd_key: &[u8; 16]) -> Result<ServerRequest>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let mut prefix = [0u8; SERVER_PREFIX_LEN];
    inner.read_exact(&mut prefix).await?;
    let (hlen, auth_id, conn_nonce) = super::server_parse_length(cmd_key, &prefix)?;
    let mut enc_header = vec![0u8; hlen + CIPHER_OVERHEAD];
    inner.read_exact(&mut enc_header).await?;
    super::server_parse_header(cmd_key, &auth_id, &conn_nonce, &enc_header)
}

/// Server-side: write the response header and wrap the stream for the body.
pub async fn server_finish<S>(mut inner: S, keys: &SessionKeys) -> Result<VmessStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let resp = encode_server_response(keys);
    inner.write_all(&resp).await?;
    inner.flush().await?;
    // server reads client->server (req), writes server->client (resp)
    VmessStream::new(
        inner,
        keys.security,
        keys.req_key,
        keys.req_nonce,
        keys.resp_key,
        keys.resp_nonce,
        keys.option,
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vmess::command_key;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn run_case(security: u8) {
        let uuid = [
            0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3,
            0x08, 0x11,
        ];
        let cmd_key = command_key(&uuid);
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        // server task: read request, echo body back through canonical framing.
        let server = tokio::spawn(async move {
            let mut server_io = server_io;
            let req = server_read_request(&mut server_io, &cmd_key).await.unwrap();
            assert_eq!(req.host, "example.com");
            assert_eq!(req.port, 443);
            assert_eq!(req.keys.security, security);
            if security == SECURITY_NONE {
                assert_eq!(req.keys.option, 0);
            } else {
                assert_eq!(req.keys.option, OPTION_CHUNK_STREAM | OPTION_CHUNK_MASKING);
            }
            let mut stream = server_finish(server_io, &req.keys).await.unwrap();
            let mut buf = vec![0u8; 4096];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                stream.write_all(&buf[..n]).await.unwrap();
                stream.flush().await.unwrap();
            }
        });

        let mut client = client_connect(client_io, cmd_key, security, "example.com", 443)
            .await
            .unwrap();

        for payload in [
            b"hello world".to_vec(),
            vec![0x5au8; 9000],
            b"final".to_vec(),
        ] {
            client.write_all(&payload).await.unwrap();
            client.flush().await.unwrap();
            let mut got = vec![0u8; payload.len()];
            client.read_exact(&mut got).await.unwrap();
            assert_eq!(got, payload);
        }
        drop(client);
        let _ = server.await;
    }

    #[tokio::test]
    async fn round_trip_aes128gcm() {
        run_case(SECURITY_AES128_GCM).await;
    }

    #[tokio::test]
    async fn round_trip_chacha20() {
        run_case(SECURITY_CHACHA20_POLY1305).await;
    }

    #[tokio::test]
    async fn round_trip_zero_uses_unframed_tcp_body() {
        run_case(SECURITY_NONE).await;
    }
}
