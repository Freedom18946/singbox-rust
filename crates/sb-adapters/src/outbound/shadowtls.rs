//! ShadowTLS outbound connector adapter.
//!
//! IMPORTANT:
//! The previous implementation modeled ShadowTLS as a standalone "TLS + HTTP
//! CONNECT tunnel". That does not match sing-box ShadowTLS semantics, where
//! ShadowTLS acts as a transport wrapper/detour rather than a leaf protocol
//! that serializes the final destination itself.
//!
//! Until transport-wrapper chaining is implemented, this adapter remains
//! registrable but rejects standalone leaf dialing at runtime so parity
//! evidence is not contaminated by the legacy tunnel model.
//!
use crate::outbound::prelude::*;
use std::time::Duration;

#[cfg(feature = "adapter-shadowtls")]
mod tls_helper {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};

    #[derive(Debug)]
    pub(super) struct NoVerifier;

    impl ServerCertVerifier for NoVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
            ]
        }
    }
}

#[cfg(feature = "adapter-shadowtls")]
use tls_helper::NoVerifier;
#[cfg(feature = "adapter-shadowtls")]
use {
    hmac::{Hmac, Mac},
    rand::RngCore,
    sha1::Sha1,
    std::pin::Pin,
    std::task::{Context, Poll},
    tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    tokio::task::JoinHandle,
};

#[cfg(feature = "adapter-shadowtls")]
type HmacSha1 = Hmac<Sha1>;

#[cfg(feature = "adapter-shadowtls")]
const TLS_HEADER_SIZE: usize = 5;
#[cfg(feature = "adapter-shadowtls")]
const TLS_RANDOM_SIZE: usize = 32;
#[cfg(feature = "adapter-shadowtls")]
const TLS_SESSION_ID_SIZE: usize = 32;
#[cfg(feature = "adapter-shadowtls")]
const SHADOWTLS_V3_HMAC_SIZE: usize = 4;
#[cfg(feature = "adapter-shadowtls")]
const HANDSHAKE: u8 = 22;
#[cfg(feature = "adapter-shadowtls")]
const ALERT: u8 = 21;
#[cfg(feature = "adapter-shadowtls")]
const APPLICATION_DATA: u8 = 23;
#[cfg(feature = "adapter-shadowtls")]
const SERVER_HELLO: u8 = 2;
#[cfg(feature = "adapter-shadowtls")]
const SERVER_RANDOM_INDEX: usize = TLS_HEADER_SIZE + 1 + 3 + 2;
#[cfg(feature = "adapter-shadowtls")]
const CLIENT_HELLO_SESSION_ID_START: usize = 1 + 3 + 2 + TLS_RANDOM_SIZE + 1;

#[cfg(feature = "adapter-shadowtls")]
#[derive(Debug)]
struct ShadowTlsV3SessionIdGenerator {
    password: String,
}

#[cfg(feature = "adapter-shadowtls")]
impl ShadowTlsV3SessionIdGenerator {
    fn new(password: String) -> Self {
        Self { password }
    }
}

#[cfg(feature = "adapter-shadowtls")]
impl rustls::client::SessionIdGenerator for ShadowTlsV3SessionIdGenerator {
    fn generate(&self, client_hello: &[u8], session_id: &mut [u8]) -> Result<(), rustls::Error> {
        if session_id.len() != TLS_SESSION_ID_SIZE {
            return Err(rustls::Error::General(format!(
                "shadowtls v3 requires a {TLS_SESSION_ID_SIZE}-byte session_id, got {} bytes",
                session_id.len()
            )));
        }
        if client_hello.len() < CLIENT_HELLO_SESSION_ID_START + TLS_SESSION_ID_SIZE {
            return Err(rustls::Error::General(
                "shadowtls v3 client hello is shorter than the session_id field".to_string(),
            ));
        }
        if client_hello.get(CLIENT_HELLO_SESSION_ID_START - 1).copied()
            != Some(TLS_SESSION_ID_SIZE as u8)
        {
            return Err(rustls::Error::General(
                "shadowtls v3 client hello did not expose a 32-byte session_id slot".to_string(),
            ));
        }

        session_id.fill(0);
        rand::rngs::OsRng
            .fill_bytes(&mut session_id[..TLS_SESSION_ID_SIZE - SHADOWTLS_V3_HMAC_SIZE]);

        let mut hmac = HmacSha1::new_from_slice(self.password.as_bytes())
            .map_err(|_| rustls::Error::General("shadowtls v3 hmac init failed".to_string()))?;
        hmac.update(&client_hello[..CLIENT_HELLO_SESSION_ID_START]);
        hmac.update(session_id);
        hmac.update(&client_hello[CLIENT_HELLO_SESSION_ID_START + TLS_SESSION_ID_SIZE..]);
        let digest = hmac.finalize().into_bytes();
        session_id[TLS_SESSION_ID_SIZE - SHADOWTLS_V3_HMAC_SIZE..]
            .copy_from_slice(&digest[..SHADOWTLS_V3_HMAC_SIZE]);
        Ok(())
    }
}

#[cfg(feature = "adapter-shadowtls")]
struct HashTrackedReadStream<S> {
    inner: S,
    hasher: HmacSha1,
}

#[cfg(feature = "adapter-shadowtls")]
impl<S> HashTrackedReadStream<S> {
    fn new(inner: S, password: &str) -> Self {
        Self {
            inner,
            hasher: HmacSha1::new_from_slice(password.as_bytes())
                .expect("hmac accepts any key length"),
        }
    }

    fn into_inner(self) -> (S, [u8; 8]) {
        let mut prefix = [0u8; 8];
        let digest = self.hasher.finalize().into_bytes();
        prefix.copy_from_slice(&digest[..8]);
        (self.inner, prefix)
    }
}

#[cfg(feature = "adapter-shadowtls")]
impl<S: AsyncRead + Unpin> AsyncRead for HashTrackedReadStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let filled = &buf.filled()[before..];
                if !filled.is_empty() {
                    self.hasher.update(filled);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

#[cfg(feature = "adapter-shadowtls")]
impl<S: AsyncWrite + Unpin> AsyncWrite for HashTrackedReadStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(feature = "adapter-shadowtls")]
struct ShadowTlsV3HandshakeStream<S> {
    inner: S,
    password: String,
    read_state: ShadowTlsV3ReadState,
    buffered_frame: Vec<u8>,
    buffered_offset: usize,
    server_random: Option<[u8; TLS_RANDOM_SIZE]>,
    read_hmac: Option<HmacSha1>,
    read_hmac_key: Option<[u8; 32]>,
    is_tls13: bool,
    authorized: bool,
}

#[cfg(feature = "adapter-shadowtls")]
enum ShadowTlsV3ReadState {
    ReadingHeader {
        header: [u8; TLS_HEADER_SIZE],
        filled: usize,
    },
    ReadingPayload {
        header: [u8; TLS_HEADER_SIZE],
        payload: Vec<u8>,
        filled: usize,
    },
}

#[cfg(feature = "adapter-shadowtls")]
struct ShadowTlsV3Established<S> {
    inner: S,
    server_random: [u8; TLS_RANDOM_SIZE],
    is_tls13: bool,
    authorized: bool,
    read_hmac: Option<HmacSha1>,
}

#[cfg(feature = "adapter-shadowtls")]
impl<S> ShadowTlsV3HandshakeStream<S> {
    fn new(inner: S, password: String) -> Self {
        Self {
            inner,
            password,
            read_state: ShadowTlsV3ReadState::ReadingHeader {
                header: [0u8; TLS_HEADER_SIZE],
                filled: 0,
            },
            buffered_frame: Vec::new(),
            buffered_offset: 0,
            server_random: None,
            read_hmac: None,
            read_hmac_key: None,
            is_tls13: false,
            authorized: false,
        }
    }

    fn finish(self) -> Result<ShadowTlsV3Established<S>> {
        if self.buffered_offset < self.buffered_frame.len() {
            return Err(AdapterError::Other(
                "shadowtls v3 handshake completed with unread transformed TLS data".to_string(),
            ));
        }
        if !matches!(
            self.read_state,
            ShadowTlsV3ReadState::ReadingHeader { filled: 0, .. }
        ) {
            return Err(AdapterError::Other(
                "shadowtls v3 handshake completed with a partial TLS frame".to_string(),
            ));
        }
        let server_random = self.server_random.ok_or_else(|| {
            AdapterError::Other(
                "shadowtls v3 handshake finished without extracting a server random".to_string(),
            )
        })?;
        Ok(ShadowTlsV3Established {
            inner: self.inner,
            server_random,
            is_tls13: self.is_tls13,
            authorized: self.authorized,
            read_hmac: self.read_hmac,
        })
    }

    fn prepare_buffered_frame(&mut self, header: [u8; TLS_HEADER_SIZE], payload: Vec<u8>) {
        let mut frame = Vec::with_capacity(TLS_HEADER_SIZE + payload.len());
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&payload);
        match header[0] {
            HANDSHAKE => {
                if frame.len() >= SERVER_RANDOM_INDEX + TLS_RANDOM_SIZE
                    && frame[TLS_HEADER_SIZE] == SERVER_HELLO
                {
                    let mut server_random = [0u8; TLS_RANDOM_SIZE];
                    server_random.copy_from_slice(
                        &frame[SERVER_RANDOM_INDEX..SERVER_RANDOM_INDEX + TLS_RANDOM_SIZE],
                    );
                    let mut hmac =
                        HmacSha1::new_from_slice(self.password.as_bytes()).expect("hmac init");
                    hmac.update(&server_random);
                    self.read_hmac_key = Some(kdf(&self.password, &server_random));
                    self.server_random = Some(server_random);
                    self.is_tls13 = server_hello_supports_tls13_frame(&frame);
                    self.authorized = !self.is_tls13;
                    self.read_hmac = Some(hmac);
                }
            }
            APPLICATION_DATA => {
                self.authorized = false;
                if frame.len() >= TLS_HEADER_SIZE + SHADOWTLS_V3_HMAC_SIZE {
                    if let (Some(read_hmac), Some(read_hmac_key)) =
                        (self.read_hmac.as_mut(), self.read_hmac_key.as_ref())
                    {
                        let payload_start = TLS_HEADER_SIZE + SHADOWTLS_V3_HMAC_SIZE;
                        let payload_len = frame.len() - payload_start;
                        let mut tag = [0u8; SHADOWTLS_V3_HMAC_SIZE];
                        tag.copy_from_slice(
                            &frame[TLS_HEADER_SIZE..TLS_HEADER_SIZE + SHADOWTLS_V3_HMAC_SIZE],
                        );
                        {
                            let payload = &mut frame[payload_start..];
                            read_hmac.update(payload);
                            let digest = read_hmac.clone().finalize().into_bytes();
                            if digest[..SHADOWTLS_V3_HMAC_SIZE] == tag {
                                xor_slice(payload, read_hmac_key);
                                self.authorized = true;
                            }
                        }
                        let digest = read_hmac.clone().finalize().into_bytes();
                        if digest[..SHADOWTLS_V3_HMAC_SIZE] == tag {
                            frame.copy_within(payload_start.., TLS_HEADER_SIZE);
                            frame.truncate(TLS_HEADER_SIZE + payload_len);
                            let new_len = (payload_len as u16).to_be_bytes();
                            frame[3..5].copy_from_slice(&new_len);
                        }
                    }
                }
            }
            _ => {}
        }
        self.buffered_frame = frame;
        self.buffered_offset = 0;
    }
}

#[cfg(feature = "adapter-shadowtls")]
impl<S: AsyncRead + Unpin> AsyncRead for ShadowTlsV3HandshakeStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.buffered_offset < self.buffered_frame.len() {
            let remaining = &self.buffered_frame[self.buffered_offset..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.buffered_offset += to_copy;
            if self.buffered_offset == self.buffered_frame.len() {
                self.buffered_frame.clear();
                self.buffered_offset = 0;
            }
            return Poll::Ready(Ok(()));
        }

        loop {
            let state = std::mem::replace(
                &mut self.read_state,
                ShadowTlsV3ReadState::ReadingHeader {
                    header: [0u8; TLS_HEADER_SIZE],
                    filled: 0,
                },
            );
            match state {
                ShadowTlsV3ReadState::ReadingHeader {
                    mut header,
                    mut filled,
                } => {
                    let mut read_buf = ReadBuf::new(&mut header[filled..]);
                    match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                        Poll::Pending => {
                            self.read_state =
                                ShadowTlsV3ReadState::ReadingHeader { header, filled };
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(err)) => {
                            self.read_state =
                                ShadowTlsV3ReadState::ReadingHeader { header, filled };
                            return Poll::Ready(Err(err));
                        }
                        Poll::Ready(Ok(())) => {
                            let read = read_buf.filled().len();
                            if read == 0 {
                                self.read_state =
                                    ShadowTlsV3ReadState::ReadingHeader { header, filled };
                                if filled == 0 {
                                    return Poll::Ready(Ok(()));
                                }
                                return Poll::Ready(Err(std::io::Error::new(
                                    std::io::ErrorKind::UnexpectedEof,
                                    "early eof while reading shadowtls v3 tls header",
                                )));
                            }
                            filled += read;
                            if filled < TLS_HEADER_SIZE {
                                self.read_state =
                                    ShadowTlsV3ReadState::ReadingHeader { header, filled };
                                return Poll::Pending;
                            }
                            let payload_len = u16::from_be_bytes([header[3], header[4]]) as usize;
                            self.read_state = ShadowTlsV3ReadState::ReadingPayload {
                                header,
                                payload: vec![0u8; payload_len],
                                filled: 0,
                            };
                        }
                    }
                }
                ShadowTlsV3ReadState::ReadingPayload {
                    header,
                    mut payload,
                    mut filled,
                } => {
                    let mut read_buf = ReadBuf::new(&mut payload[filled..]);
                    match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                        Poll::Pending => {
                            self.read_state = ShadowTlsV3ReadState::ReadingPayload {
                                header,
                                payload,
                                filled,
                            };
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(err)) => {
                            self.read_state = ShadowTlsV3ReadState::ReadingPayload {
                                header,
                                payload,
                                filled,
                            };
                            return Poll::Ready(Err(err));
                        }
                        Poll::Ready(Ok(())) => {
                            let read = read_buf.filled().len();
                            if read == 0 {
                                self.read_state = ShadowTlsV3ReadState::ReadingPayload {
                                    header,
                                    payload,
                                    filled,
                                };
                                return Poll::Ready(Err(std::io::Error::new(
                                    std::io::ErrorKind::UnexpectedEof,
                                    "early eof while reading shadowtls v3 tls payload",
                                )));
                            }
                            filled += read;
                            if filled < payload.len() {
                                self.read_state = ShadowTlsV3ReadState::ReadingPayload {
                                    header,
                                    payload,
                                    filled,
                                };
                                return Poll::Pending;
                            }
                            self.read_state = ShadowTlsV3ReadState::ReadingHeader {
                                header: [0u8; TLS_HEADER_SIZE],
                                filled: 0,
                            };
                            self.prepare_buffered_frame(header, payload);
                            let remaining = &self.buffered_frame[self.buffered_offset..];
                            let to_copy = remaining.len().min(buf.remaining());
                            buf.put_slice(&remaining[..to_copy]);
                            self.buffered_offset += to_copy;
                            if self.buffered_offset == self.buffered_frame.len() {
                                self.buffered_frame.clear();
                                self.buffered_offset = 0;
                            }
                            return Poll::Ready(Ok(()));
                        }
                    }
                }
            }
        }
    }
}

#[cfg(feature = "adapter-shadowtls")]
impl<S: AsyncWrite + Unpin> AsyncWrite for ShadowTlsV3HandshakeStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(feature = "adapter-shadowtls")]
async fn read_exact_or_eof<R>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<bool>
where
    R: AsyncRead + Unpin,
{
    let mut filled = 0;
    while filled < buf.len() {
        let n = reader.read(&mut buf[filled..]).await?;
        if n == 0 {
            if filled == 0 {
                return Ok(false);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "early eof",
            ));
        }
        filled += n;
    }
    Ok(true)
}

#[cfg(feature = "adapter-shadowtls")]
async fn read_shadowtls_application_record<R>(reader: &mut R) -> std::io::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 5];
    if !read_exact_or_eof(reader, &mut header).await? {
        return Ok(None);
    }
    if header[0] != 23 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unexpected TLS record type: {}", header[0]),
        ));
    }
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut payload = vec![0u8; length];
    read_exact_or_eof(reader, &mut payload).await?;
    Ok(Some(payload))
}

#[cfg(feature = "adapter-shadowtls")]
async fn write_tls12_record<W>(writer: &mut W, payload: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut header = [0u8; 5];
    header[0] = 23;
    header[1] = 0x03;
    header[2] = 0x03;
    header[3..5].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    writer.write_all(&header).await?;
    writer.write_all(payload).await
}

#[cfg(feature = "adapter-shadowtls")]
async fn write_chunked_tls12_records<W>(writer: &mut W, payload: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    const MAX_TLS12_RECORD: usize = 16 * 1024;
    for chunk in payload.chunks(MAX_TLS12_RECORD) {
        write_tls12_record(writer, chunk).await?;
    }
    Ok(())
}

#[cfg(feature = "adapter-shadowtls")]
async fn run_v2_bridge<S>(io: S, local: DuplexStream, first_prefix: [u8; 8]) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut io_read, mut io_write) = tokio::io::split(io);
    let (mut local_read, mut local_write) = tokio::io::split(local);

    let client_to_server = async move {
        let mut buf = [0u8; 16 * 1024];
        let mut pending_prefix = Some(first_prefix);
        loop {
            let n = local_read.read(&mut buf).await?;
            if n == 0 {
                io_write.shutdown().await?;
                return Ok::<(), std::io::Error>(());
            }
            if let Some(prefix) = pending_prefix.take() {
                let mut payload = Vec::with_capacity(prefix.len() + n);
                payload.extend_from_slice(&prefix);
                payload.extend_from_slice(&buf[..n]);
                write_tls12_record(&mut io_write, &payload).await?;
            } else {
                write_chunked_tls12_records(&mut io_write, &buf[..n]).await?;
            }
        }
    };

    let server_to_client = async move {
        while let Some(payload) = read_shadowtls_application_record(&mut io_read).await? {
            local_write.write_all(&payload).await?;
        }
        local_write.shutdown().await?;
        Ok::<(), std::io::Error>(())
    };

    tokio::try_join!(client_to_server, server_to_client)?;
    Ok(())
}

#[cfg(feature = "adapter-shadowtls")]
fn spawn_v2_bridge<S>(io: S, first_prefix: [u8; 8]) -> BoxedStream
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (user_stream, bridge_stream) = tokio::io::duplex(64 * 1024);
    let bridge_task = tokio::spawn(async move {
        if let Err(err) = run_v2_bridge(io, bridge_stream, first_prefix).await {
            tracing::debug!(error = %err, "shadowtls v2 bridge closed");
        }
    });
    boxed_bridge_stream(user_stream, bridge_task)
}

#[cfg(feature = "adapter-shadowtls")]
struct OwnedBridgeStream {
    inner: DuplexStream,
    bridge_task: JoinHandle<()>,
}

#[cfg(feature = "adapter-shadowtls")]
impl Drop for OwnedBridgeStream {
    fn drop(&mut self) {
        self.bridge_task.abort();
    }
}

#[cfg(feature = "adapter-shadowtls")]
impl AsyncRead for OwnedBridgeStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[cfg(feature = "adapter-shadowtls")]
impl AsyncWrite for OwnedBridgeStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(feature = "adapter-shadowtls")]
fn boxed_bridge_stream(stream: DuplexStream, bridge_task: JoinHandle<()>) -> BoxedStream {
    Box::new(OwnedBridgeStream {
        inner: stream,
        bridge_task,
    })
}

#[cfg(feature = "adapter-shadowtls")]
fn server_hello_supports_tls13_frame(frame: &[u8]) -> bool {
    if frame.len() < TLS_HEADER_SIZE + 4 + 2 + TLS_RANDOM_SIZE + 1 {
        return false;
    }
    let mut cursor = TLS_HEADER_SIZE + 4 + 2 + TLS_RANDOM_SIZE;
    let session_id_len = match frame.get(cursor) {
        Some(value) => *value as usize,
        None => return false,
    };
    cursor += 1 + session_id_len + 2 + 1;
    if cursor + 2 > frame.len() {
        return false;
    }
    let extensions_len = u16::from_be_bytes([frame[cursor], frame[cursor + 1]]) as usize;
    cursor += 2;
    let end = cursor + extensions_len;
    while cursor + 4 <= end && end <= frame.len() {
        let ext_type = u16::from_be_bytes([frame[cursor], frame[cursor + 1]]);
        let ext_len = u16::from_be_bytes([frame[cursor + 2], frame[cursor + 3]]) as usize;
        cursor += 4;
        if cursor + ext_len > frame.len() {
            return false;
        }
        if ext_type == 43 && ext_len == 2 {
            return u16::from_be_bytes([frame[cursor], frame[cursor + 1]]) == 0x0304;
        }
        cursor += ext_len;
    }
    false
}

#[cfg(feature = "adapter-shadowtls")]
fn new_v3_client_add_state(password: &str, server_random: [u8; TLS_RANDOM_SIZE]) -> HmacSha1 {
    let mut hmac = HmacSha1::new_from_slice(password.as_bytes()).expect("hmac init");
    hmac.update(&server_random);
    hmac.update(b"C");
    hmac
}

#[cfg(feature = "adapter-shadowtls")]
fn new_v3_server_verify_state(password: &str, server_random: [u8; TLS_RANDOM_SIZE]) -> HmacSha1 {
    let mut hmac = HmacSha1::new_from_slice(password.as_bytes()).expect("hmac init");
    hmac.update(&server_random);
    hmac.update(b"S");
    hmac
}

#[cfg(feature = "adapter-shadowtls")]
fn next_v3_tag(state: &mut HmacSha1, payload: &[u8]) -> [u8; SHADOWTLS_V3_HMAC_SIZE] {
    state.update(payload);
    let digest = state.clone().finalize().into_bytes();
    let mut tag = [0u8; SHADOWTLS_V3_HMAC_SIZE];
    tag.copy_from_slice(&digest[..SHADOWTLS_V3_HMAC_SIZE]);
    state.update(&tag);
    tag
}

#[cfg(feature = "adapter-shadowtls")]
fn verify_v3_payload(state: &mut HmacSha1, payload: &[u8], tag: &[u8]) -> bool {
    let mut check = state.clone();
    check.update(payload);
    let digest = check.finalize().into_bytes();
    if &digest[..SHADOWTLS_V3_HMAC_SIZE] == tag {
        state.update(payload);
        state.update(tag);
        true
    } else {
        false
    }
}

#[cfg(feature = "adapter-shadowtls")]
fn matches_v3_payload(state: &HmacSha1, payload: &[u8], tag: &[u8]) -> bool {
    let mut check = state.clone();
    check.update(payload);
    &check.finalize().into_bytes()[..SHADOWTLS_V3_HMAC_SIZE] == tag
}

#[cfg(feature = "adapter-shadowtls")]
fn kdf(password: &str, server_random: &[u8; TLS_RANDOM_SIZE]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(server_random);
    hasher.finalize().into()
}

#[cfg(feature = "adapter-shadowtls")]
fn xor_slice(data: &mut [u8], key: &[u8; 32]) {
    for (index, byte) in data.iter_mut().enumerate() {
        *byte ^= key[index % key.len()];
    }
}

#[cfg(feature = "adapter-shadowtls")]
async fn read_v3_application_payload<R>(
    reader: &mut R,
    verify_state: &mut HmacSha1,
    ignore_state: &mut Option<HmacSha1>,
) -> std::io::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    loop {
        let mut header = [0u8; TLS_HEADER_SIZE];
        if !read_exact_or_eof(reader, &mut header).await? {
            return Ok(None);
        }
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut frame = Vec::with_capacity(TLS_HEADER_SIZE + length);
        frame.extend_from_slice(&header);
        frame.resize(TLS_HEADER_SIZE + length, 0);
        read_exact_or_eof(reader, &mut frame[TLS_HEADER_SIZE..]).await?;
        if frame[0] == ALERT {
            return Ok(None);
        }
        if frame[0] != APPLICATION_DATA {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unexpected TLS record type: {}", frame[0]),
            ));
        }
        if frame.len() < TLS_HEADER_SIZE + SHADOWTLS_V3_HMAC_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "shadowtls v3 application frame is too short",
            ));
        }
        let tag = &frame[TLS_HEADER_SIZE..TLS_HEADER_SIZE + SHADOWTLS_V3_HMAC_SIZE];
        let payload = &frame[TLS_HEADER_SIZE + SHADOWTLS_V3_HMAC_SIZE..];
        if let Some(ignore) = ignore_state.as_ref() {
            if matches_v3_payload(ignore, payload, tag) {
                continue;
            }
            *ignore_state = None;
        }
        if verify_v3_payload(verify_state, payload, tag) {
            return Ok(Some(payload.to_vec()));
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "shadowtls v3 application verification failed",
        ));
    }
}

#[cfg(feature = "adapter-shadowtls")]
fn spawn_v3_bridge<S>(
    io: S,
    password: String,
    server_random: [u8; TLS_RANDOM_SIZE],
    read_hmac: Option<HmacSha1>,
) -> BoxedStream
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (user_stream, bridge_stream) = tokio::io::duplex(64 * 1024);
    let bridge_task = tokio::spawn(async move {
        let (mut io_read, mut io_write) = tokio::io::split(io);
        let (mut local_read, mut local_write) = tokio::io::split(bridge_stream);
        let mut add_state = new_v3_client_add_state(&password, server_random);
        let mut verify_state = new_v3_server_verify_state(&password, server_random);
        let mut ignore_state = read_hmac;

        let client_to_server = async move {
            let mut buf = [0u8; 16 * 1024];
            loop {
                let n = local_read.read(&mut buf).await?;
                if n == 0 {
                    io_write.shutdown().await?;
                    return Ok::<(), std::io::Error>(());
                }
                for chunk in buf[..n].chunks(16 * 1024) {
                    let tag = next_v3_tag(&mut add_state, chunk);
                    let mut header = [0u8; TLS_HEADER_SIZE];
                    header[0] = APPLICATION_DATA;
                    header[1] = 0x03;
                    header[2] = 0x03;
                    header[3..5].copy_from_slice(
                        &((chunk.len() + SHADOWTLS_V3_HMAC_SIZE) as u16).to_be_bytes(),
                    );
                    io_write.write_all(&header).await?;
                    io_write.write_all(&tag).await?;
                    io_write.write_all(chunk).await?;
                }
            }
        };

        let server_to_client = async move {
            while let Some(payload) =
                read_v3_application_payload(&mut io_read, &mut verify_state, &mut ignore_state)
                    .await?
            {
                local_write.write_all(&payload).await?;
            }
            local_write.shutdown().await?;
            Ok::<(), std::io::Error>(())
        };

        if let Err(err) = tokio::try_join!(client_to_server, server_to_client) {
            tracing::debug!(error = %err, "shadowtls v3 bridge closed");
        }
    });
    boxed_bridge_stream(user_stream, bridge_task)
}

/// Configuration for ShadowTLS outbound adapter
#[derive(Debug, Clone)]
pub struct ShadowTlsAdapterConfig {
    /// Decoy TLS server hostname or IP
    pub server: String,
    /// Decoy TLS server port (usually 443)
    pub port: u16,
    /// ShadowTLS protocol version.
    pub version: u8,
    /// Shared password for ShadowTLS authentication.
    pub password: String,
    /// SNI to present during TLS handshake
    pub sni: String,
    /// Optional ALPN protocol (e.g., "h2", "http/1.1")
    pub alpn: Option<String>,
    /// Skip certificate verification (INSECURE; for testing only)
    pub skip_cert_verify: bool,
    /// Optional uTLS fingerprint name for outbound TLS layer.
    pub utls_fingerprint: Option<String>,
}

impl Default for ShadowTlsAdapterConfig {
    fn default() -> Self {
        Self {
            server: "127.0.0.1".to_string(),
            port: 443,
            version: 1,
            password: String::new(),
            sni: "example.com".to_string(),
            alpn: Some("http/1.1".to_string()),
            skip_cert_verify: false,
            utls_fingerprint: None,
        }
    }
}

/// ShadowTLS outbound adapter connector
#[derive(Debug, Clone)]
pub struct ShadowTlsConnector {
    cfg: ShadowTlsAdapterConfig,
}

impl ShadowTlsConnector {
    pub fn new(cfg: ShadowTlsAdapterConfig) -> Self {
        Self { cfg }
    }

    #[cfg(feature = "adapter-shadowtls")]
    fn build_tls_config(&self, tls12_only: bool) -> tokio_rustls::rustls::ClientConfig
    where
        Self: Sized,
    {
        use std::sync::Arc;
        use tokio_rustls::rustls::ClientConfig;

        let mut tls_config = if self.cfg.skip_cert_verify {
            let builder = if tls12_only {
                ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
            } else {
                ClientConfig::builder()
            };
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth()
        } else {
            let root_store = tokio_rustls::rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            let builder = if tls12_only {
                ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
            } else {
                ClientConfig::builder()
            };
            builder
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        if let Some(alpn) = self.cfg.alpn.as_ref() {
            let protos: Vec<Vec<u8>> = alpn
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| value.as_bytes().to_vec())
                .collect();
            if !protos.is_empty() {
                tls_config.alpn_protocols = protos;
            }
        }

        if self.cfg.version == 3 {
            tls_config.resumption = rustls::client::Resumption::disabled();
            tls_config.session_id_generator = Some(Arc::new(ShadowTlsV3SessionIdGenerator::new(
                self.cfg.password.clone(),
            )));
        }

        tls_config
    }

    #[cfg(feature = "adapter-shadowtls")]
    async fn perform_tls_handshake<S>(
        &self,
        stream: S,
        tls12_only: bool,
    ) -> Result<tokio_rustls::client::TlsStream<S>>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        use std::sync::Arc;
        use tokio_rustls::TlsConnector;

        let tls_config = self.build_tls_config(tls12_only);
        let connector = TlsConnector::from(Arc::new(tls_config));
        let server_name = rustls::pki_types::ServerName::try_from(self.cfg.sni.as_str())
            .map_err(|e| AdapterError::Other(format!("Invalid ShadowTLS server name: {e}")))?
            .to_owned();

        connector
            .connect(server_name, stream)
            .await
            .map_err(|e| AdapterError::Other(format!("ShadowTLS TLS handshake failed: {e}")))
    }

    #[cfg(feature = "adapter-shadowtls")]
    async fn perform_v1_tls_camouflage<S>(&self, stream: S) -> Result<S>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let tls_stream = self.perform_tls_handshake(stream, true).await?;
        let (stream, _) = tls_stream.into_inner();
        Ok(stream)
    }

    #[cfg(feature = "adapter-shadowtls")]
    async fn perform_v3_tls_handshake<S>(&self, stream: S) -> Result<ShadowTlsV3Established<S>>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        use std::sync::Arc;
        use tokio_rustls::TlsConnector;

        let tls_config = self.build_tls_config(false);
        let connector = TlsConnector::from(Arc::new(tls_config));
        let server_name = rustls::pki_types::ServerName::try_from(self.cfg.sni.as_str())
            .map_err(|e| AdapterError::Other(format!("Invalid ShadowTLS server name: {e}")))?
            .to_owned();

        let wrapped_stream = ShadowTlsV3HandshakeStream::new(stream, self.cfg.password.clone());
        let tls_stream = connector
            .connect(server_name, wrapped_stream)
            .await
            .map_err(|e| AdapterError::Other(format!("ShadowTLS TLS handshake failed: {e}")))?;
        let (wrapped_stream, _) = tls_stream.into_inner();
        wrapped_stream.finish()
    }

    #[cfg(feature = "adapter-shadowtls")]
    pub async fn connect_detour_stream(&self, host: &str, port: u16) -> Result<BoxedStream> {
        tracing::debug!(
            requested_host = host,
            requested_port = port,
            wrapper_server = %self.cfg.server,
            wrapper_port = self.cfg.port,
            "shadowtls detour wrapper dialing configured wrapper server for requested endpoint"
        );

        match self.cfg.version {
            1..=3 => {}
            other => {
                return Err(AdapterError::Protocol(format!(
                    "ShadowTLS runtime wrapper currently supports versions 1, 2 and 3 only; configured version {} still requires protocol-specific encapsulation",
                    other
                )));
            }
        }

        let tcp_stream = crate::outbound::detour::connect_tcp_stream(
            &self.cfg.server,
            self.cfg.port,
            None,
            Duration::from_secs(30),
        )
        .await?;
        match self.cfg.version {
            1 => {
                let raw_stream = self.perform_v1_tls_camouflage(tcp_stream).await?;
                Ok(Box::new(raw_stream))
            }
            2 => {
                let hash_stream = HashTrackedReadStream::new(tcp_stream, &self.cfg.password);
                let tls_stream = self.perform_tls_handshake(hash_stream, false).await?;
                let (hash_stream, _) = tls_stream.into_inner();
                let (raw_stream, first_prefix) = hash_stream.into_inner();
                Ok(spawn_v2_bridge(raw_stream, first_prefix))
            }
            3 => {
                let established = self.perform_v3_tls_handshake(tcp_stream).await?;
                if !established.authorized {
                    return Err(AdapterError::Protocol(
                        "shadowtls v3 handshake finished without authenticated traffic".to_string(),
                    ));
                }
                tracing::debug!(
                    is_tls13 = established.is_tls13,
                    "shadowtls v3 client handshake authorized"
                );
                Ok(spawn_v3_bridge(
                    established.inner,
                    self.cfg.password.clone(),
                    established.server_random,
                    established.read_hmac,
                ))
            }
            _ => unreachable!("shadowtls detour wrapper version is prevalidated"),
        }
    }
}

#[async_trait]
impl OutboundConnector for ShadowTlsConnector {
    fn name(&self) -> &'static str {
        "shadowtls"
    }

    async fn start(&self) -> Result<()> {
        #[cfg(not(feature = "adapter-shadowtls"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-shadowtls",
        });

        #[cfg(feature = "adapter-shadowtls")]
        Ok(())
    }

    async fn dial(&self, target: Target, _opts: DialOpts) -> Result<BoxedStream> {
        #[cfg(not(feature = "adapter-shadowtls"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-shadowtls",
        });

        #[cfg(feature = "adapter-shadowtls")]
        {
            if target.kind != TransportKind::Tcp {
                return Err(AdapterError::Protocol(
                    "ShadowTLS outbound only supports TCP".to_string(),
                ));
            }

            let _span = crate::outbound::span_dial("shadowtls", &target);
            tracing::warn!(
                server = %self.cfg.server,
                port = self.cfg.port,
                version = self.cfg.version,
                sni = %self.cfg.sni,
                target = %format!("{}:{}", target.host, target.port),
                "shadowtls standalone leaf dial rejected; transport-wrapper remodel is required"
            );
            Err(AdapterError::Protocol(format!(
                "ShadowTLS standalone leaf dialing is disabled for version {}: sing-box parity requires a transport-wrapper/detour model, not the legacy TLS+CONNECT tunnel",
                self.cfg.version
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;
    use tokio::time::{timeout, Duration};

    #[test]
    fn test_shadowtls_connector_name() {
        let c = ShadowTlsConnector::new(ShadowTlsAdapterConfig::default());
        assert_eq!(c.name(), "shadowtls");
    }

    #[tokio::test]
    async fn dropping_owned_bridge_stream_aborts_bridge_task() {
        struct NotifyOnDrop(Option<oneshot::Sender<()>>);

        impl Drop for NotifyOnDrop {
            fn drop(&mut self) {
                if let Some(tx) = self.0.take() {
                    let _ = tx.send(());
                }
            }
        }

        let (done_tx, done_rx) = oneshot::channel();
        let (user_stream, _peer_stream) = tokio::io::duplex(1024);
        let bridge_task = tokio::spawn(async move {
            let _guard = NotifyOnDrop(Some(done_tx));
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;

        let bridge_stream = boxed_bridge_stream(user_stream, bridge_task);
        drop(bridge_stream);

        timeout(Duration::from_secs(1), done_rx)
            .await
            .expect("bridge task should be aborted when stream drops")
            .expect("abort drop signal should arrive");
    }
}
