use std::pin::Pin;
use std::task::{Context, Poll};
use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use super::crypto::SsrCipher;
use super::obfs::SsrObfs;
use super::protocol::SsrProtocol;

/// ShadowsocksR stream wrapper that handles encryption/decryption and obfuscation.
pub struct ShadowsocksRStream {
    inner: TcpStream,
    cipher: Box<dyn SsrCipher>,
    obfs: Box<dyn SsrObfs>,
    protocol: Box<dyn SsrProtocol>,
    read_buf: BytesMut,
    write_buf: BytesMut,
}

impl ShadowsocksRStream {
    pub fn new(
        inner: TcpStream,
        cipher: Box<dyn SsrCipher>,
        obfs: Box<dyn SsrObfs>,
        protocol: Box<dyn SsrProtocol>,
    ) -> Self {
        Self {
            inner,
            cipher,
            obfs,
            protocol,
            read_buf: BytesMut::with_capacity(4096),
            write_buf: BytesMut::with_capacity(4096),
        }
    }
}

impl AsyncRead for ShadowsocksRStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // 1. If we have decrypted data in read_buf, return it
        if !this.read_buf.is_empty() {
            let len = std::cmp::min(this.read_buf.len(), buf.remaining());
            buf.put_slice(&this.read_buf[..len]);
            this.read_buf.advance(len);
            return Poll::Ready(Ok(()));
        }

        // 2. Read from inner stream
        // We need a temporary buffer to read from inner
        let mut tmp_buf = [0u8; 4096];
        let mut tmp_read_buf = ReadBuf::new(&mut tmp_buf);
        
        match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_read_buf) {
            Poll::Ready(Ok(())) => {
                let filled = tmp_read_buf.filled();
                if filled.is_empty() {
                    return Poll::Ready(Ok(())); // EOF
                }
                
                // 3. Process data: Decode -> Post-Decrypt -> Decrypt
                // We process into this.read_buf
                let mut processed = BytesMut::with_capacity(filled.len() + 1024);
                
                // Obfs decode
                if let Err(e) = this.obfs.decode(filled, &mut processed) {
                    return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e)));
                }
                
                // Protocol post-decrypt
                let mut protocol_out = BytesMut::with_capacity(processed.len());
                if let Err(e) = this.protocol.client_post_decrypt(&processed, &mut protocol_out) {
                    return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e)));
                }
                
                // Cipher decrypt
                // We append to this.read_buf
                if let Err(e) = this.cipher.decrypt(&protocol_out, &mut this.read_buf) {
                    return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e)));
                }
                
                // 4. Return data to caller
                let len = std::cmp::min(this.read_buf.len(), buf.remaining());
                buf.put_slice(&this.read_buf[..len]);
                this.read_buf.advance(len);
                
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for ShadowsocksRStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        // 1. Process data: Encrypt -> Pre-Encrypt -> Encode
        // We write into this.write_buf
        
        // Cipher encrypt
        let mut encrypted = BytesMut::with_capacity(buf.len());
        this.cipher.encrypt(buf, &mut encrypted);
        
        // Protocol pre-encrypt
        let mut protocol_out = BytesMut::with_capacity(encrypted.len());
        this.protocol.client_pre_encrypt(&encrypted, &mut protocol_out);
        
        // Obfs encode
        // We append to this.write_buf
        this.obfs.encode(&protocol_out, &mut this.write_buf);
        
        // 2. Write to inner stream
        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Ready(Ok(n)) => {
                    this.write_buf.advance(n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
        
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        // Flush any remaining data in write_buf
        while !this.write_buf.is_empty() {
             match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Ready(Ok(n)) => {
                    this.write_buf.advance(n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}
