//! Pipe listener implementation for IPC.
//!
//! Provides platform-specific IPC listeners:
//! - Windows: Named pipes
//! - Unix: Unix domain sockets
//!
//! # Example
//! ```ignore
//! use sb_common::pipelistener::PipeListener;
//!
//! // On Unix:
//! let listener = PipeListener::bind("/tmp/singbox.sock")?;
//!
//! // On Windows:
//! let listener = PipeListener::bind(r"\\.\pipe\singbox")?;
//! ```

use std::io;
#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;
use std::path::Path;

/// Platform-agnostic pipe listener.
#[derive(Debug)]
pub struct PipeListener {
    #[cfg(unix)]
    inner: tokio::net::UnixListener,
    #[cfg(windows)]
    path: String,
}

/// Connected pipe stream.
#[derive(Debug)]
pub struct PipeStream {
    #[cfg(unix)]
    inner: tokio::net::UnixStream,
    #[cfg(windows)]
    inner: tokio::net::windows::named_pipe::NamedPipeServer,
}

impl PipeListener {
    /// Bind to a pipe/socket path.
    pub fn bind(path: impl AsRef<Path>) -> io::Result<Self> {
        #[cfg(unix)]
        {
            let path = path.as_ref();
            if path.exists() {
                let metadata = std::fs::symlink_metadata(path)?;
                if metadata.file_type().is_socket() {
                    std::fs::remove_file(path)?;
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "pipe path exists and is not a Unix socket",
                    ));
                }
            }
            let listener = tokio::net::UnixListener::bind(path)?;
            Ok(Self { inner: listener })
        }

        #[cfg(windows)]
        {
            // Windows named pipes require different API
            Ok(Self {
                path: path.as_ref().to_string_lossy().into_owned(),
            })
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = path;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Pipe listener not supported on this platform",
            ))
        }
    }

    /// Accept a connection.
    pub async fn accept(&self) -> io::Result<PipeStream> {
        #[cfg(unix)]
        {
            let (stream, _) = self.inner.accept().await?;
            Ok(PipeStream { inner: stream })
        }

        #[cfg(windows)]
        {
            // Create a new named pipe instance
            // We need to request duplex access
            let server = tokio::net::windows::named_pipe::ServerOptions::new()
                .access_inbound(true)
                .access_outbound(true)
                .create(&self.path)?;

            // Wait for a client to connect
            server.connect().await?;

            Ok(PipeStream { inner: server })
        }

        #[cfg(not(any(unix, windows)))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Pipe listener not supported on this platform",
            ))
        }
    }

    /// Get the local address (path).
    #[cfg(unix)]
    pub fn local_addr(&self) -> io::Result<tokio::net::unix::SocketAddr> {
        self.inner.local_addr()
    }
}

#[cfg(unix)]
impl PipeStream {
    /// Split into read and write halves.
    pub fn into_split(
        self,
    ) -> (
        tokio::net::unix::OwnedReadHalf,
        tokio::net::unix::OwnedWriteHalf,
    ) {
        self.inner.into_split()
    }
}

#[cfg(any(unix, windows))]
impl tokio::io::AsyncRead for PipeStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[cfg(any(unix, windows))]
impl tokio::io::AsyncWrite for PipeStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// IPC message protocol for pipe communication.
#[derive(Debug, Clone)]
pub struct IpcMessage {
    /// Message type.
    pub msg_type: u8,
    /// Message payload.
    pub payload: Vec<u8>,
}

impl IpcMessage {
    /// Create a new IPC message.
    pub fn new(msg_type: u8, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            msg_type,
            payload: payload.into(),
        }
    }

    /// Serialize message to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(5 + self.payload.len());
        buf.push(self.msg_type);
        buf.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Parse message from bytes.
    pub fn from_bytes(data: &[u8]) -> io::Result<Self> {
        if data.len() < 5 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Message too short",
            ));
        }

        let msg_type = data[0];
        let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;

        if data.len() < 5 + len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Incomplete message",
            ));
        }

        Ok(Self {
            msg_type,
            payload: data[5..5 + len].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::path::PathBuf;

    #[test]
    fn test_ipc_message_serialization() {
        let msg = IpcMessage::new(1, b"hello".to_vec());
        let bytes = msg.to_bytes();
        let parsed = IpcMessage::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.msg_type, 1);
        assert_eq!(parsed.payload, b"hello");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_pipe_listener() -> io::Result<()> {
        let path = unique_socket_path("test_pipe_listener");
        let listener = match PipeListener::bind(&path) {
            Ok(listener) => listener,
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => return Ok(()),
            Err(err) => return Err(err),
        };

        let handle = tokio::spawn(async move { listener.accept().await.map(|_| ()) });

        let _client = tokio::net::UnixStream::connect(&path).await?;

        handle
            .await
            .map_err(|err| io::Error::other(format!("accept task join failed: {err}")))??;

        let _ = std::fs::remove_file(path);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn bind_refuses_to_replace_regular_file() -> io::Result<()> {
        let path = unique_socket_path("test_pipe_listener_regular");
        std::fs::write(&path, b"not a socket")?;

        let err = PipeListener::bind(&path).expect_err("regular file must not be replaced");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path)?, b"not a socket");

        let _ = std::fs::remove_file(path);
        Ok(())
    }

    #[cfg(unix)]
    fn unique_socket_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("{}_{}.sock", name, std::process::id()))
    }
}
