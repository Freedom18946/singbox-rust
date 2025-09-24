use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("not implemented")]
    NotImplemented,
    #[error("invalid config: {0}")]
    InvalidConfig(&'static str),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

pub trait IoStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T> IoStream for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

#[async_trait::async_trait]
pub trait OutboundConnector: Send + Sync {
    async fn connect(&self, target: &Target) -> Result<Box<dyn IoStream>, ProtoError>;
}
