use crate::outbound::prelude::*;
use sb_core::outbound::{Endpoint, RouteTarget};
use tokio::net::TcpStream;

fn endpoint_for(host: &str, port: u16) -> Endpoint {
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => Endpoint::Ip(std::net::SocketAddr::new(ip, port)),
        Err(_) => Endpoint::Domain(host.to_string(), port),
    }
}

pub async fn connect_tcp_stream(
    host: &str,
    port: u16,
    detour: Option<&str>,
    timeout: std::time::Duration,
) -> Result<BoxedStream> {
    if let Some(tag) = detour.filter(|tag| !tag.trim().is_empty()) {
        let handle = sb_core::adapter::registry::runtime_outbounds().ok_or_else(|| {
            AdapterError::Other(
                "runtime outbound registry is unavailable for detour dialing".to_string(),
            )
        })?;
        let endpoint = endpoint_for(host, port);
        let stream = tokio::time::timeout(
            timeout,
            handle.connect_io(&RouteTarget::Named(tag.to_string()), endpoint),
        )
        .await
        .map_err(|_| AdapterError::Timeout(timeout))?
        .map_err(|e| AdapterError::Other(format!("detour '{tag}' dial failed: {e}")))?;
        return Ok(crate::traits::from_transport_stream(stream));
    }

    let tcp_stream = tokio::time::timeout(timeout, TcpStream::connect((host, port)))
        .await
        .map_err(|_| AdapterError::Timeout(timeout))?
        .map_err(AdapterError::Io)?;
    Ok(Box::new(tcp_stream) as BoxedStream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use sb_core::adapter::OutboundConnector as CoreOutboundConnector;
    use sb_core::outbound::{OutboundImpl, OutboundRegistry, OutboundRegistryHandle};
    use tokio::net::TcpListener;

    #[derive(Debug)]
    struct MockIoConnector;

    #[async_trait]
    impl CoreOutboundConnector for MockIoConnector {
        async fn connect(&self, _host: &str, _port: u16) -> std::io::Result<tokio::net::TcpStream> {
            Err(std::io::Error::other(
                "connect() should not be used in detour test",
            ))
        }

        async fn connect_io(
            &self,
            host: &str,
            port: u16,
        ) -> std::io::Result<sb_transport::IoStream> {
            let stream = TcpStream::connect((host, port)).await?;
            Ok(Box::new(stream))
        }
    }

    fn install_mock_runtime_outbounds() {
        let mut reg = OutboundRegistry::default();
        reg.insert(
            "mock-detour".to_string(),
            OutboundImpl::Connector(std::sync::Arc::new(MockIoConnector)),
        );
        sb_core::adapter::registry::install_runtime_outbounds(std::sync::Arc::new(
            OutboundRegistryHandle::new(reg),
        ));
    }

    #[tokio::test]
    async fn detour_connects_through_runtime_outbound_registry() {
        install_mock_runtime_outbounds();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_task = tokio::spawn(async move {
            let (_stream, _peer) = listener.accept().await.unwrap();
        });

        let mut stream = connect_tcp_stream(
            "127.0.0.1",
            addr.port(),
            Some("mock-detour"),
            std::time::Duration::from_secs(3),
        )
        .await
        .expect("detour helper should connect via runtime registry");

        tokio::io::AsyncWriteExt::write_all(&mut stream, b"ping")
            .await
            .unwrap();
        accept_task.await.unwrap();
    }

    #[tokio::test]
    async fn missing_runtime_detour_reports_explicit_error() {
        sb_core::adapter::registry::install_runtime_outbounds(std::sync::Arc::new(
            OutboundRegistryHandle::default(),
        ));

        let err = match connect_tcp_stream(
            "127.0.0.1",
            9,
            Some("missing-detour"),
            std::time::Duration::from_millis(100),
        )
        .await
        {
            Ok(_) => panic!("missing detour should fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("missing-detour"));
    }
}
