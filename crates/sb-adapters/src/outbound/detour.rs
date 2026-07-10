use crate::outbound::prelude::*;
use tokio::net::TcpStream;

#[cfg(feature = "sb-transport")]
use sb_core::outbound::{Endpoint, RouteTarget};

#[cfg(feature = "sb-transport")]
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
    #[cfg(feature = "sb-transport")]
    if let Some(tag) = detour.filter(|tag| !tag.trim().is_empty()) {
        let handle = sb_core::adapter::registry::runtime_outbounds().ok_or_else(|| {
            AdapterError::Other(
                "runtime outbound registry is unavailable for detour dialing".to_string(),
            )
        })?;
        let endpoint = endpoint_for(host, port);
        let stream = tokio::time::timeout(
            timeout,
            handle.connect_tcp_stream(&RouteTarget::Named(tag.to_string()), endpoint),
        )
        .await
        .map_err(|_| AdapterError::Timeout(timeout))?
        .map_err(|e| AdapterError::Other(format!("detour '{tag}' dial failed: {e}")))?;
        return Ok(crate::traits::from_transport_stream(stream));
    }

    #[cfg(not(feature = "sb-transport"))]
    if detour.filter(|tag| !tag.trim().is_empty()).is_some() {
        return Err(AdapterError::Other(
            "detour dialing requires the sb-transport feature".to_string(),
        ));
    }

    let tcp_stream = tokio::time::timeout(timeout, TcpStream::connect((host, port)))
        .await
        .map_err(|_| AdapterError::Timeout(timeout))?
        .map_err(AdapterError::Io)?;
    Ok(Box::new(tcp_stream) as BoxedStream)
}

#[cfg(all(test, feature = "sb-transport"))]
mod tests {
    use super::*;
    use sb_core::outbound::{OutboundImpl, OutboundRegistry, OutboundRegistryHandle};
    use serial_test::serial;
    use tokio::net::TcpListener;

    #[derive(Debug)]
    struct MockIoConnector;

    impl sb_types::Outbound for MockIoConnector {
        fn r#type(&self) -> &str {
            "mock"
        }
        fn tag(&self) -> sb_types::OutboundTag {
            sb_types::OutboundTag::new("mock-detour")
        }
        fn network(&self) -> &[sb_types::NetworkKind] {
            &[sb_types::NetworkKind::Tcp]
        }
        fn dial<'a>(
            &'a self,
            session: &'a sb_types::Session,
        ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedStream, sb_types::CoreError>> {
            Box::pin(async move {
                use tokio_util::compat::TokioAsyncReadCompatExt;
                let address = match &session.target {
                    sb_types::TargetAddr::Socket(addr) => addr.to_string(),
                    sb_types::TargetAddr::Domain(host, port) => format!("{host}:{port}"),
                };
                let stream = TcpStream::connect(address)
                    .await
                    .map_err(|err| sb_types::CoreError::io(err.to_string()))?;
                Ok(Box::new(stream.compat()) as sb_types::BoxedStream)
            })
        }
        fn listen_packet<'a>(
            &'a self,
            _session: &'a sb_types::Session,
        ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedPacketConn, sb_types::CoreError>>
        {
            Box::pin(async {
                Err(sb_types::CoreError::connect(
                    sb_types::ConnectErrorKind::Unsupported,
                    "udp unsupported",
                ))
            })
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
    #[serial]
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
    #[serial]
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
