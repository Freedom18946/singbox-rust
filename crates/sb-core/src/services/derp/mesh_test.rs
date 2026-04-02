#[cfg(test)]
mod tests {
    use crate::service::{Service, ServiceContext, StartStage};
    use crate::services::derp::protocol::{
        clamp_private_key, derive_public_key, open_from, seal_to, ClientInfoPayload, DerpFrame,
        PrivateKey, PublicKey, PROTOCOL_VERSION,
    };
    use crate::services::derp::DerpService;
    use sb_config::ir::{
        DerpMeshPeerIR, DerpOutboundTlsOptionsIR, DerpStunOptionsIR, InboundTlsOptionsIR, Listable,
        ServiceIR, ServiceType, StringOrObj,
    };
    use std::io;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;
    use tokio::time::{sleep, timeout, Instant};

    fn alloc_port() -> io::Result<u16> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        Ok(listener.local_addr()?.port())
    }

    struct TestTls {
        cert_file: tempfile::NamedTempFile,
        key_file: tempfile::NamedTempFile,
        connector: tokio_rustls::TlsConnector,
    }

    impl TestTls {
        fn new() -> Self {
            crate::tls::ensure_rustls_crypto_provider();

            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let cert_pem = cert.cert.pem();
            let key_pem = cert.key_pair.serialize_pem();

            let cert_file = tempfile::NamedTempFile::new().unwrap();
            let key_file = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(cert_file.path(), cert_pem).unwrap();
            std::fs::write(key_file.path(), key_pem).unwrap();

            let mut roots = rustls::RootCertStore::empty();
            let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
            roots.add(cert_der).expect("add root");

            let client_config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

            Self {
                cert_file,
                key_file,
                connector,
            }
        }

        fn tls_ir(&self) -> InboundTlsOptionsIR {
            InboundTlsOptionsIR {
                enabled: true,
                certificate_path: Some(self.cert_file.path().to_string_lossy().to_string()),
                key_path: Some(self.key_file.path().to_string_lossy().to_string()),
                ..Default::default()
            }
        }

        fn mesh_tls_ir(&self) -> DerpOutboundTlsOptionsIR {
            DerpOutboundTlsOptionsIR {
                enabled: true,
                ca_paths: vec![self.cert_file.path().to_string_lossy().to_string()],
                ..Default::default()
            }
        }

        async fn connect(&self, addr: SocketAddr) -> tokio_rustls::client::TlsStream<TcpStream> {
            use rustls::pki_types::ServerName;

            let stream = TcpStream::connect(addr).await.expect("connect");
            let server_name = ServerName::try_from("localhost").expect("server name");
            self.connector
                .connect(server_name, stream)
                .await
                .expect("tls connect")
        }
    }

    fn test_client_keypair(seed: u8) -> (PrivateKey, PublicKey) {
        let mut private = [seed; 32];
        clamp_private_key(&mut private);
        let public = derive_public_key(&private);
        (private, public)
    }

    async fn connect_and_handshake(
        tls: &TestTls,
        addr: SocketAddr,
        client_private_key: PrivateKey,
    ) -> (tokio_rustls::client::TlsStream<TcpStream>, PublicKey) {
        let mut stream = tls.connect(addr).await;

        let server_key_frame = DerpFrame::read_from_async(&mut stream)
            .await
            .expect("server key");
        let server_public_key = match server_key_frame {
            DerpFrame::ServerKey { key } => key,
            other => panic!("expected ServerKey, got {:?}", other.frame_type()),
        };

        let client_public_key = derive_public_key(&client_private_key);
        let info = ClientInfoPayload::new(PROTOCOL_VERSION as u32).with_can_ack_pings(true);
        let msgbox = seal_to(&client_private_key, &server_public_key, &info.to_json())
            .expect("seal client info");
        DerpFrame::ClientInfo {
            key: client_public_key,
            encrypted_info: msgbox,
        }
        .write_to_async(&mut stream)
        .await
        .expect("write client info");
        stream.flush().await.expect("flush client info");

        let server_info_frame = DerpFrame::read_from_async(&mut stream)
            .await
            .expect("server info");
        match server_info_frame {
            DerpFrame::ServerInfo { encrypted_info } => {
                let clear = open_from(&client_private_key, &server_public_key, &encrypted_info)
                    .expect("open server info");
                let clear = String::from_utf8_lossy(&clear);
                assert!(
                    clear.contains(&format!("\"version\":{}", PROTOCOL_VERSION)),
                    "unexpected ServerInfo payload: {clear}"
                );
            }
            other => panic!("expected ServerInfo, got {:?}", other.frame_type()),
        }

        (stream, client_public_key)
    }

    fn start_service(service: &Arc<DerpService>) {
        for stage in [
            StartStage::Initialize,
            StartStage::Start,
            StartStage::PostStart,
            StartStage::Started,
        ] {
            service.start(stage).unwrap();
        }
    }

    async fn wait_for_mesh_route(service: &Arc<DerpService>, key: PublicKey, label: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if service.has_remote_client(&key) {
                return;
            }
            assert!(Instant::now() < deadline, "timeout waiting for {label}");
            sleep(Duration::from_millis(25)).await;
        }
    }

    #[tokio::test]
    async fn test_mesh_forwarding() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .try_init();

        let port_a = match alloc_port() {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipping mesh test: {e}");
                return;
            }
            Err(e) => panic!("alloc_port a: {e}"),
        };
        let port_b = match alloc_port() {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipping mesh test: {e}");
                return;
            }
            Err(e) => panic!("alloc_port b: {e}"),
        };
        // PSK must be 64 lowercase hex chars (32 bytes)
        let psk = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string();

        let tls = TestTls::new();
        let tempdir = tempfile::tempdir().unwrap();
        let config_path_a = tempdir
            .path()
            .join("derp-a.key")
            .to_string_lossy()
            .to_string();
        let config_path_b = tempdir
            .path()
            .join("derp-b.key")
            .to_string_lossy()
            .to_string();

        // Server A (meshes with B)
        let ir_a = ServiceIR {
            ty: ServiceType::Derp,
            tag: Some("derp-a".to_string()),
            listen: Some("127.0.0.1".to_string()),
            listen_port: Some(port_a),
            config_path: Some(config_path_a),
            tls: Some(tls.tls_ir()),
            mesh_psk: Some(psk.clone()),
            mesh_with: Some(Listable {
                items: vec![StringOrObj(DerpMeshPeerIR {
                    server: "localhost".to_string(),
                    server_port: Some(port_b),
                    tls: Some(tls.mesh_tls_ir()),
                    ..Default::default()
                })],
            }),
            stun: Some(DerpStunOptionsIR {
                enabled: false,
                ..Default::default()
            }),
            ..Default::default()
        };

        // Server B (meshes with A)
        let ir_b = ServiceIR {
            ty: ServiceType::Derp,
            tag: Some("derp-b".to_string()),
            listen: Some("127.0.0.1".to_string()),
            listen_port: Some(port_b),
            config_path: Some(config_path_b),
            tls: Some(tls.tls_ir()),
            mesh_psk: Some(psk.clone()),
            mesh_with: Some(Listable {
                items: vec![StringOrObj(DerpMeshPeerIR {
                    server: "localhost".to_string(),
                    server_port: Some(port_a),
                    tls: Some(tls.mesh_tls_ir()),
                    ..Default::default()
                })],
            }),
            stun: Some(DerpStunOptionsIR {
                enabled: false,
                ..Default::default()
            }),
            ..Default::default()
        };

        let ctx = ServiceContext::default();
        let service_a = DerpService::from_ir(&ir_a, &ctx).expect("build a");
        let service_b = DerpService::from_ir(&ir_b, &ctx).expect("build b");

        start_service(&service_a);
        start_service(&service_b);

        // Client 1 connects to A
        let (client1_private_key, client1_key) = test_client_keypair(1);
        let (mut c1, client1_key2) = connect_and_handshake(
            &tls,
            format!("127.0.0.1:{}", port_a).parse().unwrap(),
            client1_private_key,
        )
        .await;
        assert_eq!(client1_key2, client1_key);

        // Client 2 connects to B
        let (client2_private_key, client2_key) = test_client_keypair(2);
        let (mut c2, client2_key2) = connect_and_handshake(
            &tls,
            format!("127.0.0.1:{}", port_b).parse().unwrap(),
            client2_private_key,
        )
        .await;
        assert_eq!(client2_key2, client2_key);

        wait_for_mesh_route(&service_a, client2_key, "service_a remote client route").await;
        wait_for_mesh_route(&service_b, client1_key, "service_b remote client route").await;

        // C1 sends packet to C2
        let packet_content = b"hello mesh".to_vec();
        DerpFrame::SendPacket {
            dst_key: client2_key,
            packet: packet_content.clone(),
        }
        .write_to_async(&mut c1)
        .await
        .expect("c1 send");
        c1.flush().await.expect("flush c1 send");

        // C2 should receive RecvPacket from C1
        let recv = timeout(Duration::from_secs(5), DerpFrame::read_from_async(&mut c2))
            .await
            .expect("timeout waiting for RecvPacket")
            .expect("read RecvPacket");
        match recv {
            DerpFrame::RecvPacket { src_key, packet } => {
                assert_eq!(src_key, client1_key);
                assert_eq!(packet, packet_content);
            }
            other => panic!("expected RecvPacket, got {:?}", other.frame_type()),
        }

        service_a.close().unwrap();
        service_b.close().unwrap();
    }
}
