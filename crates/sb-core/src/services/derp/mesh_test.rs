#[cfg(test)]
mod tests {
    use crate::service::{ServiceContext, StartStage};
    use crate::services::derp::build_derp_service;
    use crate::services::derp::protocol::{DerpFrame, FrameType};
    use sb_config::ir::{ServiceIR, ServiceType};
    use std::net::SocketAddr;

    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::sleep;

    fn alloc_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    }

    async fn connect_and_handshake(addr: SocketAddr, key: [u8; 32]) -> (TcpStream, [u8; 32]) {
        let mut stream = TcpStream::connect(addr).await.expect("connect");

        // Read ServerKey
        let mut buf = [0u8; 1024];
        let mut server_key = [0u8; 32];

        // We need to read frame by frame.
        // ServerKey frame: type(1) + len(4) + key(32) = 37 bytes
        stream
            .read_exact(&mut buf[0..37])
            .await
            .expect("read server key");
        assert_eq!(buf[0], FrameType::ServerKey as u8);
        server_key.copy_from_slice(&buf[5..37]);

        // Send ClientInfo
        let frame = DerpFrame::ClientInfo { key };
        let bytes = frame.to_bytes().unwrap();
        stream.write_all(&bytes).await.expect("write client info");

        (stream, server_key)
    }

    #[tokio::test]
    #[ignore] // TODO: fix broken pipe issue in mesh handshake
    async fn test_mesh_forwarding() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .try_init();

        let port_a = alloc_port();
        let port_b = alloc_port();
        let psk = "mesh_secret".to_string();

        // Server A
        let ir_a = ServiceIR {
            ty: ServiceType::Derp,
            tag: Some("derp-a".to_string()),
            derp_listen: Some("127.0.0.1".to_string()),
            derp_listen_port: Some(port_a),
            derp_mesh_psk: Some(psk.clone()),
            derp_stun_enabled: Some(false),
            resolved_listen: None,
            resolved_listen_port: None,
            ssmapi_listen: None,
            ssmapi_listen_port: None,
            ssmapi_servers: None,
            ssmapi_cache_path: None,
            ssmapi_tls_cert_path: None,
            ssmapi_tls_key_path: None,
            derp_config_path: None,
            derp_verify_client_endpoint: None,
            derp_verify_client_url: None,
            derp_home: None,
            derp_mesh_with: None,
            derp_mesh_psk_file: None,
            derp_server_key_path: None,
            derp_stun_listen_port: None,
            derp_tls_cert_path: None,
            derp_tls_key_path: None,
        };

        // Server B (meshes with A)
        let ir_b = ServiceIR {
            ty: ServiceType::Derp,
            tag: Some("derp-b".to_string()),
            derp_listen: Some("127.0.0.1".to_string()),
            derp_listen_port: Some(port_b),
            derp_mesh_psk: Some(psk.clone()),
            derp_mesh_with: Some(vec![format!("127.0.0.1:{}", port_a)]),
            derp_stun_enabled: Some(false),
            resolved_listen: None,
            resolved_listen_port: None,
            ssmapi_listen: None,
            ssmapi_listen_port: None,
            ssmapi_servers: None,
            ssmapi_cache_path: None,
            ssmapi_tls_cert_path: None,
            ssmapi_tls_key_path: None,
            derp_config_path: None,
            derp_verify_client_endpoint: None,
            derp_verify_client_url: None,
            derp_home: None,
            derp_mesh_psk_file: None,
            derp_server_key_path: None,
            derp_stun_listen_port: None,
            derp_tls_cert_path: None,
            derp_tls_key_path: None,
        };

        let ctx = ServiceContext::default();
        let service_a = build_derp_service(&ir_a, &ctx).expect("build a");
        let service_b = build_derp_service(&ir_b, &ctx).expect("build b");

        service_a.start(StartStage::Initialize).unwrap();
        service_a.start(StartStage::Start).unwrap();

        service_b.start(StartStage::Initialize).unwrap();
        service_b.start(StartStage::Start).unwrap();

        // Wait for servers to start and mesh to connect
        sleep(Duration::from_millis(500)).await;

        // Client 1 connects to A
        let client1_key = [1u8; 32];
        let (mut c1, _) = connect_and_handshake(
            format!("127.0.0.1:{}", port_a).parse().unwrap(),
            client1_key,
        )
        .await;

        // Client 2 connects to B
        let client2_key = [2u8; 32];
        let (mut c2, _) = connect_and_handshake(
            format!("127.0.0.1:{}", port_b).parse().unwrap(),
            client2_key,
        )
        .await;

        // Wait for peer presence propagation
        sleep(Duration::from_millis(200)).await;

        // C1 sends packet to C2
        let packet_content = b"hello mesh".to_vec();
        let frame = DerpFrame::SendPacket {
            dst_key: client2_key,
            packet: packet_content.clone(),
        };
        c1.write_all(&frame.to_bytes().unwrap())
            .await
            .expect("c1 send");

        // C2 should receive RecvPacket from C1
        let mut buf = [0u8; 1024];
        // Read frame header
        c2.read_exact(&mut buf[0..5]).await.expect("c2 read header");
        let frame_type = buf[0];
        let frame_len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;

        assert_eq!(frame_type, FrameType::RecvPacket as u8);

        // Read frame body
        c2.read_exact(&mut buf[0..frame_len])
            .await
            .expect("c2 read body");

        // Verify content
        // RecvPacket: src_key(32) + packet
        let src_key = &buf[0..32];
        let packet = &buf[32..frame_len];

        assert_eq!(src_key, client1_key);
        assert_eq!(packet, packet_content.as_slice());

        service_a.close().unwrap();
        service_b.close().unwrap();
    }
}
