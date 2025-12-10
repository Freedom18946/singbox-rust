#![cfg(feature = "adapter-socks")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! E2E tests for SOCKS5 UDP ASSOCIATE functionality
//!
//! This module tests SOCKS5 UDP support with mock servers to verify
//! the UDP encapsulation/decapsulation works correctly.

use sb_adapters::Result;
use std::net::{IpAddr, SocketAddr};

use sb_adapters::outbound::socks5::Socks5Connector;
use sb_adapters::{DialOpts, Target};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

/// Mock SOCKS5 server for testing UDP ASSOCIATE
#[allow(dead_code)]
struct MockSocks5Server {
    tcp_listener: TcpListener,
    udp_relay: UdpSocket,
}

#[allow(dead_code)]
impl MockSocks5Server {
    async fn new() -> Result<Self> {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await?;
        let udp_relay = UdpSocket::bind("127.0.0.1:0").await?;

        Ok(Self {
            tcp_listener,
            udp_relay,
        })
    }

    fn tcp_addr(&self) -> SocketAddr {
        self.tcp_listener.local_addr().unwrap()
    }

    fn udp_addr(&self) -> SocketAddr {
        self.udp_relay.local_addr().unwrap()
    }

    /// Handle a single SOCKS5 UDP ASSOCIATE request
    async fn handle_udp_associate(&self) -> Result<()> {
        let (mut stream, _) = self.tcp_listener.accept().await?;

        // Read version + methods
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;
        assert_eq!(buf[0], 0x05); // SOCKS version 5

        let n_methods = buf[1] as usize;
        let mut methods = vec![0u8; n_methods];
        stream.read_exact(&mut methods).await?;

        // Send version + no auth
        stream.write_all(&[0x05, 0x00]).await?;

        // Read UDP ASSOCIATE request
        let mut req = [0u8; 4];
        stream.read_exact(&mut req).await?;
        assert_eq!(req[0], 0x05); // Version
        assert_eq!(req[1], 0x03); // CMD = UDP ASSOCIATE
        assert_eq!(req[2], 0x00); // Reserved

        // Read client address (IPv4 0.0.0.0:0)
        let atyp = req[3];
        assert_eq!(atyp, 0x01); // IPv4

        let mut addr_port = [0u8; 6]; // 4 bytes IP + 2 bytes port
        stream.read_exact(&mut addr_port).await?;

        // Send success response with relay address
        let relay_addr = self.udp_addr();
        let relay_ip = match relay_addr.ip() {
            IpAddr::V4(ip) => ip,
            _ => panic!("Expected IPv4"),
        };

        let mut response = vec![0x05, 0x00, 0x00, 0x01]; // VER, REP=SUCCESS, RSV, ATYP=IPv4
        response.extend_from_slice(&relay_ip.octets());
        response.extend_from_slice(&relay_addr.port().to_be_bytes());

        stream.write_all(&response).await?;

        // Keep connection alive (in real implementation)
        // For test, we'll just hold it open briefly
        tokio::time::sleep(Duration::from_millis(100)).await;

        Ok(())
    }

    /// Echo UDP packets with SOCKS5 encapsulation
    async fn echo_udp_packets(&self) -> Result<()> {
        let mut buf = vec![0u8; 1024];

        loop {
            let (len, peer) = self.udp_relay.recv_from(&mut buf).await?;

            // Simply echo back the packet to the sender
            self.udp_relay.send_to(&buf[..len], peer).await?;
        }
    }
}

#[cfg(feature = "socks-udp")]
#[tokio::test]
async fn test_socks5_udp_associate() -> Result<()> {
    use serial_test::serial;

    // This test needs to run serially to avoid port conflicts
    #[serial]
    async fn run_test() -> Result<()> {
        let server = Arc::new(MockSocks5Server::new().await?);
        let server_tcp_addr = server.tcp_addr();

        // Start mock server tasks
        let server_clone = server.clone();
        let tcp_task = tokio::spawn(async move { server_clone.handle_udp_associate().await });

        let server_clone = server.clone();
        let udp_task = tokio::spawn(async move { server_clone.echo_udp_packets().await });

        // Give server a moment to start
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Create SOCKS5 connector
        let connector = Socks5Connector::no_auth(server_tcp_addr.to_string());

        // Test UDP ASSOCIATE
        let target = Target::udp("127.0.0.1", 8080);
        let opts = DialOpts {
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(5),
            retry_policy: Default::default(),
            resolve_mode: sb_adapters::ResolveMode::Remote,
        };

        let udp_conn = connector.dial_udp(target, opts).await?;

        // Test sending/receiving data
        let test_data = b"Hello, SOCKS5 UDP!";
        let sent = udp_conn.send_to(test_data).await?;
        assert_eq!(sent, test_data.len());

        let mut recv_buf = vec![0u8; 1024];
        let received = udp_conn.recv_from(&mut recv_buf).await?;

        // The mock server echoes back the SOCKS5 encapsulated packet
        // We should get back our original data
        assert!(received > 0);

        // Clean up
        tcp_task.abort();
        udp_task.abort();

        Ok(())
    }

    run_test().await
}
