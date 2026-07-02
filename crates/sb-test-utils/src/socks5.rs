//! Mock SOCKS5 server implementation for testing
//! 用于测试的 Mock SOCKS5 服务器实现
//!
//! Provides a minimal SOCKS5 proxy server that supports:
//! 提供一个最小化的 SOCKS5 代理服务器，支持：
//! - SOCKS5 handshake (no authentication)
//!   SOCKS5 握手（无认证）
//! - UDP ASSOCIATE command
//!   UDP ASSOCIATE 命令
//! - UDP packet echo functionality for legacy relay tests
//!   面向 legacy relay 测试的 UDP 数据包回显功能
//!
//! ## Example / 示例
//!
//! ```rust,no_run
//! use sb_test_utils::socks5::start_mock_socks5;
//!
//! #[tokio::test]
//! async fn test_socks5_udp() {
//!     let (tcp_addr, udp_addr) = start_mock_socks5().await.unwrap();
//!
//!     // Connect to TCP control address to establish association
//!     // 连接到 TCP 控制地址以建立关联
//!     // Send UDP packets to udp_addr
//!     // 发送 UDP 数据包到 udp_addr
//!     // Packets will be echoed back using the mock relay reply shape.
//!     // 数据包将以 mock relay 回复形状回显。
//! }
//! ```
//!
//! ## Strategic Implementation Notes / 战略实施说明
//!
//! Unlike a full SOCKS5 server, this mock is designed specifically for testing client-side
//! SOCKS5 relay code. It simplifies the state machine to focus on verifying that clients
//! correctly initiate connections and handle basic UDP relaying.
//! For compatibility with existing relay tests, UDP replies identify the client source as the reply
//! destination instead of preserving the request destination address.
//! 与完整 SOCKS5 服务器不同，此 Mock 专门用于测试客户端侧 SOCKS5 relay 代码。
//! 它简化了状态机，专注于验证客户端是否正确发起连接并处理基本的 UDP 中继。
//! 为兼容现有 relay 测试，UDP 回复使用客户端来源作为回复目标，而不是保留请求目标地址。

use std::net::{Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

/// Start a minimal SOCKS5 mock server.
/// 启动一个最小化的 SOCKS5 Mock 服务器。
///
/// The server supports:
/// 该服务器支持：
/// - SOCKS5 handshake (no authentication required)
///   SOCKS5 握手（无需认证）
/// - UDP ASSOCIATE command only
///   仅支持 UDP ASSOCIATE 命令
/// - UDP packet echo for relay tests (sends back received payload)
///   面向 relay 测试的 UDP 数据包回显（发回接收到的负载）
///
/// Returns a tuple of (TCP control address, UDP relay address).
/// 返回一个元组 (TCP 控制地址, UDP 中继地址)。
///
/// # Example / 示例
///
/// ```rust,no_run
/// # use sb_test_utils::socks5::start_mock_socks5;
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() {
/// let (tcp_addr, udp_addr) = start_mock_socks5().await.unwrap();
/// println!("SOCKS5 TCP: {}, UDP: {}", tcp_addr, udp_addr);
/// # }
/// ```
///
/// # Protocol Details / 协议细节
///
/// ## UDP Packet Format (SOCKS5 UDP REQUEST)
/// ## UDP 数据包格式 (SOCKS5 UDP 请求)
/// ```text
/// +----+------+------+----------+----------+----------+
/// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
/// +----+------+------+----------+----------+----------+
/// | 2  |  1   |  1   | Variable |    2     | Variable |
/// +----+------+------+----------+----------+----------+
/// ```
///
/// The mock server extracts the DATA portion and echoes it back in a SOCKS5 UDP
/// REPLY format. The reply address is the client source address for compatibility
/// with existing relay tests, not a full SOCKS5 upstream response model.
/// Mock 服务器提取 DATA 部分，并以 SOCKS5 UDP REPLY 格式将其回显。为兼容现有 relay
/// 测试，回复地址使用客户端来源地址，并不模拟完整 SOCKS5 上游响应模型。
///
/// # Errors / 错误
///
/// Returns an error if binding to TCP or UDP sockets fails.
/// 如果绑定 TCP 或 UDP 套接字失败，则返回错误。
pub async fn start_mock_socks5() -> anyhow::Result<(SocketAddr, SocketAddr)> {
    // Bind TCP control socket
    let tcp = TcpListener::bind(("127.0.0.1", 0)).await?;
    let tcp_addr = tcp.local_addr()?;

    // Bind UDP relay socket
    let udp = UdpSocket::bind(("127.0.0.1", 0)).await?;
    let udp_addr = udp.local_addr()?;

    // Spawn UDP echo loop
    spawn_udp_echo_loop(udp);

    // Spawn TCP control handler
    spawn_tcp_control_handler(tcp, udp_addr);

    Ok((tcp_addr, udp_addr))
}

/// Spawn the UDP echo loop task.
///
/// Receives SOCKS5 UDP packets, extracts the payload, and echoes it back
/// wrapped in the legacy relay-test UDP reply format.
fn spawn_udp_echo_loop(udp: UdpSocket) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let Ok((n, from)) = udp.recv_from(&mut buf).await else {
                continue;
            };

            // Parse SOCKS5 UDP REQUEST header
            // RSV(2) + FRAG(1) + ATYP(1) + DST + PORT + DATA
            if n < 3 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
                continue; // Invalid or fragmented packet
            }

            let mut i = 3usize;
            if i >= n {
                continue;
            }

            let atyp = buf[i];
            i += 1;

            // Skip destination address based on ATYP
            match atyp {
                0x01 => {
                    // IPv4: 4 bytes address + 2 bytes port
                    if i + 4 + 2 > n {
                        continue;
                    }
                    i += 4 + 2;
                }
                0x04 => {
                    // IPv6: 16 bytes address + 2 bytes port
                    if i + 16 + 2 > n {
                        continue;
                    }
                    i += 16 + 2;
                }
                0x03 => {
                    // Domain: 1 byte length + N bytes domain + 2 bytes port
                    if i >= n {
                        continue;
                    }
                    let len = buf[i] as usize;
                    i += 1;
                    if i + len + 2 > n {
                        continue;
                    }
                    i += len + 2;
                }
                _ => continue,
            }

            // Extract payload
            let payload = &buf[i..n];

            // Build legacy relay-test UDP REPLY:
            // RSV(2) + FRAG(1) + ATYP(1) + CLIENT.ADDR + CLIENT.PORT + DATA
            let mut out = Vec::with_capacity(3 + 1 + 4 + 2 + payload.len());
            out.extend_from_slice(&[0, 0, 0]); // RSV + FRAG
            out.push(0x01); // ATYP: IPv4
            out.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());
            out.extend_from_slice(&from.port().to_be_bytes());
            out.extend_from_slice(payload);

            let _ = udp.send_to(&out, from).await;
        }
    });
}

/// Spawn the TCP control handler task.
///
/// Accepts TCP connections, performs SOCKS5 handshake, and responds
/// to UDP ASSOCIATE requests with the bound UDP address.
fn spawn_tcp_control_handler(tcp: TcpListener, udp_addr: SocketAddr) {
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _peer)) = tcp.accept().await else {
                continue;
            };

            let udp_addr = udp_addr;
            tokio::spawn(async move {
                let _ = handle_socks5_handshake(&mut stream, udp_addr).await;
            });
        }
    });
}

/// Handle SOCKS5 handshake and UDP ASSOCIATE command.
async fn handle_socks5_handshake(
    stream: &mut tokio::net::TcpStream,
    udp_addr: SocketAddr,
) -> anyhow::Result<()> {
    // Read greeting: VER(1) + NMETHODS(1)
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;

    if greeting[0] != 0x05 {
        anyhow::bail!("Invalid SOCKS version: {}", greeting[0]);
    }

    let nmethods = greeting[1];
    if nmethods == 0 {
        anyhow::bail!("No authentication methods provided");
    }

    // Read methods
    let mut methods = vec![0u8; nmethods as usize];
    stream.read_exact(&mut methods).await?;

    // Check for NO AUTHENTICATION (0x00)
    if !methods.contains(&0x00) {
        // Send method not supported
        stream.write_all(&[0x05, 0xFF]).await?;
        anyhow::bail!("No supported authentication method");
    }

    // Send selected method: NO AUTHENTICATION
    stream.write_all(&[0x05, 0x00]).await?;

    // Read request: VER(1) + CMD(1) + RSV(1)
    let mut request_header = [0u8; 3];
    stream.read_exact(&mut request_header).await?;

    if request_header[0] != 0x05 {
        anyhow::bail!("Invalid SOCKS version in request");
    }

    if request_header[2] != 0x00 {
        write_socks5_reply(stream, 0x01, udp_addr).await?;
        anyhow::bail!("Invalid SOCKS reserved byte in request");
    }

    if request_header[1] != 0x03 {
        // Only support UDP ASSOCIATE (0x03)
        write_socks5_reply(stream, 0x07, udp_addr).await?;
        anyhow::bail!("Command not supported: {}", request_header[1]);
    }

    // Read ATYP and destination address
    let mut atyp = [0u8; 1];
    stream.read_exact(&mut atyp).await?;

    match atyp[0] {
        0x01 => {
            // IPv4: 4 bytes + 2 bytes port
            let mut addr = [0u8; 6];
            stream.read_exact(&mut addr).await?;
        }
        0x04 => {
            // IPv6: 16 bytes + 2 bytes port
            let mut addr = [0u8; 18];
            stream.read_exact(&mut addr).await?;
        }
        0x03 => {
            // Domain: 1 byte length + N bytes + 2 bytes port
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut domain).await?;
        }
        _ => {
            write_socks5_reply(stream, 0x08, udp_addr).await?;
            anyhow::bail!("Unsupported ATYP: {}", atyp[0]);
        }
    }

    // Send success reply with bound UDP address
    // VER(1) + REP(1) + RSV(1) + ATYP(1) + BND.ADDR + BND.PORT
    write_socks5_reply(stream, 0x00, udp_addr).await?;

    let mut drain = [0u8; 256];
    while stream.read(&mut drain).await? != 0 {}

    Ok(())
}

async fn write_socks5_reply(
    stream: &mut tokio::net::TcpStream,
    reply_code: u8,
    udp_addr: SocketAddr,
) -> anyhow::Result<()> {
    let mut reply = Vec::with_capacity(10);
    reply.extend_from_slice(&[0x05, reply_code, 0x00, 0x01]);
    reply.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());
    reply.extend_from_slice(&udp_addr.port().to_be_bytes());
    stream.write_all(&reply).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use tokio::net::{TcpStream, UdpSocket};
    use tokio::time::{timeout, Duration};

    async fn connect_and_select_no_auth(tcp_addr: SocketAddr) -> anyhow::Result<TcpStream> {
        let mut stream = TcpStream::connect(tcp_addr).await?;
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut method = [0u8; 2];
        stream.read_exact(&mut method).await?;
        assert_eq!(method, [0x05, 0x00]);
        Ok(stream)
    }

    fn is_permission_denied(err: &anyhow::Error) -> bool {
        err.chain().any(|cause| {
            cause.downcast_ref::<io::Error>().is_some_and(|err| {
                err.kind() == io::ErrorKind::PermissionDenied
                    || err.raw_os_error() == Some(1)
                    || err.raw_os_error() == Some(13)
            })
        }) || err.to_string().contains("Operation not permitted")
            || err.to_string().contains("Permission denied")
    }

    #[tokio::test]
    async fn test_start_mock_socks5() {
        let result = start_mock_socks5().await;
        let (tcp_addr, udp_addr) = match result {
            Ok(value) => value,
            Err(err) => {
                if is_permission_denied(&err) {
                    crate::skip::skip_with_reason("mock socks5 startup test", err);
                    return;
                }
                panic!("unexpected error starting mock socks5: {err:?}");
            }
        };

        assert!(tcp_addr.port() > 0);
        assert!(udp_addr.port() > 0);
        assert_ne!(tcp_addr.port(), udp_addr.port());
    }

    #[tokio::test]
    async fn tcp_udp_associate_rejects_nonzero_reserved_byte() -> anyhow::Result<()> {
        let (tcp_addr, _udp_addr) = start_mock_socks5().await?;
        let mut stream = connect_and_select_no_auth(tcp_addr).await?;

        stream
            .write_all(&[0x05, 0x03, 0x01, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;

        let mut reply = [0u8; 10];
        stream.read_exact(&mut reply).await?;
        assert_eq!(&reply[..4], &[0x05, 0x01, 0x00, 0x01]);
        Ok(())
    }

    #[tokio::test]
    async fn tcp_control_returns_failure_for_unsupported_command() -> anyhow::Result<()> {
        let (tcp_addr, _udp_addr) = start_mock_socks5().await?;
        let mut stream = connect_and_select_no_auth(tcp_addr).await?;

        stream
            .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;

        let mut reply = [0u8; 10];
        stream.read_exact(&mut reply).await?;
        assert_eq!(&reply[..4], &[0x05, 0x07, 0x00, 0x01]);
        Ok(())
    }

    #[tokio::test]
    async fn udp_echo_reply_uses_client_source_for_legacy_relay_tests() -> anyhow::Result<()> {
        let (_tcp_addr, udp_addr) = start_mock_socks5().await?;
        let client = UdpSocket::bind(("127.0.0.1", 0)).await?;
        let client_port = client.local_addr()?.port();
        let payload = b"relay-payload";

        let mut packet = Vec::new();
        packet.extend_from_slice(&[0, 0, 0, 0x01]);
        packet.extend_from_slice(&[1, 2, 3, 4]);
        packet.extend_from_slice(&5678u16.to_be_bytes());
        packet.extend_from_slice(payload);
        client.send_to(&packet, udp_addr).await?;

        let mut reply = [0u8; 128];
        let (n, _from) = timeout(Duration::from_secs(1), client.recv_from(&mut reply)).await??;

        assert_eq!(&reply[..4], &[0, 0, 0, 0x01]);
        assert_eq!(&reply[4..8], &Ipv4Addr::LOCALHOST.octets());
        assert_eq!(u16::from_be_bytes([reply[8], reply[9]]), client_port);
        assert_eq!(&reply[10..n], payload);
        Ok(())
    }
}
