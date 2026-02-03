//! Mock SOCKS5 server implementation for testing
//! 用于测试的 Mock SOCKS5 服务器实现
//!
//! Provides a minimal SOCKS5 proxy server that supports:
//! 提供一个最小化的 SOCKS5 代理服务器，支持：
//! - SOCKS5 handshake (no authentication)
//!   SOCKS5 握手（无认证）
//! - UDP ASSOCIATE command
//!   UDP ASSOCIATE 命令
//! - UDP packet echo functionality
//!   UDP 数据包回显功能
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
//!     // Packets will be echoed back
//!     // 数据包将被回显
//! }
//! ```
//!
//! ## Strategic Implementation Notes / 战略实施说明
//!
//! Unlike the full SOCKS5 implementation in `sb-inbound`, this mock server is designed specifically for
//! testing *clients* (like `sb-outbound`'s SOCKS5 outbound). It simplifies the state machine to focus
//! on verifying that clients correctly initiate connections and handle basic UDP relaying.
//! 与 `sb-inbound` 中的完整 SOCKS5 实现不同，此 Mock 服务器专门设计用于测试 *客户端*（如 `sb-outbound` 的 SOCKS5 出站）。
//! 它简化了状态机，专注于验证客户端是否正确发起连接并处理基本的 UDP 中继。

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
/// - UDP packet echo (sends back received payload)
///   UDP 数据包回显（发回接收到的负载）
///
/// Returns a tuple of (TCP control address, UDP relay address).
/// 返回一个元组 (TCP 控制地址, UDP 中继地址)。
///
/// # Example / 示例
///
/// ```rust,no_run
/// # use sb_test_utils::socks5::start_mock_socks5;
/// # #[tokio::main]
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
/// The mock server extracts the DATA portion and echoes it back
/// in a SOCKS5 UDP REPLY format.
/// Mock 服务器提取 DATA 部分，并以 SOCKS5 UDP REPLY 格式将其回显。
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
/// wrapped in a SOCKS5 UDP REPLY format.
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

            // Build SOCKS5 UDP REPLY
            // RSV(2) + FRAG(1) + ATYP(1) + BND.ADDR + BND.PORT + DATA
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
                if let Err(e) = handle_socks5_handshake(&mut stream, udp_addr).await {
                    eprintln!("SOCKS5 handshake error: {e}");
                }
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

    if request_header[1] != 0x03 {
        // Only support UDP ASSOCIATE (0x03)
        let reply = [0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        stream.write_all(&reply).await?;
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
        _ => anyhow::bail!("Unsupported ATYP: {}", atyp[0]),
    }

    // Send success reply with bound UDP address
    // VER(1) + REP(1) + RSV(1) + ATYP(1) + BND.ADDR + BND.PORT
    let mut reply = Vec::new();
    reply.extend_from_slice(&[0x05, 0x00, 0x00, 0x01]); // Success, IPv4
    reply.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());
    reply.extend_from_slice(&udp_addr.port().to_be_bytes());

    stream.write_all(&reply).await?;

    // Keep connection alive (in real SOCKS5, client should keep it open)
    // For testing purposes, we can just let it idle or close
    tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

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
                    eprintln!("Skipping: permission denied starting mock socks5");
                    return;
                }
                panic!("unexpected error starting mock socks5: {err:?}");
            }
        };

        assert!(tcp_addr.port() > 0);
        assert!(udp_addr.port() > 0);
        assert_ne!(tcp_addr.port(), udp_addr.port());
    }
}
