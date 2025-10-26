#![cfg(feature = "socks")]
//! Minimal SOCKS5-UDP probe (no TCP handshake). It directly sends a UDP datagram
//! to the server's UDP relay port with a SOCKS5 UDP header.
//! Usage:
//!   cargo run -q -p sb-adapters --example socks_udp_probe -- \
//!     127.0.0.1:UDP_BIND_ADDR <target-host> <target-port> [payload]
//! Example (DNS): payload defaults to "ping". For DNS, provide raw hex via 0x... soon if needed.
use sb_adapters::inbound::socks::udp::encode_udp_datagram;
use sb_adapters::util::parse_payload_arg;
use sb_core::net::datagram::UdpTargetAddr;
use sb_core::net::dial::per_attempt_timeout;
use sb_core::util::env::env_bool;
use std::env;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::{net::UdpSocket, time};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 && env::var("SB_SOCKS_UDP_RELAY").is_err() {
        eprintln!(
            "Usage: {} <server-udp-addr> <target-host> <target-port> [payload or 0xHEX]",
            args[0]
        );
        eprintln!("       or set SB_SOCKS_UDP_RELAY=host:port to omit the first arg");
        std::process::exit(2);
    }
    let (server, host, port, payload) = if let Ok(relay) = env::var("SB_SOCKS_UDP_RELAY") {
        if args.len() < 3 {
            eprintln!(
                "Usage: {} <target-host> <target-port> [payload or 0xHEX] (with SB_SOCKS_UDP_RELAY)",
                args[0]
            );
            std::process::exit(2);
        }
        let server: SocketAddr = relay.parse()?;
        let host = args[1].clone();
        let port: u16 = args[2].parse()?;
        let payload = if args.len() >= 4 {
            parse_payload_arg(&args[3])
        } else {
            b"ping".to_vec()
        };
        (server, host, port, payload)
    } else {
        let server: SocketAddr = args[1].parse()?;
        let host = args[2].clone();
        let port: u16 = args[3].parse()?;
        let payload = if args.len() >= 5 {
            parse_payload_arg(&args[4])
        } else {
            b"ping".to_vec()
        };
        (server, host, port, payload)
    };

    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    // 注意：下面要打印 host，因此构造目标时克隆一次，避免 move
    let target = match host.parse::<Ipv4Addr>() {
        Ok(addr) => UdpTargetAddr::Ip(SocketAddr::new(IpAddr::V4(addr), port)),
        Err(_) => match host.parse::<Ipv6Addr>() {
            Ok(addr) => UdpTargetAddr::Ip(SocketAddr::new(IpAddr::V6(addr), port)),
            Err(_) => UdpTargetAddr::Domain {
                host: host.clone(),
                port,
            },
        },
    };
    let out = encode_udp_datagram(&target, &payload);
    eprintln!(
        "relay={} target={}:{} payload_len={} bytes timeout={:?} nat_adapt={}",
        server,
        host,
        port,
        payload.len(),
        per_attempt_timeout(),
        env_bool("SB_UDP_NAT_ADAPT")
    );
    sock.send_to(&out, server).await?;

    let mut buf = vec![0u8; 64 * 1024];
    match time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf)).await {
        Ok(Ok((n, from))) => {
            println!("OK: got {} bytes from {}", n, from);
            // 打印前 64 字节十六进制预览
            let m = n.min(64);
            for (i, b) in buf[..m].iter().enumerate() {
                if i % 16 == 0 {
                    print!("\n{:04x}: ", i);
                }
                print!("{:02x} ", b);
            }
            println!();
            Ok(())
        }
        Ok(Err(e)) => Err(anyhow::anyhow!("recv error: {e}")),
        Err(_) => Err(anyhow::anyhow!("timeout waiting for response")),
    }
}
