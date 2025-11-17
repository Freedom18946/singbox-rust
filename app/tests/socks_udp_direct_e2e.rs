use sb_config::ir::{ConfigIR, InboundIR, InboundType};
use sb_core::adapter::InboundService;
use sb_core::inbound::socks5::Socks5;
use sb_core::routing::engine::Engine;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::thread;
use std::time::Duration;

fn start_udp_echo() -> (SocketAddr, thread::JoinHandle<()>) {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind udp echo");
    let addr = sock.local_addr().unwrap();
    let h = thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match sock.recv_from(&mut buf) {
                Ok((n, peer)) => {
                    let _ = sock.send_to(&buf[..n], peer);
                }
                Err(_) => break,
            }
        }
    });
    (addr, h)
}

fn socks_udp_associate(socks: SocketAddr) -> (TcpStream, SocketAddr) {
    // Connect TCP control channel
    let mut tcp = TcpStream::connect(socks).expect("connect socks");
    tcp.set_read_timeout(Some(Duration::from_secs(3))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(3))).ok();

    // Greeting: VER=5, NMETHODS=1, METHODS=[0x00]
    tcp.write_all(&[0x05, 0x01, 0x00]).expect("write greet");
    let mut rep = [0u8; 2];
    tcp.read_exact(&mut rep).expect("read greet");
    assert_eq!(rep, [0x05, 0x00]);

    // UDP ASSOCIATE request: VER=5, CMD=3, RSV=0, ATYP=IPv4, ADDR=0.0.0.0, PORT=0
    let req = [0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    tcp.write_all(&req).expect("write udp associate");
    let mut resp = [0u8; 10];
    tcp.read_exact(&mut resp).expect("read udp resp");
    assert_eq!(resp[0], 0x05);
    assert_eq!(resp[1], 0x00); // success
                               // Parse bound address
    assert_eq!(resp[3], 0x01); // IPv4
    let ip = Ipv4Addr::new(resp[4], resp[5], resp[6], resp[7]);
    let port = u16::from_be_bytes([resp[8], resp[9]]);
    (tcp, SocketAddr::from((IpAddr::V4(ip), port)))
}

fn build_socks_udp_packet(dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(10 + payload.len());
    // RSV RSV FRAG
    pkt.extend_from_slice(&[0x00, 0x00, 0x00]);
    match dst.ip() {
        IpAddr::V4(v4) => {
            pkt.push(0x01);
            pkt.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            pkt.push(0x04);
            pkt.extend_from_slice(&v6.octets());
        }
    }
    pkt.extend_from_slice(&dst.port().to_be_bytes());
    pkt.extend_from_slice(payload);
    pkt
}

fn parse_socks_udp_packet(buf: &[u8]) -> (&[u8], SocketAddr) {
    assert!(buf.len() >= 10);
    assert_eq!(&buf[0..3], &[0, 0, 0]);
    let atyp = buf[3];
    let mut i = 4usize;
    let addr = match atyp {
        0x01 => {
            let v4 = Ipv4Addr::new(buf[i], buf[i + 1], buf[i + 2], buf[i + 3]);
            i += 4;
            let port = u16::from_be_bytes([buf[i], buf[i + 1]]);
            i += 2;
            SocketAddr::from((IpAddr::V4(v4), port))
        }
        0x04 => {
            let mut seg = [0u8; 16];
            seg.copy_from_slice(&buf[i..i + 16]);
            i += 16;
            let port = u16::from_be_bytes([buf[i], buf[i + 1]]);
            i += 2;
            SocketAddr::from((IpAddr::from(seg), port))
        }
        _ => panic!("unsupported atyp"),
    };
    (&buf[i..], addr)
}

#[test]
fn socks_udp_via_direct_nat_echo() {
    // Start UDP echo server
    let (echo_addr, _echo_h) = start_udp_echo();

    // Start SOCKS5 inbound
    let l = TcpListener::bind("127.0.0.1:0").expect("bind socks");
    let socks_addr = l.local_addr().unwrap();
    drop(l);
    let mut ir = ConfigIR::default();
    ir.inbounds.push(InboundIR {
        ty: InboundType::Socks,
        listen: socks_addr.ip().to_string(),
        port: socks_addr.port(),
        sniff: false,
        udp: true,
        basic_auth: None,
        override_host: None,
        override_port: None,
    });
    let ir_static: &'static ConfigIR = Box::leak(Box::new(ir));
    let eng = Engine::new(ir_static);
    thread::spawn(move || {
        let srv =
            Socks5::new("127.0.0.1".into(), socks_addr.port()).with_engine(eng.clone_as_static());
        let _ = srv.serve();
    });
    thread::sleep(Duration::from_millis(150));

    // Perform UDP ASSOCIATE
    let (_tcp, relay_addr) = socks_udp_associate(socks_addr);

    // Send a UDP packet through SOCKS relay
    let cli = UdpSocket::bind("127.0.0.1:0").expect("bind udp client");
    cli.set_read_timeout(Some(Duration::from_secs(3))).ok();
    let payload = b"hello-udp-through-socks";
    let pkt = build_socks_udp_packet(echo_addr, payload);
    let _ = cli.send_to(&pkt, relay_addr).expect("send to relay");

    // Read response and parse
    let mut buf = [0u8; 4096];
    let (n, _src) = cli.recv_from(&mut buf).expect("recv from relay");
    let (data, _addr) = parse_socks_udp_packet(&buf[..n]);
    assert_eq!(data, payload);
}

use std::io::{Read, Write};
