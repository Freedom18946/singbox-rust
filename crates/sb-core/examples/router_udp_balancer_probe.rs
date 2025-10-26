// no extra imports needed

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Args: <host> <port> <hexpayload>
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() < 3 {
        eprintln!("Usage: router_udp_balancer_probe <host> <port> <hexpayload>");
        std::process::exit(2);
    }
    let host = args.remove(0);
    let port: u16 = args.remove(0).parse()?;
    let payload = decode_hex(&args.remove(0)).expect("bad hex");

    // Router decision (simulate UDP target)
    let dst = sb_core::net::datagram::UdpTargetAddr::Domain {
        host: host.clone(),
        port,
    };
    let decision = sb_core::router::decide_udp(&dst);
    eprintln!("[router] decision={}", decision);

    // Balancer send (behind env)
    let n = sb_core::outbound::udp_balancer::send_balanced(&payload, &dst, decision).await?;
    println!("sent {} bytes", n);
    Ok(())
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    for i in (0..b.len()).step_by(2) {
        let hi = from_hex(b[i])?;
        let lo = from_hex(b[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}
fn from_hex(x: u8) -> Option<u8> {
    match x {
        b'0'..=b'9' => Some(x - b'0'),
        b'a'..=b'f' => Some(x - b'a' + 10),
        b'A'..=b'F' => Some(x - b'A' + 10),
        _ => None,
    }
}
