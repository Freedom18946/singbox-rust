use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread,
    time::Duration,
};

// Minimal SOCKS5 stub: handshake + UDP ASSOCIATE response with configurable delay injection
// Usage:
// cargo run -q --example socks5_stub -- --listen 127.0.0.1:31080 --delay-ms 150

fn handle(mut s: TcpStream, delay_ms: u64) -> std::io::Result<()> {
    s.set_nodelay(true).ok();

    // Negotiation: VER NMETHODS METHODS
    let mut buf = [0u8; 2 + 255];
    let n = s.read(&mut buf)?;
    if n < 2 || buf[0] != 0x05 {
        return Ok(());
    }

    // Inject configurable delay to simulate slow upstream
    thread::sleep(Duration::from_millis(delay_ms));

    // Select NO-AUTH
    s.write_all(&[0x05, 0x00])?;

    // Request: VER CMD RSV ATYP ...
    let n = s.read(&mut buf)?;
    if n < 4 || buf[0] != 0x05 {
        return Ok(());
    }
    let cmd = buf[1];

    // Reply success for any command, but don't do actual forwarding
    let resp = vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0x1F, 0x90]; // 0.0.0.0:8080
    if cmd == 0x03
    /* UDP ASSOCIATE */
    {
        // Same success response
    }
    s.write_all(&resp)?;
    Ok(())
}

fn main() -> std::io::Result<()> {
    let mut listen = "127.0.0.1:31080".to_string();
    let mut delay_ms: u64 = 100;

    {
        let mut args = std::env::args().skip(1);
        while let Some(a) = args.next() {
            match a.as_str() {
                "--listen" => {
                    listen = args.next().unwrap();
                }
                "--delay-ms" => {
                    delay_ms = args.next().unwrap().parse().unwrap_or(100);
                }
                _ => {}
            }
        }
    }

    let listener = TcpListener::bind(&listen)?;
    eprintln!("stub listening on {} delay_ms={}", listen, delay_ms);

    for s in listener.incoming().flatten() {
        let d = delay_ms;
        thread::spawn(move || {
            let _ = handle(s, d);
        });
    }
    Ok(())
}
