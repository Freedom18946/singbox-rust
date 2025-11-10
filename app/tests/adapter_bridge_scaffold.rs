#[cfg(feature = "scaffold")]
mod t_scaffold {
    use sb_config::ir::{ConfigIR, InboundIR, InboundType, OutboundIR, OutboundType, RouteIR};
    use sb_core::adapter::bridge::build_bridge;
    use sb_core::routing::engine::Engine;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    #[test]
    #[ignore = "requires local networking privileges"]
    fn socks_scaffold_runs_and_forwards() {
        // echo server
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let echo_addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            for c in l.incoming() {
                if let Ok(mut s) = c {
                    std::thread::spawn(move || {
                        let mut buf = [0u8; 1024];
                        loop {
                            match s.read(&mut buf) {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    let _ = s.write_all(&buf[..n]);
                                }
                            }
                        }
                    });
                }
            }
        });
        // ir: one socks inbound + direct outbound
        let socks = TcpListener::bind("127.0.0.1:0").unwrap();
        let socks_port = socks.local_addr().unwrap().port();
        let ir = ConfigIR {
            inbounds: vec![InboundIR {
                ty: InboundType::Socks,
                listen: "127.0.0.1".into(),
                port: socks_port,
                sniff: false,
                udp: false,
                basic_auth: None,
                override_host: None,
                override_port: None,
            }],
            outbounds: vec![OutboundIR {
                ty: OutboundType::Direct,
                server: None,
                port: None,
                udp: None,
                name: Some("direct".into()),
                ..Default::default()
            }],
            route: RouteIR::default(),
            ntp: None,
            dns: None,
        };
        let eng = Engine::new(&ir);
        std::env::set_var("ADAPTER_FORCE", "scaffold");
        let br = build_bridge(&ir, eng);
        for ib in &br.inbounds {
            let i = ib.clone();
            thread::spawn(move || {
                let _ = i.serve();
            });
        }
        std::thread::sleep(Duration::from_millis(80));
        // socks handshake & echo
        use std::net::TcpStream;
        let mut s = TcpStream::connect(("127.0.0.1", socks_port)).unwrap();
        s.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut rep = [0u8; 2];
        s.read_exact(&mut rep).unwrap();
        assert_eq!(rep, [0x05, 0x00]);
        let ip = match echo_addr.ip() {
            std::net::IpAddr::V4(v) => v.octets(),
            _ => [127, 0, 0, 1],
        };
        let port = echo_addr.port().to_be_bytes();
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        req.extend_from_slice(&ip);
        req.extend_from_slice(&port);
        s.write_all(&req).unwrap();
        let mut r = [0u8; 10];
        s.read_exact(&mut r).unwrap();
        assert_eq!(r[1], 0x00);
        s.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[test]
    fn unsupported_inbound_ty_logically_fails() {
        let ir = ConfigIR {
            inbounds: vec![InboundIR {
                ty: InboundType::Naive,
                listen: "127.0.0.1".into(),
                port: 10801,
                sniff: false,
                udp: false,
                basic_auth: None,
                override_host: None,
                override_port: None,
            }],
            outbounds: vec![OutboundIR {
                ty: OutboundType::Direct,
                name: Some("direct".into()),
                ..Default::default()
            }],
            route: RouteIR::default(),
            ntp: None,
            dns: None,
        };
        let eng = Engine::new(&ir);
        std::env::set_var("ADAPTER_FORCE", "scaffold");
        let br = build_bridge(&ir, eng);
        assert_eq!(br.inbound_kinds.len(), 1);
        assert_eq!(br.inbound_kinds[0], "naive");
        let res = br.inbounds[0].serve();
        assert!(res.is_err(), "naive inbound should not be supported under scaffold");
    }
}

#[cfg(not(feature = "scaffold"))]
#[test]
fn skip_without_scaffold() { /* no-op; scaffold not enabled */
}
