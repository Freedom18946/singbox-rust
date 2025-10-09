//! E2E test for direct inbound with UDP support
//!
//! Tests that direct inbound correctly forwards both TCP and UDP traffic
//! to a fixed destination address.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use sb_core::adapter::InboundService;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

fn is_perm(e: &std::io::Error) -> bool { e.kind() == std::io::ErrorKind::PermissionDenied }

#[tokio::test]
async fn direct_inbound_tcp_forward() {
    // Setup echo server as destination
    let echo_server = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => { if is_perm(&e) { eprintln!("skipping tcp_forward due to sandbox PermissionDenied on bind: {}", e); return; } else { panic!("bind: {}", e); } }
    };
    let echo_addr = echo_server.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = echo_server.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 1024];
                    while let Ok(n) = stream.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        let _ = stream.write_all(&buf[..n]).await;
                    }
                });
            }
        }
    });

    // Give echo server time to start
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Pick inbound port explicitly (bind probe then drop)
    let probe = match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => { if is_perm(&e) { eprintln!("skipping tcp_forward due to sandbox PermissionDenied on port probe: {}", e); return; } else { panic!("probe bind: {}", e); } }
    };
    let inbound_port = probe.local_addr().unwrap().port();
    drop(probe);

    // Setup direct inbound forwarder on chosen port
    let listen_addr: SocketAddr = format!("127.0.0.1:{}", inbound_port).parse().unwrap();
    let forward = sb_core::inbound::direct::DirectForward::new(
        listen_addr,
        echo_addr.ip().to_string(),
        echo_addr.port(),
        false, // TCP only
    );

    let fwd_listen = listen_addr;

    // Start forwarder in background (use std::thread to avoid nested runtime)
    std::thread::spawn(move || {
        let _ = forward.serve();
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Test TCP forwarding
    let mut client = match TcpStream::connect(fwd_listen).await {
        Ok(s) => s,
        Err(e) => { if is_perm(&e) { eprintln!("skipping tcp_forward due to sandbox PermissionDenied on connect: {}", e); return; } else { panic!("connect: {}", e); } }
    };
    let test_data = b"Hello, Direct Inbound!";

    client.write_all(test_data).await.unwrap();

    let mut response = vec![0u8; test_data.len()];
    client.read_exact(&mut response).await.unwrap();

    assert_eq!(response, test_data, "TCP echo should match sent data");
}

#[tokio::test]
async fn direct_inbound_udp_forward() {
    // Setup UDP echo server as destination
    let echo_server = match UdpSocket::bind("127.0.0.1:0").await {
        Ok(s) => s,
        Err(e) => { if is_perm(&e) { eprintln!("skipping udp_forward due to sandbox PermissionDenied on bind: {}", e); return; } else { panic!("bind: {}", e); } }
    };
    let echo_addr = echo_server.local_addr().unwrap();

    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            if let Ok((n, src)) = echo_server.recv_from(&mut buf).await {
                let _ = echo_server.send_to(&buf[..n], src).await;
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(10)).await;

    // Pick inbound port explicitly
    let probe = match std::net::UdpSocket::bind("127.0.0.1:0") {
        Ok(s) => s,
        Err(e) => { if is_perm(&e) { eprintln!("skipping udp_forward due to sandbox PermissionDenied on port probe: {}", e); return; } else { panic!("probe bind: {}", e); } }
    };
    let inbound_port = probe.local_addr().unwrap().port();
    drop(probe);

    // Setup direct inbound forwarder with UDP enabled
    let listen_addr: SocketAddr = format!("127.0.0.1:{}", inbound_port).parse().unwrap();
    let forward = sb_core::inbound::direct::DirectForward::new(
        listen_addr,
        echo_addr.ip().to_string(),
        echo_addr.port(),
        true, // UDP enabled
    );

    let fwd_listen = listen_addr;

    // Start forwarder in background
    std::thread::spawn(move || {
        let _ = forward.serve();
    });

    tokio::time::sleep(Duration::from_millis(250)).await;

    // Test UDP forwarding
    let client = match UdpSocket::bind("127.0.0.1:0").await {
        Ok(s) => s,
        Err(e) => { if is_perm(&e) { eprintln!("skipping udp_forward due to sandbox PermissionDenied on client bind: {}", e); return; } else { panic!("client bind: {}", e); } }
    };
    let test_data = b"Hello, UDP Direct Inbound!";

    client.send_to(test_data, fwd_listen).await.unwrap();

    let mut response = vec![0u8; 1024];
    let (n, _) = tokio::time::timeout(
        Duration::from_secs(2),
        client.recv_from(&mut response),
    )
    .await
    .expect("UDP response timeout")
    .unwrap();

    assert_eq!(&response[..n], test_data, "UDP echo should match sent data");
}

#[tokio::test]
async fn direct_inbound_udp_multiple_clients() {
    // Setup UDP echo server
    let echo_server = match UdpSocket::bind("127.0.0.1:0").await {
        Ok(s) => s,
        Err(e) => { if is_perm(&e) { eprintln!("skipping udp_multi due to sandbox PermissionDenied on bind: {}", e); return; } else { panic!("bind: {}", e); } }
    };
    let echo_addr = echo_server.local_addr().unwrap();

    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            if let Ok((n, src)) = echo_server.recv_from(&mut buf).await {
                let _ = echo_server.send_to(&buf[..n], src).await;
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(10)).await;

    // Pick inbound port explicitly
    let probe = match std::net::UdpSocket::bind("127.0.0.1:0") {
        Ok(s) => s,
        Err(e) => { if is_perm(&e) { eprintln!("skipping udp_multi due to sandbox PermissionDenied on port probe: {}", e); return; } else { panic!("probe bind: {}", e); } }
    };
    let inbound_port = probe.local_addr().unwrap().port();
    drop(probe);

    // Setup direct inbound forwarder
    let listen_addr: SocketAddr = format!("127.0.0.1:{}", inbound_port).parse().unwrap();
    let forward = sb_core::inbound::direct::DirectForward::new(
        listen_addr,
        echo_addr.ip().to_string(),
        echo_addr.port(),
        true,
    );

    let fwd_listen = listen_addr;

    std::thread::spawn(move || {
        let _ = forward.serve();
    });

    tokio::time::sleep(Duration::from_millis(250)).await;

    // Test multiple concurrent UDP clients
    let mut handles = vec![];

    for i in 0..5 {
        let fwd = fwd_listen;
        let handle = tokio::spawn(async move {
            let client = match UdpSocket::bind("127.0.0.1:0").await {
                Ok(s) => s,
                Err(e) => { if is_perm(&e) { return; } else { panic!("client bind: {}", e); } }
            };
            let test_data = format!("Client {} message", i);

            client.send_to(test_data.as_bytes(), fwd).await.unwrap();

            let mut response = vec![0u8; 1024];
            let (n, _) = tokio::time::timeout(
                Duration::from_secs(2),
                client.recv_from(&mut response),
            )
            .await
            .expect("UDP response timeout")
            .unwrap();

            assert_eq!(&response[..n], test_data.as_bytes());
        });
        handles.push(handle);
    }

    // Wait for all clients
    for handle in handles {
        handle.await.unwrap();
    }
}

#[tokio::test]
async fn direct_inbound_tcp_and_udp_concurrent() {
    // Setup TCP echo server
    let tcp_echo = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => { if is_perm(&e) { eprintln!("skipping tcp_udp_concurrent due to sandbox PermissionDenied on tcp bind: {}", e); return; } else { panic!("bind: {}", e); } }
    };
    let tcp_addr = tcp_echo.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = tcp_echo.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 1024];
                    while let Ok(n) = stream.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        let _ = stream.write_all(&buf[..n]).await;
                    }
                });
            }
        }
    });

    // Setup UDP echo server on same port as TCP (different protocol)
    let udp_echo = match UdpSocket::bind(tcp_addr).await {
        Ok(s) => s,
        Err(e) => { if is_perm(&e) { eprintln!("skipping tcp_udp_concurrent due to sandbox PermissionDenied on udp bind: {}", e); return; } else { panic!("bind: {}", e); } }
    };
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            if let Ok((n, src)) = udp_echo.recv_from(&mut buf).await {
                let _ = udp_echo.send_to(&buf[..n], src).await;
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(20)).await;

    // Pick inbound port explicitly
    let probe = match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => { if is_perm(&e) { eprintln!("skipping tcp_udp_concurrent due to sandbox PermissionDenied on port probe: {}", e); return; } else { panic!("probe bind: {}", e); } }
    };
    let inbound_port = probe.local_addr().unwrap().port();
    drop(probe);

    // Setup direct inbound with both TCP and UDP
    let listen_addr: SocketAddr = format!("127.0.0.1:{}", inbound_port).parse().unwrap();
    let forward = sb_core::inbound::direct::DirectForward::new(
        listen_addr,
        tcp_addr.ip().to_string(),
        tcp_addr.port(),
        true, // Both TCP and UDP
    );

    let fwd_listen = listen_addr;

    std::thread::spawn(move || {
        let _ = forward.serve();
    });

    tokio::time::sleep(Duration::from_millis(250)).await;

    // Test TCP and UDP concurrently
    let tcp_handle = tokio::spawn({
        let addr = fwd_listen;
        async move {
            let mut client = match TcpStream::connect(addr).await { Ok(s) => s, Err(e) => { if is_perm(&e) { return; } else { panic!("connect: {}", e); } } };
            let test_data = b"TCP test";
            client.write_all(test_data).await.unwrap();
            let mut response = vec![0u8; test_data.len()];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(response, test_data);
        }
    });

    let udp_handle = tokio::spawn({
        let addr = fwd_listen;
        async move {
            let client = match UdpSocket::bind("127.0.0.1:0").await { Ok(s) => s, Err(e) => { if is_perm(&e) { return; } else { panic!("client bind: {}", e); } } };
            let test_data = b"UDP test";
            client.send_to(test_data, addr).await.unwrap();
            let mut response = vec![0u8; 1024];
            let (n, _) = tokio::time::timeout(
                Duration::from_secs(2),
                client.recv_from(&mut response),
            )
            .await
            .expect("UDP response timeout")
            .unwrap();
            assert_eq!(&response[..n], test_data);
        }
    });

    tcp_handle.await.unwrap();
    udp_handle.await.unwrap();
}
