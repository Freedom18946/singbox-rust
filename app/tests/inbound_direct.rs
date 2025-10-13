use sb_core::adapter::InboundService;
use std::net::{SocketAddr, TcpListener};
use std::thread;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_inbound_tcp_forwarding() {
    // 1) spawn backend echo server
    let backend = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                eprintln!(
                    "skipping inbound_direct due to sandbox PermissionDenied on backend bind: {}",
                    e
                );
                return;
            } else {
                panic!("bind failed: {}", e);
            }
        }
    };
    let backend_addr = backend.local_addr().unwrap();
    thread::spawn(move || loop {
        if let Ok((mut s, _)) = backend.accept() {
            std::thread::spawn(move || {
                let _ = std::io::copy(&mut s.try_clone().unwrap(), &mut s);
            });
        } else {
            break;
        }
    });

    // 2) pick inbound port
    let probe = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                eprintln!(
                    "skipping inbound_direct due to sandbox PermissionDenied on inbound bind: {}",
                    e
                );
                return;
            } else {
                panic!("bind failed: {}", e);
            }
        }
    };
    let inbound_port = probe.local_addr().unwrap().port();
    drop(probe);

    // 3) start DirectForward inbound
    let listen: SocketAddr = format!("127.0.0.1:{}", inbound_port).parse().unwrap();
    let dst_host = backend_addr.ip().to_string();
    let dst_port = backend_addr.port();
    thread::spawn(move || {
        let inbound =
            sb_core::inbound::direct::DirectForward::new(listen, dst_host, dst_port, false);
        let _ = inbound.serve();
    });

    // 4) wait a bit for server to be ready
    tokio::time::sleep(Duration::from_millis(150)).await;

    // 5) connect client to inbound and verify echo
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", inbound_port))
        .await
        .unwrap();
    let msg = b"hello-direct";
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream.write_all(msg).await.unwrap();
    let mut buf = vec![0u8; msg.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, msg);
}
