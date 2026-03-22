use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn conntrack_wiring_tcp_counts_and_cancel_work() {
    let tracker = sb_common::conntrack::shared_tracker();
    let _ = tracker.close_all();

    let (mut client, mut proxy_a) = tokio::io::duplex(4096);
    let (mut proxy_b, mut upstream) = tokio::io::duplex(4096);

    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
    let wiring = sb_core::conntrack::register_inbound_tcp_with_tracker(
        tracker.clone(),
        source,
        "example.com".to_string(),
        443,
        "example.com".to_string(),
        "test",
        Some("test-in".to_string()),
        Some("direct".to_string()),
        vec!["DIRECT".to_string()],
        Some("final".to_string()),
        None,
        None,
        None,
    );
    let id = wiring.guard.id();

    let task = tokio::spawn(async move {
        let _guard = wiring.guard;
        sb_core::net::metered::copy_bidirectional_streaming_ctl(
            &mut proxy_a,
            &mut proxy_b,
            "test",
            Duration::from_millis(50),
            None,
            None,
            Some(wiring.cancel),
            Some(wiring.traffic),
        )
        .await
    });

    // client -> upstream (upload)
    client.write_all(b"hello").await.unwrap();
    let mut buf = [0u8; 5];
    upstream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello");

    // upstream -> client (download)
    upstream.write_all(b"world").await.unwrap();
    let mut buf2 = [0u8; 5];
    client.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, b"world");

    // Allow counters to flush.
    tokio::time::sleep(Duration::from_millis(20)).await;

    let meta = tracker.get(id).expect("meta exists");
    assert!(meta.get_upload() >= 5);
    assert!(meta.get_download() >= 5);

    // Cancel via API.
    assert!(tracker.close(id));

    let res = task.await.unwrap();
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().kind(), std::io::ErrorKind::Interrupted);
    assert!(tracker.get(id).is_none());
}
