#[cfg(feature = "proto_trojan_min")]
#[tokio::test]
async fn trojan_connector_writes_hello() {
    use sb_proto::trojan_connector::TrojanConnector;
    use sb_proto::connector::{OutboundConnector, Target};
    use sb_transport::mem::DuplexDialer;
    use tokio::io::AsyncReadExt;

    // 内存双工拨号器：返回一对流，我们持有对端以读取客户端写入的首包
    let (dialer, mut server_side) = DuplexDialer::new_pair();
    let c = TrojanConnector::new(dialer, "pass");
    
    // Create target with proper structure
    let target = Target {
        host: "example.com".to_string(),
        port: 443,
    };
    
    let mut cli = c.connect(&target).await.expect("connect");

    // 读取服务端视角收到的首包
    let mut buf = vec![0u8; 128];
    let n = server_side.read(&mut buf).await.unwrap();
    let s = String::from_utf8_lossy(&buf[..n]).to_string();
    assert!(s.starts_with("pass\r\nCONNECT example.com:443\r\n\r\n"));

    // 留给后续：cli 继续读写透传
    let _ = cli;
}
