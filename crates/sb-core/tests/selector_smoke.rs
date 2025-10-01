use sb_core::adapter::OutboundConnector;
use sb_core::outbound::selector::{Member, Selector};
use std::io;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug)]
struct StubConn;
impl OutboundConnector for StubConn {
    fn connect(&self, _host: &str, _port: u16) -> io::Result<TcpStream> {
        // deterministic short sleep then return refused
        std::thread::sleep(Duration::from_millis(5));
        Err(io::Error::new(io::ErrorKind::ConnectionRefused, "stub"))
    }
}

#[test]
fn empty_pool_is_err_not_panic() {
    let sel = Selector::new("sel0".into(), vec![]);
    let res = sel.connect("127.0.0.1", 80);
    assert!(res.is_err());
    assert_eq!(res.err().unwrap().kind(), io::ErrorKind::NotFound);
}

#[test]
fn single_member_path_stable() {
    let sel = Selector::new(
        "sel1".into(),
        vec![Member {
            name: "only".into(),
            conn: Arc::new(StubConn),
        }],
    );
    // Should attempt and return error (no panic)
    let _ = sel.connect("127.0.0.1", 9);
}

#[test]
fn metrics_export_contains_outbound_label() {
    let sel = Selector::new(
        "sel2".into(),
        vec![Member {
            name: "a".into(),
            conn: Arc::new(StubConn),
        }],
    );
    let _ = sel.connect("127.0.0.1", 9);
    let text = sb_metrics::export_prometheus();
    // label set must include outbound
    assert!(text.contains("proxy_select_score{outbound=\"sel2\"}"));
}
