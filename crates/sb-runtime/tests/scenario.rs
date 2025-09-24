#![cfg(feature = "handshake_alpha")]
use sb_runtime::scenario::*;
use std::fs;
use tempfile::tempdir;
#[test]
fn scenario_smoke() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("sc.json");
    let sc = r#"{
      "name":"t",
      "steps":[
        {"action":"loopback","proto":"trojan","host":"example.com","port":443,"seed":1,"out":"target/s1.jsonl"},
        {"action":"verify_jsonl","from":"target/s1.jsonl","out":"target/s1.verify.json"},
        {"action":"assert_metrics","from":"target/s1.jsonl","expect":{"min_frames":2,"min_tx":8,"min_rx":8,"max_disorder":0}}
      ]
    }"#;
    fs::write(&p, sc).unwrap();
    let sum = run_file(&p).unwrap();
    assert_eq!(sum.total, 3);
    assert_eq!(sum.failed, 0);
}
