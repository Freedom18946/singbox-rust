#![cfg(feature = "handshake_alpha")]
use sb_runtime::scenario::*;
use std::fs;
use tempfile::tempdir;
#[test]
fn scenario_smoke() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("sc.json");
    let log_path = dir.path().join("s1.jsonl");
    let verify_path = dir.path().join("s1.verify.json");

    let sc = format!(
        r#"{{
      "name":"t",
      "steps":[
        {{"action":"loopback","proto":"trojan","host":"example.com","port":443,"seed":1,"out":"{}"}},
        {{"action":"verify_jsonl","from":"{}","out":"{}"}},
        {{"action":"assert_metrics","from":"{}","expect":{{"min_frames":2,"min_tx":8,"min_rx":8,"max_disorder":0}}}}
      ]
    }}"#,
        log_path.display(),
        log_path.display(),
        verify_path.display(),
        log_path.display()
    );

    fs::write(&p, sc).unwrap();
    let sum = run_file(&p).unwrap();
    assert_eq!(sum.total, 3);
    assert_eq!(sum.failed, 0);
}
