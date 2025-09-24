#![cfg(feature = "handshake_alpha")]
use sb_runtime::jsonl::*;
use sb_runtime::loopback::{Frame, FrameDir};
use std::fs;
use tempfile::tempdir;
#[test]
fn verify_monotonic() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("a.jsonl");
    // 写两行 tx/rx 帧
    let f1 = serde_json::to_string(&Frame {
        ts_ms: 1,
        dir: FrameDir::Tx,
        len: 10,
        head8_hex: "aa".into(),
        tail8_hex: "aa".into(),
    })
    .unwrap();
    let f2 = serde_json::to_string(&Frame {
        ts_ms: 2,
        dir: FrameDir::Rx,
        len: 8,
        head8_hex: "bb".into(),
        tail8_hex: "bb".into(),
    })
    .unwrap();
    fs::write(&p, format!("{f1}\n{f2}\n")).unwrap();
    let v = basic_verify(&p).unwrap();
    assert_eq!(v.get("frames").unwrap().as_u64().unwrap(), 2);
    assert_eq!(v.get("ts_disorder").unwrap().as_u64().unwrap(), 0);
}
#[test]
fn verify_disorder() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("b.jsonl");
    let f1 = serde_json::to_string(&Frame {
        ts_ms: 2,
        dir: FrameDir::Tx,
        len: 10,
        head8_hex: "aa".into(),
        tail8_hex: "aa".into(),
    })
    .unwrap();
    let f2 = serde_json::to_string(&Frame {
        ts_ms: 1,
        dir: FrameDir::Rx,
        len: 8,
        head8_hex: "bb".into(),
        tail8_hex: "bb".into(),
    })
    .unwrap();
    fs::write(&p, format!("{f1}\n{f2}\n")).unwrap();
    let v = basic_verify(&p).unwrap();
    assert_eq!(v.get("ts_disorder").unwrap().as_u64().unwrap(), 1);
}
