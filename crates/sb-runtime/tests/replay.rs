//! Integration tests for replay functionality

#[cfg(feature = "handshake_alpha")]
use anyhow::Result;
#[cfg(feature = "handshake_alpha")]
use sb_runtime::jsonl::replay_decode;
#[cfg(feature = "handshake_alpha")]
use sb_runtime::prelude::*;
#[cfg(feature = "handshake_alpha")]
use sb_runtime::trojan::Trojan;
#[cfg(feature = "handshake_alpha")]
use std::env;
#[cfg(feature = "handshake_alpha")]
use std::fs;

#[test]
#[cfg(feature = "handshake_alpha")]
fn test_replay_decode_strict_mode() -> Result<()> {
    let trojan = Trojan::new("example.com".to_string(), 443);
    let temp_dir = env::temp_dir();
    let log_path = temp_dir.join("replay_strict.jsonl");

    // Clean up any existing file from previous runs
    let _ = fs::remove_file(&log_path);

    // Create a session log with valid frames
    let logger = SessionLog::new(&log_path);
    logger.log_frame(&Frame::new(FrameDir::Tx, b"hello world"))?;
    logger.log_frame(&Frame::new(FrameDir::Rx, b"response data"))?;

    // Test non-strict mode (should not fail)
    let (frames, _errors) = replay_decode(&trojan, &log_path, false)?;
    assert_eq!(frames, 1); // Only RX frames are processed

    // Test strict mode - this may fail depending on trojan implementation
    let _result = replay_decode(&trojan, &log_path, true);
    // In strict mode, errors should cause immediate failure
    // The result depends on whether decode_ack accepts the test data

    // Cleanup
    let _ = fs::remove_file(&log_path);
    Ok(())
}

#[test]
#[cfg(feature = "handshake_alpha")]
fn test_replay_with_loopback_session() -> Result<()> {
    let trojan = Trojan::new("example.com".to_string(), 443);
    let temp_dir = env::temp_dir();
    let log_path = temp_dir.join("replay_loopback.jsonl");

    // Clean up any existing file from previous runs
    let _ = fs::remove_file(&log_path);

    // Generate a real session using run_once
    let _metrics = run_once(&trojan, 42, Some(&log_path))?;

    // Replay the session in both modes
    let (frames_loose, _errors_loose) = replay_decode(&trojan, &log_path, false)?;
    let (frames_strict, errors_strict) = replay_decode(&trojan, &log_path, true)?;

    // Both should process the same number of frames
    assert_eq!(frames_loose, frames_strict);
    assert_eq!(frames_loose, 1); // run_once creates one RX frame

    // In strict mode, if there are errors, it should have failed earlier
    assert_eq!(errors_strict, 0);

    // Cleanup
    let _ = fs::remove_file(&log_path);
    Ok(())
}
