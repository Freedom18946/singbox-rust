//! Golden output tests for handshake determinism and length stability.
//! Tests specific seeds against protocols to ensure consistent behavior.

#![cfg(feature = "handshake_alpha")]

use sb_runtime::prelude::*;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

/// Test seeds for golden outputs
const GOLDEN_SEEDS: &[u64] = &[1, 42, 100];

/// Convert bytes to hex string for debugging
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Generate golden output for a protocol and seed
fn generate_golden(proto_name: &str, seed: u64) -> Value {
    let bytes = match proto_name {
        "TROJAN" => {
            let trojan = trojan::Trojan::new("example.com".to_string(), 443);
            trojan.encode_init(seed)
        }
        "VMESS" => {
            let vmess = vmess::Vmess::new("example.com".to_string(), 443);
            vmess.encode_init(seed)
        }
        _ => panic!("Unknown protocol: {}", proto_name),
    };

    let len = bytes.len();
    let head16 = hex_encode(&bytes[..len.min(16)]);
    let tail16 = if len <= 16 {
        head16.clone()
    } else {
        hex_encode(&bytes[len - 16..])
    };

    serde_json::json!({
        "len": len,
        "head16": head16,
        "tail16": tail16
    })
}

/// Ensure target/golden directory exists
fn ensure_golden_dir() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); // Go up to workspace root
    path.pop();
    path.push("target");
    path.push("golden");

    fs::create_dir_all(&path).expect("Failed to create target/golden directory");
    path
}

/// Test that generates golden outputs and validates length stability
#[test]
fn test_golden_outputs() {
    let golden_dir = ensure_golden_dir();

    for &seed in GOLDEN_SEEDS {
        for proto in &["TROJAN", "VMESS"] {
            // Generate golden output
            let golden = generate_golden(proto, seed);

            // Write to target/golden/PROTO.SEED.json
            let filename = format!("{}.{}.json", proto, seed);
            let filepath = golden_dir.join(&filename);

            let json_str =
                serde_json::to_string_pretty(&golden).expect("Failed to serialize golden output");

            fs::write(&filepath, json_str).expect("Failed to write golden output file");

            // Validate that output is deterministic
            let golden2 = generate_golden(proto, seed);
            assert_eq!(
                golden, golden2,
                "Golden output must be deterministic for {}:{}",
                proto, seed
            );

            // Basic length validation (non-zero and reasonable upper bound)
            let len = golden["len"]
                .as_u64()
                .expect("Golden output missing len field");
            assert!(
                len > 0,
                "Golden output length must be positive for {}:{}",
                proto,
                seed
            );
            assert!(
                len < 10000,
                "Golden output length too large for {}:{}",
                proto,
                seed
            );

            println!(
                "Generated golden: {} -> len={} head16={} tail16={}",
                filename,
                len,
                golden["head16"].as_str().unwrap_or(""),
                golden["tail16"].as_str().unwrap_or("")
            );
        }
    }

    // Also write the seed=42 pair specifically (docs reference)
    for proto in &["TROJAN", "VMESS"] {
        let g = generate_golden(proto, 42);
        let p = golden_dir.join(format!("{}.{}.json", proto, 42));
        fs::write(&p, serde_json::to_string_pretty(&g).unwrap()).unwrap();
    }
}

/// Property test: Verify that different seeds produce different outputs
#[test]
fn test_property_different_seeds() {
    let trojan = trojan::Trojan::new("test.example.org".to_string(), 8080);

    let seeds = [1, 2, 42, 100, 999];
    let mut outputs = Vec::new();

    for &seed in &seeds {
        let bytes = trojan.encode_init(seed);
        outputs.push(bytes);
    }

    // Verify all outputs are different
    for i in 0..outputs.len() {
        for j in (i + 1)..outputs.len() {
            assert_ne!(
                outputs[i], outputs[j],
                "Different seeds {} and {} must produce different outputs",
                seeds[i], seeds[j]
            );
        }
    }
}

/// Property test: Verify encode→decode roundtrip consistency
#[test]
fn test_property_roundtrip() {
    let trojan = trojan::Trojan::new("roundtrip.test".to_string(), 9090);
    let vmess = vmess::Vmess::new("roundtrip.test".to_string(), 9090);

    let test_seeds = [0, 1, 42, 100, 256, 65535];

    for &seed in &test_seeds {
        // Test Trojan roundtrip
        let trojan_bytes = trojan.encode_init(seed);
        let trojan_slice = &trojan_bytes[..trojan_bytes.len().min(32)];
        trojan
            .decode_ack(trojan_slice)
            .expect("Trojan decode_ack failed");

        // Test Vmess roundtrip
        let vmess_bytes = vmess.encode_init(seed);
        let vmess_slice = &vmess_bytes[..vmess_bytes.len().min(32)];
        vmess
            .decode_ack(vmess_slice)
            .expect("Vmess decode_ack failed");
    }
}

/// Property test: Verify context (host/port) affects output
#[test]
fn test_property_context_affects_output() {
    let seed = 42;

    // Different contexts should produce different outputs
    let trojan1 = trojan::Trojan::new("host1.example.com".to_string(), 443);
    let trojan2 = trojan::Trojan::new("host2.example.com".to_string(), 443);
    let trojan3 = trojan::Trojan::new("host1.example.com".to_string(), 8080);

    let bytes1 = trojan1.encode_init(seed);
    let bytes2 = trojan2.encode_init(seed);
    let bytes3 = trojan3.encode_init(seed);

    assert_ne!(
        bytes1, bytes2,
        "Different hostnames must produce different outputs"
    );
    assert_ne!(
        bytes1, bytes3,
        "Different ports must produce different outputs"
    );
    assert_ne!(
        bytes2, bytes3,
        "Different hostname+port must produce different outputs"
    );
}

/// Property test: Verify minimum output length constraints
#[test]
fn test_property_min_length() {
    let seed = 123;

    let trojan = trojan::Trojan::new("min.length.test".to_string(), 443);
    let vmess = vmess::Vmess::new("min.length.test".to_string(), 443);

    let trojan_bytes = trojan.encode_init(seed);
    let vmess_bytes = vmess.encode_init(seed);

    // Ensure minimum reasonable length for handshake data
    assert!(
        trojan_bytes.len() >= 8,
        "Trojan output too short: {}",
        trojan_bytes.len()
    );
    assert!(
        vmess_bytes.len() >= 8,
        "Vmess output too short: {}",
        vmess_bytes.len()
    );

    // Ensure not just zeros (basic entropy check)
    assert!(
        trojan_bytes.iter().any(|&b| b != 0),
        "Trojan output is all zeros"
    );
    assert!(
        vmess_bytes.iter().any(|&b| b != 0),
        "Vmess output is all zeros"
    );
}
