//! Build script for compiling V2Ray API protobuf files
//!
//! This script conditionally compiles gRPC service definitions from protobuf files
//! when the `v2ray-api` feature is enabled. Each proto module is compiled separately
//! to avoid namespace conflicts and maintain clean separation of concerns.

use std::path::Path;

/// Proto compilation configuration: (descriptor name, proto files)
const PROTO_CONFIGS: &[(&str, &[&str])] = &[
    // V2Ray statistics API for traffic and connection metrics
    ("v2ray_stats", &["proto/app/stats/command/command.proto"]),
    // Proxy manager API for inbound/outbound management
    (
        "v2ray_proxyman",
        &[
            "proto/app/proxyman/command/command.proto",
            "proto/core/config.proto",
        ],
    ),
    // Router API for routing rule management
    ("v2ray_router", &["proto/app/router/command/command.proto"]),
    // Logging API for log level control
    ("v2ray_log", &["proto/app/log/command/command.proto"]),
];

const PROTO_INCLUDE_DIR: &str = "proto";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Check if v2ray-api feature is enabled via environment variables
    let has_v2ray_feature = std::env::var("CARGO_FEATURE_V2RAY_API").is_ok();

    if has_v2ray_feature {
        let out_dir = std::env::var("OUT_DIR")?;
        compile_protos(&out_dir)?;
        println!("cargo:rerun-if-changed={PROTO_INCLUDE_DIR}/");
    }

    Ok(())
}

/// Compiles all V2Ray proto definitions to the specified output directory.
///
/// Each proto module is compiled separately with its own file descriptor set
/// to prevent namespace conflicts between different V2Ray API services.
fn compile_protos(out_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    for &(descriptor_name, proto_files) in PROTO_CONFIGS {
        compile_proto_module(out_dir, descriptor_name, proto_files)?;
    }
    Ok(())
}

/// Compiles a single proto module with the given configuration.
fn compile_proto_module(
    out_dir: &str,
    descriptor_name: &str,
    proto_files: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    let descriptor_path = Path::new(out_dir).join(format!("{descriptor_name}.bin"));

    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .out_dir(out_dir)
        .file_descriptor_set_path(descriptor_path)
        .compile(proto_files, &[PROTO_INCLUDE_DIR])?;

    Ok(())
}
