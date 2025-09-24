//! Build script for compiling V2Ray API protobuf files

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Check if v2ray-api feature is enabled via environment variables
    let has_v2ray_feature = std::env::var("CARGO_FEATURE_V2RAY_API").is_ok();

    if has_v2ray_feature {
        let out_dir = std::env::var("OUT_DIR")?;

        // Compile each proto file separately to avoid namespace conflicts
        tonic_build::configure()
            .build_server(true)
            .build_client(false)
            .out_dir(&out_dir)
            .file_descriptor_set_path(format!("{}/v2ray_stats.bin", out_dir))
            .compile(&["proto/app/stats/command/command.proto"], &["proto"])?;

        tonic_build::configure()
            .build_server(true)
            .build_client(false)
            .out_dir(&out_dir)
            .file_descriptor_set_path(format!("{}/v2ray_proxyman.bin", out_dir))
            .compile(
                &[
                    "proto/app/proxyman/command/command.proto",
                    "proto/core/config.proto",
                ],
                &["proto"],
            )?;

        tonic_build::configure()
            .build_server(true)
            .build_client(false)
            .out_dir(&out_dir)
            .file_descriptor_set_path(format!("{}/v2ray_router.bin", out_dir))
            .compile(&["proto/app/router/command/command.proto"], &["proto"])?;

        tonic_build::configure()
            .build_server(true)
            .build_client(false)
            .out_dir(&out_dir)
            .file_descriptor_set_path(format!("{}/v2ray_log.bin", out_dir))
            .compile(&["proto/app/log/command/command.proto"], &["proto"])?;

        println!("cargo:rerun-if-changed=proto/");
    }

    Ok(())
}
