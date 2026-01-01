fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Only compile if service_v2ray_api feature is enabled
    // Note: Cargo features are env vars like CARGO_FEATURE_SERVICE_V2RAY_API
    // Only compile if service_v2ray_api feature is enabled
    // Note: We use cfg check for compile-time dependency check, and existing env check for runtime consistency
    #[cfg(feature = "service_v2ray_api")]
    if std::env::var("CARGO_FEATURE_SERVICE_V2RAY_API").is_ok() {
        tonic_build::configure()
            .build_server(true)
            .build_client(false)  // We only implement the server
            .compile(
                &["proto/v2ray/stats/command.proto"],
                &["proto"], // Include path
            )?;
            
        println!("cargo:rerun-if-changed=proto/v2ray/stats/command.proto");
    }
    Ok(())
}
