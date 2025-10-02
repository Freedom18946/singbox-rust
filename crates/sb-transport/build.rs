fn main() {
    // Only compile proto files when grpc feature is enabled
    #[cfg(feature = "transport_grpc")]
    {
        tonic_build::compile_protos("proto/tunnel.proto")
            .unwrap_or_else(|e| panic!("Failed to compile proto files: {}", e));
    }
}
