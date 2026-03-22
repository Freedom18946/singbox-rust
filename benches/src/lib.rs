//! Shared utilities for sing-box benchmarks

use bytes::Bytes;
use rand::Rng;

/// Generate random data of specified size
pub fn generate_random_data(size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; size];
    rand::thread_rng().fill(&mut buf[..]);
    buf
}

/// Generate random bytes
pub fn generate_random_bytes(size: usize) -> Bytes {
    Bytes::from(generate_random_data(size))
}

/// Setup tracing for benchmarks
pub fn setup_tracing() {
    use tracing_subscriber::EnvFilter;

    match tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .try_init()
    {
        Ok(()) => {}
        Err(err) => {
            if !err.to_string().contains("already been set") {
                eprintln!("benchmark tracing init skipped: {err}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random_data() {
        let data = generate_random_data(1024);
        assert_eq!(data.len(), 1024);
    }
}
