use anyhow::Result;
use std::fs;
use std::path::Path;

/// Simple atomic file write implementation for CLI tools
pub fn write_atomic<P: AsRef<Path>>(path: P, contents: &[u8]) -> Result<()> {
    let path = path.as_ref();
    let temp_path = path.with_extension("tmp");

    // Write to temporary file first
    fs::write(&temp_path, contents)?;

    // Atomically rename to final destination
    fs::rename(temp_path, path)?;

    Ok(())
}
