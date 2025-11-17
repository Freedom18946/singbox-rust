#![allow(dead_code)]
//! Test fixture loading utilities

use std::fs;
use std::path::{Path, PathBuf};

/// Get the path to the fixtures directory relative to the tests directory.
///
/// # Example
///
/// ```no_run
/// let fixtures_dir = fixtures_dir();
/// let jwt_key = fixtures_dir.join("auth/jwks.json");
/// ```
pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

/// Load a fixture file as a string.
///
/// Path is relative to the fixtures directory.
///
/// # Example
///
/// ```no_run
/// let jwks = load_fixture("auth/jwks.json");
/// assert!(jwks.contains("keys"));
/// ```
///
/// # Panics
///
/// Panics if the file cannot be read or does not exist.
pub fn load_fixture(relative_path: impl AsRef<Path>) -> String {
    let path = fixtures_dir().join(relative_path.as_ref());
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to load fixture at {:?}: {}", path, e))
}

/// Load a fixture file as bytes.
///
/// Path is relative to the fixtures directory.
///
/// # Example
///
/// ```no_run
/// let yaml = load_fixture_bytes("geo/legacy/config.yaml");
/// assert!(!yaml.is_empty());
/// ```
///
/// # Panics
///
/// Panics if the file cannot be read or does not exist.
pub fn load_fixture_bytes(relative_path: impl AsRef<Path>) -> Vec<u8> {
    let path = fixtures_dir().join(relative_path.as_ref());
    fs::read(&path).unwrap_or_else(|e| panic!("Failed to load fixture at {:?}: {}", path, e))
}

/// Check if a fixture file exists.
///
/// Path is relative to the fixtures directory.
///
/// # Example
///
/// ```no_run
/// if fixture_exists("auth/jwks.json") {
///     let jwks = load_fixture("auth/jwks.json");
///     // Use jwks
/// }
/// ```
pub fn fixture_exists(relative_path: impl AsRef<Path>) -> bool {
    fixtures_dir().join(relative_path.as_ref()).exists()
}

/// Get the path to a specific fixture file.
///
/// Does not check if the file exists.
///
/// # Example
///
/// ```no_run
/// let geo_path = fixture_path("geo/legacy/config.yaml");
/// let content = std::fs::read_to_string(&geo_path).unwrap();
/// ```
pub fn fixture_path(relative_path: impl AsRef<Path>) -> PathBuf {
    fixtures_dir().join(relative_path.as_ref())
}
