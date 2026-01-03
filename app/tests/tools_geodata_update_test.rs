#![cfg(feature = "tools")]

use sha2::{Digest, Sha256};
use tempfile::{tempdir, NamedTempFile};

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

fn write_fixture_file(data: &[u8]) -> NamedTempFile {
    let file = NamedTempFile::new().expect("fixture file");
    std::fs::write(file.path(), data).expect("write fixture");
    file
}

#[test]
fn tools_geodata_update_handles_file_urls() {
    let tmp = tempdir().expect("temp dir");

    let geoip_body = b"geoip-fixture-data".to_vec();
    let geosite_body = b"geosite-fixture-data".to_vec();
    let geoip_sha = sha256_hex(&geoip_body);
    let geosite_sha = sha256_hex(&geosite_body);

    let geoip_file = write_fixture_file(&geoip_body);
    let geosite_file = write_fixture_file(&geosite_body);
    let geoip_url = format!("file://{}", geoip_file.path().display());
    let geosite_url = format!("file://{}", geosite_file.path().display());

    assert_cmd::cargo::cargo_bin_cmd!("tools")
        .args([
            "geodata-update",
            "--dest",
            tmp.path().to_str().unwrap(),
            "--geoip-url",
            &geoip_url,
            "--geosite-url",
            &geosite_url,
            "--geoip-sha256",
            &geoip_sha,
            "--geosite-sha256",
            &geosite_sha,
        ])
        .assert()
        .success();

    let geoip_path = tmp.path().join("geoip.db");
    let geosite_path = tmp.path().join("geosite.db");
    assert_eq!(std::fs::read(&geoip_path).expect("read geoip"), geoip_body);
    assert_eq!(
        std::fs::read(&geosite_path).expect("read geosite"),
        geosite_body
    );
}
