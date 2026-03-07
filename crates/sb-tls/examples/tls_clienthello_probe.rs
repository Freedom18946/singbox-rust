use base64::Engine as _;
use rustls::pki_types::ServerName;
use sb_tls::utls::{UtlsConfig, UtlsFingerprint};
use serde::Serialize;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::Duration;

#[derive(Serialize)]
struct ProbeOutput {
    engine: &'static str,
    profile_requested: String,
    profile_effective: &'static str,
    client_hello_b64: String,
    record_len: usize,
}

fn effective_profile_name(fp: &UtlsFingerprint) -> &'static str {
    use UtlsFingerprint::{
        Custom, Firefox63, Firefox65, Firefox99, Firefox105, Safari, SafariIos15, SafariIos16,
    };

    match fp {
        Firefox63 | Firefox65 | Firefox99 | Firefox105 => "firefox_105_template",
        Safari | SafariIos15 | SafariIos16 => "safari_ios16_template",
        Custom(_) => "custom_template",
        _ => "chrome_110_template",
    }
}

fn capture_client_hello(
    profile: UtlsFingerprint,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;

    let (tx, rx) = mpsc::channel::<Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>>();
    std::thread::spawn(move || {
        let result = (|| -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
            let (mut conn, _) = listener.accept()?;
            conn.set_read_timeout(Some(Duration::from_secs(3)))?;

            let mut header = [0u8; 5];
            conn.read_exact(&mut header)?;
            let body_len = u16::from_be_bytes([header[3], header[4]]) as usize;
            let mut body = vec![0u8; body_len];
            conn.read_exact(&mut body)?;

            let mut record = Vec::with_capacity(5 + body_len);
            record.extend_from_slice(&header);
            record.extend_from_slice(&body);
            Ok(record)
        })();
        let _ = tx.send(result);
    });

    let config = UtlsConfig::new("example.com")
        .with_fingerprint(profile)
        .with_insecure(true)
        .build_client_config();

    let mut stream = TcpStream::connect(addr)?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;

    let server_name = ServerName::try_from("example.com")
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?
        .to_owned();
    let mut conn = rustls::ClientConnection::new(config, server_name)?;
    conn.write_tls(&mut stream)?;
    stream.flush()?;

    rx.recv_timeout(Duration::from_secs(4))
        .unwrap_or_else(|_| Err("capture timeout".into()))
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let profile_requested = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "chrome".to_string());
    let profile: UtlsFingerprint = profile_requested.parse().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid profile '{profile_requested}': {e}"),
        )
    })?;

    let bytes = capture_client_hello(profile.clone())?;
    let output = ProbeOutput {
        engine: "rust",
        profile_requested,
        profile_effective: effective_profile_name(&profile),
        client_hello_b64: base64::engine::general_purpose::STANDARD.encode(bytes.as_slice()),
        record_len: bytes.len(),
    };

    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}
