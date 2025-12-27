use anyhow::{anyhow, Context, Result};
use std::sync::Arc;
use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;

pub(crate) struct TlsMaterial<'a> {
    pub cert_pem: Option<&'a str>,
    pub cert_path: Option<&'a str>,
    pub key_pem: Option<&'a str>,
    pub key_path: Option<&'a str>,
}

impl<'a> TlsMaterial<'a> {
    pub(crate) fn from_paths(cert_path: &'a str, key_path: &'a str) -> Self {
        Self {
            cert_pem: None,
            cert_path: Some(cert_path),
            key_pem: None,
            key_path: Some(key_path),
        }
    }
}

pub(crate) fn build_tls_acceptor(
    material: TlsMaterial<'_>,
    alpn: Option<&[String]>,
) -> Result<Arc<TlsAcceptor>> {
    let (certs, key) = load_cert_and_key(material)?;
    let builder = rustls::ServerConfig::builder().with_no_client_auth();
    let mut config = builder
        .with_single_cert(certs, key)
        .map_err(|e| anyhow!("tls config error: {}", e))?;
    if let Some(alpn) = alpn {
        config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    }
    Ok(Arc::new(TlsAcceptor::from(Arc::new(config))))
}

fn load_cert_and_key(
    material: TlsMaterial<'_>,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_pem = read_pem_bytes(material.cert_pem, material.cert_path, "certificate")?;
    let key_pem = read_pem_bytes(material.key_pem, material.key_path, "private key")?;

    let mut cert_reader = std::io::Cursor::new(cert_pem);
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed to parse certificate PEM")?;
    if certs.is_empty() {
        return Err(anyhow!("no certificates found in PEM data"));
    }

    let mut key_reader = std::io::Cursor::new(key_pem);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .context("failed to parse private key")?
        .ok_or_else(|| anyhow!("no private key found in PEM data"))?;

    Ok((certs, key))
}

fn read_pem_bytes(pem: Option<&str>, path: Option<&str>, label: &str) -> Result<Vec<u8>> {
    if let Some(pem) = pem {
        return Ok(pem.as_bytes().to_vec());
    }
    if let Some(path) = path {
        return std::fs::read(path)
            .with_context(|| format!("failed to read {} from {}", label, path));
    }
    Err(anyhow!(
        "missing {} material; provide PEM data or file path",
        label
    ))
}
