//! R89: 最小 Outbound Registry（feature=outbound_registry）
//! - 仅支持 trojan/ss2022 两类条目注册
//! - 构造时注入 Dialer（Tcp/Tls 由调用者决定）；仅用于测试/只读 admin
#[cfg(feature = "proto_ss2022_min")]
use crate::ss2022_min::Ss2022Hello;
use crate::trojan_min::TrojanHello;
use sb_transport::dialer::{Dialer, TcpDialer};
#[cfg(feature = "transport_tls")]
use sb_transport::tls::{webpki_roots_config, TlsDialer};
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub enum OutboundKind {
    Trojan,
    Ss2022,
}

#[derive(Debug, Clone)]
pub struct OutboundSpec {
    pub name: String,
    pub kind: OutboundKind,
    pub password: Option<String>,
    pub method: Option<String>, // ss2022
}

#[derive(Default)]
pub struct Registry {
    specs: BTreeMap<String, OutboundSpec>,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            specs: BTreeMap::new(),
        }
    }
    pub fn insert(&mut self, spec: OutboundSpec) {
        self.specs.insert(spec.name.clone(), spec);
    }
    pub fn names(&self) -> Vec<String> {
        self.specs.keys().cloned().collect()
    }
    pub fn get(&self, name: &str) -> Option<&OutboundSpec> {
        self.specs.get(name)
    }
}

/// 构造最小连接并写首包（仅 trojan），返回 Ok(()) 表示已写入
pub async fn trojan_dryrun_tcp(
    name: &str,
    reg: &Registry,
    host: &str,
    port: u16,
) -> Result<(), String> {
    let spec = reg.get(name).ok_or_else(|| "not found".to_string())?;
    match spec.kind {
        OutboundKind::Trojan => {
            let pass = spec.password.clone().unwrap_or_default();
            let mut s = TcpDialer
                .connect(host, port)
                .await
                .map_err(|e| format!("{:?}", e))?;
            let hello = TrojanHello {
                password: pass,
                host: host.into(),
                port,
            };
            let buf = hello.to_bytes();
            tokio::io::AsyncWriteExt::write_all(&mut s, &buf)
                .await
                .map_err(|e| format!("{:?}", e))?;
            tokio::io::AsyncWriteExt::flush(&mut s)
                .await
                .map_err(|e| format!("{:?}", e))?;
            Ok(())
        }
        _ => Err("kind not supported".into()),
    }
}

/// trojan + TLS（若编译开启），否则回退 TCP
pub async fn trojan_dryrun_tls_env(
    name: &str,
    reg: &Registry,
    host: &str,
    port: u16,
) -> Result<(), String> {
    let spec = reg.get(name).ok_or_else(|| "not found".to_string())?;
    match spec.kind {
        OutboundKind::Trojan => {
            let pass = spec.password.clone().unwrap_or_default();
            #[cfg(feature = "transport_tls")]
            {
                let d = TlsDialer::from_env(TcpDialer, webpki_roots_config());
                let mut s = d
                    .connect(host, port)
                    .await
                    .map_err(|e| format!("{:?}", e))?;
                let hello = TrojanHello {
                    password: pass,
                    host: host.into(),
                    port,
                };
                let buf = hello.to_bytes();
                tokio::io::AsyncWriteExt::write_all(&mut s, &buf)
                    .await
                    .map_err(|e| format!("{:?}", e))?;
                tokio::io::AsyncWriteExt::flush(&mut s)
                    .await
                    .map_err(|e| format!("{:?}", e))?;
                return Ok(());
            }
            #[cfg(not(feature = "transport_tls"))]
            {
                // 回退 TCP
                let mut s = TcpDialer
                    .connect(host, port)
                    .await
                    .map_err(|e| format!("{:?}", e))?;
                let hello = TrojanHello {
                    password: pass,
                    host: host.into(),
                    port,
                };
                let buf = hello.to_bytes();
                tokio::io::AsyncWriteExt::write_all(&mut s, &buf)
                    .await
                    .map_err(|e| format!("{:?}", e))?;
                tokio::io::AsyncWriteExt::flush(&mut s)
                    .await
                    .map_err(|e| format!("{:?}", e))?;
                Ok(())
            }
        }
        _ => Err("kind not supported".into()),
    }
}

pub fn ss2022_hello_bytes(
    name: &str,
    reg: &Registry,
    host: &str,
    port: u16,
) -> Result<Vec<u8>, String> {
    let spec = reg.get(name).ok_or_else(|| "not found".to_string())?;
    match spec.kind {
        OutboundKind::Ss2022 => {
            #[cfg(feature = "proto_ss2022_min")]
            let method = spec
                .method
                .clone()
                .unwrap_or_else(|| "2022-blake3-aes-256-gcm".into());
            let pass = spec.password.clone().unwrap_or_default();
            #[cfg(feature = "proto_ss2022_min")]
            {
                return Ok(Ss2022Hello {
                    method,
                    password: pass,
                    host: host.into(),
                    port,
                }
                .to_bytes());
            }
            #[cfg(not(feature = "proto_ss2022_min"))]
            {
                return Err("ss2022 disabled".into());
            }
        }
        _ => Err("kind not supported".into()),
    }
}
