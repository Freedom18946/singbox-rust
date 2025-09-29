use crate::model::ListenAddr;
use serde::{de::Error as DeError, Deserialize, Deserializer, Serializer};

/// Serde helpers for (de)serializing ListenAddr from either string "ip:port"
/// or object form {"addr"/"address"/"host": "...", "port": N}.
pub mod listen_addr {
    use super::*;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<ListenAddr, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Str(String),
            Obj(Obj),
        }

        #[derive(Deserialize)]
        struct Obj {
            #[serde(alias = "addr", alias = "address", alias = "host")]
            address: Option<String>,
            port: Option<u16>,
        }

        match Raw::deserialize(deserializer)? {
            Raw::Str(s) => parse_from_string(&s).map_err(D::Error::custom),
            Raw::Obj(Obj { address, port }) => {
                let addr = address.unwrap_or_else(|| "127.0.0.1".to_string());
                let port = port.ok_or_else(|| D::Error::custom("missing 'port' field"))?;
                Ok(ListenAddr { addr, port })
            }
        }
    }

    pub fn serialize<S>(value: &ListenAddr, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{}:{}", value.addr, value.port))
    }

    fn parse_from_string(s: &str) -> Result<ListenAddr, String> {
        // Support "[::1]:1080" and "127.0.0.1:1080"
        if s.starts_with('[') {
            // IPv6 bracketed
            let close = s
                .find(']')
                .ok_or_else(|| "invalid listen addr: missing ']'".to_string())?;
            let host = &s[1..close];
            let rest = &s[close + 1..];
            let port = rest
                .strip_prefix(':')
                .ok_or_else(|| "invalid listen addr: missing ':port'".to_string())?;
            let port: u16 = port.parse().map_err(|_| "invalid port".to_string())?;
            return Ok(ListenAddr {
                addr: host.to_string(),
                port,
            });
        }
        // IPv4 or hostname with last ':' as separator
        let (host, port_str) = s
            .rsplit_once(':')
            .ok_or_else(|| "invalid listen addr, expect 'host:port'".to_string())?;
        let port: u16 = port_str.parse().map_err(|_| "invalid port".to_string())?;
        Ok(ListenAddr {
            addr: host.to_string(),
            port,
        })
    }
}
