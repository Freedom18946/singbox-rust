use crate::model::ListenAddr;
use serde::{de::Error as DeError, Deserialize, Deserializer, Serializer};

/// Helper to deserialize a single value or a list into a Vec.
pub fn deserialize_string_or_list<'de, T, D>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrList<T> {
        Single(T),
        List(Vec<T>),
    }

    match StringOrList::deserialize(deserializer)? {
        StringOrList::Single(s) => Ok(vec![s]),
        StringOrList::List(l) => Ok(l),
    }
}

/// Serde helpers for (de)serializing [`ListenAddr`] from either string `"ip:port"`
/// or object form `{"addr"/"address"/"host": "...", "port": N}`.
///
/// # Format Support
/// - **String**: `"127.0.0.1:8080"`, `"[::1]:8080"` (IPv6 bracketed)
/// - **Object**: `{"address": "127.0.0.1", "port": 8080}`
///
/// Aliases: `addr`, `address`, `host` are all accepted for the address field.
pub mod listen_addr {
    use super::*;

    /// Deserialize [`ListenAddr`] from string or object representation.
    ///
    /// # Errors
    /// Returns a deserialization error if:
    /// - String format is malformed (missing port, invalid brackets)
    /// - Object format is missing required `port` field
    /// - Port value is out of `u16` range
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
                let addr = address.unwrap_or_else(|| "127.0.0.1".to_owned());
                let port = port.ok_or_else(|| D::Error::custom("missing required field 'port'"))?;
                Ok(ListenAddr { addr, port })
            }
        }
    }

    /// Serialize [`ListenAddr`] into string format `"addr:port"`.
    ///
    /// # Errors
    /// Returns a serialization error if the serializer fails.
    pub fn serialize<S>(value: &ListenAddr, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let formatted = format!("{}:{}", value.addr, value.port);
        serializer.serialize_str(&formatted)
    }

    /// Parse `ListenAddr` from string format.
    ///
    /// Supports both IPv4/hostname (`"host:port"`) and IPv6 bracketed (`"[::1]:port"`).
    fn parse_from_string(s: &str) -> Result<ListenAddr, String> {
        // Support "[::1]:1080" and "127.0.0.1:1080"
        if let Some(stripped) = s.strip_prefix('[') {
            // IPv6 bracketed format
            return parse_ipv6_bracketed(stripped);
        }
        // IPv4 or hostname with last ':' as separator
        parse_host_port(s)
    }

    /// Parse IPv6 bracketed format `[addr]:port`.
    fn parse_ipv6_bracketed(s: &str) -> Result<ListenAddr, String> {
        let close = s
            .find(']')
            .ok_or_else(|| "invalid IPv6 listen address: missing closing bracket ']'".to_owned())?;
        let host = &s[..close];
        let rest = &s[close + 1..];
        let port_str = rest
            .strip_prefix(':')
            .ok_or_else(|| "invalid IPv6 listen address: missing ':port' after ']'".to_owned())?;
        let port: u16 = port_str
            .parse()
            .map_err(|_| format!("invalid port number: '{port_str}'"))?;
        Ok(ListenAddr {
            addr: host.to_owned(),
            port,
        })
    }

    /// Parse standard `host:port` format (IPv4 or hostname).
    fn parse_host_port(s: &str) -> Result<ListenAddr, String> {
        let (host, port_str) = s
            .rsplit_once(':')
            .ok_or_else(|| format!("invalid listen address '{s}': expected 'host:port' format"))?;
        let port: u16 = port_str
            .parse()
            .map_err(|_| format!("invalid port number: '{port_str}'"))?;
        Ok(ListenAddr {
            addr: host.to_owned(),
            port,
        })
    }
}
