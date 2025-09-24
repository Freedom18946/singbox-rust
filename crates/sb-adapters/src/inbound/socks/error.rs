use std::io;

#[allow(dead_code)]
#[derive(thiserror::Error, Debug)]
pub enum SocksError {
    #[error("general failure")]
    GeneralFailure,
    #[error("connection not allowed")]
    ConnectionNotAllowed,
    #[error("network unreachable")]
    NetworkUnreachable,
    #[error("host unreachable")]
    HostUnreachable,
    #[error("connection refused")]
    ConnectionRefused,
    #[error("TTL expired")]
    TtlExpired,
    #[error("command not supported")]
    CommandNotSupported,
    #[error("address type not supported")]
    AddrTypeNotSupported,
}

impl SocksError {
    pub fn reply_code(&self) -> u8 {
        match self {
            SocksError::GeneralFailure => 0x01,
            SocksError::ConnectionNotAllowed => 0x02,
            SocksError::NetworkUnreachable => 0x03,
            SocksError::HostUnreachable => 0x04,
            SocksError::ConnectionRefused => 0x05,
            SocksError::TtlExpired => 0x06,
            SocksError::CommandNotSupported => 0x07,
            SocksError::AddrTypeNotSupported => 0x08,
        }
    }
}

pub fn map_connect_error(e: &io::Error) -> SocksError {
    use io::ErrorKind::*;
    match e.kind() {
        ConnectionRefused => SocksError::ConnectionRefused,
        NotFound | HostUnreachable => SocksError::HostUnreachable,
        NetworkUnreachable => SocksError::NetworkUnreachable,
        TimedOut => SocksError::TtlExpired,
        _ => SocksError::GeneralFailure,
    }
}