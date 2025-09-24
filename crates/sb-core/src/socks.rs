use crate::error::Error;
use std::io;

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Rep {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    ConnectionNotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    AddrTypeNotSupported = 0x08,
}

pub fn map_error_to_rep(e: &Error) -> Rep {
    match e {
        Error::Unauthorized | Error::Forbidden => Rep::ConnectionNotAllowed,
        Error::Timeout(_) => Rep::HostUnreachable,
        Error::Unreachable => Rep::NetworkUnreachable,
        Error::Refused => Rep::ConnectionRefused,
        Error::Protocol(_) | Error::Canceled | Error::Internal(_) => Rep::GeneralFailure,
        Error::Io(err) => match err.kind() {
            io::ErrorKind::TimedOut => Rep::HostUnreachable,
            io::ErrorKind::ConnectionRefused => Rep::ConnectionRefused,
            io::ErrorKind::AddrInUse | io::ErrorKind::AddrNotAvailable => Rep::HostUnreachable,
            io::ErrorKind::NotConnected
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset => Rep::HostUnreachable,
            _ => Rep::GeneralFailure,
        },
    }
}
