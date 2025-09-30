use crate::net::udp_nat::TargetAddr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Unified address representation for SOCKS-style protocols
#[derive(Clone, Debug)]
pub enum Addr {
    Domain(String),
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl Addr {
    pub fn from_target_addr(target: &TargetAddr) -> Self {
        match target {
            TargetAddr::Ip(sa) => match sa.ip() {
                IpAddr::V4(v4) => Addr::V4(v4),
                IpAddr::V6(v6) => Addr::V6(v6),
            },
            TargetAddr::Domain(domain, _) => {
                // Try to parse as IP first
                match domain.parse::<IpAddr>() {
                    Ok(IpAddr::V4(v4)) => Addr::V4(v4),
                    Ok(IpAddr::V6(v6)) => Addr::V6(v6),
                    _ => Addr::Domain(domain.clone()),
                }
            }
        }
    }
}

/// Encode address in Shadowsocks/SOCKS format: ATYP + ADDR + PORT
pub fn encode_ss_addr(addr: &Addr, port: u16, buf: &mut Vec<u8>) {
    match addr {
        Addr::V4(ip) => {
            buf.push(0x01); // ATYP: IPv4
            buf.extend_from_slice(&ip.octets());
        }
        Addr::V6(ip) => {
            buf.push(0x04); // ATYP: IPv6
            buf.extend_from_slice(&ip.octets());
        }
        Addr::Domain(domain) => {
            buf.push(0x03); // ATYP: Domain
            let domain_bytes = domain.as_bytes();
            buf.push(domain_bytes.len() as u8);
            buf.extend_from_slice(domain_bytes);
        }
    }
    buf.extend_from_slice(&port.to_be_bytes());
}

/// Extract port from TargetAddr
pub fn get_port_from_target(target: &TargetAddr) -> u16 {
    match target {
        TargetAddr::Ip(sa) => sa.port(),
        TargetAddr::Domain(_, port) => *port,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    #[test]
    fn test_encode_ipv4_addr() {
        let addr = Addr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let mut buf = Vec::new();
        encode_ss_addr(&addr, 8080, &mut buf);

        assert_eq!(buf.len(), 1 + 4 + 2); // ATYP + IPv4 + Port
        assert_eq!(buf[0], 0x01); // IPv4 ATYP
        assert_eq!(&buf[1..5], &[192, 168, 1, 1]);
        assert_eq!(&buf[5..7], &[0x1f, 0x90]); // 8080 in big-endian
    }

    #[test]
    fn test_encode_ipv6_addr() {
        let addr = Addr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let mut buf = Vec::new();
        encode_ss_addr(&addr, 443, &mut buf);

        assert_eq!(buf.len(), 1 + 16 + 2); // ATYP + IPv6 + Port
        assert_eq!(buf[0], 0x04); // IPv6 ATYP
        assert_eq!(&buf[17..19], &[0x01, 0xbb]); // 443 in big-endian
    }

    #[test]
    fn test_encode_domain_addr() {
        let addr = Addr::Domain("example.com".to_string());
        let mut buf = Vec::new();
        encode_ss_addr(&addr, 80, &mut buf);

        assert_eq!(buf.len(), 1 + 1 + 11 + 2); // ATYP + LEN + Domain + Port
        assert_eq!(buf[0], 0x03); // Domain ATYP
        assert_eq!(buf[1], 11); // Domain length
        assert_eq!(&buf[2..13], b"example.com");
        assert_eq!(&buf[13..15], &[0x00, 0x50]); // 80 in big-endian
    }

    #[test]
    fn test_from_target_addr_ip() {
        let target = TargetAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 22));
        let addr = Addr::from_target_addr(&target);

        match addr {
            Addr::V4(ip) => assert_eq!(ip, Ipv4Addr::new(10, 0, 0, 1)),
            _ => assert!(false, "Expected IPv4 address from target"),
        }
    }

    #[test]
    fn test_from_target_addr_domain() {
        let target = TargetAddr::Domain("github.com".to_string(), 443);
        let addr = Addr::from_target_addr(&target);

        match addr {
            Addr::Domain(domain) => assert_eq!(domain, "github.com"),
            _ => assert!(false, "Expected domain address from target"),
        }
    }

    #[test]
    fn test_from_target_addr_domain_with_ip() {
        let target = TargetAddr::Domain("127.0.0.1".to_string(), 8080);
        let addr = Addr::from_target_addr(&target);

        match addr {
            Addr::V4(ip) => assert_eq!(ip, Ipv4Addr::new(127, 0, 0, 1)),
            _ => assert!(false, "Expected IPv4 address parsed from domain string"),
        }
    }
}
