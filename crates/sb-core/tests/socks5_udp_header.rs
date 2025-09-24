#[test]
fn header_build_v4() {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 53));
    let mut v = Vec::new();
    // 复用 inbound 的构造函数（若为私有，可复制到测试）
    {
        fn build(buf: &mut Vec<u8>, dst: SocketAddr) {
            buf.push(0);
            buf.push(0);
            buf.push(0);
            match dst {
                SocketAddr::V4(sa) => {
                    buf.push(0x01);
                    buf.extend_from_slice(&sa.ip().octets());
                    buf.extend_from_slice(&sa.port().to_be_bytes());
                }
                SocketAddr::V6(sa) => {
                    buf.push(0x04);
                    buf.extend_from_slice(&sa.ip().octets());
                    buf.extend_from_slice(&sa.port().to_be_bytes());
                }
            }
        }
        build(&mut v, dst);
    }
    assert_eq!(v.len(), 3 + 1 + 4 + 2);
    assert_eq!(v[3], 0x01);
}

#[test]
fn header_build_v6() {
    use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
    let dst = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        53,
        0,
        0,
    ));
    let mut v = Vec::new();
    {
        fn build(buf: &mut Vec<u8>, dst: SocketAddr) {
            buf.push(0);
            buf.push(0);
            buf.push(0);
            match dst {
                SocketAddr::V4(sa) => {
                    buf.push(0x01);
                    buf.extend_from_slice(&sa.ip().octets());
                    buf.extend_from_slice(&sa.port().to_be_bytes());
                }
                SocketAddr::V6(sa) => {
                    buf.push(0x04);
                    buf.extend_from_slice(&sa.ip().octets());
                    buf.extend_from_slice(&sa.port().to_be_bytes());
                }
            }
        }
        build(&mut v, dst);
    }
    assert_eq!(v.len(), 3 + 1 + 16 + 2);
    assert_eq!(v[3], 0x04);
}
