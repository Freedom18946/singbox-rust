//! 轻量 DNS 报文解析（只取我们需要的最小字段）
//! - 解析单问题的 QNAME/QTYPE 作为缓存键
//! - 解析应答报文的最小 TTL（从 AN/NS 里扫描）
//! - 支持压缩指针（RFC 1035），限制递归深度避免恶意包

use std::net::IpAddr;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct QuestionKey {
    /// 小写域名（末尾无点）
    pub name: String,
    /// QTYPE（A=1, AAAA=28, ...）
    pub qtype: u16,
}

/// DNS Record for compatibility with existing code
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub rtype: u16,
    pub class: u16,
    pub ttl: u32,
    pub data: Vec<u8>,
}

impl Record {
    pub fn new(name: String, rtype: u16, class: u16, ttl: u32, data: Vec<u8>) -> Self {
        Self {
            name,
            rtype,
            class,
            ttl,
            data,
        }
    }

    /// Try to parse data as IPv4 address (for A records)
    pub fn as_ipv4(&self) -> Option<std::net::Ipv4Addr> {
        if self.rtype == 1 && self.data.len() == 4 {
            Some(std::net::Ipv4Addr::new(
                self.data[0],
                self.data[1],
                self.data[2],
                self.data[3],
            ))
        } else {
            None
        }
    }

    /// Try to parse data as IPv6 address (for AAAA records)
    pub fn as_ipv6(&self) -> Option<std::net::Ipv6Addr> {
        if self.rtype == 28 && self.data.len() == 16 {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&self.data);
            Some(std::net::Ipv6Addr::from(bytes))
        } else {
            None
        }
    }

    /// Convert to IP address if possible
    pub fn as_ip(&self) -> Option<IpAddr> {
        self.as_ipv4()
            .map(IpAddr::V4)
            .or_else(|| self.as_ipv6().map(IpAddr::V6))
    }
}

/// 从查询报文中解析 QuestionKey（只支持 QDCOUNT=1）
pub fn parse_question_key(pkt: &[u8]) -> Option<QuestionKey> {
    if pkt.len() < 12 {
        return None;
    }
    let qd = u16::from_be_bytes([pkt[4], pkt[5]]);
    if qd != 1 {
        return None;
    }
    // 跳过头
    let mut off = 12usize;
    let (name, new_off) = read_name(pkt, off, 0).ok()?;
    off = new_off;
    if pkt.len() < off + 4 {
        return None;
    }
    let qtype = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
    let qclass = u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]);
    if qclass != 1 {
        return None;
    } // 仅 IN
    Some(QuestionKey {
        name: normalize_name(&name),
        qtype,
    })
}

/// 解析应答中的最小 TTL；AN/NS/AR 任意区段都可能含有
pub fn parse_min_ttl(pkt: &[u8]) -> Option<u64> {
    if pkt.len() < 12 {
        return None;
    }
    let an = u16::from_be_bytes([pkt[6], pkt[7]]) as usize;
    let ns = u16::from_be_bytes([pkt[8], pkt[9]]) as usize;
    let ar = u16::from_be_bytes([pkt[10], pkt[11]]) as usize;
    // 跳过问题
    let mut off = 12usize;
    let qd = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    for _ in 0..qd {
        let (_qname, noff) = read_name(pkt, off, 0).ok()?;
        off = noff + 4; // qtype+qclass
        if pkt.len() < off {
            return None;
        }
    }
    // 扫描 RRs
    let mut min_ttl: Option<u32> = None;
    for _ in 0..(an + ns + ar) {
        let (_name, noff) = read_name(pkt, off, 0).ok()?;
        off = noff;
        if pkt.len() < off + 10 {
            return None;
        }
        // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2)
        let ttl = u32::from_be_bytes([pkt[off + 4], pkt[off + 5], pkt[off + 6], pkt[off + 7]]);
        let rdlen = u16::from_be_bytes([pkt[off + 8], pkt[off + 9]]) as usize;
        off += 10;
        if pkt.len() < off + rdlen {
            return None;
        }
        off += rdlen;
        min_ttl = Some(match min_ttl {
            Some(cur) => cur.min(ttl),
            None => ttl,
        });
    }
    min_ttl.map(|v| v as u64)
}

/// 读取 DNS 名称（支持压缩），返回 (name, new_off)
fn read_name(pkt: &[u8], off: usize, depth: usize) -> Result<(String, usize), ()> {
    if depth > 8 {
        return Err(());
    } // 防御性：限制指针嵌套
    let mut labels: Vec<String> = Vec::with_capacity(6);
    let mut jumped = false;
    let mut cur_off = off;
    loop {
        if cur_off >= pkt.len() {
            return Err(());
        }
        let len = pkt[cur_off];
        cur_off += 1;
        match len {
            0 => break,
            l if l & 0xC0 == 0xC0 => {
                // 压缩指针
                if cur_off >= pkt.len() {
                    return Err(());
                }
                let b2 = pkt[cur_off] as usize;
                cur_off += 1;
                let ptr = (((l as usize) & 0x3F) << 8) | b2;
                if ptr >= pkt.len() {
                    return Err(());
                }
                let (suffix, _) = read_name(pkt, ptr, depth + 1)?;
                labels.push(suffix);
                jumped = true;
                break;
            }
            l => {
                let l = l as usize;
                if cur_off + l > pkt.len() {
                    return Err(());
                }
                let s = &pkt[cur_off..cur_off + l];
                let label = std::str::from_utf8(s).map_err(|_| ())?.to_string();
                labels.push(label);
                cur_off += l;
            }
        }
    }
    let name = labels.join(".");
    let new_off = if jumped { off + 2 } else { cur_off };
    Ok((name, new_off))
}

fn normalize_name(name: &str) -> String {
    let mut s = name.trim_end_matches('.').to_ascii_lowercase();
    // 规范空名
    if s.is_empty() {
        s.push('.');
        s.pop();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    // example.com A 查询与解析
    #[test]
    fn parse_q_example_com() {
        let query: [u8; 29] = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0x07, b'e', b'x', b'a', b'm',
            b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let k = parse_question_key(&query).expect("key");
        assert_eq!(k.name, "example.com");
        assert_eq!(k.qtype, 1);
    }

    // 伪造一个响应，包含两个答案不同 TTL，取最小值
    #[test]
    fn parse_min_ttl_simple() {
        // Header: ID=0x1234, QR=1, AN=2, QD=1
        let mut resp = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        ];
        // QNAME example.com
        resp.extend_from_slice(&[
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, 0x00, 0x01,
        ]);
        // AN1: name ptr, TYPE A, CLASS IN, TTL=30, RDLEN=4, RDATA=1.2.3.4
        resp.extend_from_slice(&[
            0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 30, 0x00, 0x04, 1, 2, 3, 4,
        ]);
        // AN2: name ptr, TYPE A, CLASS IN, TTL=5, RDLEN=4, RDATA=5.6.7.8
        resp.extend_from_slice(&[
            0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 5, 0x00, 0x04, 5, 6, 7, 8,
        ]);
        let ttl = parse_min_ttl(&resp).expect("ttl");
        assert_eq!(ttl, 5);
    }
}
