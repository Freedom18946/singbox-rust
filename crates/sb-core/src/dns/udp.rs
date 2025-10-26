//! Minimal UDP DNS client (A/AAAA only) for tests/e2e and local validation.
use anyhow::Result;
use rand::{thread_rng, Rng};
use std::net::IpAddr;

pub fn build_query(host: &str, qtype: u16) -> Result<Vec<u8>> {
    let mut rng = thread_rng();
    let id: u16 = rng.gen();
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(&id.to_be_bytes()); // ID
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
                                                // QNAME
    for label in host.split('.') {
        let b = label.as_bytes();
        out.push(b.len() as u8);
        out.extend_from_slice(b);
    }
    out.push(0); // root
    out.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
    out.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    Ok(out)
}

pub fn parse_answers(buf: &[u8], expect_qtype: u16) -> Result<(Vec<IpAddr>, Option<u32>)> {
    if buf.len() < 12 {
        return Err(anyhow::anyhow!("short dns"));
    }
    let _id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let rcode = flags & 0x000F;
    if rcode == 3 {
        return Ok((Vec::new(), None));
    } // NXDOMAIN
      // counts
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    // skip question
    let mut i = 12usize;
    for _ in 0..qd {
        while i < buf.len() && buf[i] != 0 {
            let l = buf[i] as usize;
            i += 1 + l;
        }
        i += 1; // root
        i += 4; // QTYPE + QCLASS
    }
    let mut ips = Vec::new();
    let mut min_ttl: Option<u32> = None;
    for _ in 0..an {
        // NAME (skip: label or pointer)
        if i >= buf.len() {
            break;
        }
        if buf[i] & 0xC0 == 0xC0 {
            i += 2;
        } else {
            while i < buf.len() && buf[i] != 0 {
                let l = buf[i] as usize;
                i += 1 + l;
            }
            i += 1;
        }
        if i + 10 > buf.len() {
            break;
        }
        let atype = u16::from_be_bytes([buf[i], buf[i + 1]]);
        i += 2;
        let _aclass = u16::from_be_bytes([buf[i], buf[i + 1]]);
        i += 2;
        let ttl = u32::from_be_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
        i += 4;
        let rdlen = u16::from_be_bytes([buf[i], buf[i + 1]]) as usize;
        i += 2;
        if i + rdlen > buf.len() {
            break;
        }
        if atype == 1 && expect_qtype == 1 && rdlen == 4 {
            let ip = IpAddr::from([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
            ips.push(ip);
            min_ttl = Some(min_ttl.map_or(ttl, |x| x.min(ttl)));
        } else if atype == 28 && expect_qtype == 28 && rdlen == 16 {
            let mut b = [0u8; 16];
            b.copy_from_slice(&buf[i..i + 16]);
            let ip = IpAddr::from(b);
            ips.push(ip);
            min_ttl = Some(min_ttl.map_or(ttl, |x| x.min(ttl)));
        }
        i += rdlen;
    }
    Ok((ips, min_ttl))
}
