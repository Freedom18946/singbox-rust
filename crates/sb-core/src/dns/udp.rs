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
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT (may update for EDNS0)
                                                // QNAME
    for label in host.split('.') {
        let b = label.as_bytes();
        out.push(b.len() as u8);
        out.extend_from_slice(b);
    }
    out.push(0); // root
    out.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
    out.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN

    // Optionally append EDNS0 Client Subnet if configured via env
    if let Some((family, src_prefix, scope_prefix, addr_bytes)) = parse_client_subnet_env() {
        // Set ARCOUNT=1
        out[10] = 0;
        out[11] = 1;
        // OPT pseudo-RR
        out.push(0); // NAME root
        out.extend_from_slice(&41u16.to_be_bytes()); // TYPE=OPT(41)
        out.extend_from_slice(&4096u16.to_be_bytes()); // CLASS=UDP payload size
        out.extend_from_slice(&0u32.to_be_bytes()); // TTL (extended RCODE/flags)=0
                                                    // Build ECS option
        let mut opt = Vec::with_capacity(8 + addr_bytes.len());
        opt.extend_from_slice(&8u16.to_be_bytes()); // OPTION-CODE = 8 (Client Subnet)
                                                    // ECS data: FAMILY(2) + SOURCE(1) + SCOPE(1) + ADDRESS (ceil(src/8))
        let addr_len = addr_bytes.len() as u16;
        let data_len = 4u16 + addr_len; // 2+1+1 + addr
        opt.extend_from_slice(&data_len.to_be_bytes()); // OPTION-LENGTH
        opt.extend_from_slice(&family.to_be_bytes());
        opt.push(src_prefix);
        opt.push(scope_prefix);
        opt.extend_from_slice(&addr_bytes);
        // RDLEN
        out.extend_from_slice(&(opt.len() as u16).to_be_bytes());
        out.extend_from_slice(&opt);
    }
    Ok(out)
}

fn parse_client_subnet_env() -> Option<(u16, u8, u8, Vec<u8>)> {
    let s = std::env::var("SB_DNS_CLIENT_SUBNET").ok()?;
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (ip_str, prefix_opt) = if let Some((a, p)) = s.split_once('/') {
        (a, p.parse::<u8>().ok())
    } else {
        (s, None)
    };
    if let Ok(ipv4) = ip_str.parse::<std::net::Ipv4Addr>() {
        let prefix = prefix_opt.unwrap_or(24).min(32);
        let mut b = ipv4.octets();
        mask_prefix(&mut b, prefix);
        let addr_len = (prefix as usize).div_ceil(8);
        return Some((1, prefix, 0, b[..addr_len].to_vec()));
    }
    if let Ok(ipv6) = ip_str.parse::<std::net::Ipv6Addr>() {
        let prefix = prefix_opt.unwrap_or(56).min(128);
        let mut b = ipv6.octets();
        mask_prefix(&mut b, prefix);
        let addr_len = (prefix as usize).div_ceil(8);
        return Some((2, prefix, 0, b[..addr_len].to_vec()));
    }
    None
}

fn mask_prefix(bytes: &mut [u8], prefix: u8) {
    let full = (prefix / 8) as usize;
    let rem = (prefix % 8) as usize;
    if full < bytes.len() {
        for i in full + 1..bytes.len() {
            bytes[i] = 0;
        }
        if rem > 0 {
            let mask = (!0u8) << (8 - rem);
            bytes[full] &= mask;
        }
    }
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
