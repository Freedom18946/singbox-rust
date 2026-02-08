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
    pub const fn new(name: String, rtype: u16, class: u16, ttl: u32, data: Vec<u8>) -> Self {
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
    min_ttl.map(u64::from)
}

/// 读取 DNS 名称（支持压缩），返回 (name, `new_off`)
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

// ============================================================================
// Wire-format response builder + helpers (L2.10.1)
// ============================================================================

/// Build a DNS response from a query packet, answer IPs, TTL, and RCODE.
///
/// Copies the question section from the query, sets QR=1, RD=1, RA=1,
/// and appends A/AAAA answer records for each IP.
pub fn build_dns_response(query: &[u8], ips: &[IpAddr], ttl: u32, rcode: u8) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }

    // Find the end of the question section
    let qd = u16::from_be_bytes([query[4], query[5]]) as usize;
    let mut off = 12usize;
    for _ in 0..qd {
        let (_name, noff) = read_name(query, off, 0).ok()?;
        off = noff + 4; // QTYPE + QCLASS
        if off > query.len() {
            return None;
        }
    }

    let answer_count = ips.len() as u16;
    let mut resp = Vec::with_capacity(off + ips.len() * 28);

    // Header: copy ID, set flags
    resp.extend_from_slice(&query[0..2]); // Transaction ID
    // Flags: QR=1, Opcode=0, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE
    resp.push(0x81); // QR=1, RD=1
    resp.push(0x80 | (rcode & 0x0F)); // RA=1, RCODE

    // Counts
    resp.extend_from_slice(&query[4..6]); // QDCOUNT (copy from query)
    resp.extend_from_slice(&answer_count.to_be_bytes()); // ANCOUNT
    resp.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    resp.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

    // Copy question section
    resp.extend_from_slice(&query[12..off]);

    // Answer records using pointer to first QNAME (0xC00C = offset 12)
    let name_ptr = 0xC00Cu16.to_be_bytes();
    let ttl_bytes = ttl.to_be_bytes();

    for ip in ips {
        resp.extend_from_slice(&name_ptr);
        match ip {
            IpAddr::V4(v4) => {
                resp.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
                resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
                resp.extend_from_slice(&ttl_bytes);
                resp.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
                resp.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                resp.extend_from_slice(&28u16.to_be_bytes()); // TYPE AAAA
                resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
                resp.extend_from_slice(&ttl_bytes);
                resp.extend_from_slice(&16u16.to_be_bytes()); // RDLENGTH
                resp.extend_from_slice(&v6.octets());
            }
        }
    }

    Some(resp)
}

/// Extract RCODE from a DNS response packet (lower 4 bits of byte 3).
pub fn extract_rcode(pkt: &[u8]) -> Option<u8> {
    if pkt.len() < 4 {
        return None;
    }
    Some(pkt[3] & 0x0F)
}

/// Parse all A/AAAA answer IPs from a DNS response.
pub fn parse_all_answer_ips(pkt: &[u8]) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    if pkt.len() < 12 {
        return ips;
    }

    let an = u16::from_be_bytes([pkt[6], pkt[7]]) as usize;
    let qd = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;

    // Skip question section
    let mut off = 12usize;
    for _ in 0..qd {
        if let Ok((_name, noff)) = read_name(pkt, off, 0) {
            off = noff + 4; // QTYPE + QCLASS
        } else {
            return ips;
        }
        if off > pkt.len() {
            return ips;
        }
    }

    // Parse answer records
    for _ in 0..an {
        if let Ok((_name, noff)) = read_name(pkt, off, 0) {
            off = noff;
        } else {
            break;
        }
        if pkt.len() < off + 10 {
            break;
        }
        let rtype = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
        let rdlen = u16::from_be_bytes([pkt[off + 8], pkt[off + 9]]) as usize;
        off += 10;
        if pkt.len() < off + rdlen {
            break;
        }
        match rtype {
            1 if rdlen == 4 => {
                ips.push(IpAddr::V4(std::net::Ipv4Addr::new(
                    pkt[off],
                    pkt[off + 1],
                    pkt[off + 2],
                    pkt[off + 3],
                )));
            }
            28 if rdlen == 16 => {
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(&pkt[off..off + 16]);
                ips.push(IpAddr::V6(std::net::Ipv6Addr::from(bytes)));
            }
            _ => {}
        }
        off += rdlen;
    }

    ips
}

/// Get the transaction ID from a DNS packet.
pub fn get_query_id(pkt: &[u8]) -> Option<u16> {
    if pkt.len() < 2 {
        return None;
    }
    Some(u16::from_be_bytes([pkt[0], pkt[1]]))
}

/// Set the transaction ID in a DNS packet (modifies in place).
pub fn set_response_id(response: &mut [u8], id: u16) {
    if response.len() >= 2 {
        let bytes = id.to_be_bytes();
        response[0] = bytes[0];
        response[1] = bytes[1];
    }
}

// ============================================================================
// EDNS0 Client Subnet (ECS) wire-format helpers (L2.10.20)
// ============================================================================

/// Mask IP address bytes according to a prefix length, zeroing bits beyond the prefix.
fn mask_prefix(bytes: &mut [u8], prefix: u8) {
    let full = (prefix / 8) as usize;
    let rem = (prefix % 8) as usize;
    if full < bytes.len() {
        if rem > 0 {
            let mask = (!0u8) << (8 - rem);
            bytes[full] &= mask;
        }
        for item in bytes.iter_mut().skip(full + if rem > 0 { 1 } else { 0 }) {
            *item = 0;
        }
    }
}

/// Parse a subnet string ("IP/prefix") into (family, source_prefix, address_bytes).
///
/// Returns `None` if the string is malformed.
/// - family: 1 = IPv4, 2 = IPv6
/// - source_prefix: prefix length
/// - address_bytes: masked IP bytes, truncated to ceil(prefix/8) bytes
pub fn parse_subnet(subnet: &str) -> Option<(u16, u8, Vec<u8>)> {
    let (ip_str, prefix_str) = subnet.split_once('/')?;
    let prefix = prefix_str.parse::<u8>().ok()?;

    if let Ok(ipv4) = ip_str.parse::<std::net::Ipv4Addr>() {
        if prefix > 32 {
            return None;
        }
        let mut b = ipv4.octets();
        mask_prefix(&mut b, prefix);
        let addr_len = (prefix as usize).div_ceil(8);
        Some((1, prefix, b[..addr_len].to_vec()))
    } else if let Ok(ipv6) = ip_str.parse::<std::net::Ipv6Addr>() {
        if prefix > 128 {
            return None;
        }
        let mut b = ipv6.octets();
        mask_prefix(&mut b, prefix);
        let addr_len = (prefix as usize).div_ceil(8);
        Some((2, prefix, b[..addr_len].to_vec()))
    } else {
        None
    }
}

/// Inject EDNS0 Client Subnet (ECS) option into a DNS wire-format message.
///
/// If the message already has an OPT record in the additional section, the ECS
/// option is appended to its existing RDATA. If not, a new OPT record is added.
///
/// `subnet` format: `"IP/prefix"` (e.g. `"1.2.3.0/24"` or `"2001:db8::/32"`).
///
/// Returns `true` if successfully injected, `false` on parse error.
pub fn inject_edns0_client_subnet(message: &mut Vec<u8>, subnet: &str) -> bool {
    // Parse the subnet specification
    let (family, src_prefix, addr_bytes) = match parse_subnet(subnet) {
        Some(v) => v,
        None => return false,
    };

    // Build the ECS option payload:
    //   OPTION-CODE(2) + OPTION-LENGTH(2) + FAMILY(2) + SOURCE-PREFIX(1) + SCOPE-PREFIX(1) + ADDRESS(var)
    let ecs_data_len = 4u16 + addr_bytes.len() as u16; // family(2)+src(1)+scope(1)+addr
    let mut ecs_option = Vec::with_capacity(4 + ecs_data_len as usize);
    ecs_option.extend_from_slice(&8u16.to_be_bytes()); // OPTION-CODE = 8 (Client Subnet)
    ecs_option.extend_from_slice(&ecs_data_len.to_be_bytes()); // OPTION-LENGTH
    ecs_option.extend_from_slice(&family.to_be_bytes()); // FAMILY
    ecs_option.push(src_prefix); // SOURCE PREFIX-LENGTH
    ecs_option.push(0); // SCOPE PREFIX-LENGTH (0 for queries)
    ecs_option.extend_from_slice(&addr_bytes); // ADDRESS

    // We need to parse the DNS header to locate the additional section
    if message.len() < 12 {
        return false;
    }

    let qdcount = u16::from_be_bytes([message[4], message[5]]) as usize;
    let ancount = u16::from_be_bytes([message[6], message[7]]) as usize;
    let nscount = u16::from_be_bytes([message[8], message[9]]) as usize;
    let arcount = u16::from_be_bytes([message[10], message[11]]) as usize;

    // Skip question section
    let mut off = 12usize;
    for _ in 0..qdcount {
        match skip_name(message, off) {
            Some(noff) => off = noff + 4, // QTYPE(2) + QCLASS(2)
            None => return false,
        }
        if off > message.len() {
            return false;
        }
    }

    // Skip answer + authority sections
    for _ in 0..(ancount + nscount) {
        match skip_name(message, off) {
            Some(noff) => off = noff,
            None => return false,
        }
        if message.len() < off + 10 {
            return false;
        }
        let rdlen = u16::from_be_bytes([message[off + 8], message[off + 9]]) as usize;
        off += 10 + rdlen;
        if off > message.len() {
            return false;
        }
    }

    // Now we're at the start of the additional section.
    // Scan AR records looking for OPT (TYPE=41)
    let ar_start = off;
    let mut opt_offset: Option<usize> = None; // offset of the OPT record's name field
    let mut opt_rdlen_offset: Option<usize> = None; // offset of RDLENGTH field
    let mut opt_rdata_end: Option<usize> = None; // end of OPT RDATA

    let mut cur = ar_start;
    for _ in 0..arcount {
        let rec_start = cur;
        match skip_name(message, cur) {
            Some(noff) => cur = noff,
            None => return false,
        }
        if message.len() < cur + 10 {
            return false;
        }
        let rtype = u16::from_be_bytes([message[cur], message[cur + 1]]);
        let rdlen = u16::from_be_bytes([message[cur + 8], message[cur + 9]]) as usize;
        if rtype == 41 && opt_offset.is_none() {
            opt_offset = Some(rec_start);
            opt_rdlen_offset = Some(cur + 8);
            opt_rdata_end = Some(cur + 10 + rdlen);
        }
        cur += 10 + rdlen;
        if cur > message.len() {
            return false;
        }
    }

    if let (Some(_), Some(rdlen_off), Some(rdata_end)) =
        (opt_offset, opt_rdlen_offset, opt_rdata_end)
    {
        // OPT record exists: append ECS option to its RDATA
        let old_rdlen = u16::from_be_bytes([message[rdlen_off], message[rdlen_off + 1]]);
        let new_rdlen = old_rdlen + ecs_option.len() as u16;
        let new_rdlen_bytes = new_rdlen.to_be_bytes();
        message[rdlen_off] = new_rdlen_bytes[0];
        message[rdlen_off + 1] = new_rdlen_bytes[1];
        // Insert ECS option bytes at rdata_end (just after existing RDATA)
        message.splice(rdata_end..rdata_end, ecs_option);
    } else {
        // No OPT record: append a new one
        // OPT pseudo-RR: NAME(1=root) + TYPE(2=41) + CLASS(2=4096 UDP size) + TTL(4=0) + RDLENGTH(2) + RDATA
        let mut opt_rr = Vec::with_capacity(1 + 2 + 2 + 4 + 2 + ecs_option.len());
        opt_rr.push(0); // NAME = root
        opt_rr.extend_from_slice(&41u16.to_be_bytes()); // TYPE = OPT
        opt_rr.extend_from_slice(&4096u16.to_be_bytes()); // CLASS = UDP payload size
        opt_rr.extend_from_slice(&0u32.to_be_bytes()); // TTL = extended RCODE + flags
        opt_rr.extend_from_slice(&(ecs_option.len() as u16).to_be_bytes()); // RDLENGTH
        opt_rr.extend_from_slice(&ecs_option); // RDATA (the ECS option)

        message.extend_from_slice(&opt_rr);

        // Increment ARCOUNT
        let new_arcount = (arcount as u16) + 1;
        let ar_bytes = new_arcount.to_be_bytes();
        message[10] = ar_bytes[0];
        message[11] = ar_bytes[1];
    }

    true
}

/// Parse EDNS0 Client Subnet from a DNS message (query or response).
///
/// Returns the subnet as `"IP/prefix"` string, or `None` if not present.
/// For responses, the scope prefix is reflected in the returned prefix length
/// only if non-zero; otherwise the source prefix is used.
pub fn parse_edns0_client_subnet(message: &[u8]) -> Option<String> {
    if message.len() < 12 {
        return None;
    }

    let qdcount = u16::from_be_bytes([message[4], message[5]]) as usize;
    let ancount = u16::from_be_bytes([message[6], message[7]]) as usize;
    let nscount = u16::from_be_bytes([message[8], message[9]]) as usize;
    let arcount = u16::from_be_bytes([message[10], message[11]]) as usize;

    // Skip question section
    let mut off = 12usize;
    for _ in 0..qdcount {
        off = skip_name(message, off)?;
        off += 4; // QTYPE + QCLASS
        if off > message.len() {
            return None;
        }
    }

    // Skip answer + authority sections
    for _ in 0..(ancount + nscount) {
        off = skip_name(message, off)?;
        if message.len() < off + 10 {
            return None;
        }
        let rdlen = u16::from_be_bytes([message[off + 8], message[off + 9]]) as usize;
        off += 10 + rdlen;
        if off > message.len() {
            return None;
        }
    }

    // Scan additional section for OPT record
    for _ in 0..arcount {
        off = skip_name(message, off)?;
        if message.len() < off + 10 {
            return None;
        }
        let rtype = u16::from_be_bytes([message[off], message[off + 1]]);
        let rdlen = u16::from_be_bytes([message[off + 8], message[off + 9]]) as usize;
        let rdata_start = off + 10;
        off = rdata_start + rdlen;
        if off > message.len() {
            return None;
        }

        if rtype == 41 {
            // This is the OPT record. Parse its RDATA as a series of EDNS0 options.
            let mut opt_off = rdata_start;
            while opt_off + 4 <= rdata_start + rdlen {
                let opt_code =
                    u16::from_be_bytes([message[opt_off], message[opt_off + 1]]);
                let opt_len =
                    u16::from_be_bytes([message[opt_off + 2], message[opt_off + 3]]) as usize;
                opt_off += 4;
                if opt_off + opt_len > rdata_start + rdlen {
                    break;
                }

                if opt_code == 8 && opt_len >= 4 {
                    // ECS option: FAMILY(2) + SOURCE-PREFIX(1) + SCOPE-PREFIX(1) + ADDRESS(var)
                    let family =
                        u16::from_be_bytes([message[opt_off], message[opt_off + 1]]);
                    let source_prefix = message[opt_off + 2];
                    let scope_prefix = message[opt_off + 3];
                    let addr_data = &message[opt_off + 4..opt_off + opt_len];

                    let prefix = if scope_prefix > 0 {
                        scope_prefix
                    } else {
                        source_prefix
                    };

                    match family {
                        1 => {
                            // IPv4
                            let mut octets = [0u8; 4];
                            let copy_len = addr_data.len().min(4);
                            octets[..copy_len].copy_from_slice(&addr_data[..copy_len]);
                            let ip = std::net::Ipv4Addr::from(octets);
                            return Some(format!("{ip}/{prefix}"));
                        }
                        2 => {
                            // IPv6
                            let mut octets = [0u8; 16];
                            let copy_len = addr_data.len().min(16);
                            octets[..copy_len].copy_from_slice(&addr_data[..copy_len]);
                            let ip = std::net::Ipv6Addr::from(octets);
                            return Some(format!("{ip}/{prefix}"));
                        }
                        _ => {}
                    }
                }
                opt_off += opt_len;
            }
        }
    }
    None
}

/// Skip a DNS name (handling labels and compression pointers), returning the
/// offset just past the name. Returns `None` on malformed data.
fn skip_name(pkt: &[u8], mut off: usize) -> Option<usize> {
    let mut jumped = false;
    let mut result_off = off; // track the offset to return (before first jump)
    let mut depth = 0u8;
    loop {
        if depth > 64 || off >= pkt.len() {
            return None;
        }
        let b = pkt[off];
        if b == 0 {
            off += 1;
            if !jumped {
                result_off = off;
            }
            break;
        }
        if b & 0xC0 == 0xC0 {
            // Compression pointer
            if off + 1 >= pkt.len() {
                return None;
            }
            if !jumped {
                result_off = off + 2;
                jumped = true;
            }
            let ptr = (((b as usize) & 0x3F) << 8) | pkt[off + 1] as usize;
            if ptr >= pkt.len() {
                return None;
            }
            off = ptr;
            depth += 1;
        } else {
            let len = b as usize;
            off += 1 + len;
            if off > pkt.len() {
                return None;
            }
        }
    }
    Some(result_off)
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

    // ===== L2.10.1 tests =====

    fn example_com_a_query() -> Vec<u8> {
        vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0x07, b'e', b'x', b'a', b'm',
            b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
        ]
    }

    #[test]
    fn build_response_roundtrip() {
        let query = example_com_a_query();
        let ips = vec![
            IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4)),
            IpAddr::V4(std::net::Ipv4Addr::new(5, 6, 7, 8)),
        ];
        let resp = build_dns_response(&query, &ips, 60, 0).expect("build");

        // Verify transaction ID preserved
        assert_eq!(get_query_id(&resp), Some(0x1234));

        // Verify QR=1
        assert_eq!(resp[2] & 0x80, 0x80);

        // Verify RCODE=0
        assert_eq!(extract_rcode(&resp), Some(0));

        // Verify answer count
        let an = u16::from_be_bytes([resp[6], resp[7]]);
        assert_eq!(an, 2);

        // Verify IPs can be parsed back
        let parsed = parse_all_answer_ips(&resp);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(parsed[1], IpAddr::V4(std::net::Ipv4Addr::new(5, 6, 7, 8)));

        // Verify TTL
        let ttl = parse_min_ttl(&resp);
        assert_eq!(ttl, Some(60));
    }

    #[test]
    fn build_response_ipv6() {
        let query = vec![
            0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0x07, b'e', b'x', b'a', b'm',
            b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x1C, 0x00, 0x01,
        ];
        let ip6 = IpAddr::V6("2001:db8::1".parse().unwrap());
        let resp = build_dns_response(&query, &[ip6], 300, 0).expect("build");
        let parsed = parse_all_answer_ips(&resp);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], ip6);
    }

    #[test]
    fn build_response_nxdomain() {
        let query = example_com_a_query();
        let resp = build_dns_response(&query, &[], 0, 3).expect("build");
        assert_eq!(extract_rcode(&resp), Some(3)); // NXDOMAIN
        assert!(parse_all_answer_ips(&resp).is_empty());
    }

    #[test]
    fn set_response_id_works() {
        let query = example_com_a_query();
        let mut resp = build_dns_response(&query, &[], 0, 0).expect("build");
        assert_eq!(get_query_id(&resp), Some(0x1234));
        set_response_id(&mut resp, 0xFFFF);
        assert_eq!(get_query_id(&resp), Some(0xFFFF));
    }

    #[test]
    fn extract_rcode_short_packet() {
        assert_eq!(extract_rcode(&[0, 0, 0]), None);
        assert_eq!(extract_rcode(&[0, 0, 0, 0x05]), Some(5));
    }

    #[test]
    fn get_query_id_short_packet() {
        assert_eq!(get_query_id(&[0xAB]), None);
        assert_eq!(get_query_id(&[0xAB, 0xCD]), Some(0xABCD));
    }

    // ===== L2.10.20 ECS tests =====

    #[test]
    fn parse_subnet_ipv4() {
        let (family, prefix, bytes) = parse_subnet("1.2.3.0/24").unwrap();
        assert_eq!(family, 1);
        assert_eq!(prefix, 24);
        assert_eq!(bytes, vec![1, 2, 3]);
    }

    #[test]
    fn parse_subnet_ipv6() {
        let (family, prefix, bytes) = parse_subnet("2001:db8::/32").unwrap();
        assert_eq!(family, 2);
        assert_eq!(prefix, 32);
        assert_eq!(bytes, vec![0x20, 0x01, 0x0d, 0xb8]);
    }

    #[test]
    fn parse_subnet_invalid() {
        assert!(parse_subnet("not-an-ip/24").is_none());
        assert!(parse_subnet("1.2.3.4").is_none()); // no slash
        assert!(parse_subnet("1.2.3.4/abc").is_none()); // non-numeric prefix
        assert!(parse_subnet("1.2.3.4/33").is_none()); // prefix too large for IPv4
    }

    #[test]
    fn ecs_inject_then_parse_roundtrip_ipv4() {
        let mut query = example_com_a_query();
        assert!(parse_edns0_client_subnet(&query).is_none());

        let ok = inject_edns0_client_subnet(&mut query, "1.2.3.0/24");
        assert!(ok);

        let subnet = parse_edns0_client_subnet(&query).expect("should find ECS");
        assert_eq!(subnet, "1.2.3.0/24");

        // Verify ARCOUNT was incremented to 1
        let arcount = u16::from_be_bytes([query[10], query[11]]);
        assert_eq!(arcount, 1);
    }

    #[test]
    fn ecs_inject_then_parse_roundtrip_ipv6() {
        let mut query = example_com_a_query();
        let ok = inject_edns0_client_subnet(&mut query, "2001:db8::/32");
        assert!(ok);

        let subnet = parse_edns0_client_subnet(&query).expect("should find ECS");
        assert_eq!(subnet, "2001:db8::/32");
    }

    #[test]
    fn ecs_inject_into_message_with_no_opt() {
        // Start with a plain query (no AR section)
        let mut query = example_com_a_query();
        assert_eq!(u16::from_be_bytes([query[10], query[11]]), 0); // ARCOUNT=0

        let ok = inject_edns0_client_subnet(&mut query, "10.0.0.0/8");
        assert!(ok);

        // ARCOUNT should now be 1
        assert_eq!(u16::from_be_bytes([query[10], query[11]]), 1);

        // Should be parseable
        let subnet = parse_edns0_client_subnet(&query).expect("should find ECS");
        assert_eq!(subnet, "10.0.0.0/8");
    }

    #[test]
    fn ecs_inject_into_message_with_existing_opt() {
        // Build a query that already has an OPT record (ARCOUNT=1)
        let mut query = example_com_a_query();
        // Add an OPT record with no options
        query[10] = 0;
        query[11] = 1; // ARCOUNT = 1
        query.push(0); // NAME = root
        query.extend_from_slice(&41u16.to_be_bytes()); // TYPE = OPT
        query.extend_from_slice(&4096u16.to_be_bytes()); // CLASS = UDP payload size
        query.extend_from_slice(&0u32.to_be_bytes()); // TTL = 0
        query.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH = 0

        let ok = inject_edns0_client_subnet(&mut query, "192.168.1.0/24");
        assert!(ok);

        // ARCOUNT should still be 1 (no new record added)
        assert_eq!(u16::from_be_bytes([query[10], query[11]]), 1);

        // Should be parseable
        let subnet = parse_edns0_client_subnet(&query).expect("should find ECS");
        assert_eq!(subnet, "192.168.1.0/24");
    }

    #[test]
    fn ecs_parse_returns_none_for_no_ecs() {
        let query = example_com_a_query();
        assert!(parse_edns0_client_subnet(&query).is_none());
    }

    #[test]
    fn ecs_inject_invalid_subnet_returns_false() {
        let mut query = example_com_a_query();
        assert!(!inject_edns0_client_subnet(&mut query, "garbage"));
        assert!(!inject_edns0_client_subnet(&mut query, "1.2.3.4")); // no prefix
    }

    #[test]
    fn ecs_inject_short_packet_returns_false() {
        let mut short = vec![0u8; 6]; // too short for DNS header
        assert!(!inject_edns0_client_subnet(&mut short, "1.2.3.0/24"));
    }

    #[test]
    fn ecs_parse_response_with_answers() {
        // Build a response with answers, then inject ECS
        let query = example_com_a_query();
        let ips = vec![IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4))];
        let mut resp = build_dns_response(&query, &ips, 60, 0).expect("build");

        let ok = inject_edns0_client_subnet(&mut resp, "172.16.0.0/12");
        assert!(ok);

        let subnet = parse_edns0_client_subnet(&resp).expect("should find ECS");
        assert_eq!(subnet, "172.16.0.0/12");

        // Answers should still be parseable
        let parsed = parse_all_answer_ips(&resp);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn mask_prefix_zeroes_trailing_bits() {
        let mut b = [0xFF, 0xFF, 0xFF, 0xFF];
        mask_prefix(&mut b, 20);
        assert_eq!(b, [0xFF, 0xFF, 0xF0, 0x00]);

        let mut b2 = [0xFF, 0xFF, 0xFF, 0xFF];
        mask_prefix(&mut b2, 0);
        assert_eq!(b2, [0x00, 0x00, 0x00, 0x00]);

        let mut b3 = [0xFF, 0xFF, 0xFF, 0xFF];
        mask_prefix(&mut b3, 32);
        assert_eq!(b3, [0xFF, 0xFF, 0xFF, 0xFF]);
    }
}
