use anyhow::{Context, Result};
use async_trait::async_trait;
use std::net::IpAddr;
use tokio::net::lookup_host;

use super::DnsTransport;

pub struct LocalTransport;

impl LocalTransport {
    pub fn new() -> Self {
        Self
    }

    fn build_response(&self, query_packet: &[u8], ips: &[IpAddr], _qtype: u16) -> Result<Vec<u8>> {
        if query_packet.len() < 12 {
            return Err(anyhow::anyhow!("Query packet too short"));
        }

        let id = &query_packet[0..2];
        let mut response = Vec::with_capacity(512);

        // Header
        response.extend_from_slice(id); // ID
                                        // Flags: QR=1, Opcode=0, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=0
                                        // 0x8180 = 1000 0001 1000 0000
        response.extend_from_slice(&[0x81, 0x80]);

        // Counts
        response.extend_from_slice(&query_packet[4..6]); // QDCOUNT (copy from query)

        // ANCOUNT (Answer Count)
        let answer_count = ips.len() as u16;
        response.extend_from_slice(&answer_count.to_be_bytes());

        response.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        response.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

        // Question Section (copy from query)
        // We need to find the end of the question section.
        // It starts at offset 12.
        let mut offset = 12;
        while offset < query_packet.len() {
            let len = query_packet[offset] as usize;
            offset += 1;
            if len == 0 {
                break;
            }
            offset += len;
        }
        offset += 4; // QTYPE + QCLASS

        if offset > query_packet.len() {
            return Err(anyhow::anyhow!("Invalid query packet"));
        }

        response.extend_from_slice(&query_packet[12..offset]);

        // Answer Section
        // We need the domain name for the answer records.
        // Since we are just responding to the question, we can use a pointer to the QNAME.
        // QNAME starts at offset 12 in the packet.
        // Pointer is 0xC000 | offset. 12 = 0x0C. So 0xC00C.
        let name_ptr = 0xC00Cu16.to_be_bytes();

        for ip in ips {
            response.extend_from_slice(&name_ptr);

            match ip {
                IpAddr::V4(ipv4) => {
                    response.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
                    response.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
                    response.extend_from_slice(&60u32.to_be_bytes()); // TTL 60s
                    response.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH 4
                    response.extend_from_slice(&ipv4.octets());
                }
                IpAddr::V6(ipv6) => {
                    response.extend_from_slice(&28u16.to_be_bytes()); // TYPE AAAA
                    response.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
                    response.extend_from_slice(&60u32.to_be_bytes()); // TTL 60s
                    response.extend_from_slice(&16u16.to_be_bytes()); // RDLENGTH 16
                    response.extend_from_slice(&ipv6.octets());
                }
            }
        }

        Ok(response)
    }

    fn parse_query(&self, packet: &[u8]) -> Result<(String, u16)> {
        if packet.len() < 12 {
            return Err(anyhow::anyhow!("Packet too short"));
        }

        let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
        if qdcount != 1 {
            return Err(anyhow::anyhow!("Only single question supported"));
        }

        let mut offset = 12;
        let mut domain = String::new();

        loop {
            if offset >= packet.len() {
                return Err(anyhow::anyhow!("Unexpected end of packet"));
            }
            let len = packet[offset] as usize;
            offset += 1;
            if len == 0 {
                break;
            }
            if !domain.is_empty() {
                domain.push('.');
            }
            if offset + len > packet.len() {
                return Err(anyhow::anyhow!("Label too long"));
            }
            let label = std::str::from_utf8(&packet[offset..offset + len])
                .context("Invalid UTF-8 in domain label")?;
            domain.push_str(label);
            offset += len;
        }

        if offset + 4 > packet.len() {
            return Err(anyhow::anyhow!("Packet too short for QTYPE/QCLASS"));
        }

        let qtype = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        // let qclass = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);

        Ok((domain, qtype))
    }
}

impl Default for LocalTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DnsTransport for LocalTransport {
    async fn query(&self, packet: &[u8]) -> Result<Vec<u8>> {
        let (domain, qtype) = self.parse_query(packet)?;

        // Only support A (1) and AAAA (28)
        if qtype != 1 && qtype != 28 {
            // Return empty response with NoError (or NotImp?)
            // For now, let's just return empty answer section
            return self.build_response(packet, &[], qtype);
        }

        // Use system resolver
        // lookup_host needs a port, so we append :53
        let addrs_iter = lookup_host(format!("{}:53", domain)).await;

        let mut ips = Vec::new();
        if let Ok(addrs) = addrs_iter {
            for addr in addrs {
                let ip = addr.ip();
                match (qtype, ip) {
                    (1, IpAddr::V4(_)) => ips.push(ip),
                    (28, IpAddr::V6(_)) => ips.push(ip),
                    _ => {}
                }
            }
        }

        self.build_response(packet, &ips, qtype)
    }

    fn name(&self) -> &'static str {
        "local"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_local_transport_parse_query() {
        let transport = LocalTransport::new();
        // A simple query for "example.com" A record
        // Header: ID=1234, QR=0, Opcode=0, AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=0
        // QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        let mut packet = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        // QNAME: 7example3com0
        packet.extend_from_slice(b"\x07example\x03com\x00");
        // QTYPE: A (1)
        packet.extend_from_slice(&1u16.to_be_bytes());
        // QCLASS: IN (1)
        packet.extend_from_slice(&1u16.to_be_bytes());

        let (domain, qtype) = transport.parse_query(&packet).expect("parse failed");
        assert_eq!(domain, "example.com");
        assert_eq!(qtype, 1);
    }

    #[test]
    fn test_local_transport_build_response() {
        let transport = LocalTransport::new();
        let mut query_packet = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        query_packet.extend_from_slice(b"\x07example\x03com\x00");
        query_packet.extend_from_slice(&1u16.to_be_bytes());
        query_packet.extend_from_slice(&1u16.to_be_bytes());

        let ips = vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))];
        let response = transport
            .build_response(&query_packet, &ips, 1)
            .expect("build failed");

        // Check ID
        assert_eq!(response[0], 0x12);
        assert_eq!(response[1], 0x34);
        // Check QR bit (response)
        assert_eq!(response[2] & 0x80, 0x80);
        // Check ANCOUNT
        assert_eq!(response[7], 1);

        // Check answer section presence (basic check)
        assert!(response.len() > query_packet.len());
    }
}
