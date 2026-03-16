#![no_main]
//! Structured VMess protocol fuzzer
//!
//! Uses `arbitrary` to generate structured VMess-like protocol data for targeted
//! fuzzing of the address parsing component via real production code.
//!
//! Generates properly-framed address blocks and exercises `parse_ss_addr()`
//! and `parse_trojan_request()` with structured inputs that are more likely
//! to reach deeper parsing states than pure random bytes.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Structured address block matching SOCKS5-like format used by VMess/VLESS/SS/Trojan
#[derive(Arbitrary, Debug)]
struct AddressBlock {
    /// Address type: 1=IPv4, 2=Domain (SS uses 3 for domain), 3=IPv6 (SS uses 4 for IPv6)
    address_type: u8,
    /// Raw address data (interpreted based on address_type)
    address_data: Vec<u8>,
    /// Target port
    port: u16,
}

impl AddressBlock {
    /// Encode as SOCKS5-style address block (as used by parse_ss_addr)
    /// Format: atyp(1) + addr(variable) + port(2)
    fn to_ss_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Map to valid address types for parse_ss_addr: 1=IPv4, 3=Domain, 4=IPv6
        let atyp = match self.address_type % 4 {
            0 => 1u8,  // IPv4
            1 => 3u8,  // Domain
            2 => 4u8,  // IPv6 (SS uses 4, not 3)
            _ => 1u8,  // Default to IPv4
        };
        data.push(atyp);

        match atyp {
            1 => {
                // IPv4: exactly 4 bytes
                for i in 0..4 {
                    data.push(*self.address_data.get(i).unwrap_or(&0));
                }
            }
            3 => {
                // Domain: length byte + domain bytes
                let domain_len = self.address_data.len().min(253) as u8;
                data.push(domain_len);
                data.extend_from_slice(&self.address_data[..domain_len as usize]);
            }
            4 => {
                // IPv6: exactly 16 bytes
                for i in 0..16 {
                    data.push(*self.address_data.get(i).unwrap_or(&0));
                }
            }
            _ => {}
        }

        // Port (big-endian)
        data.extend_from_slice(&self.port.to_be_bytes());
        data
    }
}

/// Structured Trojan request for targeted fuzzing
#[derive(Arbitrary, Debug)]
struct TrojanRequest {
    /// 56 bytes of hex-like data for the password hash
    hash_bytes: [u8; 56],
    /// Command byte (0x01=CONNECT, 0x02=UDP)
    command: u8,
    /// Address block
    address: AddressBlock,
}

impl TrojanRequest {
    fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // SHA224 hash (56 hex bytes) - make them valid hex chars
        for &b in &self.hash_bytes {
            let hex_char = match b % 16 {
                0..=9 => b'0' + (b % 10),
                _ => b'a' + (b % 6),
            };
            data.push(hex_char);
        }

        // CRLF
        data.extend_from_slice(b"\r\n");

        // Command (constrain to valid values)
        data.push(if self.command.is_multiple_of(2) { 0x01 } else { 0x02 });

        // Address block
        data.extend_from_slice(&self.address.to_ss_bytes());

        // Final CRLF
        data.extend_from_slice(b"\r\n");

        data
    }
}

#[derive(Arbitrary, Debug)]
enum FuzzInput {
    /// Raw bytes for parse_ss_addr
    RawAddress(Vec<u8>),
    /// Structured address block
    StructuredAddress(AddressBlock),
    /// Structured Trojan request
    StructuredTrojan(TrojanRequest),
}

fuzz_target!(|input: FuzzInput| {
    match input {
        FuzzInput::RawAddress(data) => {
            let _ = sb_adapters::inbound::shadowsocks::parse_ss_addr(&data);
            let _ = sb_adapters::inbound::trojan::parse_trojan_request(&data);
        }
        FuzzInput::StructuredAddress(addr) => {
            let bytes = addr.to_ss_bytes();
            let _ = sb_adapters::inbound::shadowsocks::parse_ss_addr(&bytes);
        }
        FuzzInput::StructuredTrojan(req) => {
            let bytes = req.to_bytes();
            let _ = sb_adapters::inbound::trojan::parse_trojan_request(&bytes);
            // Also parse the address portion independently
            if bytes.len() > 59 {
                let _ = sb_adapters::inbound::shadowsocks::parse_ss_addr(&bytes[59..]);
            }
        }
    }
});
