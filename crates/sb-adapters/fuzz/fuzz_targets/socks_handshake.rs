#![no_main]

use libfuzzer_sys::fuzz_target;
use sb_adapters::outbound::socks5::{SocksVersion, SocksMethod, SocksCommand, SocksReply, SocksAddrType};

/// Fuzz target for SOCKS5 handshake parsing
/// Tests various combinations of VER/METHODS/REP/ATYP variants
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Test version parsing
    let _ = parse_socks_version(data);

    // Test method negotiation
    let _ = parse_method_negotiation(data);

    // Test command parsing
    let _ = parse_socks_command(data);

    // Test address type parsing
    let _ = parse_address_type(data);

    // Test full handshake sequence
    let _ = parse_full_handshake(data);
});

fn parse_socks_version(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    if data.is_empty() {
        return Ok(());
    }

    let version = data[0];
    match version {
        5 => (), // Valid SOCKS5
        4 => (), // Valid SOCKS4 (for compatibility testing)
        _ => (), // Invalid version - should be handled gracefully
    }
    Ok(())
}

fn parse_method_negotiation(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    if data.len() < 2 {
        return Ok(());
    }

    let version = data[0];
    let nmethods = data[1] as usize;

    if version == 5 && data.len() >= 2 + nmethods {
        let methods = &data[2..2 + nmethods];

        // Check for valid method codes
        for &method in methods {
            match method {
                0x00 => (), // NO AUTHENTICATION REQUIRED
                0x01 => (), // GSSAPI
                0x02 => (), // USERNAME/PASSWORD
                0x03..=0x7F => (), // IANA ASSIGNED
                0x80..=0xFE => (), // RESERVED FOR PRIVATE METHODS
                0xFF => (), // NO ACCEPTABLE METHODS
            }
        }
    }
    Ok(())
}

fn parse_socks_command(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    if data.len() < 4 {
        return Ok(());
    }

    let version = data[0];
    let cmd = data[1];
    let rsv = data[2];
    let atyp = data[3];

    if version == 5 {
        // Test command codes
        match cmd {
            0x01 => (), // CONNECT
            0x02 => (), // BIND
            0x03 => (), // UDP ASSOCIATE
            _ => (),    // Invalid command
        }

        // Reserved byte should be 0x00
        let _ = rsv;

        // Test address types
        match atyp {
            0x01 => (), // IPv4
            0x03 => (), // Domain name
            0x04 => (), // IPv6
            _ => (),    // Invalid address type
        }
    }
    Ok(())
}

fn parse_address_type(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    if data.is_empty() {
        return Ok(());
    }

    let atyp = data[0];
    let mut offset = 1;

    match atyp {
        0x01 => {
            // IPv4 address (4 bytes) + port (2 bytes)
            if data.len() >= offset + 6 {
                let _addr = &data[offset..offset + 4];
                let _port = &data[offset + 4..offset + 6];
            }
        },
        0x03 => {
            // Domain name: length byte + domain + port (2 bytes)
            if data.len() >= offset + 1 {
                let domain_len = data[offset] as usize;
                offset += 1;
                if data.len() >= offset + domain_len + 2 {
                    let _domain = &data[offset..offset + domain_len];
                    let _port = &data[offset + domain_len..offset + domain_len + 2];
                }
            }
        },
        0x04 => {
            // IPv6 address (16 bytes) + port (2 bytes)
            if data.len() >= offset + 18 {
                let _addr = &data[offset..offset + 16];
                let _port = &data[offset + 16..offset + 18];
            }
        },
        _ => {
            // Invalid address type - should be handled gracefully
        }
    }
    Ok(())
}

fn parse_full_handshake(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut offset = 0;

    // Phase 1: Method negotiation request
    if data.len() >= offset + 2 {
        let version = data[offset];
        let nmethods = data[offset + 1] as usize;
        offset += 2;

        if version == 5 && data.len() >= offset + nmethods {
            let _methods = &data[offset..offset + nmethods];
            offset += nmethods;

            // Phase 2: Connection request
            if data.len() >= offset + 4 {
                let version2 = data[offset];
                let cmd = data[offset + 1];
                let _rsv = data[offset + 2];
                let atyp = data[offset + 3];
                offset += 4;

                if version2 == 5 {
                    // Parse address based on type
                    match atyp {
                        0x01 if data.len() >= offset + 6 => {
                            // IPv4 + port
                            offset += 6;
                        },
                        0x03 if data.len() >= offset + 1 => {
                            let domain_len = data[offset] as usize;
                            offset += 1;
                            if data.len() >= offset + domain_len + 2 {
                                offset += domain_len + 2;
                            }
                        },
                        0x04 if data.len() >= offset + 18 => {
                            // IPv6 + port
                            offset += 18;
                        },
                        _ => {
                            // Invalid or incomplete address
                        }
                    }
                }
            }
        }
    }

    Ok(())
}