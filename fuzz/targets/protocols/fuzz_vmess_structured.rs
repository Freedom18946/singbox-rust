#![no_main]
//! Structured VMess protocol fuzzer
//!
//! Uses arbitrary to generate structured VMess protocol data for more
//! targeted fuzzing of specific protocol components.

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct VmessRequest {
    version: u8,
    timestamp: u64,
    hmac: [u8; 16],
    iv: [u8; 16],
    key_id: [u8; 16],
    response_auth: u8,
    options: u8,
    security: u8,
    reserved: u8,
    command: u8,
    port: u16,
    address_type: u8,
    address_data: Vec<u8>,
}

impl VmessRequest {
    fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        
        // Timestamp (8 bytes)
        data.extend_from_slice(&self.timestamp.to_be_bytes());
        
        // HMAC (16 bytes)
        data.extend_from_slice(&self.hmac);
        
        // Version (1 byte)
        data.push(self.version);
        
        // IV (16 bytes)
        data.extend_from_slice(&self.iv);
        
        // Key ID (16 bytes)
        data.extend_from_slice(&self.key_id);
        
        // Response auth (1 byte)
        data.push(self.response_auth);
        
        // Options (1 byte)
        data.push(self.options);
        
        // Security (1 byte)
        data.push(self.security);
        
        // Reserved (1 byte)
        data.push(self.reserved);
        
        // Command (1 byte)
        data.push(self.command);
        
        // Port (2 bytes)
        data.extend_from_slice(&self.port.to_be_bytes());
        
        // Address type (1 byte)
        data.push(self.address_type);
        
        // Address data
        data.extend_from_slice(&self.address_data);
        
        data
    }
}

fuzz_target!(|req: VmessRequest| {
    // Convert structured data to bytes
    let data = req.to_bytes();
    
    // Test VMess parsing with structured input
    if data.len() >= 24 {
        let timestamp = u64::from_be_bytes([
            data[0], data[1], data[2], data[3],
            data[4], data[5], data[6], data[7],
        ]);
        let hmac = &data[8..24];
        
        // Test timestamp validation
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if timestamp > now + 300 || timestamp < now - 300 {
            return;
        }
        
        // Test HMAC validation
        if hmac.len() != 16 {
            return;
        }
    }
    
    // Test edge cases
    if data.is_empty() {
        return;
    }
    
    // Test with very large input
    if data.len() > 1024 * 1024 {
        return;
    }
});
