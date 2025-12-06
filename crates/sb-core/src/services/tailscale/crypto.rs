use snow::{Builder, HandshakeState, TransportState};
use std::io;
use thiserror::Error;

/// Noise protocol parameters used by Tailscale (Noise_IK_25519_ChaChaPoly_BLAKE2s).
const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// Error type for Tailscale crypto operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Noise error: {0}")]
    Noise(#[from] snow::Error),
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Invalid state")]
    InvalidState,
}

/// Tailscale Noise Protocol Handler.
pub struct TailscaleNoise {
    state: Option<NoiseState>,
}

enum NoiseState {
    Handshaking(Box<HandshakeState>),
    Transport(TransportState),
}

impl TailscaleNoise {
    /// Initialize a new Noise handshake (Initiator side).
    pub fn new(local_private_key: &[u8], remote_public_key: &[u8]) -> Result<Self, CryptoError> {
        let builder = Builder::new(NOISE_PARAMS.parse().unwrap());
        
        let state = builder
            .local_private_key(local_private_key)
            .remote_public_key(remote_public_key)
            .build_initiator()?;

        Ok(Self {
            state: Some(NoiseState::Handshaking(Box::new(state))),
        })
    }

    /// Initialize a new Noise handshake (Responder side - for simulation/testing).
    pub fn new_responder(local_private_key: &[u8], remote_public_key: &[u8]) -> Result<Self, CryptoError> {
        let builder = Builder::new(NOISE_PARAMS.parse().unwrap());
        
        let state = builder
            .local_private_key(local_private_key)
            .remote_public_key(remote_public_key)
            .build_responder()?;

        Ok(Self {
            state: Some(NoiseState::Handshaking(Box::new(state))),
        })
    }

    /// Perform the first handshake message (write).
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut buffer = vec![0u8; 65535];
        let state = self.state.take().ok_or(CryptoError::InvalidState)?;

        match state {
            NoiseState::Handshaking(mut s) => {
                let len = s.write_message(payload, &mut buffer)?;
                if s.is_handshake_finished() {
                    self.state = Some(NoiseState::Transport(s.into_transport_mode()?));
                } else {
                    self.state = Some(NoiseState::Handshaking(s));
                }
                buffer.truncate(len);
                Ok(buffer)
            }
            NoiseState::Transport(mut s) => {
                let len = s.write_message(payload, &mut buffer)?;
                self.state = Some(NoiseState::Transport(s));
                buffer.truncate(len);
                Ok(buffer)
            }
        }
    }

    /// Process a received message (read).
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut buffer = vec![0u8; 65535];
        let state = self.state.take().ok_or(CryptoError::InvalidState)?;

        match state {
            NoiseState::Handshaking(mut s) => {
                let len = s.read_message(message, &mut buffer)?;
                if s.is_handshake_finished() {
                    self.state = Some(NoiseState::Transport(s.into_transport_mode()?));
                } else {
                    self.state = Some(NoiseState::Handshaking(s));
                }
                buffer.truncate(len);
                Ok(buffer)
            }
            NoiseState::Transport(mut s) => {
                let len = s.read_message(message, &mut buffer)?;
                self.state = Some(NoiseState::Transport(s));
                buffer.truncate(len);
                Ok(buffer)
            }
        }
    }

    /// Check if handshake is complete.
    pub fn is_handshake_complete(&self) -> bool {
        matches!(self.state, Some(NoiseState::Transport(_)))
    }
    
    /// Encrypt a packet (transport phase).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Reuse write_message which handles transport state
        self.write_message(plaintext)
    }

    /// Decrypt a packet (transport phase).
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Reuse read_message which handles transport state
        self.read_message(ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noise_handshake() {
        // Generate static keys
        let builder = Builder::new(NOISE_PARAMS.parse().unwrap());
        let client_key = builder.generate_keypair().unwrap();
        let server_key = builder.generate_keypair().unwrap();

        // Client initiates
        let mut client = TailscaleNoise::new(&client_key.private, &server_key.public).unwrap();
        
        // Server responds (mocking server logic for test)
        let builder_res = Builder::new(NOISE_PARAMS.parse().unwrap());
        let mut server_state = builder_res
            .local_private_key(&server_key.private)
            .remote_public_key(&client_key.public)
            .build_responder()
            .unwrap();

        // 1. Client -> Server
        let msg1 = client.write_message(b"hello server").unwrap();
        
        // Server reads
        let mut buf = vec![0u8; 65535];
        let len = server_state.read_message(&msg1, &mut buf).unwrap();
        assert_eq!(&buf[..len], b"hello server");

        // 2. Server -> Client
        let len_resp = server_state.write_message(b"hello client", &mut buf).unwrap();
        let msg2 = &buf[..len_resp];
        
        // Client reads
        let resp = client.read_message(msg2).unwrap();
        assert_eq!(&resp, b"hello client");
        
        assert!(client.is_handshake_complete());
    }
}
