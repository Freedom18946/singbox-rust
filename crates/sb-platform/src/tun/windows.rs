//! Windows TUN device guard.
//!
//! WinTun support requires a real FFI binding to the WinTun DLL. This module
//! validates configuration but fails creation explicitly until that binding is
//! wired, so callers do not observe a fake active adapter.

use super::{TunConfig, TunDevice, TunError};

/// Windows TUN device state.
pub struct WindowsTun {
    name: String,
    mtu: u32,
    active: bool,
}

impl WindowsTun {
    fn validate_config(config: &TunConfig) -> Result<(), TunError> {
        if config.name.is_empty() || config.name.len() > 127 || config.name.contains(['/', '\0']) {
            return Err(TunError::InvalidConfig("Invalid adapter name".to_string()));
        }
        Ok(())
    }

    fn wintun_unavailable() -> TunError {
        TunError::OperationFailed("WinTun adapter support is not wired in sb-platform".to_string())
    }
}

impl TunDevice for WindowsTun {
    fn create(config: &TunConfig) -> Result<Self, TunError>
    where
        Self: Sized,
    {
        Self::validate_config(config)?;
        Err(Self::wintun_unavailable())
    }

    fn read(&mut self, _buf: &mut [u8]) -> Result<usize, TunError> {
        if !self.active {
            return Err(TunError::OperationFailed(
                "Device is not active".to_string(),
            ));
        }

        Err(Self::wintun_unavailable())
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize, TunError> {
        if !self.active {
            return Err(TunError::OperationFailed(
                "Device is not active".to_string(),
            ));
        }

        if buf.is_empty() {
            return Ok(0);
        }

        Err(Self::wintun_unavailable())
    }

    fn close(&mut self) -> Result<(), TunError> {
        self.active = false;
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn mtu(&self) -> u32 {
        self.mtu
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

impl Drop for WindowsTun {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_windows_tun_config() {
        let config = TunConfig {
            name: "TestWinTun".to_string(),
            mtu: 1400,
            ipv4: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            ..Default::default()
        };

        assert_eq!(config.name, "TestWinTun");
        assert_eq!(config.mtu, 1400);
        assert!(config.ipv4.is_some());
    }

    #[test]
    fn test_invalid_config() {
        let config = TunConfig {
            name: String::new(),
            ..Default::default()
        };

        let result = WindowsTun::create(&config);
        assert!(matches!(result, Err(TunError::InvalidConfig(_))));
    }

    #[test]
    fn test_wintun_creation_fails_until_bound() {
        let config = TunConfig {
            name: "TestWinTun".to_string(),
            ..Default::default()
        };

        let result = WindowsTun::create(&config);
        assert!(matches!(result, Err(TunError::OperationFailed(_))));
    }
}
