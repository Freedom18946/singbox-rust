//! Integration tests for the TUN device abstraction layer.

use sb_platform::tun::validation::{validate_auto_route, TunValidationConfig};
use sb_platform::tun::{create_platform_device, AsyncTunDevice, TunConfig, TunError, TunManager};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn is_environmental_tun_error(error: &TunError) -> bool {
    match error {
        TunError::UnsupportedPlatform
        | TunError::PermissionDenied
        | TunError::DeviceNotFound(_)
        | TunError::DeviceBusy(_)
        | TunError::OperationFailed(_)
        | TunError::IoError(_) => true,
        TunError::InvalidConfig(_) => false,
    }
}

#[test]
fn test_tun_device_abstraction_config() {
    let config = TunConfig {
        name: "test-tun0".to_string(),
        mtu: 1400,
        ipv4: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 100, 1))),
        ipv6: Some(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))),
        auto_route: false,
        table: Some(100),
    };

    assert_eq!(config.name, "test-tun0");
    assert_eq!(config.mtu, 1400);
    assert!(config.ipv4.is_some());
    assert!(config.ipv6.is_some());
    assert_eq!(config.table, Some(100));
}

#[test]
fn test_platform_device_creation_reports_real_outcome() {
    let config = TunConfig {
        name: platform_test_name(),
        mtu: 1500,
        ..Default::default()
    };

    match create_platform_device(&config) {
        Ok(mut device) => {
            assert!(!device.name().is_empty());
            assert_eq!(device.mtu(), 1500);
            assert!(device.is_active());
            assert!(device.close().is_ok());
        }
        Err(error) => assert!(
            is_environmental_tun_error(&error),
            "unexpected TUN creation error: {error:?}"
        ),
    }
}

#[tokio::test]
async fn test_async_tun_device_creation_reports_real_outcome() {
    let config = TunConfig {
        name: platform_test_name(),
        mtu: 1400,
        ..Default::default()
    };

    match AsyncTunDevice::new(&config) {
        Ok(mut async_device) => {
            assert!(!async_device.name().is_empty());
            assert_eq!(async_device.mtu(), 1400);
            assert!(async_device.is_active());
            assert!(async_device.close().is_ok());
        }
        Err(error) => assert!(
            is_environmental_tun_error(&error),
            "unexpected async TUN creation error: {error:?}"
        ),
    }
}

#[test]
fn test_tun_manager_empty_operations() {
    let mut manager = TunManager::new();

    assert!(manager.list_devices().is_empty());
    assert!(manager.remove_device("missing-device").is_ok());
    assert!(manager.close_all().is_ok());
}

#[test]
fn test_tun_validation_rejects_invalid_config() {
    let config = TunValidationConfig {
        name: "invalid/name".to_string(),
        mtu: 100,
        auto_redirect: true,
        auto_route: false,
        ..Default::default()
    };

    let result = validate_auto_route(&config);
    assert!(!result.is_valid());
    assert!(result.errors().len() >= 2);
}

#[test]
fn test_platform_specific_default_name() {
    let config = TunConfig::default();

    #[cfg(target_os = "linux")]
    assert_eq!(config.name, "tun0");

    #[cfg(target_os = "macos")]
    assert_eq!(config.name, "utun8");

    #[cfg(target_os = "windows")]
    assert_eq!(config.name, "wintun");

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    assert_eq!(config.name, "tun0");
}

#[test]
fn test_tun_config_validation() {
    let default_config = TunConfig::default();
    assert!(!default_config.name.is_empty());
    assert_eq!(default_config.mtu, 1500);
    assert!(default_config.ipv4.is_none());
    assert!(default_config.ipv6.is_none());
    assert!(!default_config.auto_route);
    assert!(default_config.table.is_none());

    let custom_config = TunConfig {
        name: "custom-tun".to_string(),
        mtu: 1400,
        ipv4: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        ipv6: Some(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))),
        auto_route: true,
        table: Some(42),
    };

    assert_eq!(custom_config.name, "custom-tun");
    assert_eq!(custom_config.mtu, 1400);
    assert!(custom_config.ipv4.is_some());
    assert!(custom_config.ipv6.is_some());
    assert!(custom_config.auto_route);
    assert_eq!(custom_config.table, Some(42));
}

#[test]
fn test_error_types_comprehensive() {
    let errors = vec![
        TunError::UnsupportedPlatform,
        TunError::DeviceNotFound("test-device".to_string()),
        TunError::PermissionDenied,
        TunError::DeviceBusy("test-device".to_string()),
        TunError::InvalidConfig("invalid setting".to_string()),
        TunError::OperationFailed("operation failed".to_string()),
        TunError::IoError(std::io::Error::other("test error")),
    ];

    for error in errors {
        assert!(!error.to_string().is_empty());
    }
}

fn platform_test_name() -> String {
    #[cfg(target_os = "macos")]
    return "utun".to_string();

    #[cfg(target_os = "windows")]
    return "TestWinTun".to_string();

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    "test-tun0".to_string()
}
