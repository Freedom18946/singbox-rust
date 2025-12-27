//! Routing context population helpers.
//!
//! This module provides utilities to populate `RouteCtx` fields from various
//! sources including Clash API, platform monitors, and process information.
//!
//! # Sources
//! - `clash_mode`: From ClashApiServer::get_mode()
//! - `client`: Inferred from User-Agent or TLS ClientHello
//! - `network_type`: From platform NetworkMonitor
//! - `network_is_expensive`: From platform NetworkMonitor
//! - `network_is_constrained`: From platform NetworkMonitor
//! - `user`/`user_id`/`group`/`group_id`: From process info lookup

#[allow(unused_imports)]
use std::sync::Arc;

/// Source of routing context information.
#[derive(Debug, Clone, Default)]
pub struct ContextSource {

    /// Network monitor for network type info.
    #[cfg(feature = "platform")]
    pub network_monitor: Option<Arc<sb_platform::monitor::NetworkMonitor>>,
}

/// Owned routing context data for population.
#[derive(Debug, Clone, Default)]
pub struct ContextData {
    /// Clash mode (rule/global/direct).
    pub clash_mode: Option<String>,
    /// Detected client (Chrome/Firefox/Clash/etc).
    pub client: Option<String>,
    /// Android package name.
    pub package_name: Option<String>,
    /// Network type (wifi/cellular/ethernet).
    pub network_type: Option<String>,
    /// Whether network is metered/expensive.
    pub network_is_expensive: Option<bool>,
    /// Whether network is constrained.
    pub network_is_constrained: Option<bool>,
    /// OS-level user name.
    pub user: Option<String>,
    /// OS-level user ID.
    pub user_id: Option<u32>,
    /// OS-level group name.
    pub group: Option<String>,
    /// OS-level group ID.
    pub group_id: Option<u32>,
}

impl ContextData {
    /// Populate from available sources.
    #[allow(unused_variables, unused_mut)]
    pub fn populate(source: &ContextSource) -> Self {
        let mut data = Self::default();



        // Populate network info from platform monitor
        #[cfg(feature = "platform")]
        if let Some(ref monitor) = source.network_monitor {
            data.network_type = Some(monitor.get_network_type().to_string());
            data.network_is_expensive = Some(monitor.is_expensive());
            data.network_is_constrained = Some(monitor.is_constrained());
        }

        data
    }

    /// Infer client from User-Agent string.
    pub fn infer_client_from_user_agent(&mut self, user_agent: Option<&str>) {
        if let Some(ua) = user_agent {
            let ua_lower = ua.to_lowercase();
            self.client = if ua_lower.contains("clash") {
                Some("Clash".to_string())
            } else if ua_lower.contains("chrome") {
                Some("Chrome".to_string())
            } else if ua_lower.contains("firefox") {
                Some("Firefox".to_string())
            } else if ua_lower.contains("safari") {
                Some("Safari".to_string())
            } else if ua_lower.contains("edge") {
                Some("Edge".to_string())
            } else if ua_lower.contains("curl") {
                Some("curl".to_string())
            } else if ua_lower.contains("wget") {
                Some("wget".to_string())
            } else {
                None
            };
        }
    }

    /// Populate process info for a given source port (Unix only).
    #[cfg(unix)]
    pub fn populate_process_info(&mut self, _source_port: u16) {
        // TODO: Lookup process by source port using /proc/net/tcp or lsof
        // For now, use current process info as fallback
        unsafe {
            self.user_id = Some(libc::getuid());
            self.group_id = Some(libc::getgid());
        }

        // Try to resolve user/group names
        #[cfg(target_os = "linux")]
        {
            if let Some(uid) = self.user_id {
                self.user = get_user_name(uid);
            }
            if let Some(gid) = self.group_id {
                self.group = get_group_name(gid);
            }
        }
    }

    /// Set Android package name (platform-specific).
    #[cfg(target_os = "android")]
    pub fn set_package_name(&mut self, package: impl Into<String>) {
        self.package_name = Some(package.into());
    }

    /// Try to resolve package name from UID (Android stub).
    #[cfg(target_os = "android")]
    pub fn resolve_package_from_uid(&mut self, _uid: u32) {
        // TODO: Implement /data/system/packages.list parsing or PackageManager lookup
    }
}

/// Get user name from UID (Linux only).
#[cfg(target_os = "linux")]
fn get_user_name(uid: u32) -> Option<String> {
    use std::ffi::CStr;
    unsafe {
        let pwd = libc::getpwuid(uid);
        if !pwd.is_null() {
            let name = CStr::from_ptr((*pwd).pw_name);
            return name.to_str().ok().map(String::from);
        }
    }
    None
}

/// Get group name from GID (Linux only).
#[cfg(target_os = "linux")]
fn get_group_name(gid: u32) -> Option<String> {
    use std::ffi::CStr;
    unsafe {
        let grp = libc::getgrgid(gid);
        if !grp.is_null() {
            let name = CStr::from_ptr((*grp).gr_name);
            return name.to_str().ok().map(String::from);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_data_default() {
        let data = ContextData::default();
        assert!(data.clash_mode.is_none());
        assert!(data.client.is_none());
    }

    #[test]
    fn test_infer_client_from_user_agent() {
        let mut data = ContextData::default();

        data.infer_client_from_user_agent(Some("Mozilla/5.0 (Windows NT) Chrome/100"));
        assert_eq!(data.client, Some("Chrome".to_string()));

        data.infer_client_from_user_agent(Some("ClashForAndroid/3.0"));
        assert_eq!(data.client, Some("Clash".to_string()));

        data.infer_client_from_user_agent(Some("curl/7.68.0"));
        assert_eq!(data.client, Some("curl".to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn test_populate_process_info() {
        let mut data = ContextData::default();
        data.populate_process_info(0);

        // Should have at least user_id and group_id
        assert!(data.user_id.is_some());
        assert!(data.group_id.is_some());
    }
}
