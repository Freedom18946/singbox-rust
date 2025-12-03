//! System Proxy Manager
//! 系统代理管理器
//!
//! Manages system-wide proxy settings with Go-parity interface monitoring.
//! 管理系统级代理设置，具有与 Go 对等的接口监控功能。
//!
//! ## Features
//! - Cross-platform support (macOS, Linux, Windows, Android)
//! - Interface monitor callbacks (macOS) for automatic proxy updates
//! - SOCKS/HTTP proxy configuration
//!
//! ## Go Parity (`common/settings/system_proxy.go`)
//! - `IsEnabled()` - Check if proxy is enabled
//! - `Enable()` - Enable system proxy
//! - `Disable()` - Disable system proxy
//! - Interface monitor callbacks (macOS)

use std::{
    collections::HashMap,
    io,
    io::ErrorKind,
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
};

use parking_lot::{Mutex, RwLock};
use tracing::{debug, info};

#[cfg(any(target_os = "linux", target_os = "android"))]
use tracing::warn;

/// Get the name of the default network interface.
/// 获取默认网络接口的名称。
#[must_use]
pub fn get_default_interface_name() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        default_interface_macos()
    }
    #[cfg(target_os = "linux")]
    {
        default_interface_linux()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        None
    }
}

#[cfg(target_os = "android")]
use libc::geteuid;

/// Network interface information.
/// 网络接口信息。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceInfo {
    /// Interface name (e.g., "en0", "eth0").
    /// 接口名称（例如 "en0", "eth0"）。
    pub name: String,
    /// Interface index.
    /// 接口索引。
    pub index: u32,
}

impl InterfaceInfo {
    /// Create new interface info.
    /// 创建新的接口信息。
    pub fn new(name: impl Into<String>, index: u32) -> Self {
        Self {
            name: name.into(),
            index,
        }
    }
}

/// Callback type for interface update events.
/// 接口更新事件的回调类型。
pub type InterfaceUpdateCallback = Box<dyn Fn(Option<&InterfaceInfo>, u32) + Send + Sync>;

/// Default interface monitor trait.
/// 默认接口监控 trait。
///
/// Mirrors Go's `tun.DefaultInterfaceMonitor` for proxy auto-update.
/// 镜像 Go 的 `tun.DefaultInterfaceMonitor` 用于代理自动更新。
pub trait DefaultInterfaceMonitor: Send + Sync {
    /// Get the current default interface.
    /// 获取当前默认接口。
    fn default_interface(&self) -> Option<InterfaceInfo>;

    /// Register a callback for interface updates.
    /// 注册接口更新回调。
    ///
    /// Returns a handle that can be used to unregister the callback.
    /// 返回一个可用于注销回调的句柄。
    fn register_callback(&self, callback: InterfaceUpdateCallback) -> usize;

    /// Unregister a callback by handle.
    /// 通过句柄注销回调。
    fn unregister_callback(&self, handle: usize);
}

/// Simple interface monitor implementation using polling.
/// 使用轮询的简单接口监控实现。
#[derive(Default)]
pub struct SimpleInterfaceMonitor {
    callbacks: RwLock<HashMap<usize, InterfaceUpdateCallback>>,
    next_id: Mutex<usize>,
    current_interface: RwLock<Option<InterfaceInfo>>,
}

impl SimpleInterfaceMonitor {
    /// Create a new simple interface monitor.
    /// 创建新的简单接口监控。
    #[must_use]
    pub fn new() -> Self {
        let monitor = Self::default();

        // Initialize with current interface
        #[cfg(target_os = "macos")]
        {
            if let Some(name) = default_interface_macos() {
                *monitor.current_interface.write() = Some(InterfaceInfo::new(name, 0));
            }
        }

        monitor
    }

    /// Trigger an interface update check.
    /// 触发接口更新检查。
    pub fn check_interface(&self) {
        #[cfg(target_os = "macos")]
        {
            let new_interface = default_interface_macos().map(|name| InterfaceInfo::new(name, 0));
            let current = self.current_interface.read().clone();

            if new_interface != current {
                debug!(
                    old=?current.as_ref().map(|i| &i.name),
                    new=?new_interface.as_ref().map(|i| &i.name),
                    "Interface changed"
                );
                (*self.current_interface.write()).clone_from(&new_interface);

                // Notify all callbacks
                let callbacks = self.callbacks.read();
                for callback in callbacks.values() {
                    callback(new_interface.as_ref(), 0);
                }
            }
        }
    }
}

impl DefaultInterfaceMonitor for SimpleInterfaceMonitor {
    fn default_interface(&self) -> Option<InterfaceInfo> {
        self.current_interface.read().clone()
    }

    fn register_callback(&self, callback: InterfaceUpdateCallback) -> usize {
        let mut next_id = self.next_id.lock();
        let id = *next_id;
        *next_id += 1;
        drop(next_id); // Release lock early

        self.callbacks.write().insert(id, callback);
        debug!(callback_id = id, "Registered interface callback");
        id
    }

    fn unregister_callback(&self, handle: usize) {
        self.callbacks.write().remove(&handle);
        debug!(callback_id = handle, "Unregistered interface callback");
    }
}

/// Cross-platform system proxy manager with Go-parity interface monitoring.
/// 跨平台系统代理管理器，具有与 Go 对等的接口监控功能。
///
/// ## Go Parity
/// Mirrors `common/settings/system_proxy.go` with:
/// - Platform-specific proxy configuration
/// - Interface monitor callbacks (macOS)
/// - Automatic proxy update on interface change
pub struct SystemProxyManager {
    port: u16,
    support_socks: bool,
    enabled: AtomicBool,
    interface_name: Mutex<String>,
    monitor: Option<Arc<dyn DefaultInterfaceMonitor>>,
    callback_handle: Mutex<Option<usize>>,
}

impl SystemProxyManager {
    /// Create a new system proxy manager without interface monitoring.
    /// 创建新的系统代理管理器（不带接口监控）。
    #[must_use]
    pub fn new(port: u16, support_socks: bool) -> Self {
        Self {
            port,
            support_socks,
            enabled: AtomicBool::new(false),
            interface_name: Mutex::new(String::new()),
            monitor: None,
            callback_handle: Mutex::new(None),
        }
    }

    /// Create a new system proxy manager with interface monitoring (Go parity).
    /// 创建带接口监控的新系统代理管理器（Go 对等）。
    ///
    /// ## macOS Behavior
    /// When the default interface changes, the proxy will be automatically
    /// updated on the new interface.
    /// 当默认接口变化时，代理将自动在新接口上更新。
    pub fn with_monitor(
        port: u16,
        support_socks: bool,
        monitor: Arc<dyn DefaultInterfaceMonitor>,
    ) -> Self {
        Self {
            port,
            support_socks,
            enabled: AtomicBool::new(false),
            interface_name: Mutex::new(String::new()),
            monitor: Some(monitor),
            callback_handle: Mutex::new(None),
        }
    }

    /// Check if the system proxy is enabled.
    /// 检查系统代理是否已启用。
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    /// Enable system proxy pointing to 127.0.0.1:port.
    /// 启用指向 127.0.0.1:port 的系统代理。
    ///
    /// # Errors
    /// Returns error if system command for proxy configuration fails
    pub fn enable(&self) -> io::Result<()> {
        #[cfg(target_os = "macos")]
        {
            // Register interface callback if monitor is available
            if let Some(ref monitor) = self.monitor {
                let enabled = Arc::new(AtomicBool::new(true));
                let port = self.port;
                let support_socks = self.support_socks;

                let callback =
                    Box::new(move |new_interface: Option<&InterfaceInfo>, _flags: u32| {
                        if !enabled.load(Ordering::SeqCst) {
                            return;
                        }
                        if let Some(iface) = new_interface {
                            debug!(interface = %iface.name, "Interface changed, updating proxy");
                            // Update proxy on new interface
                            let _ = update_macos_proxy(&iface.name, port, support_socks);
                        }
                    });

                let handle = monitor.register_callback(callback);
                *self.callback_handle.lock() = Some(handle);
            }

            self.update_proxy_internal()?;
        }

        #[cfg(target_os = "linux")]
        {
            self.enable_linux()?;
        }

        #[cfg(target_os = "windows")]
        {
            self.enable_windows()?;
        }

        #[cfg(target_os = "android")]
        {
            self.enable_android()?;
        }

        #[cfg(not(any(
            target_os = "macos",
            target_os = "linux",
            target_os = "windows",
            target_os = "android"
        )))]
        {
            warn!("System proxy not supported on this platform");
        }

        self.enabled.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Disable system proxy.
    /// 禁用系统代理。
    ///
    /// # Errors
    /// Returns error if system command for proxy disable fails
    pub fn disable(&self) -> io::Result<()> {
        // Unregister callback if any
        if let Some(ref monitor) = self.monitor {
            let value = self.callback_handle.lock().take();
            if let Some(handle) = value {
                monitor.unregister_callback(handle);
            }
        }

        #[cfg(target_os = "macos")]
        {
            self.disable_macos();
        }

        #[cfg(target_os = "linux")]
        {
            self.disable_linux()?;
        }

        #[cfg(target_os = "windows")]
        {
            self.disable_windows()?;
        }

        #[cfg(target_os = "android")]
        {
            self.disable_android()?;
        }

        #[cfg(not(any(
            target_os = "macos",
            target_os = "linux",
            target_os = "windows",
            target_os = "android"
        )))]
        {
            warn!("System proxy not supported on this platform");
        }

        self.enabled.store(false, Ordering::SeqCst);
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn update_proxy_internal(&self) -> io::Result<()> {
        let new_interface = self.monitor.as_ref().map_or_else(
            || default_interface_macos().map(|name| InterfaceInfo::new(name, 0)),
            |monitor| monitor.default_interface(),
        );

        let current_name = self.interface_name.lock().clone();

        if let Some(ref iface) = new_interface {
            if iface.name == current_name {
                return Ok(());
            }

            // Disable on old interface if any
            if !current_name.is_empty() {
                disable_macos_proxy(&current_name, self.support_socks);
            }

            // Enable on new interface
            (*self.interface_name.lock()).clone_from(&iface.name);
            update_macos_proxy(&iface.name, self.port, self.support_socks)?;
        }

        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn disable_macos(&self) {
        let interface_name = self.interface_name.lock().clone();
        if interface_name.is_empty() {
            return;
        }

        disable_macos_proxy(&interface_name, self.support_socks);
        *self.interface_name.lock() = String::new();
    }

    #[cfg(target_os = "linux")]
    fn enable_linux(&self) -> io::Result<()> {
        let port = self.port.to_string();
        let addr = "127.0.0.1";
        let has_gsettings = command_exists("gsettings");
        let kde = detect_kde_writer();

        if has_gsettings {
            let _ = Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy.http", "host", addr])
                .output();
            let _ = Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy.http", "port", &port])
                .output();
            let _ = Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy.https", "host", addr])
                .output();
            let _ = Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy.https", "port", &port])
                .output();
            if self.support_socks {
                let _ = Command::new("gsettings")
                    .args(["set", "org.gnome.system.proxy.socks", "host", addr])
                    .output();
                let _ = Command::new("gsettings")
                    .args(["set", "org.gnome.system.proxy.socks", "port", &port])
                    .output();
                let _ = Command::new("gsettings")
                    .args(["set", "org.gnome.system.proxy", "use-same-proxy", "true"])
                    .output();
            }
            let _ = Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy", "mode", "manual"])
                .output();
        }

        if let Some(kcmd) = kde {
            set_kde_proxy(&kcmd, "http", addr, &port)?;
            set_kde_proxy(&kcmd, "https", addr, &port)?;
            if self.support_socks {
                set_kde_proxy(&kcmd, "socks", addr, &port)?;
            }
            let _ = Command::new(&kcmd)
                .args([
                    "--file",
                    "kioslaverc",
                    "--group",
                    "Proxy Settings",
                    "--key",
                    "ProxyType",
                    "1",
                ])
                .output();
            let _ = Command::new("dbus-send")
                .args([
                    "--type=signal",
                    "/KIO/Scheduler",
                    "org.kde.KIO.Scheduler.reparseSlaveConfiguration",
                    "string:''",
                ])
                .output();
        }

        if !has_gsettings && kde.is_none() {
            warn!("System proxy unsupported desktop environment");
        }

        info!("System proxy set to {addr}:{port} (linux)");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn disable_linux(&self) -> io::Result<()> {
        let has_gsettings = command_exists("gsettings");
        let kde = detect_kde_writer();

        if has_gsettings {
            let _ = Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy", "mode", "none"])
                .output();
        }

        if let Some(kcmd) = kde {
            let _ = Command::new(&kcmd)
                .args([
                    "--file",
                    "kioslaverc",
                    "--group",
                    "Proxy Settings",
                    "--key",
                    "ProxyType",
                    "0",
                ])
                .output();
            let _ = Command::new("dbus-send")
                .args([
                    "--type=signal",
                    "/KIO/Scheduler",
                    "org.kde.KIO.Scheduler.reparseSlaveConfiguration",
                    "string:''",
                ])
                .output();
        }

        info!("System proxy disabled (linux)");
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn enable_windows(&self) -> io::Result<()> {
        // Registry-based; wininet equivalent would require FFI.
        let proxy_server = if self.support_socks {
            format!(
                "http=127.0.0.1:{p};https=127.0.0.1:{p};socks=127.0.0.1:{p}",
                p = self.port
            )
        } else {
            format!("http=127.0.0.1:{p};https=127.0.0.1:{p}", p = self.port)
        };

        let _ = Command::new("reg")
            .args([
                "add",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                "/v",
                "ProxyEnable",
                "/t",
                "REG_DWORD",
                "/d",
                "1",
                "/f",
            ])
            .output();

        let _ = Command::new("reg")
            .args([
                "add",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                "/v",
                "ProxyServer",
                "/t",
                "REG_SZ",
                "/d",
                &proxy_server,
                "/f",
            ])
            .output();

        info!("System proxy set on Windows -> 127.0.0.1:{}", self.port);
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn disable_windows(&self) -> io::Result<()> {
        let _ = Command::new("reg")
            .args([
                "add",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                "/v",
                "ProxyEnable",
                "/t",
                "REG_DWORD",
                "/d",
                "0",
                "/f",
            ])
            .output();
        info!("System proxy disabled (windows)");
        Ok(())
    }
}

// macOS helper functions

#[cfg(target_os = "macos")]
fn default_interface_macos() -> Option<String> {
    let output = Command::new("route")
        .args(["get", "default"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix("interface:") {
            return Some(rest.trim().to_string());
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn macos_hardware_port_map() -> io::Result<HashMap<String, String>> {
    let output = Command::new("networksetup")
        .arg("-listallhardwareports")
        .stdout(Stdio::piped())
        .output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let mut map = HashMap::new();
    let mut current_port: Option<String> = None;
    for line in text.lines() {
        if let Some(port) = line.strip_prefix("Hardware Port:") {
            current_port = Some(port.trim().to_string());
        } else if let Some(dev) = line.strip_prefix("Device:") {
            if let Some(port_name) = current_port.take() {
                map.insert(dev.trim().to_string(), port_name);
            }
        }
    }
    Ok(map)
}

#[cfg(target_os = "macos")]
fn get_interface_display_name(interface_name: &str) -> io::Result<String> {
    let mapping = macos_hardware_port_map()?;
    mapping.get(interface_name).cloned().ok_or_else(|| {
        io::Error::new(
            ErrorKind::NotFound,
            format!("{interface_name} not found in networksetup"),
        )
    })
}

#[cfg(target_os = "macos")]
fn update_macos_proxy(interface_name: &str, port: u16, support_socks: bool) -> io::Result<()> {
    let display_name = get_interface_display_name(interface_name)?;
    let port_str = port.to_string();
    let addr = "127.0.0.1";

    if support_socks {
        let _ = Command::new("networksetup")
            .args(["-setsocksfirewallproxy", &display_name, addr, &port_str])
            .output();
    }
    let _ = Command::new("networksetup")
        .args(["-setwebproxy", &display_name, addr, &port_str])
        .output();
    let _ = Command::new("networksetup")
        .args(["-setsecurewebproxy", &display_name, addr, &port_str])
        .output();

    info!(
        "System proxy set on macOS interface {} -> {}:{}",
        display_name, addr, port
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn disable_macos_proxy(interface_name: &str, support_socks: bool) {
    let Ok(display_name) = get_interface_display_name(interface_name) else {
        return; // Interface may have been removed
    };

    if support_socks {
        let _ = Command::new("networksetup")
            .args(["-setsocksfirewallproxystate", &display_name, "off"])
            .output();
    }
    let _ = Command::new("networksetup")
        .args(["-setwebproxystate", &display_name, "off"])
        .output();
    let _ = Command::new("networksetup")
        .args(["-setsecurewebproxystate", &display_name, "off"])
        .output();

    info!("System proxy disabled on macOS interface {}", display_name);
}

// Linux helper functions

#[cfg(any(target_os = "linux", target_os = "android"))]
fn command_exists(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn detect_kde_writer() -> Option<String> {
    const CANDIDATES: [&str; 2] = ["kwriteconfig6", "kwriteconfig5"];
    for candidate in CANDIDATES {
        if command_exists(candidate) {
            return Some(candidate.to_string());
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn set_kde_proxy(cmd: &str, proxy_type: &str, host: &str, port: &str) -> io::Result<()> {
    let url = if proxy_type == "socks" {
        format!("socks://{host}:{port}")
    } else {
        format!("http://{host}:{port}")
    };
    let _ = Command::new(cmd)
        .args([
            "--file",
            "kioslaverc",
            "--group",
            "Proxy Settings",
            "--key",
            &format!("{proxy_type}Proxy"),
            &url,
        ])
        .output()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn default_interface_linux() -> Option<String> {
    // Simple implementation parsing /proc/net/route
    // Destination 00000000 is default route
    if let Ok(content) = std::fs::read_to_string("/proc/net/route") {
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 && parts[1] == "00000000" {
                return Some(parts[0].to_string());
            }
        }
    }
    None
}

// Android helper functions

#[cfg(target_os = "android")]
fn detect_rish() -> Option<String> {
    if command_exists("rish") {
        Some("rish".to_string())
    } else {
        None
    }
}

#[cfg(target_os = "android")]
fn run_android_shell(use_rish: bool, rish_path: Option<String>, args: &[&str]) -> io::Result<()> {
    let status = if use_rish {
        let rish = rish_path.unwrap_or_else(|| "rish".to_string());
        let mut cmdline = String::from("settings");
        for a in args {
            cmdline.push(' ');
            cmdline.push_str(a);
        }
        Command::new("sh")
            .args([rish.as_str(), "-c", &cmdline])
            .status()
    } else {
        Command::new("settings").args(args).status()
    }?;

    if status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            ErrorKind::Other,
            format!("settings command failed: {:?}", status.code()),
        ))
    }
}

#[cfg(target_os = "android")]
impl SystemProxyManager {
    fn enable_android(&self) -> io::Result<()> {
        // SAFETY: geteuid is a simple syscall that returns the effective user ID
        let uid = unsafe { geteuid() as u32 };
        let allow_direct = uid == 0 || uid == 1000 || uid == 2000;
        let rish = detect_rish();
        if !allow_direct && rish.is_none() {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "root/system uid or rish required to set system proxy",
            ));
        }
        let use_rish = !allow_direct;
        run_android_shell(
            use_rish,
            rish,
            &[
                "put",
                "global",
                "http_proxy",
                &format!("127.0.0.1:{}", self.port),
            ],
        )?;
        if self.support_socks {
            warn!("Android system proxy only configures http_proxy; SOCKS is not supported");
        }
        info!("System proxy set on Android -> 127.0.0.1:{}", self.port);
        Ok(())
    }

    fn disable_android(&self) -> io::Result<()> {
        // SAFETY: geteuid is a simple syscall that returns the effective user ID
        let uid = unsafe { geteuid() as u32 };
        let allow_direct = uid == 0 || uid == 1000 || uid == 2000;
        let rish = detect_rish();
        if !allow_direct && rish.is_none() {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "root/system uid or rish required to clear system proxy",
            ));
        }
        let use_rish = !allow_direct;
        run_android_shell(use_rish, rish, &["put", "global", "http_proxy", ":0"])?;
        info!("System proxy disabled on Android");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_info() {
        let info = InterfaceInfo::new("en0", 1);
        assert_eq!(info.name, "en0");
        assert_eq!(info.index, 1);
    }

    #[test]
    fn test_simple_interface_monitor() {
        let monitor = SimpleInterfaceMonitor::new();

        let callback_called = Arc::new(AtomicBool::new(false));
        let callback_called_clone = callback_called.clone();

        let _handle = monitor.register_callback(Box::new(move |_iface, _flags| {
            callback_called_clone.store(true, Ordering::SeqCst);
        }));

        // On non-macOS, the interface will be None
        #[cfg(not(target_os = "macos"))]
        assert!(monitor.default_interface().is_none());
    }

    #[test]
    fn test_system_proxy_manager_creation() {
        let manager = SystemProxyManager::new(8080, true);
        assert!(!manager.is_enabled());
        assert_eq!(manager.port, 8080);
        assert!(manager.support_socks);
    }

    #[test]
    fn test_system_proxy_manager_with_monitor() {
        let monitor = Arc::new(SimpleInterfaceMonitor::new());
        let manager = SystemProxyManager::with_monitor(8080, true, monitor);
        assert!(!manager.is_enabled());
        assert!(manager.monitor.is_some());
    }
}
