/// Network monitor for retrieving network status and tracking changes.
///
/// This module abstracts platform-specific network monitoring capabilities.
/// - Linux: Uses netlink sockets via rtnetlink
/// - macOS/Windows: Best-effort interface probing
use parking_lot::RwLock;
use std::sync::Arc;

/// Network event types for callback notification.
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// A network interface was added or came online.
    LinkUp {
        /// Network interface name that came up.
        interface: String,
    },
    /// A network interface was removed or went offline.
    LinkDown {
        /// Network interface name that went down.
        interface: String,
    },
    /// An IP address was added to an interface.
    AddressAdded {
        /// Network interface name.
        interface: String,
        /// IP address that was added.
        address: String,
    },
    /// An IP address was removed from an interface.
    AddressRemoved {
        /// Network interface name.
        interface: String,
        /// IP address that was removed.
        address: String,
    },
    /// Network route changed.
    RouteChanged,
    /// General network change (unspecified).
    Changed,
}

/// Callback type for network change notifications.
pub type NetworkChangeCallback = Box<dyn Fn(NetworkEvent) + Send + Sync>;

/// Network monitor for retrieving network status and registering change callbacks.
#[derive(Default)]
pub struct NetworkMonitor {
    callbacks: Arc<RwLock<Vec<NetworkChangeCallback>>>,
    #[cfg(target_os = "linux")]
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl std::fmt::Debug for NetworkMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkMonitor")
            .field("callbacks_count", &self.callbacks.read().len())
            .finish()
    }
}

impl Clone for NetworkMonitor {
    fn clone(&self) -> Self {
        Self {
            callbacks: self.callbacks.clone(),
            #[cfg(target_os = "linux")]
            running: self.running.clone(),
        }
    }
}

impl NetworkMonitor {
    /// Create a new network monitor instance.
    pub fn new() -> Self {
        Self {
            callbacks: Arc::new(RwLock::new(Vec::new())),
            #[cfg(target_os = "linux")]
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Register a callback to be notified of network changes.
    pub fn register_callback(&self, callback: NetworkChangeCallback) {
        self.callbacks.write().push(callback);
        tracing::debug!(
            callbacks = self.callbacks.read().len(),
            "Network change callback registered"
        );
    }

    /// Notify all registered callbacks of a network event.
    #[cfg(any(test, target_os = "linux"))]
    fn notify(&self, event: NetworkEvent) {
        let callbacks = self.callbacks.read();
        for callback in callbacks.iter() {
            callback(event.clone());
        }
    }

    /// Get the current network type (e.g., "wifi", "cellular", "ethernet").
    pub fn get_network_type(&self) -> &'static str {
        #[cfg(target_os = "macos")]
        {
            get_network_type_macos()
        }
        #[cfg(target_os = "windows")]
        {
            get_network_type_windows()
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            "unknown"
        }
    }

    /// Check if the current network is expensive (e.g., cellular data).
    pub fn is_expensive(&self) -> bool {
        #[cfg(target_os = "macos")]
        {
            matches!(get_network_type_macos(), "cellular")
        }
        #[cfg(target_os = "windows")]
        {
            matches!(get_network_type_windows(), "cellular")
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            false
        }
    }

    /// Check if the current network is constrained (e.g., low data mode).
    pub fn is_constrained(&self) -> bool {
        // No platform currently supports constrained network detection
        false
    }

    /// Start listening for network changes.
    /// On Linux, this spawns a background task to listen to netlink events.
    #[cfg(target_os = "linux")]
    pub fn start(
        &self,
    ) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error + Send + Sync>> {
        use std::sync::atomic::Ordering;

        if self.running.load(Ordering::SeqCst) {
            return Err("NetworkMonitor already running".into());
        }
        self.running.store(true, Ordering::SeqCst);

        let monitor = self.clone();
        let handle = tokio::spawn(async move {
            if let Err(e) = monitor.listen_netlink().await {
                tracing::error!(error = %e, "NetworkMonitor netlink listener error");
            }
        });

        tracing::info!("NetworkMonitor started (Linux netlink)");
        Ok(handle)
    }

    /// Start listening for network changes.
    ///
    /// Non-Linux platforms currently expose status probing but no change listener.
    #[cfg(not(target_os = "linux"))]
    pub fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!("NetworkMonitor change listener unavailable on this platform");
        Ok(())
    }

    /// Stop listening for network changes.
    #[cfg(target_os = "linux")]
    pub fn stop(&self) {
        use std::sync::atomic::Ordering;
        self.running.store(false, Ordering::SeqCst);
        tracing::info!("NetworkMonitor stopped");
    }

    /// Stop listening for network changes.
    #[cfg(not(target_os = "linux"))]
    pub fn stop(&self) {
        tracing::info!("NetworkMonitor stopped");
    }

    /// Listen to Linux netlink socket for network events.
    #[cfg(all(target_os = "linux", feature = "linux"))]
    async fn listen_netlink(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use futures::stream::TryStreamExt;
        use rtnetlink::new_connection;
        use std::sync::atomic::Ordering;

        let (connection, handle, _messages) = new_connection()?;

        // Spawn the connection driver
        tokio::spawn(connection);

        tracing::debug!("NetworkMonitor: netlink connection established");

        let mut previous_snapshot = None;
        while self.running.load(Ordering::SeqCst) {
            let mut links = handle.link().get().execute();
            let mut link_count = 0;

            loop {
                match links.try_next().await {
                    Ok(Some(_link)) => {
                        link_count += 1;
                    }
                    Ok(None) => break,
                    Err(e) => {
                        tracing::warn!(error = %e, "NetworkMonitor: netlink poll error");
                        break;
                    }
                }
            }

            let current_snapshot = NetworkSnapshot { link_count };
            if let Some(event) = network_snapshot_event(previous_snapshot, current_snapshot) {
                self.notify(event);
            }
            previous_snapshot = Some(current_snapshot);

            // Small delay between polls
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }

        Ok(())
    }

    /// Listen to Linux netlink socket when netlink support is disabled.
    #[cfg(all(target_os = "linux", not(feature = "linux")))]
    async fn listen_netlink(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::warn!("NetworkMonitor: netlink support disabled (linux feature not enabled)");
        Ok(())
    }
}

#[cfg(any(test, target_os = "linux"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NetworkSnapshot {
    link_count: usize,
}

#[cfg(any(test, target_os = "linux"))]
fn network_snapshot_event(
    previous: Option<NetworkSnapshot>,
    current: NetworkSnapshot,
) -> Option<NetworkEvent> {
    match previous {
        None => None,
        Some(previous) if previous == current => None,
        Some(_) => Some(NetworkEvent::Changed),
    }
}

#[cfg(target_os = "macos")]
fn get_network_type_macos() -> &'static str {
    use std::collections::HashSet;
    use std::ffi::CStr;

    let mut names = HashSet::new();
    // SAFETY: libc::getifaddrs is a standard POSIX function that populates
    // a linked list of interface addresses. We check the return value and
    // properly free the memory with freeifaddrs at the end.
    unsafe {
        let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut addrs) != 0 {
            return "unknown";
        }

        let mut cursor = addrs;
        while !cursor.is_null() {
            let ifa = &*cursor;
            if !ifa.ifa_name.is_null() {
                let flags = ifa.ifa_flags as i32;
                let is_up = flags & libc::IFF_UP != 0;
                let is_running = flags & libc::IFF_RUNNING != 0;
                let is_loopback = flags & libc::IFF_LOOPBACK != 0;
                if is_up && is_running && !is_loopback {
                    if let Ok(name) = CStr::from_ptr(ifa.ifa_name).to_str() {
                        names.insert(name.to_string());
                    }
                }
            }
            cursor = (*cursor).ifa_next;
        }

        libc::freeifaddrs(addrs);
    }

    if names.iter().any(|n| n.starts_with("pdp_ip")) {
        return "cellular";
    }
    if names
        .iter()
        .any(|n| n.starts_with("awdl") || n.starts_with("llw"))
    {
        return "wifi";
    }
    if names.iter().any(|n| n.starts_with("en")) {
        return "ethernet";
    }

    "unknown"
}

#[cfg(target_os = "windows")]
fn get_network_type_windows() -> &'static str {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_PREFIX, IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211,
        IF_TYPE_SOFTWARE_LOOPBACK, IF_TYPE_WWANPP, IF_TYPE_WWANPP2, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows::Win32::Networking::WinSock::AF_UNSPEC;

    let mut buffer_size: u32 = 15000;
    let mut buffer: Vec<u8>;

    loop {
        buffer = vec![0u8; buffer_size as usize];
        // SAFETY: buffer points to writable storage of buffer_size bytes, and
        // buffer_size remains valid for GetAdaptersAddresses to update.
        let result = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                GAA_FLAG_INCLUDE_PREFIX,
                None,
                Some(buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut buffer_size,
            )
        };
        match result {
            0 => break,
            111 => continue,
            _ => return "unknown",
        }
    }

    let mut saw_wifi = false;
    let mut saw_ethernet = false;
    let mut saw_cellular = false;

    let mut adapter_ptr = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    // SAFETY: We iterate a valid linked list returned by GetAdaptersAddresses.
    // The backing buffer is kept alive for the whole traversal.
    unsafe {
        while !adapter_ptr.is_null() {
            let adapter = &*adapter_ptr;
            if adapter.OperStatus == IfOperStatusUp && adapter.IfType != IF_TYPE_SOFTWARE_LOOPBACK {
                match adapter.IfType {
                    IF_TYPE_WWANPP | IF_TYPE_WWANPP2 => saw_cellular = true,
                    IF_TYPE_IEEE80211 => saw_wifi = true,
                    IF_TYPE_ETHERNET_CSMACD => saw_ethernet = true,
                    _ => {}
                }
            }
            adapter_ptr = adapter.Next;
        }
    }

    if saw_cellular {
        "cellular"
    } else if saw_wifi {
        "wifi"
    } else if saw_ethernet {
        "ethernet"
    } else {
        "unknown"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn test_callback_registration() {
        let monitor = NetworkMonitor::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        monitor.register_callback(Box::new(move |_event| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        }));

        // Trigger notification
        monitor.notify(NetworkEvent::Changed);
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        // Second notification
        monitor.notify(NetworkEvent::LinkUp {
            interface: "eth0".into(),
        });
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_default_values() {
        let monitor = NetworkMonitor::new();
        let network_type = monitor.get_network_type();
        assert!(matches!(
            network_type,
            "unknown" | "wifi" | "cellular" | "ethernet"
        ));
        if network_type == "cellular" {
            assert!(monitor.is_expensive());
        } else {
            assert!(!monitor.is_expensive());
        }
        assert!(!monitor.is_constrained());
    }

    #[test]
    fn test_network_snapshot_event() {
        let first = NetworkSnapshot { link_count: 1 };
        let changed = NetworkSnapshot { link_count: 2 };

        assert!(network_snapshot_event(None, first).is_none());
        assert!(network_snapshot_event(Some(first), first).is_none());
        assert!(matches!(
            network_snapshot_event(Some(first), changed),
            Some(NetworkEvent::Changed)
        ));
    }
}
