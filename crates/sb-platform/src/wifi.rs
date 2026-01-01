use std::sync::Mutex;
use std::time::{Duration, Instant};

/// WiFi connection information
#[derive(Debug, Clone)]
pub struct WifiInfo {
    /// Service Set Identifier (Network Name)
    pub ssid: String,
    /// Basic Service Set Identifier (MAC Address of AP)
    pub bssid: String,
}

use once_cell::sync::Lazy;

// Simple cache to avoid spawning processes too frequently
static WIFI_CACHE: Lazy<Mutex<Option<(WifiInfo, Instant)>>> = Lazy::new(|| Mutex::new(None));

const CACHE_TTL: Duration = Duration::from_secs(5);

/// Get current WiFi SSID and BSSID
pub fn get_wifi_info() -> Option<WifiInfo> {
    // Check cache
    if let Ok(guard) = WIFI_CACHE.lock() {
        if let Some((info, time)) = &*guard {
            if time.elapsed() < CACHE_TTL {
                return Some(info.clone());
            }
        }
    }

    // Refresh
    let info = fetch_wifi_info_platform();

    // Update cache
    if let Ok(mut guard) = WIFI_CACHE.lock() {
        if let Some(i) = &info {
            *guard = Some((i.clone(), Instant::now()));
        }
    }

    info
}

#[cfg(target_os = "macos")]
fn fetch_wifi_info_platform() -> Option<WifiInfo> {
    use std::process::Command;

    // Use absolute path for safety and exact version match, though usually on PATH
    let output = Command::new("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport")
        .arg("-I")
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_airport_output(&stdout)
}

#[cfg(target_os = "macos")]
fn parse_airport_output(output: &str) -> Option<WifiInfo> {
    let mut ssid = None;
    let mut bssid = None;

    for line in output.lines() {
        let line = line.trim();
        if let Some(val) = line.strip_prefix("SSID: ") {
            ssid = Some(val.trim().to_string());
        } else if let Some(val) = line.strip_prefix("BSSID: ") {
            bssid = Some(val.trim().to_string());
        }
    }

    match (ssid, bssid) {
        (Some(ssid), Some(bssid)) => Some(WifiInfo { ssid, bssid }),
        _ => None,
    }
}

#[cfg(not(target_os = "macos"))]
fn fetch_wifi_info_platform() -> Option<WifiInfo> {
    // Other platforms stub
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "macos")]
    fn test_parse_airport() {
        let output = "
     agrCtlRSSI: -45
     agrExtRSSI: 0
    agrCtlNoise: -91
    agrExtNoise: 0
          state: running
        op mode: station 
     lastTxRate: 866
        maxRate: 1300
802.11 auth: open
      link auth: wpa2-psk
          BSSID: 11:22:33:44:55:66
           SSID: MyWiFiNetwork
            MCS: 9
  channel: 149,80
";
        let info = parse_airport_output(output).expect("should parse");
        assert_eq!(info.ssid, "MyWiFiNetwork");
        assert_eq!(info.bssid, "11:22:33:44:55:66");
    }
}
