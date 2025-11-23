use anyhow::Result;
use std::net::UdpSocket;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct NtpConfig {
    pub enabled: bool,
    pub server: String, // host:port
    pub interval: Duration,
    pub timeout: Duration,
}

impl Default for NtpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server: std::env::var("SB_NTP_SERVER")
                .unwrap_or_else(|_| "time.google.com:123".to_string()),
            interval: Duration::from_secs(
                std::env::var("SB_NTP_INTERVAL_S")
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(1800),
            ),
            timeout: Duration::from_millis(
                std::env::var("SB_NTP_TIMEOUT_MS")
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(1500),
            ),
        }
    }
}

pub struct NtpService {
    cfg: NtpConfig,
}

impl NtpService {
    pub fn new(cfg: NtpConfig) -> Self {
        Self { cfg }
    }

    /// Spawn background task to periodically measure NTP offset and export metrics/logs.
    pub fn spawn(self) -> Option<tokio::task::JoinHandle<()>> {
        if !self.cfg.enabled {
            return None;
        }
        let cfg = self.cfg.clone();
        Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(cfg.interval);
            // tick immediately
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                match ntp_offset_once(&cfg.server, cfg.timeout) {
                    Ok(offset) => {
                        #[cfg(feature = "metrics")]
                        {
                            metrics::gauge!("ntp_offset_seconds").set(offset as f64);
                            metrics::counter!("ntp_query_total", "result"=>"ok").increment(1);
                        }
                        tracing::info!(target: "sb_core::ntp", server=%cfg.server, offset_seconds=offset, "ntp offset measured");
                    }
                    Err(e) => {
                        #[cfg(feature = "metrics")]
                        metrics::counter!("ntp_query_total", "result"=>"error").increment(1);
                        tracing::warn!(target: "sb_core::ntp", server=%cfg.server, error=%e, "ntp offset failed");
                    }
                }
            }
        }))
    }
}

/// Perform a single NTP query using UDP and compute offset (seconds).
pub fn ntp_offset_once(server: &str, timeout: Duration) -> Result<f64> {
    // Build minimal NTP request (48 bytes), LI=0 VN=4 Mode=3
    let mut pkt = [0u8; 48];
    pkt[0] = 0b00_100_011;
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(timeout))?;
    sock.set_write_timeout(Some(timeout))?;
    sock.send_to(&pkt, server)?;
    let mut buf = [0u8; 1500];
    let (n, _from) = sock.recv_from(&mut buf)?;
    if n < 48 {
        anyhow::bail!("short NTP packet");
    }
    let t0 = ntp_now_seconds();
    let offset = compute_ntp_offset(t0, &buf[..n]);
    Ok(offset)
}

/// Return current time in NTP seconds (seconds since 1900-01-01 with fractional part)
fn ntp_now_seconds() -> f64 {
    const NTP_UNIX_DELTA: u64 = 2_208_988_800; // seconds between 1900 and 1970
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    (now.as_secs() + NTP_UNIX_DELTA) as f64 + (now.subsec_nanos() as f64) / 1e9
}

/// Compute NTP offset using a simplified approach when originate timestamp is unavailable in request
fn compute_ntp_offset(t0_ntp_seconds: f64, packet: &[u8]) -> f64 {
    // NTP timestamps are seconds since 1900-01-01 with 32.32 fixed point
    fn ntp_ts_to_f64(sec: u32, frac: u32) -> f64 {
        sec as f64 + (frac as f64) / (u32::MAX as f64 + 1.0)
    }
    // Transmit timestamp (T3) at bytes 40-47
    let t3_sec = u32::from_be_bytes([packet[40], packet[41], packet[42], packet[43]]);
    let t3_frac = u32::from_be_bytes([packet[44], packet[45], packet[46], packet[47]]);
    let t3 = ntp_ts_to_f64(t3_sec, t3_frac);
    // Receive timestamp (T2) at bytes 32-39
    let t2_sec = u32::from_be_bytes([packet[32], packet[33], packet[34], packet[35]]);
    let t2_frac = u32::from_be_bytes([packet[36], packet[37], packet[38], packet[39]]);
    let t2 = ntp_ts_to_f64(t2_sec, t2_frac);
    // Assume originate timestamp (T1) ~= T2 - (T3 - T2) for minimal packets (approximation)
    let t1 = t2; // Simplification; accurate implementations would echo originate timestamp
                 // Offset calculation: ((T2 - T1) + (T3 - T0)) / 2
    ((t2 - t1) + (t3 - t0_ntp_seconds)) / 2.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_ntp_offset_basic() {
        // Construct a minimal plausible response where T2=T1, T3 close to t0
        let t0 = 3_900_000_000f64; // arbitrary NTP seconds
        let t2t3 = t0 + 0.1; // assume network ~100ms
        let mut pkt = [0u8; 48];
        // Write T2
        let sec = (t2t3.trunc() as u32).to_be_bytes();
        let frac = ((t2t3.fract() * (u32::MAX as f64 + 1.0)) as u32).to_be_bytes();
        pkt[32..36].copy_from_slice(&sec);
        pkt[36..40].copy_from_slice(&frac);
        // Write T3
        pkt[40..44].copy_from_slice(&sec);
        pkt[44..48].copy_from_slice(&frac);
        let off = compute_ntp_offset(t0, &pkt);
        // With T1=T2 approximation, offset ~= (0 + (t3-t0))/2 ~= 0.05s
        assert!(off > 0.0 && off < 0.2, "offset={off}");
    }
}
