use std::time::Duration;

/// 读取布尔环境变量：存在且不为 "0" / "false" / "off" 则为 true（大小写不敏感）
pub fn env_bool(key: &str) -> bool {
    match std::env::var(key) {
        Ok(v) => {
            let s = v.trim().to_ascii_lowercase();
            !(s.is_empty() || s == "0" || s == "false" || s == "off" || s == "no")
        }
        Err(_) => false,
    }
}

/// 读取无符号整数环境（失败则返回默认值）
pub fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

/// 读取"毫秒"时长环境（失败走默认值）
pub fn env_duration_ms(key: &str, default_ms: u64) -> Duration {
    Duration::from_millis(env_u64(key, default_ms))
}

/// 读取"秒"时长环境（失败走默认值，至少 1s）
pub fn env_duration_secs_min1(key: &str, default_secs: u64) -> Duration {
    let v = env_u64(key, default_secs).max(1);
    Duration::from_secs(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_env_bool() {
        std::env::set_var("T1", "1");
        assert!(env_bool("T1"));
        std::env::set_var("T2", "true");
        assert!(env_bool("T2"));
        std::env::set_var("T3", "off");
        assert!(!env_bool("T3"));
        std::env::remove_var("T4");
        assert!(!env_bool("T4"));
    }
    #[test]
    fn test_env_numbers() {
        std::env::set_var("N1", "1500");
        assert_eq!(env_u64("N1", 7), 1500);
        assert_eq!(env_duration_ms("N1", 5).as_millis(), 1500);
        std::env::set_var("N2", "0"); // min1 生效
        assert_eq!(env_duration_secs_min1("N2", 9).as_secs(), 1);
    }
}
