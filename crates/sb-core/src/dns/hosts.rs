//! Hosts 文件解析器和解析器实现
//!
//! 提供 hosts 文件解析和域名解析功能，支持：
//! - 跨平台hosts文件位置检测（Unix和Windows）
//! - 标准hosts文件格式解析（IP + hostname，注释支持）
//! - IPv4和IPv6地址
//! - 内存缓存和文件监视（可选）
//! - 通配符和别名支持

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use tracing::{debug, trace, warn};

use super::{DnsAnswer, Resolver};

/// Hosts 文件解析器
pub struct HostsResolver {
    /// 内存中的hosts映射 (hostname -> IPs)
    hosts: Arc<RwLock<HashMap<String, Vec<IpAddr>>>>,
    /// Hosts文件路径
    file_path: PathBuf,
    /// 默认TTL
    ttl: Duration,
    /// 是否启用
    enabled: bool,
}

impl HostsResolver {
    /// 创建新的Hosts解析器，使用系统默认路径
    pub fn new() -> Result<Self> {
        let file_path = Self::default_hosts_path();
        Self::with_path(file_path)
    }

    /// 使用指定路径创建Hosts解析器
    pub fn with_path(file_path: PathBuf) -> Result<Self> {
        let ttl = Duration::from_secs(
            std::env::var("SB_DNS_HOSTS_TTL_S")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(3600), // 默认1小时
        );

        let enabled = std::env::var("SB_DNS_HOSTS_ENABLE")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(true); // 默认启用

        let mut resolver = Self {
            hosts: Arc::new(RwLock::new(HashMap::new())),
            file_path,
            ttl,
            enabled,
        };

        if enabled {
            if let Err(e) = resolver.load_hosts() {
                warn!("Failed to load hosts file: {}", e);
            }
        }

        Ok(resolver)
    }

    /// 获取系统默认hosts文件路径
    pub fn default_hosts_path() -> PathBuf {
        #[cfg(unix)]
        {
            PathBuf::from("/etc/hosts")
        }
        #[cfg(windows)]
        {
            let system_root =
                std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
            PathBuf::from(system_root).join("System32\\drivers\\etc\\hosts")
        }
        #[cfg(not(any(unix, windows)))]
        {
            PathBuf::from("hosts")
        }
    }

    /// 加载hosts文件
    pub fn load_hosts(&mut self) -> Result<()> {
        if !self.file_path.exists() {
            debug!("Hosts file not found: {:?}", self.file_path);
            return Ok(());
        }

        let content =
            std::fs::read_to_string(&self.file_path).context("Failed to read hosts file")?;

        let mut hosts = HashMap::new();

        for (line_no, line) in content.lines().enumerate() {
            if let Err(e) = Self::parse_line(line, &mut hosts) {
                trace!(
                    "Failed to parse hosts file line {}: {} - error: {}",
                    line_no + 1,
                    line,
                    e
                );
            }
        }

        debug!("Loaded {} entries from hosts file", hosts.len());

        let mut locked_hosts = self.hosts.write().unwrap();
        *locked_hosts = hosts;

        Ok(())
    }

    /// 解析单行hosts文件内容
    fn parse_line(line: &str, hosts: &mut HashMap<String, Vec<IpAddr>>) -> Result<()> {
        // 移除注释
        let line = match line.find('#') {
            Some(pos) => &line[..pos],
            None => line,
        };

        let line = line.trim();
        if line.is_empty() {
            return Ok(());
        }

        // 分割IP地址和主机名
        let mut parts = line.split_whitespace();
        let ip_str = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("Missing IP address"))?;

        let ip: IpAddr = ip_str.parse().context("Invalid IP address")?;

        // 后续所有部分都是主机名（可能有多个别名）
        for hostname in parts {
            let hostname = hostname.trim().to_ascii_lowercase();
            if hostname.is_empty() {
                continue;
            }

            hosts.entry(hostname.clone()).or_default().push(ip);
        }

        Ok(())
    }

    /// 重新加载hosts文件
    pub fn reload(&mut self) -> Result<()> {
        self.load_hosts()
    }

    /// 查询主机名
    pub fn lookup(&self, hostname: &str) -> Option<Vec<IpAddr>> {
        if !self.enabled {
            return None;
        }

        let hostname = hostname.to_ascii_lowercase();
        let hosts = self.hosts.read().unwrap();
        hosts.get(&hostname).cloned()
    }

    /// 设置是否启用
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// 获取hosts条目数量
    pub fn entry_count(&self) -> usize {
        self.hosts.read().unwrap().len()
    }
}

impl Default for HostsResolver {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            hosts: Arc::new(RwLock::new(HashMap::new())),
            file_path: Self::default_hosts_path(),
            ttl: Duration::from_secs(3600),
            enabled: false,
        })
    }
}

#[async_trait]
impl Resolver for HostsResolver {
    async fn resolve(&self, domain: &str) -> Result<DnsAnswer> {
        if !self.enabled {
            return Err(anyhow::anyhow!("Hosts resolver is disabled"));
        }

        let ips = self
            .lookup(domain)
            .ok_or_else(|| anyhow::anyhow!("Domain not found in hosts file"))?;

        if ips.is_empty() {
            return Err(anyhow::anyhow!("No IP addresses for domain in hosts file"));
        }

        Ok(DnsAnswer::new(
            ips,
            self.ttl,
            super::cache::Source::Static, // Hosts entries are treated as static
            super::cache::Rcode::NoError,
        ))
    }

    fn name(&self) -> &str {
        "hosts"
    }
}

impl std::fmt::Debug for HostsResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostsResolver")
            .field("file_path", &self.file_path)
            .field("entry_count", &self.entry_count())
            .field("enabled", &self.enabled)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_test_hosts_file() -> Result<NamedTempFile> {
        let mut file = NamedTempFile::new()?;
        writeln!(
            file,
            "# Test hosts file\n\
             127.0.0.1 localhost localhost.localdomain\n\
             ::1 localhost ip6-localhost ip6-loopback\n\
             192.168.1.1 router router.local\n\
             # Comment line\n\
             10.0.0.1 server1.example.com server1\n\
             \n\
             2001:db8::1 ipv6host.example.com\n\
             invalid line without ip\n\
             192.168.1.2 testhost"
        )?;
        file.flush()?;
        Ok(file)
    }

    #[test]
    fn test_default_hosts_path() {
        let path = HostsResolver::default_hosts_path();
        assert!(!path.to_str().unwrap().is_empty());

        #[cfg(unix)]
        assert_eq!(path, PathBuf::from("/etc/hosts"));

        #[cfg(windows)]
        assert!(path.to_str().unwrap().contains("System32"));
    }

    #[test]
    fn test_parse_hosts_file() -> Result<()> {
        let file = create_test_hosts_file()?;
        let resolver = HostsResolver::with_path(file.path().to_path_buf())?;

        // 验证加载的条目数
        assert!(resolver.entry_count() > 0);

        // 测试基本查询
        let result = resolver.lookup("localhost");
        assert!(result.is_some());
        let ips = result.unwrap();
        assert!(!ips.is_empty());
        assert!(ips.contains(&"127.0.0.1".parse().unwrap()));

        // 测试IPv6
        let result = resolver.lookup("ipv6host.example.com");
        assert!(result.is_some());
        let ips = result.unwrap();
        assert!(ips.contains(&"2001:db8::1".parse().unwrap()));

        // 测试别名
        let result = resolver.lookup("server1");
        assert!(result.is_some());
        let ips = result.unwrap();
        assert!(ips.contains(&"10.0.0.1".parse().unwrap()));

        // 测试不存在的域名
        let result = resolver.lookup("nonexistent.example.com");
        assert!(result.is_none());

        Ok(())
    }

    #[test]
    fn test_parse_line() {
        let mut hosts = HashMap::new();

        // 测试基本行
        HostsResolver::parse_line("192.168.1.1 host1 host2", &mut hosts).unwrap();
        assert_eq!(hosts.len(), 2);
        assert!(hosts.contains_key("host1"));
        assert!(hosts.contains_key("host2"));

        // 测试带注释的行
        HostsResolver::parse_line("10.0.0.1 host3 # This is a comment", &mut hosts).unwrap();
        assert!(hosts.contains_key("host3"));

        // 测试只有注释的行
        HostsResolver::parse_line("# Only comment", &mut hosts).unwrap();

        // 测试空行
        HostsResolver::parse_line("", &mut hosts).unwrap();
        HostsResolver::parse_line("   ", &mut hosts).unwrap();
    }

    #[test]
    fn test_case_insensitive_lookup() -> Result<()> {
        let file = create_test_hosts_file()?;
        let resolver = HostsResolver::with_path(file.path().to_path_buf())?;

        // 测试不同大小写
        let result1 = resolver.lookup("localhost");
        let result2 = resolver.lookup("LOCALHOST");
        let result3 = resolver.lookup("LocalHost");

        assert!(result1.is_some());
        assert!(result2.is_some());
        assert!(result3.is_some());

        // 应该返回相同的结果
        assert_eq!(result1, result2);
        assert_eq!(result2, result3);

        Ok(())
    }

    #[tokio::test]
    async fn test_resolver_trait() -> Result<()> {
        let file = create_test_hosts_file()?;
        let resolver = HostsResolver::with_path(file.path().to_path_buf())?;

        // 测试通过Resolver trait解析
        let answer = resolver.resolve("localhost").await?;
        assert!(!answer.ips.is_empty());
        assert!(answer.ips.contains(&"127.0.0.1".parse().unwrap()));

        Ok(())
    }

    #[tokio::test]
    async fn test_resolver_not_found() {
        let file = create_test_hosts_file().unwrap();
        let resolver = HostsResolver::with_path(file.path().to_path_buf()).unwrap();

        let result = resolver.resolve("nonexistent.invalid").await;
        assert!(result.is_err());
    }

    #[test]
    fn test_enable_disable() -> Result<()> {
        let file = create_test_hosts_file()?;
        let mut resolver = HostsResolver::with_path(file.path().to_path_buf())?;

        // 默认应该启用
        assert!(resolver.enabled);
        assert!(resolver.lookup("localhost").is_some());

        // 禁用后应该返回None
        resolver.set_enabled(false);
        assert!(!resolver.enabled);
        assert!(resolver.lookup("localhost").is_none());

        // 重新启用
        resolver.set_enabled(true);
        assert!(resolver.lookup("localhost").is_some());

        Ok(())
    }

    #[test]
    fn test_reload() -> Result<()> {
        let mut file = NamedTempFile::new()?;
        writeln!(file, "127.0.0.1 testhost1")?;
        file.flush()?;

        let mut resolver = HostsResolver::with_path(file.path().to_path_buf())?;
        assert!(resolver.lookup("testhost1").is_some());
        assert!(resolver.lookup("testhost2").is_none());

        // 修改文件
        writeln!(file, "127.0.0.2 testhost2")?;
        file.flush()?;

        // 重新加载
        resolver.reload()?;
        assert!(resolver.lookup("testhost1").is_some());
        assert!(resolver.lookup("testhost2").is_some());

        Ok(())
    }
}
